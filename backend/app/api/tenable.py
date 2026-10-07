from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy import select
from types import SimpleNamespace
from urllib.parse import urlparse
from cryptography.fernet import Fernet, InvalidToken
from ..auth import admin
from ..config import settings
from ..db import get_db, SessionLocal
from ..models import SyncJob, IntegrationSettings, Audit, Asset, now
from ..services import ingest
from ..integrations.tenable import TenableClient, TenableError, normalize, first, canonical_severity, normalized_asset_tags
from ..schemas import TenableConfiguration

router = APIRouter(prefix='/tenable', tags=['Tenable'])
MAX_ACTIONABLE_VULNERABILITIES = 500000
PROGRESS_COMMIT_INTERVAL = 250

def cipher():
    key = settings().credential_encryption_key
    if not key:
        raise HTTPException(503, 'Set CREDENTIAL_ENCRYPTION_KEY on the server before saving Tenable credentials')
    try: return Fernet(key.encode())
    except ValueError: raise HTTPException(503, 'CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key')

def client_config(state):
    if not state or not state.access_key_encrypted or not state.secret_key_encrypted:
        raise HTTPException(409, 'Configure Tenable credentials first')
    try:
        access = cipher().decrypt(state.access_key_encrypted.encode()).decode()
        secret = cipher().decrypt(state.secret_key_encrypted.encode()).decode()
    except InvalidToken:
        raise HTTPException(503, 'Stored Tenable credentials cannot be decrypted with the current server key')
    base = settings()
    return SimpleNamespace(tenable_base_url=state.base_url or 'https://cloud.tenable.com', tenable_allowed_hosts=base.tenable_allowed_hosts,
                           tenable_access_key=access, tenable_secret_key=secret)

def sync_summary(job):
    counts = job.counts or {}
    if not counts:
        return None
    parts = [f"{counts.get('received', 0):,} actionable findings processed"]
    if counts.get('created'):
        parts.append(f"{counts['created']:,} new")
    if counts.get('updated'):
        parts.append(f"{counts['updated']:,} updated")
    if counts.get('informational_skipped'):
        parts.append(f"{counts['informational_skipped']:,} informational skipped")
    if counts.get('batches_processed'):
        parts.append(f"{counts['batches_processed']:,} batches complete")
    if job.status == 'Running':
        parts.append(f"{counts.get('progress_percent', 0)}% in progress")
    return ' · '.join(parts)

@router.get('')
def status(request: Request, user=Depends(admin), db=Depends(get_db)):
    state = db.get(IntegrationSettings, 1)
    jobs = db.scalars(select(SyncJob).where(SyncJob.workspace == request.state.session.workspace).order_by(SyncJob.id.desc()).limit(50)).all()
    env_configured = bool(settings().tenable_access_key and settings().tenable_secret_key)
    return {'enabled': bool(state and state.enabled), 'configured': bool(state and state.access_key_encrypted and state.secret_key_encrypted) or env_configured,
            'access_key_set': bool(state and state.access_key_encrypted) or bool(settings().tenable_access_key),
            'secret_key_set': bool(state and state.secret_key_encrypted) or bool(settings().tenable_secret_key),
            'base_url': state.base_url if state else 'https://cloud.tenable.com',
            'last_success': next((j.finished_at.isoformat() for j in jobs if j.status == 'Succeeded'), None),
            'last_failure': next((j.finished_at.isoformat() for j in jobs if j.status == 'Failed'), None),
            'jobs': [{'id': j.id, 'kind': j.kind, 'status': j.status, 'counts': j.counts, 'error': j.error or sync_summary(j), 'started_at': j.started_at.isoformat(), 'finished_at': j.finished_at.isoformat() if j.finished_at else None} for j in jobs]}

@router.put('')
def configure(data: TenableConfiguration, user=Depends(admin), db=Depends(get_db)):
    state = db.get(IntegrationSettings, 1)
    if not state:
        state = IntegrationSettings(id=1)
        db.add(state)
    state.enabled = data.enabled
    state.base_url = data.base_url
    encrypted = cipher()
    if data.access_key: state.access_key_encrypted = encrypted.encrypt(data.access_key.encode()).decode()
    if data.secret_key: state.secret_key_encrypted = encrypted.encrypt(data.secret_key.encode()).decode()
    # Validate the URL and allowlist before committing, without making a network request.
    parsed = urlparse(data.base_url)
    if parsed.scheme != 'https' or parsed.hostname not in settings().tenable_allowed_hosts.split(',') or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise HTTPException(422, 'Tenable URL must use HTTPS and an approved hostname')
    db.add(Audit(actor_id=user.id, action='tenable.configured', entity='integration', details={'enabled': data.enabled, 'base_url': data.base_url, 'credentials_updated': bool(data.access_key or data.secret_key)}))
    db.commit()
    return {'enabled': state.enabled}

@router.post('/test')
async def test(user=Depends(admin), db=Depends(get_db)):
    client = None
    try:
        state = db.get(IntegrationSettings, 1)
        client = TenableClient(client_config(state) if state and state.access_key_encrypted else settings())
        await client.test()
    except TenableError as exc:
        db.add(Audit(actor_id=user.id, action='tenable.test_failed', entity='integration', details={'error': str(exc)}))
        db.commit()
        raise HTTPException(502, str(exc))
    finally:
        if client:
            await client.close()
    db.add(Audit(actor_id=user.id, action='tenable.test_success', entity='integration'))
    db.commit()
    return {'message': 'Connection authenticated successfully'}

async def run_sync(job_id, actor_id):
    client = None
    try:
        with SessionLocal() as db:
            job = db.get(SyncJob, job_id)
            state = db.get(IntegrationSettings, 1)
            client = TenableClient(client_config(state) if state and state.access_key_encrypted else settings())
            counts = {'received': 0, 'created': 0, 'updated': 0, 'informational_skipped': 0,
                      'batches_processed': 0, 'progress_percent': 0}
            identity_cache = {}
            since_commit = 0
            async for rows in client.export(job.kind):
                for row in rows:
                    if job.kind == 'vulnerabilities':
                        # Filter before accounting: informational records never consume
                        # capacity or create/update a VRAP finding.
                        if canonical_severity(row.get('severity')) == 'Informational':
                            counts['informational_skipped'] += 1
                            continue
                        counts['received'] += 1
                        if counts['received'] > MAX_ACTIONABLE_VULNERABILITIES:
                            raise TenableError('Sync limit of 500,000 actionable vulnerabilities exceeded; narrow the Tenable export or use a durable worker for larger exports')
                        _, created = ingest(db, normalize(row), 'Tenable', row, update_existing=True, workspace=job.workspace, actor_id=actor_id, cache=identity_cache)
                    else:
                        counts['received'] += 1
                        external = row.get('id') or row.get('uuid')
                        if not external:
                            raise TenableError('Asset export is missing an identifier')
                        host = first(row.get('hostnames')) or first(row.get('fqdns')) or first(row.get('ipv4s')) or external
                        asset = db.scalar(select(Asset).where(Asset.external_id == external, Asset.workspace == job.workspace)) or db.scalar(select(Asset).where(Asset.hostname == str(host).lower(), Asset.workspace == job.workspace))
                        created = not asset
                        if not asset:
                            asset = Asset(hostname=str(host).lower(), external_id=external, workspace=job.workspace)
                            db.add(asset)
                        asset.external_id, asset.ip, asset.os, asset.tags = external, first(row.get('ipv4s')), first(row.get('operating_systems')), normalized_asset_tags(row.get('tags'))
                    counts['created' if created else 'updated'] += 1
                    since_commit += 1
                    if since_commit >= PROGRESS_COMMIT_INTERVAL:
                        # Publish partial findings and visible job progress while the
                        # export continues. This avoids a long all-or-nothing wait.
                        job.counts = dict(counts)
                        db.commit()
                        db.refresh(job)
                        if job.status == 'Cancel requested':
                            job.status, job.finished_at = 'Cancelled', now()
                            job.counts = dict(counts)
                            db.commit()
                            return
                        since_commit = 0
                counts['batches_processed'] += 1
                counts['progress_percent'] = min(99, counts['batches_processed'])
                job.counts = dict(counts)
                db.commit()
                db.refresh(job)
                if job.status == 'Cancel requested':
                    job.status, job.finished_at = 'Cancelled', now()
                    job.counts = dict(counts)
                    db.commit()
                    return
                since_commit = 0
            counts['progress_percent'] = 100
            job.status, job.counts, job.finished_at = 'Succeeded', counts, now()
            db.add(Audit(actor_id=actor_id, action='tenable.synced', entity='sync', entity_id=job.id, details=counts))
            db.commit()
    except Exception as exc:
        with SessionLocal() as db:
            job = db.get(SyncJob, job_id)
            job.status, job.finished_at = 'Failed', now()
            job.error = str(exc) if isinstance(exc, TenableError) else 'Sync stopped while normalizing or persisting upstream data; completed batches remain available.'
            db.add(Audit(actor_id=actor_id, action='tenable.sync_failed', entity='sync', entity_id=job.id, details={'error': job.error}))
            db.commit()
    finally:
        if client:
            await client.close()

@router.post('/sync/{kind}', status_code=202)
def sync(kind: str, background: BackgroundTasks, request: Request, user=Depends(admin), db=Depends(get_db)):
    if kind not in ('assets', 'vulnerabilities'):
        raise HTTPException(422, 'Choose assets or vulnerabilities')
    state = db.get(IntegrationSettings, 1)
    if not state or not state.enabled:
        raise HTTPException(409, 'Enable the integration first')
    if not ((state.access_key_encrypted and state.secret_key_encrypted) or (settings().tenable_access_key and settings().tenable_secret_key)):
        raise HTTPException(409, 'Configure credentials on the server first')
    if db.scalar(select(SyncJob).where(SyncJob.status.in_(('Running', 'Cancel requested')))):
        raise HTTPException(409, 'A sync is already running')
    job = SyncJob(kind=kind, workspace=request.state.session.workspace)
    db.add(job)
    db.flush()
    db.add(Audit(actor_id=user.id, action='tenable.sync_started', entity='sync', entity_id=job.id))
    db.commit()
    background.add_task(run_sync, job.id, user.id)
    return {'id': job.id, 'status': 'Running'}

@router.post('/sync/{job_id}/cancel')
def cancel_sync(job_id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    job = db.get(SyncJob, job_id)
    if not job or job.workspace != request.state.session.workspace:
        raise HTTPException(404, 'Synchronization job not found')
    if job.status != 'Running':
        raise HTTPException(409, 'Only a running synchronization can be stopped')
    job.status = 'Cancel requested'
    db.add(Audit(actor_id=user.id, action='tenable.sync_cancel_requested', entity='sync', entity_id=job.id))
    db.commit()
    return {'id': job.id, 'status': job.status}
