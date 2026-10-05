from pathlib import PurePath
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request, BackgroundTasks
from sqlalchemy import select, update
from pydantic import ValidationError
from ..db import get_db, SessionLocal
from ..auth import writer
from ..models import ImportBatch, ImportRow, Audit, Asset, Vulnerability, Finding
from ..schemas import MappingInput
from ..services import ingest, identity
from ..imports.parser import parse_file, normalize, MAX_BYTES, FIELDS

router = APIRouter(prefix='/imports', tags=['Imports'])

def batch_for(db, id, user):
    batch = db.get(ImportBatch, id)
    if not batch:
        raise HTTPException(404, 'Import not found')
    if batch.owner_id != user.id and user.role != 'Administrator':
        raise HTTPException(403, 'This import belongs to another analyst')
    if batch.status == 'Imported':
        raise HTTPException(409, 'This batch was already imported')
    return batch

@router.get('')
def batches(request: Request, user=Depends(writer), db=Depends(get_db)):
    query = select(ImportBatch).where(ImportBatch.workspace == request.state.session.workspace).order_by(ImportBatch.id.desc())
    if user.role != 'Administrator':
        query = query.where(ImportBatch.owner_id == user.id)
    return [{'id': b.id, 'filename': b.filename, 'status': b.status, 'counts': b.counts, 'date': b.created_at.isoformat()} for b in db.scalars(query.limit(100))]

@router.post('/preview')
async def preview(request: Request, file: UploadFile = File(...), user=Depends(writer), db=Depends(get_db)):
    content = await file.read(MAX_BYTES + 1)
    try:
        headers, rows = parse_file(file.filename or '', file.content_type, content)
    except Exception as exc:
        if isinstance(exc, (ValueError, UnicodeError)):
            raise HTTPException(422, str(exc)[:200])
        raise HTTPException(422, 'Could not parse file. Use a valid CSV or XLSX workbook.')
    batch = ImportBatch(owner_id=user.id, filename=PurePath(file.filename).name[:255], source='CSV' if file.filename.lower().endswith('.csv') else 'Excel', headers=headers, counts={'detected': len(rows)}, workspace=request.state.session.workspace)
    db.add(batch)
    db.flush()
    for number, row in rows:
        db.add(ImportRow(import_id=batch.id, row_number=number, original=row))
    db.add(Audit(actor_id=user.id, action='import.previewed', entity='import', entity_id=batch.id, details={'rows': len(rows)}))
    db.commit()
    aliases = {
        'hostname': ['hostname', 'host', 'asset', 'asset.name', 'asset.host_name'],
        'ip': ['ip', 'ip address', 'asset.display_ipv4_address'],
        'name': ['name', 'plugin name', 'plugin_name', 'definition.name'],
        'plugin_id': ['plugin id', 'plugin_id', 'definition.id'],
        'cves': ['cve', 'cves', 'definition.cve'],
        'cvss': ['cvss', 'cvss v3'],
        'vpr': ['vpr', 'definition.vpr.score'],
        'kev': ['kev', 'definition.vpr.drivers_on_cisa_kev'],
        'exploit_available': ['exploit_available', 'definition.exploitability_ease'],
        'first_seen': ['first_seen', 'first observed', 'first_observed'],
        'last_seen': ['last_seen', 'last seen'],
        'asset_tags': ['asset.tags', 'asset_tags', 'tags', 'asset tags'],
    }
    # Prefer aliases in declared order. Tenable exports include both asset.name
    # and asset.host_name, but the latter is blank for some assets.
    mapping = {f: next((h for alias in aliases.get(f, [f, f.replace('_', ' ')])
                        for h in headers if h.lower() == alias), '') for f in FIELDS}
    return {'id': batch.id, 'headers': headers, 'rows': [r for _, r in rows[:10]], 'detected': len(rows), 'fields': FIELDS, 'mapping': mapping}

def validate_rows(db, batch, mapping):
    if set(mapping) - set(FIELDS) or any(c and c not in batch.headers for c in mapping.values()):
        raise HTTPException(422, 'Mapping contains unknown fields or headers')
    if not mapping.get('name') or not (mapping.get('hostname') or mapping.get('ip')):
        raise HTTPException(422, 'Map Plugin Name and either Hostname or IP')
    seen, valid, errors, duplicates = set(), [], [], 0
    for row in db.scalars(select(ImportRow).where(ImportRow.import_id == batch.id).order_by(ImportRow.row_number)):
        try:
            data = normalize(row.original, mapping)
            key = (data.hostname.lower(), identity(data), data.port, data.protocol)
            exists = db.scalar(select(Finding.id).join(Asset).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id).where(Asset.hostname == key[0], Vulnerability.identity == key[1], Finding.port == key[2], Finding.protocol == key[3]))
            if key in seen or exists:
                duplicates += 1
                row.errors = ['Duplicate finding; skipped']
            else:
                valid.append((row, data))
                row.errors = []
            seen.add(key)
        except (ValueError, ValidationError) as exc:
            message = '; '.join(f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors()) if isinstance(exc, ValidationError) else str(exc)
            row.errors = [message[:1000]]
            errors.append({'row': row.row_number, 'error': message[:1000]})
    counts = {'detected': batch.counts['detected'], 'valid': len(valid), 'rejected': len(errors), 'duplicates': duplicates}
    return valid, errors, counts

@router.post('/{id}/validate')
def validate(id: int, data: MappingInput, user=Depends(writer), db=Depends(get_db)):
    batch = batch_for(db, id, user)
    _, errors, counts = validate_rows(db, batch, data.mapping)
    batch.mapping, batch.counts, batch.status = data.mapping, counts, 'Validated'
    db.commit()
    return {'counts': counts, 'errors': errors}

@router.post('/{id}/commit')
def commit(id: int, data: MappingInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    batch = batch_for(db, id, user)
    if batch.status != 'Validated' or batch.mapping != data.mapping:
        raise HTTPException(409, 'Validate this mapping before importing')
    claimed = db.execute(update(ImportBatch).where(ImportBatch.id == id, ImportBatch.status == 'Validated').values(status='Importing'))
    if claimed.rowcount != 1:
        raise HTTPException(409, 'Import already in progress')
    valid, errors, counts = validate_rows(db, batch, data.mapping)
    for row, normalized in valid:
        finding, _ = ingest(db, normalized, batch.source, row.original, workspace=request.state.session.workspace)
        row.instance_id = finding.id
    counts['imported'] = len(valid)
    batch.status, batch.counts = 'Imported', counts
    db.add(Audit(actor_id=user.id, action='import.committed', entity='import', entity_id=id, details=counts))
    db.commit()
    return {'counts': counts, 'errors': errors}

def run_import_job(id: int, actor_id: int, workspace: str):
    """Durable in-process worker: state and progress live in the database.

    A process restart leaves an Importing job visible and retryable rather than
    falsely reporting success. A dedicated queue can run this same worker later.
    """
    with SessionLocal() as db:
        batch = db.get(ImportBatch, id)
        if not batch or batch.status != 'Queued': return
        batch.status = 'Importing'; db.commit()
        try:
            valid, errors, counts = validate_rows(db, batch, batch.mapping)
            counts.update({'processed': 0, 'imported': 0})
            batch.counts = counts; db.commit()
            for index, (row, normalized) in enumerate(valid, 1):
                db.refresh(batch)
                if batch.status == 'Cancelling':
                    batch.status = 'Cancelled'; batch.counts = {**batch.counts, 'processed': index - 1}; db.commit(); return
                finding, _ = ingest(db, normalized, batch.source, row.original, workspace=workspace)
                row.instance_id = finding.id
                if index % 250 == 0:
                    batch.counts = {**batch.counts, 'processed': index, 'imported': index}; db.commit()
            batch.status = 'Imported'; batch.counts = {**counts, 'processed': len(valid), 'imported': len(valid)}
            db.add(Audit(actor_id=actor_id, action='import.committed', entity='import', entity_id=id, details=batch.counts)); db.commit()
        except Exception as exc:
            db.rollback(); batch = db.get(ImportBatch, id)
            if batch:
                batch.status = 'Failed'; batch.counts = {**(batch.counts or {}), 'error': str(exc)[:500]}; db.commit()

@router.post('/{id}/queue', status_code=202)
def queue_import(id: int, data: MappingInput, request: Request, tasks: BackgroundTasks, user=Depends(writer), db=Depends(get_db)):
    batch = batch_for(db, id, user)
    if batch.status not in ('Validated', 'Failed', 'Cancelled') or batch.mapping != data.mapping:
        raise HTTPException(409, 'Validate this mapping before queueing the import')
    batch.status = 'Queued'; batch.counts = {**batch.counts, 'processed': 0}; db.commit()
    tasks.add_task(run_import_job, id, user.id, request.state.session.workspace)
    return {'id': id, 'status': 'Queued', 'message': 'Import queued. You can leave this page and monitor its progress.'}

@router.post('/{id}/cancel')
def cancel_import(id: int, user=Depends(writer), db=Depends(get_db)):
    batch = db.get(ImportBatch, id)
    if not batch or (batch.owner_id != user.id and user.role != 'Administrator'): raise HTTPException(404, 'Import not found')
    if batch.status not in ('Queued', 'Importing'): raise HTTPException(409, 'Only queued or running imports can be cancelled')
    batch.status = 'Cancelling' if batch.status == 'Importing' else 'Cancelled'; db.commit()
    return {'id': id, 'status': batch.status}

@router.post('/{id}/retry', status_code=202)
def retry_import(id: int, request: Request, tasks: BackgroundTasks, user=Depends(writer), db=Depends(get_db)):
    batch = db.get(ImportBatch, id)
    if not batch or (batch.owner_id != user.id and user.role != 'Administrator'): raise HTTPException(404, 'Import not found')
    if batch.status not in ('Failed', 'Cancelled', 'Importing'):
        raise HTTPException(409, 'Only failed, cancelled, or interrupted imports can be retried')
    if not batch.mapping: raise HTTPException(409, 'Validate the mapping before retrying')
    batch.status = 'Queued'; batch.counts = {**(batch.counts or {}), 'processed': 0}; db.commit()
    tasks.add_task(run_import_job, id, user.id, request.state.session.workspace)
    return {'id': id, 'status': 'Queued'}
