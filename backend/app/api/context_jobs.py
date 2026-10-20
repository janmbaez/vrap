"""Durable context classification proposals; approval remains an independent workflow."""
import logging
from threading import Event, Thread

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..auth import writer
from ..db import SessionLocal, get_db
from ..models import (Asset, AssetClassificationChangeRequest, Audit,
                      ContextClassificationJob)
from ..context_required import create_request

router = APIRouter(tags=['Workbench'])


def output(job):
    queued = max(0, len(job.asset_ids) - job.processed)
    return {key: getattr(job, key) for key in ('id', 'status', 'awaiting_approval',
                                               'unchanged', 'conflicted', 'failed', 'errors')} | {
        'processed': job.total_assets - queued, 'total': job.total_assets, 'queued': queued,
        'preview_id': job.preview_id}


@router.get('/smart-assessment/context-required/jobs')
def list_jobs(request: Request, user=Depends(writer), db=Depends(get_db)):
    rows = db.scalars(select(ContextClassificationJob).where(
        ContextClassificationJob.workspace == request.state.session.workspace)
        .order_by(ContextClassificationJob.id.desc()).limit(20)).all()
    return {'items': [output(row) for row in rows]}


@router.get('/smart-assessment/context-required/jobs/{id}')
def progress(id: int, request: Request, user=Depends(writer), db=Depends(get_db)):
    job = db.get(ContextClassificationJob, id)
    if not job or job.workspace != request.state.session.workspace:
        raise HTTPException(404, 'Classification job not found')
    return output(job)


@router.post('/smart-assessment/context-required/jobs/{id}/cancel')
def cancel(id: int, request: Request, user=Depends(writer), db=Depends(get_db)):
    job = db.scalar(select(ContextClassificationJob).where(
        ContextClassificationJob.id == id,
        ContextClassificationJob.workspace == request.state.session.workspace).with_for_update())
    if not job:
        raise HTTPException(404, 'Classification job not found')
    if job.status not in ('Queued', 'Running'):
        raise HTTPException(409, 'Only queued or running jobs can be canceled')
    job.status = 'Cancel requested'
    db.add(Audit(actor_id=user.id, action='asset.classification_bulk.cancel_requested',
                 entity='classification_job', entity_id=job.id, details={'workspace': job.workspace}))
    db.commit()
    return output(job)


@router.post('/smart-assessment/context-required/jobs/{id}/retry')
def retry(id: int, request: Request, user=Depends(writer), db=Depends(get_db)):
    job = db.scalar(select(ContextClassificationJob).where(
        ContextClassificationJob.id == id,
        ContextClassificationJob.workspace == request.state.session.workspace).with_for_update())
    if not job:
        raise HTTPException(404, 'Classification job not found')
    if job.status not in ('Completed with errors', 'Canceled'):
        raise HTTPException(409, 'Only failed or canceled jobs can be retried')
    ids = list(job.retry_ids)
    if job.status == 'Canceled':
        ids += job.asset_ids[job.processed:]
    ids = list(dict.fromkeys(ids))
    if not ids:
        raise HTTPException(409, 'No unresolved assets remain in this job')
    job.asset_ids, job.processed, job.failed, job.conflicted = ids, 0, 0, 0
    job.errors, job.retry_ids, job.status = [], [], 'Queued'
    db.add(Audit(actor_id=user.id, action='asset.classification_bulk.retried',
                 entity='classification_job', entity_id=job.id,
                 details={'workspace': job.workspace, 'asset_count': len(ids)}))
    db.commit()
    return output(job)


def process_batch(db, size=100):
    job = db.scalar(select(ContextClassificationJob).where(
        ContextClassificationJob.status.in_(['Queued', 'Running', 'Cancel requested']))
        .order_by(ContextClassificationJob.id).with_for_update(skip_locked=True).limit(1))
    if not job:
        return False
    if job.status == 'Cancel requested':
        job.status = 'Canceled'
        db.commit()
        return True
    job.status = 'Running'
    batch = job.asset_ids[job.processed:job.processed + size]
    retry_ids = list(job.retry_ids)
    errors = list(job.errors)
    for asset_id in batch:
        proposal = job.proposals[str(asset_id)]
        changes = proposal['changes']
        if not changes:
            job.unchanged += 1
            job.processed += 1
            continue
        try:
            with db.begin_nested():
                asset = db.scalar(select(Asset).where(Asset.id == asset_id,
                    Asset.workspace == job.workspace).with_for_update())
                if not asset or asset.context_version != proposal['version']:
                    raise HTTPException(409, 'Asset context changed; review and preview it again')
                before = {key: (asset.context or {}).get(key) for key in changes}
                if before != proposal['before']:
                    raise HTTPException(409, 'Asset context changed; review and preview it again')
                pending = db.scalars(select(AssetClassificationChangeRequest).where(
                    AssetClassificationChangeRequest.asset_id == asset_id,
                    AssetClassificationChangeRequest.workspace == job.workspace,
                    AssetClassificationChangeRequest.status == 'Requested')).all()
                if any(set(item.proposed_context or {}) & set(changes) for item in pending):
                    raise HTTPException(409, 'An overlapping approval request is pending')
                create_request(db, asset, changes, before, job.requested_by, job.workspace,
                               job.justification, job.evidence, job.preview_id, job.id)
            job.awaiting_approval += 1
        except (HTTPException, IntegrityError) as exc:
            if isinstance(exc, HTTPException) and exc.status_code == 409:
                job.conflicted += 1
            else:
                job.failed += 1
            if len(errors) < 500:
                errors.append({'asset_id': asset_id,
                               'error': str(exc.detail) if isinstance(exc, HTTPException) else 'Database conflict'})
            retry_ids.append(asset_id)
        job.processed += 1
    job.errors = errors
    job.retry_ids = retry_ids
    if job.processed >= len(job.asset_ids):
        job.status = 'Completed with errors' if job.failed or job.conflicted else 'Completed'
    db.commit()
    return True


def start_worker():
    stop = Event()
    def run():
        while not stop.is_set():
            try:
                with SessionLocal() as db:
                    worked = process_batch(db)
                if not worked:
                    stop.wait(1)
            except Exception:
                logging.getLogger(__name__).exception('Context classification worker will retry its checkpoint')
                stop.wait(5)
    Thread(target=run, daemon=True, name='context-classification').start()
    return stop
