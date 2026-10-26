"""Durable approval processing; browser requests only enqueue and poll."""
from threading import Event, Thread
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from ..auth import admin
from ..db import SessionLocal, get_db
from ..models import ClassificationDecisionJob, AssetClassificationChangeRequest, AssetClassificationMission, Asset, User, Audit
from ..schemas import ClassificationChangeDecision
from .core import apply_classification_decision

router = APIRouter()

class Submission(ClassificationChangeDecision):
    request_ids: list[int] = Field(default_factory=list, max_length=100000)
    all_pending: bool = False
    excluded_ids: list[int] = Field(default_factory=list, max_length=100000)
    through_id: int | None = None
    idempotency_key: str = Field(min_length=1, max_length=120)

def output(job):
    return {key: getattr(job, key) for key in ('id','status','processed','succeeded','skipped','failed','errors')} | {
        'total': len(job.request_ids), 'approved': job.succeeded if job.payload['status'] == 'Approved' else 0,
        'rejected': job.succeeded if job.payload['status'] == 'Rejected' else 0,
        'blocked': len(job.request_ids) - job.processed if job.status == 'Blocked' else 0,
        'stale': sum(count for reason, count in (job.payload.get('blocked_reasons') or {}).items()
                     if 'context changed' in reason.lower())}

def eligibility(db, workspace, ids, reviewer, decision):
    """Check the same owner/GRC gates before a job can enter the worker queue."""
    counts = {}; examples = []
    for start in range(0, len(ids), 500):
        batch = ids[start:start+500]
        rows = db.execute(select(AssetClassificationChangeRequest, Asset, AssetClassificationMission)
            .outerjoin(Asset, Asset.id == AssetClassificationChangeRequest.asset_id)
            .outerjoin(AssetClassificationMission, (AssetClassificationMission.asset_id == AssetClassificationChangeRequest.asset_id) & (AssetClassificationMission.workspace == workspace))
            .where(AssetClassificationChangeRequest.id.in_(batch), AssetClassificationChangeRequest.workspace == workspace)).all()
        pending_by_asset = {}
        if decision == 'Approved':
            for pending in db.scalars(select(AssetClassificationChangeRequest).where(
                AssetClassificationChangeRequest.workspace == workspace,
                AssetClassificationChangeRequest.status == 'Requested',
                AssetClassificationChangeRequest.asset_id.in_({item.asset_id for item, _, _ in rows}))):
                pending_by_asset.setdefault(pending.asset_id, []).append(pending)
        bulk_ids = set(db.scalars(select(Audit.details['request_id'].as_integer()).where(
            Audit.action == 'asset.classification_change_requested.bulk',
            Audit.entity_id.in_([item.asset_id for item, _, _ in rows]))))
        owner_audits = {}
        owner_ids = {mission.owner_reviewer_id for _, _, mission in rows if mission and mission.owner_reviewer_id}
        owners = {owner.id: owner for owner in db.scalars(select(User).where(User.id.in_(owner_ids)))}
        for audit in db.scalars(select(Audit).where(Audit.action == 'asset.classification_owner_validated',
                Audit.entity == 'classification_change_request', Audit.entity_id.in_(batch)).order_by(Audit.id.desc())):
            owner_audits.setdefault(audit.entity_id, audit)
        for item, asset, mission in rows:
            reason = None
            if item.status != 'Requested':
                continue
            if decision == 'Approved' and any(other.id != item.id and
                    set(other.proposed_context or {}) & set(item.proposed_context or {})
                    for other in pending_by_asset.get(item.asset_id, [])):
                reason = 'Duplicate or conflicting pending change targets this asset'
            elif decision == 'Approved' and (not asset or asset.workspace != workspace or asset.context_version != item.expected_context_version):
                reason = 'Asset context changed; submit a fresh classification request'
            elif item.id in bulk_ids and reviewer.id == item.requested_by:
                reason = 'Assign an independent GRC reviewer; the submitter cannot decide this bulk request'
            elif item.id in bulk_ids and not (item.evidence or '').strip():
                reason = 'Attach request evidence'
            elif item.id in bulk_ids and decision == 'Approved':
                owner = owner_audits.get(item.id)
                if not mission or mission.grc_reviewer_id != reviewer.id:
                    reason = 'Assign this administrator as the independent GRC reviewer'
                elif not mission.owner_reviewer_id or mission.owner_reviewer_id in (reviewer.id, item.requested_by):
                    reason = 'Assign an independent asset owner reviewer'
                elif not owners.get(mission.owner_reviewer_id) or not owners[mission.owner_reviewer_id].active or owners[mission.owner_reviewer_id].role == 'Viewer':
                    reason = 'Assign an active owner reviewer with validation permission'
                elif not owner or owner.actor_id != mission.owner_reviewer_id or not (owner.details or {}).get('evidence') or not (owner.details or {}).get('justification'):
                    reason = 'Complete owner validation with evidence and rationale'
                elif owner.details.get('context_version') != item.expected_context_version or owner.details.get('proposed') != item.proposed_context:
                    reason = 'Owner validation is stale; validate the current proposal'
            if reason:
                counts[reason] = counts.get(reason, 0) + 1
                if len(examples) < 20: examples.append({'request_id': item.id, 'reason': reason})
    return {'blocked': sum(counts.values()), 'reasons': counts, 'examples': examples}


def selection_ids(db, workspace, data):
    ids = list(dict.fromkeys(data.request_ids))
    if data.all_pending:
        if data.through_id is None:
            raise HTTPException(422, 'Select all pending requests before submitting')
        excluded = set(data.excluded_ids)
        ids = [id for id in db.scalars(select(AssetClassificationChangeRequest.id).where(
            AssetClassificationChangeRequest.workspace == workspace,
            AssetClassificationChangeRequest.status == 'Requested',
            AssetClassificationChangeRequest.id <= data.through_id).order_by(AssetClassificationChangeRequest.id))
            if id not in excluded]
    else:
        found = set()
        for start in range(0, len(ids), 500):
            found.update(db.scalars(select(AssetClassificationChangeRequest.id).where(
                AssetClassificationChangeRequest.workspace == workspace,
                AssetClassificationChangeRequest.id.in_(ids[start:start + 500]))))
        if found != set(ids):
            raise HTTPException(404, 'Selection contains unavailable requests')
    if not ids:
        raise HTTPException(422, 'No pending requests selected')
    return ids


@router.post('/classification-decision-jobs/preview')
def preview(data: Submission, request: Request, user=Depends(admin), db=Depends(get_db)):
    ids = selection_ids(db, request.state.session.workspace, data)
    check = eligibility(db, request.state.session.workspace, ids, user, data.status)
    return {'total': len(ids), 'eligible': len(ids) - check['blocked'], **check}

@router.post('/classification-decision-jobs', status_code=202)
def submit(data: Submission, request: Request, user=Depends(admin), db=Depends(get_db)):
    workspace = request.state.session.workspace
    existing = db.scalar(select(ClassificationDecisionJob).where(ClassificationDecisionJob.workspace == workspace, ClassificationDecisionJob.idempotency_key == data.idempotency_key))
    ids = list(dict.fromkeys(data.request_ids))
    selection = {'all_pending': data.all_pending, 'request_ids': ids, 'excluded_ids': sorted(set(data.excluded_ids)), 'through_id': data.through_id}
    payload = {'status': data.status, 'justification': data.justification.strip(), 'selection': selection}
    if not payload['justification']:
        raise HTTPException(422, 'A decision rationale is required')
    if existing:
        if {key: value for key, value in existing.payload.items() if key != 'blocked_reasons'} != payload:
            raise HTTPException(409, 'Idempotency key belongs to a different decision')
        return output(existing)
    ids = selection_ids(db, workspace, data)
    check = eligibility(db, workspace, ids, user, data.status)
    if check['blocked']:
        raise HTTPException(422, {'message': 'Approval prerequisites are incomplete. Resolve them before starting a job.', **check})
    job = ClassificationDecisionJob(workspace=workspace, requested_by=user.id, idempotency_key=data.idempotency_key, payload=payload, request_ids=ids)
    db.add(job); db.flush()
    db.add(Audit(actor_id=user.id, action='classification.bulk_decision_queued', entity='classification_job', entity_id=job.id, details={'total':len(ids),'decision':data.status}))
    db.commit()
    return output(job)

@router.get('/classification-decision-jobs/{id}')
def progress(id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    job = db.get(ClassificationDecisionJob, id)
    if not job or job.workspace != request.state.session.workspace:
        raise HTTPException(404, 'Job not found')
    return output(job)

@router.get('/classification-decision-jobs')
def recent_jobs(request: Request, user=Depends(admin), db=Depends(get_db)):
    jobs = db.scalars(select(ClassificationDecisionJob).where(ClassificationDecisionJob.workspace == request.state.session.workspace)
        .order_by(ClassificationDecisionJob.id.desc()).limit(10)).all()
    return [output(job) for job in jobs]

@router.post('/classification-decision-jobs/{id}/resume')
def resume(id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    job = db.scalar(select(ClassificationDecisionJob).where(ClassificationDecisionJob.id == id).with_for_update())
    if not job or job.workspace != request.state.session.workspace:
        raise HTTPException(404, 'Job not found')
    if job.status != 'Blocked':
        raise HTTPException(409, 'Only blocked jobs can resume; recover completed jobs as a new attempt')
    check = eligibility(db, job.workspace, job.request_ids[job.processed:], user, job.payload['status'])
    if check['blocked']:
        raise HTTPException(422, {'message': 'Resolve approval prerequisites before resuming.', **check})
    job.requested_by = user.id
    job.payload = {key: value for key, value in job.payload.items() if key != 'blocked_reasons'}
    job.status = 'Queued'
    db.add(Audit(actor_id=user.id, action='classification.bulk_decision_resumed', entity='classification_job', entity_id=id,
                 details={'total': len(job.request_ids), 'resume_from': job.processed}))
    db.commit()
    return output(job)


@router.post('/classification-decision-jobs/{id}/recover', status_code=202)
def recover(id: int, request: Request, idempotency_key: str = Query(min_length=1, max_length=120),
            user=Depends(admin), db=Depends(get_db)):
    old = db.get(ClassificationDecisionJob, id)
    if not old or old.workspace != request.state.session.workspace:
        raise HTTPException(404, 'Job not found')
    if old.status != 'Completed with errors':
        raise HTTPException(409, 'Only completed jobs with failures can be recovered')
    existing = db.scalar(select(ClassificationDecisionJob).where(
        ClassificationDecisionJob.workspace == old.workspace,
        ClassificationDecisionJob.idempotency_key == idempotency_key))
    if existing:
        if existing.payload.get('recovery_of') != id:
            raise HTTPException(409, 'Idempotency key belongs to another attempt')
        return output(existing)
    remaining = []
    for start in range(0, len(old.request_ids), 500):
        remaining.extend(db.scalars(select(AssetClassificationChangeRequest.id).where(
            AssetClassificationChangeRequest.workspace == old.workspace,
            AssetClassificationChangeRequest.status == 'Requested',
            AssetClassificationChangeRequest.id.in_(old.request_ids[start:start + 500]))))
    if not remaining:
        raise HTTPException(409, 'No pending failed requests remain')
    check = eligibility(db, old.workspace, remaining, user, old.payload['status'])
    if check['blocked']:
        raise HTTPException(422, {'message': 'Resolve prerequisites before recovery.', **check})
    fresh = ClassificationDecisionJob(workspace=old.workspace, requested_by=user.id,
        idempotency_key=idempotency_key, status='Queued',
        payload={'status':old.payload['status'], 'justification':old.payload['justification'],
                 'recovery_of':id}, request_ids=remaining)
    db.add(fresh);db.flush()
    db.add(Audit(actor_id=user.id, action='classification.bulk_decision_recovered',
        entity='classification_job', entity_id=fresh.id,
        details={'previous_job_id':id, 'pending_requests':len(remaining), 'workspace':old.workspace}))
    db.commit()
    return output(fresh)

def process_one(db):
    job = db.scalar(select(ClassificationDecisionJob).where(ClassificationDecisionJob.status.in_(['Queued','Running'])).order_by(ClassificationDecisionJob.id).with_for_update(skip_locked=True).limit(1))
    if not job: return False
    if job.status == 'Queued':
        reviewer = db.get(User, job.requested_by)
        if not reviewer or not reviewer.active or reviewer.role != 'Administrator':
            job.status = 'Blocked'
            job.errors = [*job.errors[:99], {'request_id': None, 'error': 'Assigned GRC administrator is unavailable'}]
            db.commit()
            return True
        check = eligibility(db, job.workspace, job.request_ids[job.processed:], reviewer, job.payload['status'])
        if check['blocked']:
            job.status = 'Blocked'
            job.payload = {**job.payload, 'blocked_reasons': check['reasons']}
            job.errors = [*job.errors[:80], *[{'request_id': example['request_id'], 'error': example['reason']}
                                             for example in check['examples']]]
            db.add(Audit(actor_id=reviewer.id, action='classification.bulk_decision_blocked',
                entity='classification_job', entity_id=job.id,
                details={'processed': job.processed, 'blocked': check['blocked'], 'reasons': check['reasons']}))
            db.commit()
            return True
    job.status = 'Running'
    if job.processed < len(job.request_ids):
        request_id = job.request_ids[job.processed]
        try:
            with db.begin_nested():
                user = db.get(User, job.requested_by)
                if not user or not user.active or user.role != 'Administrator':
                    raise HTTPException(403, 'Administrator permission is no longer available')
                item = db.scalar(select(AssetClassificationChangeRequest).where(AssetClassificationChangeRequest.id == request_id).with_for_update())
                if not item or item.workspace != job.workspace:
                    raise HTTPException(404, 'Request unavailable')
                if item.status != 'Requested':
                    job.skipped += 1
                else:
                    apply_classification_decision(request_id, ClassificationChangeDecision(status=job.payload['status'], justification=job.payload['justification']), job.workspace, user, db, commit=False)
                    job.succeeded += 1
        except HTTPException as exc:
            if exc.status_code in (403, 409):
                job.status = 'Blocked'
                job.payload = {**job.payload, 'blocked_reasons': {str(exc.detail): 1}}
                job.errors = [*job.errors[:99], {'request_id':request_id,'error':str(exc.detail)}]
                db.add(Audit(actor_id=job.requested_by, action='classification.bulk_decision_blocked', entity='classification_job', entity_id=job.id,
                             details={'request_id':request_id,'reason':str(exc.detail),'processed':job.processed}))
                db.commit()
                return True
            job.failed += 1
            if len(job.errors) < 100:
                job.errors = [*job.errors, {'request_id':request_id,'error':str(exc.detail)}]
        except IntegrityError:
            job.failed += 1
            if len(job.errors) < 100:
                job.errors = [*job.errors, {'request_id':request_id,'error':'The decision conflicts with existing data.'}]
        except SQLAlchemyError:
            raise
        except Exception:
            import logging
            logging.getLogger(__name__).exception('Classification request %s failed', request_id)
            job.failed += 1
            if len(job.errors) < 100:
                job.errors = [*job.errors, {'request_id':request_id,'error':'Processing failed; inspect server logs before retrying.'}]
        # Unexpected infrastructure failures roll back the entire checkpoint
        # and remain pending for the next worker iteration/restart.
        job.processed += 1
    if job.processed == len(job.request_ids):
        job.status = 'Completed with errors' if job.failed else 'Completed'
    db.commit()
    return True

def start_worker():
    stop = Event()
    def run():
        while not stop.is_set():
            try:
                with SessionLocal() as db:
                    worked = process_one(db)
                if not worked: stop.wait(1)
            except Exception:
                import logging
                logging.getLogger(__name__).exception('Classification worker will retry its pending checkpoint')
                stop.wait(5)
    thread = Thread(target=run, daemon=True, name='classification-decisions')
    thread.start()
    return stop
