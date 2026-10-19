"""Durable approval processing; browser requests only enqueue and poll."""
from threading import Event, Thread
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from ..auth import admin
from ..db import SessionLocal, get_db
from ..models import ClassificationDecisionJob, AssetClassificationChangeRequest, User, Audit
from ..schemas import ClassificationChangeDecision
from .core import apply_classification_decision

router = APIRouter()

class Submission(ClassificationChangeDecision):
    request_ids: list[int] = Field(default_factory=list, max_length=100000)
    all_pending: bool = False
    excluded_ids: list[int] = Field(default_factory=list, max_length=100000)
    through_id: int | None = None
    idempotency_key: str = Field(min_length=1, max_length=120)

def self_authored_bulk_request(db, workspace, user_id, ids, *, all_pending=False, through_id=None, excluded_ids=None):
    """Find one bulk proposal authored by the reviewer before enqueuing a large job."""
    base = (select(AssetClassificationChangeRequest.id)
            .join(Audit, and_(
                Audit.action == 'asset.classification_change_requested.bulk',
                Audit.entity_id == AssetClassificationChangeRequest.asset_id,
                Audit.details['request_id'].as_integer() == AssetClassificationChangeRequest.id))
            .where(AssetClassificationChangeRequest.workspace == workspace,
                   AssetClassificationChangeRequest.requested_by == user_id))
    if all_pending:
        query = base.where(AssetClassificationChangeRequest.status == 'Requested',
                           AssetClassificationChangeRequest.id <= through_id)
        if excluded_ids:
            query = query.where(~AssetClassificationChangeRequest.id.in_(excluded_ids))
        return db.scalar(query.limit(1))
    for start in range(0, len(ids), 500):
        found = db.scalar(base.where(AssetClassificationChangeRequest.id.in_(ids[start:start + 500])).limit(1))
        if found is not None:
            return found
    return None


def output(job):
    return {key: getattr(job, key) for key in ('id','status','processed','succeeded','skipped','failed','errors')} | {'total': len(job.request_ids)}

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
        if existing.payload != payload:
            raise HTTPException(409, 'Idempotency key belongs to a different decision')
        return output(existing)
    if data.all_pending:
        if data.through_id is None:
            raise HTTPException(422, 'Select all pending requests before submitting')
        excluded = set(data.excluded_ids)
        ids = [id for id in db.scalars(select(AssetClassificationChangeRequest.id).where(AssetClassificationChangeRequest.workspace == workspace, AssetClassificationChangeRequest.status == 'Requested', AssetClassificationChangeRequest.id <= data.through_id).order_by(AssetClassificationChangeRequest.id)) if id not in excluded]
    else:
        found = set()
        for start in range(0, len(ids), 500):
            found.update(db.scalars(select(AssetClassificationChangeRequest.id).where(AssetClassificationChangeRequest.workspace == workspace, AssetClassificationChangeRequest.id.in_(ids[start:start+500]))))
        if found != set(ids):
            raise HTTPException(404, 'Selection contains unavailable requests')
    if not ids:
        raise HTTPException(422, 'No pending requests selected')
    conflicting = self_authored_bulk_request(
        db, workspace, user.id, ids, all_pending=data.all_pending,
        through_id=data.through_id, excluded_ids=data.excluded_ids)
    if conflicting is not None:
        raise HTTPException(403, f'Request #{conflicting} was submitted by your account. '
                            'Bulk classifications require a different GRC administrator '
                            'and independent owner validation before approval.')
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

def process_one(db):
    job = db.scalar(select(ClassificationDecisionJob).where(ClassificationDecisionJob.status.in_(['Queued','Running'])).order_by(ClassificationDecisionJob.id).with_for_update(skip_locked=True).limit(1))
    if not job: return False
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
                if item.status == job.payload['status']:
                    job.skipped += 1
                else:
                    apply_classification_decision(request_id, ClassificationChangeDecision(status=job.payload['status'], justification=job.payload['justification']), job.workspace, user, db, commit=False)
                    job.succeeded += 1
        except HTTPException as exc:
            # A global SoD/reviewer prerequisite must not consume tens of
            # thousands of pending requests as individual failed decisions.
            if exc.status_code == 403 and str(exc.detail) in (
                'Bulk classification requires an independent GRC reviewer',
                'Independent assigned owner validation and GRC approval are required',
            ):
                job.status = 'Blocked'
                if len(job.errors) < 100:
                    job.errors = [*job.errors, {'request_id': request_id, 'error': str(exc.detail)}]
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
