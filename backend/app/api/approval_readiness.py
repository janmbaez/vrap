"""Read-only approval readiness and governed reviewer actions for bulk context requests."""
from collections import Counter, defaultdict
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..auth import admin, writer
from ..db import get_db
from ..models import (Asset, AssetClassificationChangeRequest as Change,
                      AssetClassificationMission as Mission, AssetClassificationMissionHistory,
                      ApprovedRaciReviewerMapping, Audit, User)
from ..context_required import create_request

router = APIRouter(tags=['Approval readiness'])


def bulk_request_ids(db, workspace):
    # Audit rows predate workspace metadata, so resolve their request IDs back
    # through the authoritative change row before exposing them to a workspace.
    ids = set()
    for details in db.scalars(select(Audit.details).where(
            Audit.action == 'asset.classification_change_requested.bulk')):
        if isinstance(details, dict) and details.get('request_id'):
            ids.add(int(details['request_id']))
    if not ids:
        return []
    return sorted(db.scalars(select(Change.id).where(
        Change.workspace == workspace, Change.id.in_(ids))).all())


def inspect(db, workspace, reviewer=None, selected_ids=None):
    ids = selected_ids if selected_ids is not None else bulk_request_ids(db, workspace)
    rows = []
    for start in range(0, len(ids), 500):
        batch = ids[start:start + 500]
        items = db.execute(select(Change, Asset, Mission)
            .outerjoin(Asset, Asset.id == Change.asset_id)
            .outerjoin(Mission, (Mission.asset_id == Change.asset_id) & (Mission.workspace == workspace))
            .where(Change.workspace == workspace, Change.id.in_(batch))).all()
        validations = {}
        for audit in db.scalars(select(Audit).where(Audit.action == 'asset.classification_owner_validated',
                Audit.entity == 'classification_change_request', Audit.entity_id.in_(batch))
                .order_by(Audit.id.desc())):
            validations.setdefault(audit.entity_id, audit)
        users = {u.id: u for u in db.scalars(select(User).where(User.id.in_({v for _, _, mission in items
            if mission for v in (mission.owner_reviewer_id, mission.grc_reviewer_id) if v})))}
        for item, asset, mission in items:
            validation = validations.get(item.id)
            owner_id = mission.owner_reviewer_id if mission else None
            grc_id = mission.grc_reviewer_id if mission else None
            owner = users.get(owner_id)
            grc = users.get(grc_id)
            current = bool(asset and asset.workspace == workspace and asset.context_version == item.expected_context_version)
            valid_owner = bool(validation and owner and owner.active and owner.role != 'Viewer'
                and validation.actor_id == owner_id and owner_id not in (item.requested_by, grc_id)
                and (validation.details or {}).get('context_version') == item.expected_context_version
                and (validation.details or {}).get('proposed') == item.proposed_context
                and (validation.details or {}).get('evidence') and (validation.details or {}).get('justification'))
            independent_grc = bool(grc and grc.active and grc.role == 'Administrator'
                and grc_id not in (item.requested_by, owner_id))
            rows.append({'id': item.id, 'asset_id': item.asset_id, 'hostname': asset.hostname if asset else 'Missing asset',
                'requested_by': item.requested_by, 'owner_reviewer_id': owner_id, 'grc_reviewer_id': grc_id,
                'owner_validated': valid_owner, 'context_current': current,
                'status': item.status, 'expected_context_version': item.expected_context_version,
                'actual_context_version': asset.context_version if asset else None,
                'proposed': item.proposed_context, 'before': item.before_context,
                'evidence': item.evidence, 'justification': item.justification,
                'independent_grc': independent_grc})
    pending_by_asset = defaultdict(list)
    asset_ids = list({row['asset_id'] for row in rows})
    for start in range(0, len(asset_ids), 500):
        for pending in db.scalars(select(Change).where(Change.workspace == workspace,
                Change.status == 'Requested', Change.asset_id.in_(asset_ids[start:start + 500]))):
            pending_by_asset[pending.asset_id].append(pending)
    for row in rows:
        conflicts = [other for other in pending_by_asset[row['asset_id']] if other.id != row['id']
                     and set(other.proposed_context or {}) & set(row['proposed'])]
        row['conflicting_ids'] = [other.id for other in conflicts]
        row['equivalent_ids'] = [other.id for other in conflicts if other.proposed_context == row['proposed']
                                 and other.before_context == row['before']]
        if row['status'] != 'Requested':
            row['readiness'] = 'Completed'
        elif not row['context_current']:
            row['readiness'] = 'Stale Context'
        elif conflicts:
            row['readiness'] = 'Duplicate/Conflicting'
        elif not row['owner_reviewer_id'] or not row['grc_reviewer_id'] or not row['independent_grc']:
            row['readiness'] = 'Missing Reviewer'
        elif not row['owner_validated']:
            row['readiness'] = 'Ready for Owner Validation'
        else:
            row['readiness'] = 'Ready for GRC'
        if reviewer is not None and row['readiness'] == 'Ready for GRC' and row['grc_reviewer_id'] != reviewer.id:
            row['readiness'] = 'Missing Reviewer'
    return rows


class Selection(BaseModel):
    request_ids: list[int] = Field(min_length=1, max_length=1000)
    excluded_ids: list[int] = Field(default_factory=list, max_length=1000)


def selected_rows(db, workspace, data, reviewer=None):
    ids = list(dict.fromkeys(data.request_ids))
    if any(id <= 0 for id in ids):
        raise HTTPException(422, 'Request IDs must be positive')
    if not set(ids).issubset(set(bulk_request_ids(db, workspace))):
        raise HTTPException(404, 'Selection contains unavailable bulk requests')
    rows = inspect(db, workspace, reviewer, ids)
    if len(rows) != len(ids):
        raise HTTPException(404, 'Selection contains unavailable requests')
    return [row for row in rows if row['id'] not in data.excluded_ids]


@router.get('/approval-readiness')
def center(request: Request, status: str | None = None, offset: int = Query(0, ge=0),
           limit: int = Query(50, ge=1, le=100), user=Depends(writer), db=Depends(get_db)):
    rows = inspect(db, request.state.session.workspace)
    counts = Counter(row['readiness'] for row in rows)
    if status:
        rows = [row for row in rows if row['readiness'] == status]
    rows.sort(key=lambda row: row['id'], reverse=True)
    return {'counts': dict(counts), 'total': len(rows), 'items': rows[offset:offset + limit]}


@router.post('/approval-readiness/preview')
def preview(data: Selection, request: Request, user=Depends(admin), db=Depends(get_db)):
    rows = selected_rows(db, request.state.session.workspace, data, user)
    counts = Counter(row['readiness'] for row in rows)
    return {'total': len(rows), 'eligible': counts['Ready for GRC'],
            'blocked': len(rows) - counts['Ready for GRC'], 'counts': dict(counts),
            'examples': [{'request_id': row['id'], 'readiness': row['readiness']}
                         for row in rows if row['readiness'] != 'Ready for GRC'][:20]}


class AssignReviewers(Selection):
    grc_reviewer_id: int
    owner_overrides: dict[int, int] = Field(default_factory=dict)
    justification: str = Field(min_length=1, max_length=5000)


@router.post('/approval-readiness/prepare')
def prepare(data: Selection, request: Request, user=Depends(admin), db=Depends(get_db)):
    """One-click administrator preparation: choose eligible RACI owners and a
    distinct active GRC administrator, then record the normal assignment audit.
    It never performs owner attestation or GRC approval.
    """
    workspace = request.state.session.workspace
    rows = selected_rows(db, workspace, data)
    if not rows:
        raise HTTPException(422, 'No requests selected')
    admins = [candidate for candidate in db.scalars(select(User).where(
        User.active.is_(True), User.role == 'Administrator')).all()
              if candidate.id != user.id]
    assets = {asset.id: asset for asset in db.scalars(select(Asset).where(
        Asset.workspace == workspace, Asset.id.in_([row['asset_id'] for row in rows])))}
    users = db.scalars(select(User).where(User.active.is_(True))).all()
    mappings = {mapping.owner_name: mapping for mapping in db.scalars(select(ApprovedRaciReviewerMapping).where(
        ApprovedRaciReviewerMapping.workspace == workspace,
        ApprovedRaciReviewerMapping.active.is_(True)))}
    assignments = []
    blocked = []
    for row in rows:
        if row['readiness'] != 'Missing Reviewer' or row['status'] != 'Requested':
            blocked.append({'request_id': row['id'], 'reason': row['readiness']})
            continue
        owner = approved_owner_user(assets.get(row['asset_id']), users, mappings)
        grc = next((candidate for candidate in admins
                    if len({row['requested_by'], owner.id if owner else 0, candidate.id}) == 3), None)
        if not owner or not grc:
            blocked.append({'request_id': row['id'], 'reason': 'No independent approved RACI owner/GRC administrator'})
            continue
        assignments.append((row, owner.id, grc.id))
    for row, owner_id, grc_id in assignments:
        mission = db.scalar(select(Mission).where(Mission.asset_id == row['asset_id'],
            Mission.workspace == workspace).with_for_update())
        if not mission:
            blocked.append({'request_id': row['id'], 'reason': 'Classification mission missing'})
            continue
        mission.owner_reviewer_id, mission.grc_reviewer_id = owner_id, grc_id
        db.add(AssetClassificationMissionHistory(mission_id=mission.id, asset_id=mission.asset_id,
            workspace=workspace, actor_id=user.id, action='admin_prepare_reviewers',
            status=mission.status, current_step=mission.current_step,
            responses={'request_id': row['id'], 'owner_id': owner_id, 'grc_id': grc_id}))
        db.add(Audit(actor_id=user.id, action='asset.classification_reviewers_prepared',
            entity='classification_change_request', entity_id=row['id'],
            details={'workspace': workspace, 'owner_id': owner_id, 'grc_id': grc_id,
                     'automated': True}))
    db.commit()
    return {'prepared': len(assignments), 'blocked': blocked,
            'message': 'Reviewers prepared. Owner attestation and independent GRC approval are still required.'}


def approved_owner_user(asset, users, mappings):
    context = asset.context or {}
    provenance = asset.context_provenance or {}
    for key in ('business_owner', 'it_owner', 'application_owner', 'remediation_owner', 'patching_group'):
        if (provenance.get(key) or {}).get('approval_state') != 'Approved':
            continue
        value = str(context.get(key) or '').strip().casefold()
        matched = [user for user in users if user.username.casefold() == value and user.active and user.role != 'Viewer']
        if len(matched) == 1:
            return matched[0]
        mapping = mappings.get(value)
        if mapping:
            matched = [user for user in users if user.id == mapping.validator_id and user.active and user.role != 'Viewer']
            if len(matched) == 1:
                return matched[0]
    return None


@router.get('/approval-readiness/owner-mappings')
def list_owner_mappings(request: Request, user=Depends(admin), db=Depends(get_db)):
    return [{'id': row.id, 'owner_name': row.owner_name, 'validator_id': row.validator_id,
             'approved_by': row.approved_by, 'evidence': row.evidence, 'active': row.active}
            for row in db.scalars(select(ApprovedRaciReviewerMapping).where(
                ApprovedRaciReviewerMapping.workspace == request.state.session.workspace)
                .order_by(ApprovedRaciReviewerMapping.owner_name))]


class OwnerMapping(BaseModel):
    owner_name: str = Field(min_length=1, max_length=200)
    validator_id: int
    evidence: str = Field(min_length=1, max_length=10000)
    justification: str = Field(min_length=1, max_length=5000)


@router.post('/approval-readiness/owner-mappings')
def save_owner_mapping(data: OwnerMapping, request: Request, user=Depends(admin), db=Depends(get_db)):
    workspace = request.state.session.workspace
    validator = db.get(User, data.validator_id)
    if not validator or not validator.active or validator.role == 'Viewer' or validator.id == user.id:
        raise HTTPException(422, 'Choose an active independent owner validator')
    name = data.owner_name.strip().casefold()
    # A mapping delegates an already approved RACI owner/team. It never grants
    # authority to an unapproved, free-text classification.
    approved = False
    for asset in db.scalars(select(Asset).where(Asset.workspace == workspace)):
        for key in ('business_owner', 'it_owner', 'application_owner', 'remediation_owner', 'patching_group'):
            if str((asset.context or {}).get(key) or '').strip().casefold() == name and \
                    (asset.context_provenance or {}).get(key, {}).get('approval_state') == 'Approved':
                approved = True
                break
        if approved:
            break
    if not approved:
        raise HTTPException(422, 'This owner/team does not appear in approved RACI context in this workspace')
    row = db.scalar(select(ApprovedRaciReviewerMapping).where(
        ApprovedRaciReviewerMapping.workspace == workspace,
        ApprovedRaciReviewerMapping.owner_name == name).with_for_update())
    if not row:
        row = ApprovedRaciReviewerMapping(workspace=workspace, owner_name=name,
            validator_id=validator.id, approved_by=user.id,
            evidence=data.evidence.strip(), justification=data.justification.strip(), active=True)
        db.add(row)
    else:
        row.validator_id, row.approved_by = validator.id, user.id
        row.evidence, row.justification, row.active = data.evidence.strip(), data.justification.strip(), True
    db.flush()
    db.add(Audit(actor_id=user.id, action='asset.raci_owner_validator_mapped',
        entity='raci_reviewer_mapping', entity_id=row.id,
        details={'workspace': workspace, 'owner_name': name, 'validator_id': validator.id,
                 'evidence': row.evidence, 'justification': row.justification}))
    db.commit()
    return {'id': row.id, 'owner_name': name, 'validator_id': validator.id}


@router.post('/approval-readiness/assign-reviewers')
def assign_reviewers(data: AssignReviewers, request: Request, user=Depends(admin), db=Depends(get_db)):
    workspace = request.state.session.workspace
    rows = selected_rows(db, workspace, data)
    grc = db.get(User, data.grc_reviewer_id)
    if not grc or not grc.active or grc.role != 'Administrator':
        raise HTTPException(422, 'Choose an active GRC administrator')
    assets = {asset.id: asset for asset in db.scalars(select(Asset).where(Asset.id.in_(
        [row['asset_id'] for row in rows]), Asset.workspace == workspace))}
    users = db.scalars(select(User).where(User.active.is_(True))).all()
    mappings = {mapping.owner_name: mapping for mapping in db.scalars(
        select(ApprovedRaciReviewerMapping).where(ApprovedRaciReviewerMapping.workspace == workspace,
                                                  ApprovedRaciReviewerMapping.active.is_(True)))}
    assignments = []
    for row in rows:
        asset = assets.get(row['asset_id'])
        owner = approved_owner_user(asset, users, mappings) if asset else None
        override = data.owner_overrides.get(row['asset_id'])
        if override and (not owner or owner.id != override):
            raise HTTPException(422, f'Asset {row["hostname"]}: owner override must match an approved RACI owner')
        if row['status'] != 'Requested' or row['readiness'] in ('Stale Context', 'Duplicate/Conflicting'):
            raise HTTPException(409, f'Request #{row["id"]} is stale, conflicting or decided')
        if not owner or len({row['requested_by'], owner.id, grc.id}) != 3:
            raise HTTPException(422, f'Asset {row["hostname"]}: no independent approved RACI owner and GRC reviewer mapping')
        assignments.append((row, owner.id))
    for row, owner_id in assignments:
        mission = db.scalar(select(Mission).where(Mission.asset_id == row['asset_id'], Mission.workspace == workspace).with_for_update())
        if not mission:
            raise HTTPException(409, f'Asset {row["hostname"]} has no classification mission')
        mission.owner_reviewer_id, mission.grc_reviewer_id = owner_id, grc.id
        db.add(AssetClassificationMissionHistory(mission_id=mission.id, asset_id=mission.asset_id,
            workspace=workspace, actor_id=user.id, action='bulk_reviewers_assigned',
            status=mission.status, current_step=mission.current_step,
            responses={'request_id': row['id'], 'owner_id': owner_id, 'grc_id': grc.id,
                       'justification': data.justification.strip()}))
        db.add(Audit(actor_id=user.id, action='asset.classification_reviewers_assigned.bulk',
            entity='classification_change_request', entity_id=row['id'],
            details={'workspace': workspace, 'owner_id': owner_id, 'grc_id': grc.id,
                     'justification': data.justification.strip()}))
    db.commit()
    return {'assigned': len(assignments)}


class OwnerAttestation(Selection):
    justification: str = Field(min_length=1, max_length=5000)
    evidence: str = Field(min_length=1, max_length=10000)


class DirectApproval(Selection):
    justification: str = Field(min_length=1, max_length=5000)
    idempotency_key: str = Field(min_length=1, max_length=120)


@router.post('/approval-readiness/approve-selected', status_code=202)
def approve_selected(data: DirectApproval, request: Request, user=Depends(admin), db=Depends(get_db)):
    """Single-action GRC approval for requests already passing every gate."""
    from .classification_jobs import selection_ids, eligibility, output
    from ..models import ClassificationDecisionJob
    workspace = request.state.session.workspace
    ids = selection_ids(db, workspace, data)
    check = eligibility(db, workspace, ids, user, 'Approved')
    if check['blocked']:
        raise HTTPException(422, {'message': 'Some selected requests still need attention.', **check})
    existing = db.scalar(select(ClassificationDecisionJob).where(
        ClassificationDecisionJob.workspace == workspace,
        ClassificationDecisionJob.idempotency_key == data.idempotency_key))
    if existing:
        return output(existing)
    payload = {'status': 'Approved', 'justification': data.justification.strip(),
               'selection': {'all_pending': False, 'request_ids': ids, 'excluded_ids': [], 'through_id': None}}
    job = ClassificationDecisionJob(workspace=workspace, requested_by=user.id,
        idempotency_key=data.idempotency_key, payload=payload, request_ids=ids)
    db.add(job); db.flush()
    db.add(Audit(actor_id=user.id, action='classification.bulk_decision_queued',
        entity='classification_job', entity_id=job.id,
        details={'total': len(ids), 'decision': 'Approved', 'readiness_center': True}))
    db.commit()
    return output(job)


@router.post('/approval-readiness/validate-owner')
def validate_owner(data: OwnerAttestation, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = request.state.session.workspace
    rows = selected_rows(db, workspace, data)
    if not rows:
        raise HTTPException(422, 'No requests selected')
    # A shared attestation is permitted only for one technically compatible proposal.
    proposals = {(json.dumps(row['proposed'], sort_keys=True), row['evidence']) for row in rows}
    if len(proposals) != 1:
        raise HTTPException(422, 'Selected proposals or supporting evidence differ; validate separate cohorts')
    if any(row['readiness'] != 'Ready for Owner Validation' or row['owner_reviewer_id'] != user.id
           for row in rows):
        raise HTTPException(409, 'Selection includes requests that are stale, conflicting or assigned to another owner')
    for row in rows:
        db.add(Audit(actor_id=user.id, action='asset.classification_owner_validated',
            entity='classification_change_request', entity_id=row['id'],
            details={'workspace': workspace, 'context_version': row['expected_context_version'],
                     'proposed': row['proposed'], 'justification': data.justification.strip(),
                     'evidence': data.evidence.strip()}))
        mission = db.scalar(select(Mission).where(Mission.asset_id == row['asset_id'], Mission.workspace == workspace))
        mission.status, mission.updated_by = 'Pending GRC Approval', user.id
        db.add(AssetClassificationMissionHistory(mission_id=mission.id, asset_id=mission.asset_id,
            workspace=workspace, actor_id=user.id, action='owner_validated_bulk',
            status=mission.status, current_step=mission.current_step,
            responses={'request_id': row['id'], 'evidence': data.evidence.strip(),
                       'justification': data.justification.strip()}))
    db.commit()
    return {'validated': len(rows)}


class ReviewedAction(Selection):
    justification: str = Field(min_length=1, max_length=5000)


@router.post('/approval-readiness/deduplicate')
def deduplicate(data: ReviewedAction, request: Request, user=Depends(admin), db=Depends(get_db)):
    workspace = request.state.session.workspace
    rows = selected_rows(db, workspace, data)
    if not rows:
        raise HTTPException(422, 'No requests selected')
    selected = {row['id'] for row in rows}
    groups = defaultdict(list)
    for row in rows:
        if row['status'] != 'Requested' or not row['context_current']:
            raise HTTPException(409, f'Request #{row["id"]} is not a current pending request')
        if any(id not in selected for id in row['conflicting_ids']):
            raise HTTPException(409, f'Request #{row["id"]} has a conflicting request outside the selection')
        groups[row['asset_id']].append(row)
    superseded = []
    for group in groups.values():
        if len(group) < 2:
            continue
        if any(set(row['conflicting_ids']) - set(row['equivalent_ids']) for row in group):
            raise HTTPException(409, 'Selection contains different proposals; review them individually')
        canonical = min(group, key=lambda row: row['id'])
        superseded.extend((row['id'], canonical['id']) for row in group if row['id'] != canonical['id'])
    if not superseded:
        raise HTTPException(422, 'No equivalent duplicate requests selected')
    for duplicate_id, canonical_id in superseded:
        item = db.get(Change, duplicate_id)
        item.status = 'Superseded'
        item.decision_justification = data.justification.strip()
        db.add(Audit(actor_id=user.id, action='asset.classification_duplicate_superseded',
            entity='classification_change_request', entity_id=duplicate_id,
            details={'workspace': workspace, 'canonical_request_id': canonical_id,
                     'justification': data.justification.strip()}))
    db.commit()
    return {'superseded': len(superseded), 'canonical_ids': sorted({id for _, id in superseded})}


@router.get('/approval-readiness/{id}/rebase')
def rebase_preview(id: int, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = request.state.session.workspace
    item = db.get(Change, id)
    if not item or item.workspace != workspace or id not in set(bulk_request_ids(db, workspace)):
        raise HTTPException(404, 'Request not found')
    asset = db.get(Asset, item.asset_id)
    if not asset or asset.workspace != workspace:
        raise HTTPException(404, 'Asset not found')
    current = asset.context or {}
    conflicts = [key for key in item.proposed_context if current.get(key) not in
                 (item.before_context.get(key), item.proposed_context[key])]
    pending = [key for key, value in item.proposed_context.items() if current.get(key) != value]
    protected = [key for key in pending if (asset.context_provenance or {}).get(key, {}).get('approval_state') == 'Approved']
    return {'request_id': id, 'asset_id': asset.id, 'expected_version': item.expected_context_version,
            'current_version': asset.context_version, 'before': item.before_context, 'current': current,
            'proposed': item.proposed_context, 'pending_fields': pending,
            'conflicts': conflicts, 'protected_fields': protected,
            'eligible': item.status == 'Requested' and not conflicts and not protected and bool(pending)}


class RebaseInput(BaseModel):
    expected_current_version: int
    justification: str = Field(min_length=1, max_length=5000)
    evidence: str = Field(min_length=1, max_length=10000)


@router.post('/approval-readiness/{id}/rebase')
def rebase(id: int, data: RebaseInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    preview = rebase_preview(id, request, user, db)
    if preview['current_version'] != data.expected_current_version:
        raise HTTPException(409, 'Asset changed since rebase preview; preview again')
    if not preview['eligible']:
        raise HTTPException(409, 'Request has conflicting, protected, or no remaining changes; review manually')
    item = db.get(Change, id)
    asset = db.scalar(select(Asset).where(Asset.id == item.asset_id).with_for_update())
    changes = {key: item.proposed_context[key] for key in preview['pending_fields']}
    before = {key: (asset.context or {}).get(key) for key in changes}
    item.status = 'Superseded'
    item.decision_justification = data.justification.strip()
    new_id = create_request(db, asset, changes, before, user.id, item.workspace,
                            data.justification.strip(), data.evidence.strip(), f'rebase-{id}')
    db.add(Audit(actor_id=user.id, action='asset.classification_request_rebased',
        entity='classification_change_request', entity_id=new_id,
        details={'workspace': item.workspace, 'previous_request_id': id,
                 'old_version': item.expected_context_version, 'current_version': asset.context_version,
                 'justification': data.justification.strip()}))
    db.commit()
    return {'request_id': new_id, 'previous_request_id': id, 'status': 'Requested'}
