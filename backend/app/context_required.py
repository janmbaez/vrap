"""Authoritative context-required cohort, shared by listing and bulk proposals."""
import hashlib
import json
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException
from sqlalchemy import select, func, case, or_, and_, exists, update

from .models import (Finding, Asset, Vulnerability, Assessment, AssetRegulatoryScope,
                     AssetClassificationChangeRequest, AssetClassificationMission, Audit,
                     AssetClassificationMissionHistory)
from .query import asset_tag_has, json_list_has
from .services import active_methodology
from .regulatory import normalize_scopes

GOVERNED = {'asset_criticality', 'business_criticality', 'data_classification', 'regulatory',
            'environment', 'exposure', 'business_owner', 'it_owner', 'application_owner', 'asset_group'}
PREVIEW = 'asset.classification_bulk.previewed'
CONFIRMED = 'asset.classification_bulk.confirmed'


def bulk_reviews(db, workspace, user, offset, limit):
    request = AssetClassificationChangeRequest
    bulk = exists(select(Audit.id).where(Audit.action == 'asset.classification_change_requested.bulk',
                                        Audit.entity_id == request.asset_id,
                                        Audit.details['request_id'].as_integer() == request.id))
    query = (select(request, Asset.hostname, AssetClassificationMission)
             .join(Asset, Asset.id == request.asset_id)
             .join(AssetClassificationMission, AssetClassificationMission.asset_id == request.asset_id)
             .where(request.workspace == workspace, Asset.workspace == workspace,
                    AssetClassificationMission.workspace == workspace, request.status == 'Requested', bulk))
    if user.role != 'Administrator':
        query = query.where(or_(request.requested_by == user.id, AssetClassificationMission.owner_reviewer_id == user.id,
                                AssetClassificationMission.grc_reviewer_id == user.id))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.execute(query.order_by(request.id.desc()).offset(offset).limit(limit)).all()
    ids = [item.id for item, _, _ in rows]
    validations = {audit.entity_id: audit for audit in db.scalars(select(Audit).where(
        Audit.action == 'asset.classification_owner_validated', Audit.entity_id.in_(ids)).order_by(Audit.id))}
    items = []
    for item, hostname, mission in rows:
        owner = validations.get(item.id)
        validated = bool(owner and owner.actor_id == mission.owner_reviewer_id
                         and owner.actor_id != item.requested_by
                         and owner.details.get('context_version') == item.expected_context_version
                         and owner.details.get('proposed') == item.proposed_context)
        items.append({'id': item.id, 'asset_id': item.asset_id, 'hostname': hostname,
                      'requested_by': item.requested_by, 'before': item.before_context, 'proposed': item.proposed_context,
                      'justification': item.justification, 'evidence': item.evidence,
                      'owner_reviewer_id': mission.owner_reviewer_id, 'grc_reviewer_id': mission.grc_reviewer_id,
                      'owner_validated': validated})
    return {'items': items, 'total': total}


def category_expression():
    os = func.lower(func.coalesce(func.nullif(Asset.os, ''), Vulnerability.technical['os'].as_string(), ''))
    device = func.lower(func.coalesce(Vulnerability.technical['device_type'].as_string(), ''))
    product = func.lower(func.coalesce(func.nullif(Vulnerability.technical['product'].as_string(), ''),
                                     Vulnerability.technical['software_family'].as_string(), ''))
    def contains(column, words):
        return or_(*(column.contains(word) for word in words))
    return case(
        (os.contains('windows') & contains(os, ('server', 'datacenter')), 'Windows Servers'),
        (os.contains('windows'), 'Windows Workstations'),
        (contains(os, ('linux', 'unix', 'ubuntu', 'red hat', 'rhel', 'debian')), 'Linux Servers'),
        (contains(device, ('network', 'router', 'switch', 'firewall')), 'Network Devices'),
        (contains(device, ('storage', 'san', 'nas')) | contains(product, ('powerscale', 'storage')), 'Storage'),
        (contains(product, ('sql', 'oracle', 'postgres', 'database')), 'Databases'),
        (contains(product, ('aws', 'azure', 'gcp', 'cloud')), 'Cloud'),
        (product != '', 'Applications'), else_='Unknown')


def missing_value(field):
    value = Asset.context[field].as_string()
    missing = or_(value.is_(None), value == '', value == '[]')
    if field == 'regulatory':
        missing = missing & ~exists(select(1).where(AssetRegulatoryScope.asset_id == Asset.id,
                                                    AssetRegulatoryScope.active.is_(True)))
    return missing


def cohort_query(db, workspace, filters):
    required = active_methodology(db).configuration.get('required_context', [])
    if filters.missing_field and filters.missing_field not in required:
        raise HTTPException(422, 'Missing field must be required by the active methodology')
    latest = select(func.max(Assessment.id)).where(Assessment.instance_id == Finding.id).correlate(Finding).scalar_subquery()
    query = (select(Finding, Asset, Vulnerability, Assessment, category_expression().label('category'))
             .join(Asset, Asset.id == Finding.asset_id)
             .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
             .join(Assessment, Assessment.id == latest)
             .where(Finding.workspace == workspace, Asset.workspace == workspace,
                    Assessment.status == 'Context Required'))
    if filters.q:
        query = query.where(or_(Asset.hostname.icontains(filters.q, autoescape=True),
                                Asset.ip.icontains(filters.q, autoescape=True)))
    if filters.os:
        os = func.coalesce(func.nullif(Asset.os, ''), Vulnerability.technical['os'].as_string(), '')
        query = query.where(os.icontains(filters.os, autoescape=True))
    if filters.subcategory:
        query = query.where(category_expression() == filters.subcategory)
    if filters.device_type:
        query = query.where(Vulnerability.technical['device_type'].as_string() == filters.device_type)
    if filters.missing_field:
        query = query.where(missing_value(filters.missing_field))
    if filters.environment:
        query = query.where(Asset.context['environment'].as_string() == filters.environment)
    if filters.raci_owner:
        owners = [Asset.context[key].as_string() for key in
                  ('business_owner', 'it_owner', 'application_owner', 'remediation_owner')]
        query = query.where(and_(*(or_(owner.is_(None), owner == '', owner == 'Unassigned') for owner in owners))
                            if filters.raci_owner == 'Unassigned' else or_(*(owner == filters.raci_owner for owner in owners)))
    if filters.tag:
        query = query.where(asset_tag_has(db, filters.tag))
    if filters.regulatory:
        membership = exists(select(1).where(AssetRegulatoryScope.asset_id == Asset.id,
                                            AssetRegulatoryScope.active.is_(True)))
        if filters.regulatory == 'None':
            query = query.where(~membership, json_list_has(db, Asset.context['regulatory'], 'None'))
        else:
            query = query.where(or_(json_list_has(db, Asset.context['regulatory'], filters.regulatory),
                                    exists(select(1).where(AssetRegulatoryScope.asset_id == Asset.id,
                                           AssetRegulatoryScope.active.is_(True),
                                           AssetRegulatoryScope.scope == filters.regulatory))))
    return query, required


def list_context(db, workspace, filters, limit, offset):
    query, required = cohort_query(db, workspace, filters)
    counts = query.with_only_columns(Finding.id.label('finding_id'), Asset.id.label('asset_id')).order_by(None).subquery()
    total, assets_total = db.execute(select(func.count(), func.count(func.distinct(counts.c.asset_id))).select_from(counts)).one()
    rows = db.execute(query.order_by(Asset.hostname, Finding.id).offset(offset).limit(limit)).all()
    scoped_assets = set(db.scalars(select(AssetRegulatoryScope.asset_id).where(
        AssetRegulatoryScope.asset_id.in_({asset.id for _, asset, _, _, _ in rows}),
        AssetRegulatoryScope.active.is_(True)))) if 'regulatory' in required else set()
    items = [{'finding_id': finding.id, 'plugin_id': vuln.plugin_id, 'category': category,
              'name': vuln.name, 'asset': {'id': asset.id, 'hostname': asset.hostname, 'ip': asset.ip,
                                         'os': asset.os or (vuln.technical or {}).get('os'), 'tags': asset.tags},
              'missing_fields': [key for key in required if (asset.context or {}).get(key) in (None, '', [])
                                 and not (key == 'regulatory' and asset.id in scoped_assets)],
              'technical_completed': True, 'risk_assessed': False, 'status': 'Context Required'}
             for finding, asset, vuln, assessment, category in rows]
    return {'items': items, 'total': total, 'assets_total': assets_total, 'limit': limit, 'offset': offset,
            'filters': filters.model_dump()}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def bulk_context(db, workspace, user, data):
    from .schemas import ContextRequiredFilters
    query, _ = cohort_query(db, workspace, data.selection or ContextRequiredFilters())
    if data.selection is None:
        query = query.where(Asset.id.in_(set(data.asset_ids)))
    rows = db.execute(query.order_by(Finding.id)).all()
    ids = sorted({asset.id for _, asset, _, _, _ in rows})
    if not ids:
        raise HTTPException(422, 'The selection matches no assets')
    if data.selection is None and ids != sorted(set(data.asset_ids)):
        raise HTTPException(409, 'Selected assets are no longer in this workspace context-required cohort. Preview again.')
    # A database subquery keeps parameter counts bounded even for large cohorts.
    asset_scope = query.with_only_columns(Asset.id).order_by(None)
    assets = db.scalars(select(Asset).where(Asset.id.in_(asset_scope)).order_by(Asset.id)
                        .with_for_update().execution_options(populate_existing=True)).all()
    rows = db.execute(query.order_by(Finding.id).execution_options(populate_existing=True)).all()
    if ids != [asset.id for asset in assets] or ids != sorted({asset.id for _, asset, _, _, _ in rows}):
        raise HTTPException(409, 'Cohort changed during verification. Preview again.')
    pending = db.scalars(select(AssetClassificationChangeRequest).where(
        AssetClassificationChangeRequest.asset_id.in_(asset_scope),
        AssetClassificationChangeRequest.workspace == workspace,
        AssetClassificationChangeRequest.status == 'Requested').order_by(AssetClassificationChangeRequest.id)).all()
    extras = set(data.per_asset_changes) - {str(i) for i in ids}
    if extras:
        raise HTTPException(422, 'Per-asset changes must belong to the selected cohort')
    memberships = db.execute(select(AssetRegulatoryScope.asset_id, AssetRegulatoryScope.scope,
                                   AssetRegulatoryScope.active, AssetRegulatoryScope.approval_state).where(
        AssetRegulatoryScope.asset_id.in_(asset_scope)).order_by(AssetRegulatoryScope.id)).all()
    regulatory = {}
    approved_regulatory = set()
    for asset_id, scope, active, approval in memberships:
        if active:
            regulatory.setdefault(asset_id, set()).add(scope)
            if approval == 'Approved':
                approved_regulatory.add(asset_id)
    proposed = {}
    before = {}
    approved_fields = 0
    for asset in assets:
        incoming = data.per_asset_changes.get(str(asset.id), data.changes).model_dump(exclude_none=True)
        if set(incoming) - GOVERNED or not incoming:
            raise HTTPException(422, 'Select at least one governed context field; tags and asset type are not classification changes')
        current = dict(asset.context or {})
        scopes = regulatory.get(asset.id, set()) | set(normalize_scopes(current.get('regulatory')))
        if scopes or current.get('regulatory'):
            current['regulatory'] = sorted(scopes) or ['None']
        if 'regulatory' in incoming:
            incoming['regulatory'] = normalize_scopes(incoming['regulatory']) or ['None']
        proposed[asset.id] = {key: value for key, value in incoming.items() if current.get(key) != value}
        before[asset.id] = {key: current.get(key) for key in proposed[asset.id]}
        approved_fields += sum(1 for key in proposed[asset.id]
                               if (key == 'regulatory' and asset.id in approved_regulatory)
                               or (isinstance((asset.context_provenance or {}).get(key), dict)
                                   and asset.context_provenance[key].get('approval_state') == 'Approved'))
    pending_conflicts = {item.asset_id for item in pending if set(item.proposed_context or {}) & set(proposed[item.asset_id])}
    binding = {'workspace': workspace, 'actor_id': user.id,
               'asset_ids': sorted(set(data.asset_ids)),
               'selection': data.selection.model_dump() if data.selection is not None else None,
               'justification': data.justification.strip(), 'evidence': data.evidence.strip(),
               'changes': data.changes.model_dump(exclude_none=True),
               'per_asset_changes': {key: value.model_dump(exclude_none=True) for key, value in data.per_asset_changes.items()}}
    state = {'binding': binding, 'methodology': active_methodology(db).configuration,
             'assets': [(a.id, a.context_version, a.context, a.context_provenance) for a in assets],
             'findings': [(f.id, f.revision, a.id, assessment.id) for f, a, _, assessment, _ in rows],
             'pending': [(r.id, r.asset_id, r.expected_context_version, r.proposed_context) for r in pending],
             'memberships': [list(row) for row in memberships]}
    summary = {'assets_selected': len(ids), 'findings_selected': len(rows),
               'proposed_assets': sum(bool(value) for value in proposed.values()),
               'proposed_fields': sum(len(value) for value in proposed.values()),
               'unchanged': sum(not value for value in proposed.values()),
               'approval_conflicts': approved_fields, 'pending_conflicts': len(pending_conflicts)}
    if data.dry_run:
        nonce = secrets.token_urlsafe(32)
        preview = Audit(actor_id=user.id, action=PREVIEW, entity='classification_bulk', details={
            **binding, 'state_hash': fingerprint(state), 'nonce_hash': fingerprint(nonce),
            'cohort_asset_ids': ids, 'summary': summary})
        db.add(preview); db.commit(); db.refresh(preview)
        return {'status': 'Preview', **summary, 'preview_token': f'{preview.id}.{nonce}',
                'expires_at': (preview.created_at.replace(tzinfo=timezone.utc) + timedelta(minutes=15)).isoformat()}
    if not data.confirmed or not data.preview_token:
        raise HTTPException(422, 'Explicit confirmation of a verified preview is required')
    if not data.justification.strip() or not data.evidence.strip():
        raise HTTPException(422, 'Justification and real evidence reference are required before submission')
    preview_id, _, nonce = data.preview_token.partition('.')
    preview = db.get(Audit, int(preview_id)) if preview_id.isdigit() and 0 < int(preview_id) < 2**63 else None
    if (not preview or preview.action != PREVIEW or preview.actor_id != user.id
            or preview.details.get('workspace') != workspace
            or not secrets.compare_digest(preview.details.get('nonce_hash', ''), fingerprint(nonce))
            or preview.created_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc) - timedelta(minutes=15)
            or preview.details.get('state_hash') != fingerprint(state)):
        raise HTTPException(409, 'Selection or context changed, or preview expired/used. Preview again before confirming.')
    if pending_conflicts:
        raise HTTPException(409, 'Overlapping classification requests await approval; resolve them and preview again.')
    if not summary['proposed_assets']:
        raise HTTPException(422, 'No classification changes remain to submit')
    # Atomically consume confirmation, including on SQLite; parallel/replayed submissions cannot duplicate requests.
    consumed = db.execute(update(Audit).where(Audit.id == preview.id, Audit.action == PREVIEW).values(action=CONFIRMED))
    if consumed.rowcount != 1:
        raise HTTPException(409, 'Preview already confirmed. Reload before submitting again.')
    requested = []
    missions = {m.asset_id: m for m in db.scalars(select(AssetClassificationMission).where(
        AssetClassificationMission.asset_id.in_(asset_scope), AssetClassificationMission.workspace == workspace))}
    for asset in assets:
        changes = proposed[asset.id]
        if not changes:
            continue
        item = AssetClassificationChangeRequest(asset_id=asset.id, workspace=workspace, requested_by=user.id,
            expected_context_version=asset.context_version,
            before_context=before[asset.id], proposed_context=changes,
            justification=data.justification.strip(), evidence=data.evidence.strip())
        db.add(item); db.flush(); requested.append(item.id)
        mission = missions.get(asset.id)
        if not mission:
            mission = AssetClassificationMission(asset_id=asset.id, workspace=workspace, created_by=user.id, updated_by=user.id)
            db.add(mission)
        mission.status = 'Pending Owner Validation'
        mission.current_step = 5
        mission.updated_by = user.id
        db.flush()
        db.add(AssetClassificationMissionHistory(mission_id=mission.id, asset_id=asset.id, workspace=workspace,
            actor_id=user.id, action='submitted_for_approval', status=mission.status,
            current_step=5, responses={'request_id': item.id, 'preview_id': preview.id, 'proposed': changes}))
        db.add(Audit(actor_id=user.id, action='asset.classification_change_requested.bulk', entity='asset', entity_id=asset.id,
                     details={'request_id': item.id, 'preview_id': preview.id, 'workspace': workspace,
                              'before': item.before_context, 'proposed': changes,
                              'expected_context_version': asset.context_version}))
    db.add(Audit(actor_id=user.id, action='asset.classification_bulk.submitted', entity='classification_bulk',
                 entity_id=preview.id, details={'workspace': workspace, 'summary': summary,
                                               'request_ids': requested, 'state_hash': fingerprint(state)}))
    db.commit()
    return {'status': 'Awaiting Approval', **summary, 'requests_created': len(requested), 'request_ids': requested}
