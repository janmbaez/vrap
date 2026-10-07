from datetime import datetime, timezone, timedelta
from copy import copy
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, update, delete, func, case, cast, Float, or_
from sqlalchemy.exc import IntegrityError
from ..db import get_db
from ..auth import require_user, writer, admin, passwords
from ..models import *
from ..schemas import FindingCreate, AssessmentInput, MethodologyCreate, UserCreate, UserRoleUpdate, AssetUpdate, AssetEdit, AssetCreate, AssetRuleInput, SavedFilterInput
from ..asset_rules import ASSET_CONTEXT_KEYS, resolve_rules, resolve_rule_list
from ..services import active_methodology, ingest, get_finding, detail, latest_assessment
from ..risk.engine import calculate
from ..query import finding_query, validate_filters

router = APIRouter(tags=['Workbench'])

@router.get('/saved-filters')
def saved_filters(request: Request, user=Depends(require_user), db=Depends(get_db)):
    rows = db.scalars(select(SavedFilter).where(SavedFilter.workspace == request.state.session.workspace,
                                                 SavedFilter.user_id == user.id).order_by(SavedFilter.name)).all()
    return [{'id': row.id, 'name': row.name, 'filters': row.filters} for row in rows]

@router.post('/saved-filters', status_code=201)
def save_filter(data: SavedFilterInput, request: Request, user=Depends(require_user), db=Depends(get_db)):
    validate_filters(data.filters)
    existing = db.scalar(select(SavedFilter).where(SavedFilter.workspace == request.state.session.workspace,
                                                    SavedFilter.user_id == user.id, SavedFilter.name == data.name))
    if existing:
        existing.filters = data.filters
        row = existing
    else:
        row = SavedFilter(workspace=request.state.session.workspace, user_id=user.id, name=data.name, filters=data.filters)
        db.add(row)
    db.commit(); db.refresh(row)
    return {'id': row.id, 'name': row.name, 'filters': row.filters}

@router.delete('/saved-filters/{id}')
def delete_filter(id: int, request: Request, user=Depends(require_user), db=Depends(get_db)):
    row = db.get(SavedFilter, id)
    if not row or row.workspace != request.state.session.workspace or row.user_id != user.id:
        raise HTTPException(404, 'Saved filter not found')
    db.delete(row); db.commit()
    return {'deleted': id}

@router.get('/findings')
def findings(request: Request, q: str = '', severity: str = '', source: str = '', status: str = '', residual: str = '', inherent: str = '', appetite: str = '', business: str = '', classification: str = '', regulatory: str = '', plugin_id: str = '', asset_group: str = '', asset_tag: str = '', vulnerability_tag: str = '', business_owner: str = '', it_owner: str = '', application_owner: str = '', limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0), user=Depends(require_user), db=Depends(get_db)):
    filters = {key: value for key, value in {
        'q': q, 'severity': severity, 'source': source, 'status': status, 'residual': residual,
        'inherent': inherent, 'appetite': appetite, 'business': business, 'classification': classification,
        'regulatory': regulatory, 'plugin_id': plugin_id, 'asset_group': asset_group, 'asset_tag': asset_tag, 'vulnerability_tag': vulnerability_tag,
        'business_owner': business_owner, 'it_owner': it_owner, 'application_owner': application_owner}.items() if value}
    statement = finding_query(db, request.state.session.workspace, filters).order_by(Finding.id)
    total = db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
    page = db.scalars(statement.limit(limit).offset(offset)).all()
    return {'items': [detail(db, finding) for finding in page], 'total': total}

@router.post('/findings', status_code=201)
def create_finding(data: FindingCreate, request: Request, user=Depends(writer), db=Depends(get_db)):
    finding, created = ingest(db, data, workspace=request.state.session.workspace)
    if not created:
        raise HTTPException(409, 'This asset/plugin/port/protocol finding already exists')
    db.add(Audit(actor_id=user.id, action='finding.created', entity='finding', entity_id=finding.id))
    db.commit()
    return detail(db, finding)

@router.get('/assessment-groups')
def assessment_groups(request: Request, q: str = '', severity: str = '', limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(require_user), db=Depends(get_db)):
    workspace = request.state.session.workspace
    assessed_ids = select(Assessment.instance_id).distinct().subquery()
    severity_value = func.coalesce(Finding.observed['severity'].as_string(), Vulnerability.technical['severity'].as_string())
    severity_rank = case((severity_value == 'Critical', 4), (severity_value == 'High', 3), (severity_value == 'Medium', 2), (severity_value == 'Low', 1), else_=0)
    query = (select(Vulnerability.id, Vulnerability.name, Vulnerability.plugin_id,
                    func.count(Finding.id).label('findings'), func.count(func.distinct(Finding.asset_id)).label('assets'),
                    func.count(assessed_ids.c.instance_id).label('assessed'), func.max(severity_rank).label('severity_rank'))
             .join(Finding, Finding.vulnerability_id == Vulnerability.id)
             .outerjoin(assessed_ids, assessed_ids.c.instance_id == Finding.id)
             .where(Finding.workspace == workspace))
    if q:
        query = query.where((Vulnerability.name.ilike(f'%{q}%')) | (Vulnerability.plugin_id.ilike(f'%{q}%')) | (Vulnerability.cves.cast(Text).ilike(f'%{q}%')))
    if severity:
        query = query.where(severity_value == severity)
    grouped = query.group_by(Vulnerability.id, Vulnerability.name, Vulnerability.plugin_id)
    total = db.scalar(select(func.count()).select_from(grouped.subquery())) or 0
    rows = db.execute(grouped.order_by(func.max(severity_rank).desc(), func.count(Finding.id).desc(), Vulnerability.name).limit(limit).offset(offset)).all()
    levels = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Informational'}
    return {'total': total, 'items': [{'id': row.id, 'name': row.name, 'plugin_id': row.plugin_id, 'cves': db.get(Vulnerability, row.id).cves,
                                      'findings': row.findings, 'assets': row.assets, 'assessed': row.assessed,
                                      'severity': levels.get(row.severity_rank, 'Informational')} for row in rows]}

@router.get('/assessment-groups/{vulnerability_id}')
def assessment_group(vulnerability_id: int, request: Request, limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0), user=Depends(require_user), db=Depends(get_db)):
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if not vulnerability: raise HTTPException(404, 'Plugin group not found')
    base = (select(Finding).join(Asset).where(Finding.workspace == request.state.session.workspace,
                                                Finding.vulnerability_id == vulnerability_id).order_by(Asset.hostname, Finding.id))
    total = db.scalar(select(func.count()).select_from(base.order_by(None).subquery())) or 0
    rows = db.scalars(base.limit(limit).offset(offset)).all()
    return {'id': vulnerability.id, 'name': vulnerability.name, 'plugin_id': vulnerability.plugin_id, 'cves': vulnerability.cves,
            'total': total, 'items': [{'finding_id': finding.id, 'asset': detail(db, finding)['asset'],
                                      'context': db.get(Asset, finding.asset_id).context,
                                      'status': detail(db, finding)['status']} for finding in rows]}

@router.put('/assessment-groups/{vulnerability_id}/assets')
def update_group_assets(vulnerability_id: int, data: AssetUpdate, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = request.state.session.workspace
    changes = data.model_dump(exclude_none=True)
    if not changes: raise HTTPException(422, 'Select at least one asset context value')
    asset_ids = db.scalars(select(Finding.asset_id).where(Finding.workspace == workspace,
                                                          Finding.vulnerability_id == vulnerability_id).distinct()).all()
    if not asset_ids: raise HTTPException(404, 'Plugin group not found')
    assets = db.scalars(select(Asset).where(Asset.id.in_(asset_ids), Asset.workspace == workspace)).all()
    for asset in assets:
        asset.context = {**asset.context, **changes}
    affected_findings = db.execute(update(Finding).where(Finding.asset_id.in_(asset_ids), Finding.workspace == workspace).values(revision=Finding.revision + 1)).rowcount
    db.add(Audit(actor_id=user.id, action='assessment_group.asset_context_updated', entity='vulnerability', entity_id=vulnerability_id,
                 details={'assets': len(assets), 'findings_flagged': affected_findings, 'changes': changes}))
    db.commit()
    return {'assets_updated': len(assets), 'findings_flagged': affected_findings}

@router.get('/findings/{id}')
def finding(id: int, request: Request, user=Depends(require_user), db=Depends(get_db)):
    record = get_finding(db, id)
    if record.workspace != request.state.session.workspace: raise HTTPException(404, 'Finding not found')
    return detail(db, record)

def preview_score(db, finding, data):
    method = active_methodology(db)
    if method.id != data.methodology_id:
        raise HTTPException(409, 'Methodology changed. Reload before calculating or saving.')
    technical = {**db.get(Vulnerability, finding.vulnerability_id).technical, **finding.observed}
    ctx = data.context.engine_values()
    # Validate extensible factor values against their versioned definitions.
    for factor in method.configuration['factors']:
        value = ctx.get(factor['key'])
        if value is None:
            continue
        if factor['kind'] == 'boolean' and type(value) is not bool:
            raise HTTPException(422, f"{factor['key']} must be boolean")
        if factor['kind'] == 'mapping' and value not in factor['values']:
            raise HTTPException(422, f"Invalid {factor['key']}")
        if factor['kind'] == 'multi' and (not isinstance(value, list) or any(v not in factor['values'] for v in value)):
            raise HTTPException(422, f"Invalid {factor['key']}")
        if factor['kind'] == 'linear' and (type(value) not in (int, float) or not 0 <= value <= 1e9):
            raise HTTPException(422, f"Invalid {factor['key']}")
    result = calculate(technical, ctx, [c.model_dump() for c in data.controls], method.configuration, datetime.now(timezone.utc).date())
    result.update({'methodology_id': method.id, 'methodology_version': method.version})
    return method, result

@router.post('/findings/{id}/preview')
def preview(id: int, data: AssessmentInput, request: Request, user=Depends(require_user), db=Depends(get_db)):
    record = get_finding(db, id)
    if record.workspace != request.state.session.workspace: raise HTTPException(404, 'Finding not found')
    _, result = preview_score(db, record, data)
    return result

@router.post('/findings/{id}/assessments', status_code=201)
def save_assessment(id: int, data: AssessmentInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    finding = get_finding(db, id)
    if finding.workspace != request.state.session.workspace: raise HTTPException(404, 'Finding not found')
    method, result = preview_score(db, finding, data)
    if not data.justification.strip():
        raise HTTPException(422, 'A justification is required for the audit trail')
    if data.decision == 'Risk Accepted' or data.status == 'Risk Accepted':
        if user.role != 'Administrator':
            raise HTTPException(403, 'Only an Administrator can approve risk acceptance')
        if data.decision != 'Risk Accepted' or data.status != 'Risk Accepted':
            raise HTTPException(422, 'Risk acceptance decision and status must agree')
    if data.decision == 'Within Risk Appetite' and result['above_appetite']:
        raise HTTPException(422, 'Residual risk is above appetite')
    if result['missing_required'] and data.status not in ('Context Required', 'Assessment In Progress'):
        raise HTTPException(422, 'Required context is missing: ' + ', '.join(result['missing_required']))
    previous = latest_assessment(db, id)
    previous_score = db.scalar(select(RiskScore).where(RiskScore.assessment_id == previous.id)) if previous else None
    change = db.execute(update(Finding).where(Finding.id == id, Finding.revision == data.expected_revision).values(revision=Finding.revision + 1))
    if change.rowcount != 1:
        raise HTTPException(409, 'Finding changed. Reload before saving.')
    assessment = Assessment(instance_id=id, revision=data.expected_revision + 1, methodology_id=method.id, analyst_id=user.id,
                            context=data.context.model_dump(), notes=data.notes, justification=data.justification, decision=data.decision, status=data.status)
    db.add(assessment)
    db.flush()
    rules = {r['name']: r for r in method.configuration['controls']}
    for c in data.controls:
        if c.name not in rules:
            raise HTTPException(422, 'Unknown control: ' + c.name)
        db.add(AssessmentControl(assessment_id=assessment.id, component=rules[c.name]['component'], **c.model_dump()))
    result['asset_snapshot'] = detail(db, finding)['asset']
    db.add(RiskScore(assessment_id=assessment.id, result=result))
    db.add(Audit(actor_id=user.id, action='assessment.saved', entity='finding', entity_id=id, details={'assessment_id': assessment.id, 'previous_residual': previous_score.result['residual'] if previous_score else None, 'new_residual': result['residual'], 'reason': data.justification, 'methodology_version': method.version, 'decision': data.decision, 'status': data.status}))
    db.commit()
    return detail(db, finding)

@router.get('/findings/{id}/history')
def history(id: int, request: Request, user=Depends(require_user), db=Depends(get_db)):
    record = get_finding(db, id)
    if record.workspace != request.state.session.workspace: raise HTTPException(404, 'Finding not found')
    rows = db.scalars(select(Assessment).where(Assessment.instance_id == id).order_by(Assessment.revision.desc()))
    return [{'id': a.id, 'revision': a.revision, 'analyst': db.get(User, a.analyst_id).username, 'date': a.created_at.isoformat(), 'status': a.status, 'decision': a.decision, 'notes': a.notes, 'justification': a.justification, 'score': db.scalar(select(RiskScore).where(RiskScore.assessment_id == a.id)).result} for a in rows]

def _asset_output(asset):
    return {'id': asset.id, 'hostname': asset.hostname, 'external_id': asset.external_id, 'ip': asset.ip,
            'os': asset.os, 'tags': asset.tags, 'context': asset.context}

@router.get('/assets')
def assets(request: Request, q: str = '', asset_criticality: str = '', business_criticality: str = '', environment: str = '', asset_type: str = '', owner: str = '', tag: str = '', regulatory: str = '', data_classification: str = '', limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(require_user), db=Depends(get_db)):
    workspace = request.state.session.workspace
    query = select(Asset).where(Asset.workspace == workspace)
    if q.strip():
        term = f'%{q.strip()}%'
        query = query.where(or_(Asset.hostname.ilike(term), Asset.ip.ilike(term), Asset.os.ilike(term), Asset.external_id.ilike(term),
                                Asset.context['business_owner'].as_string().ilike(term), Asset.context['it_owner'].as_string().ilike(term),
                                Asset.context['application_owner'].as_string().ilike(term), Asset.context['asset_group'].as_string().ilike(term)))
    context_filters = {'asset_criticality': asset_criticality, 'business_criticality': business_criticality,
                       'environment': environment, 'data_classification': data_classification}
    for key, value in context_filters.items():
        if value.strip(): query = query.where(Asset.context[key].as_string() == value.strip())
    if asset_type.strip(): query = query.where(Asset.context['asset_type'].as_string() == asset_type.strip())
    if owner.strip():
        value = owner.strip(); query = query.where(or_(Asset.context['business_owner'].as_string() == value, Asset.context['it_owner'].as_string() == value, Asset.context['application_owner'].as_string() == value))
    if tag.strip():
        from ..query import asset_tag_has
        query = query.where(asset_tag_has(db, tag.strip()))
    if regulatory.strip():
        from ..query import json_list_has
        query = query.where(json_list_has(db, Asset.context['regulatory'], regulatory.strip()))
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    rows = db.scalars(query.order_by(Asset.hostname, Asset.id).limit(limit).offset(offset)).all()
    return {'items': [_asset_output(asset) for asset in rows], 'total': total, 'limit': limit, 'offset': offset}

@router.post('/assets', status_code=201)
def create_asset(data: AssetCreate, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = request.state.session.workspace
    if db.scalar(select(Asset.id).where(Asset.workspace == workspace, Asset.hostname == data.hostname.lower())):
        raise HTTPException(409, 'An asset with this hostname already exists in this environment')
    if data.external_id and db.scalar(select(Asset.id).where(Asset.workspace == workspace, Asset.external_id == data.external_id)):
        raise HTTPException(409, 'An asset with this external ID already exists in this environment')
    fields = data.model_dump(exclude_none=True)
    context = {key: fields.pop(key) for key in list(fields) if key in {'asset_criticality','business_criticality','data_classification','regulatory','environment','exposure','business_owner','it_owner','application_owner','asset_group','asset_type'}}
    asset = Asset(hostname=fields.pop('hostname').lower(), workspace=workspace, tags=list(dict.fromkeys(fields.pop('tags', [])))[:100], context=context, **fields)
    db.add(asset); db.flush()
    db.add(Audit(actor_id=user.id, action='asset.created', entity='asset', entity_id=asset.id, details={'hostname':asset.hostname, 'workspace':workspace}))
    db.commit(); db.refresh(asset)
    return _asset_output(asset)

@router.put('/assets/{id}')
def update_asset(id: int, data: AssetEdit, request: Request, user=Depends(writer), db=Depends(get_db)):
    asset = db.get(Asset, id)
    if not asset or asset.workspace != request.state.session.workspace: raise HTTPException(404, 'Asset not found')
    before = _asset_output(asset)
    changes = data.model_dump(exclude_none=True)
    if 'hostname' in changes:
        hostname = changes.pop('hostname').lower()
        duplicate = db.scalar(select(Asset.id).where(Asset.workspace == asset.workspace, Asset.hostname == hostname, Asset.id != asset.id))
        if duplicate: raise HTTPException(409, 'An asset with this hostname already exists in this environment')
        asset.hostname = hostname
    for field in ('ip', 'os', 'external_id'):
        if field in changes:
            value = changes.pop(field)
            if field == 'external_id' and value:
                duplicate = db.scalar(select(Asset.id).where(Asset.workspace == asset.workspace, Asset.external_id == value, Asset.id != asset.id))
                if duplicate: raise HTTPException(409, 'An asset with this external ID already exists in this environment')
            setattr(asset, field, value)
    if 'tags' in changes:
        asset.tags = list(dict.fromkeys(changes.pop('tags')))[:100]
    asset.context = {**asset.context, **changes}
    findings = db.scalars(select(Finding).where(Finding.asset_id == id, Finding.workspace == request.state.session.workspace)).all()
    for record in findings: record.revision += 1
    db.add(Audit(actor_id=user.id, action='asset.context_updated', entity='asset', entity_id=id,
                 details={'before': before, 'after': _asset_output(asset), 'findings_flagged': len(findings)}))
    db.commit()
    return {**_asset_output(asset), 'findings_flagged': len(findings)}

@router.delete('/assets/{id}')
def delete_asset(id: int, request: Request, user=Depends(writer), db=Depends(get_db)):
    asset = db.get(Asset, id)
    if not asset or asset.workspace != request.state.session.workspace: raise HTTPException(404, 'Asset not found')
    finding_ids = select(Finding.id).where(Finding.asset_id == asset.id, Finding.workspace == asset.workspace)
    campaign_reference = db.scalar(select(CampaignFinding.id).where(CampaignFinding.finding_id.in_(finding_ids)).limit(1))
    evidence_reference = db.scalar(select(CampaignEvidence.id).where(CampaignEvidence.finding_id.in_(finding_ids)).limit(1))
    if campaign_reference or evidence_reference:
        raise HTTPException(409, 'This asset is retained by review-campaign history and cannot be deleted')
    assessment_ids = select(Assessment.id).where(Assessment.instance_id.in_(finding_ids))
    finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.id.in_(finding_ids))) or 0
    snapshot = _asset_output(asset)
    try:
        db.execute(delete(RiskException).where(RiskException.finding_id.in_(finding_ids)))
        db.execute(delete(FindingWorkflow).where(FindingWorkflow.finding_id.in_(finding_ids)))
        db.execute(delete(AssessmentControl).where(AssessmentControl.assessment_id.in_(assessment_ids)))
        db.execute(delete(RiskScore).where(RiskScore.assessment_id.in_(assessment_ids)))
        db.execute(delete(Assessment).where(Assessment.instance_id.in_(finding_ids)))
        db.execute(update(ImportRow).where(ImportRow.instance_id.in_(finding_ids)).values(instance_id=None))
        db.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
        db.delete(asset)
        db.add(Audit(actor_id=user.id, action='asset.deleted', entity='asset', entity_id=id, details={'asset':snapshot, 'findings_deleted':finding_count, 'workspace':request.state.session.workspace}))
        db.commit()
    except Exception:
        db.rollback(); raise
    return {'deleted': id, 'findings_deleted': finding_count}

def _reconcile_asset_rule_effects(db, workspace, prior_rules):
    """Remove obsolete rule-derived values while leaving explicit asset edits intact."""
    current_rules = db.scalars(select(AssetRule).where(AssetRule.active.is_(True)).order_by(AssetRule.priority, AssetRule.id)).all()
    changed = 0
    for asset in db.scalars(select(Asset) if workspace is None else select(Asset).where(Asset.workspace == workspace)):
        old_context, _, _ = resolve_rule_list(prior_rules, asset.hostname, asset.ip, asset.tags)
        new_context, new_controls, new_applied = resolve_rule_list(current_rules, asset.hostname, asset.ip, asset.tags)
        context = dict(asset.context or {})
        previous_managed = context.pop('_rule_context', old_context)
        for key, value in previous_managed.items():
            if context.get(key) == value:
                context.pop(key, None)
        managed = {}
        for key, value in new_context.items():
            if key not in context:
                context[key] = value
                managed[key] = value
        if managed:
            context['_rule_context'] = managed
        context['applied_rules'] = new_applied
        context_changed = context != asset.context
        finding_query = select(Finding).where(Finding.asset_id == asset.id)
        if workspace is not None:
            finding_query = finding_query.where(Finding.workspace == workspace)
        findings = db.scalars(finding_query).all()
        finding_changed = False
        for record in findings:
            observed = dict(record.observed or {})
            if observed.get('default_controls', []) != new_controls or observed.get('applied_rules', []) != new_applied:
                observed['default_controls'] = new_controls
                observed['applied_rules'] = new_applied
                record.observed = observed
                record.revision += 1
                finding_changed = True
        if context_changed:
            asset.context = context
        if context_changed or finding_changed:
            changed += 1
    return changed

@router.get('/asset-rules')
def asset_rules(user=Depends(require_user), db=Depends(get_db)):
    return [{'id': r.id, 'name': r.name, 'priority': r.priority, 'active': r.active, 'match_type': r.match_type,
             'match_value': r.match_value, 'context': r.context, 'controls': r.controls, 'created_at': r.created_at.isoformat()}
            for r in db.scalars(select(AssetRule).order_by(AssetRule.priority, AssetRule.id))]

@router.post('/asset-rules', status_code=201)
def create_asset_rule(data: AssetRuleInput, user=Depends(admin), db=Depends(get_db)):
    rules = {r['name']: r for r in active_methodology(db).configuration['controls']}
    for control in data.controls:
        if control.name not in rules: raise HTTPException(422, 'Unknown control: ' + control.name)
        if control.validated and not control.evidence.strip(): raise HTTPException(422, 'Validated rule controls require evidence')
    rule = AssetRule(name=data.name, priority=data.priority, active=data.active, match_type=data.match_type,
                     match_value=data.match_value.strip(), context=data.context.model_dump(exclude_none=True),
                     controls=[c.model_dump() for c in data.controls], created_by=user.id)
    db.add(rule); db.flush()
    db.add(Audit(actor_id=user.id, action='asset_rule.created', entity='asset_rule', entity_id=rule.id,
                 details={'name': rule.name, 'match_type': rule.match_type, 'match_value': rule.match_value}))
    db.commit()
    return {'id': rule.id, 'name': rule.name}

@router.put('/asset-rules/{id}')
def update_asset_rule(id: int, data: AssetRuleInput, user=Depends(admin), db=Depends(get_db)):
    rule = db.get(AssetRule, id)
    if not rule: raise HTTPException(404, 'Asset rule not found')
    if data.name != rule.name and db.scalar(select(AssetRule.id).where(AssetRule.name == data.name)):
        raise HTTPException(409, 'An asset rule with this name already exists')
    prior_rules = [copy(item) for item in db.scalars(select(AssetRule).where(AssetRule.active.is_(True)).order_by(AssetRule.priority, AssetRule.id))]
    values = data.model_dump(exclude_none=True)
    values['context'] = data.context.model_dump(exclude_none=True)
    for key, value in values.items():
        setattr(rule, key, value if key != 'match_value' else value.strip())
    affected = _reconcile_asset_rule_effects(db, None, prior_rules) if not rule.active else 0
    db.add(Audit(actor_id=user.id, action='asset_rule.updated', entity='asset_rule', entity_id=id, details={'name':rule.name,'active':rule.active,'match_type':rule.match_type,'match_value':rule.match_value,'assets_reconciled':affected}))
    db.commit(); return {'id': rule.id, 'name': rule.name, 'active': rule.active, 'assets_reconciled': affected}

@router.delete('/asset-rules/{id}')
def delete_asset_rule(id: int, user=Depends(admin), db=Depends(get_db)):
    rule = db.get(AssetRule, id)
    if not rule: raise HTTPException(404, 'Asset rule not found')
    prior_rules = [copy(item) for item in db.scalars(select(AssetRule).where(AssetRule.active.is_(True)).order_by(AssetRule.priority, AssetRule.id))]
    db.delete(rule); db.flush()
    affected = _reconcile_asset_rule_effects(db, None, prior_rules)
    db.add(Audit(actor_id=user.id, action='asset_rule.deleted', entity='asset_rule', entity_id=id, details={'name':rule.name, 'assets_reconciled': affected}))
    db.commit(); return {'deleted': id, 'assets_reconciled': affected}

@router.post('/asset-rules/{id}/apply')
def apply_asset_rule(id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    rule = db.get(AssetRule, id)
    if not rule: raise HTTPException(404, 'Rule not found')
    changed = 0
    for asset in db.scalars(select(Asset).where(Asset.workspace == request.state.session.workspace)):
        rule_context, controls, applied = resolve_rules(db, asset.hostname, asset.ip, asset.tags)
        if not any(item['id'] == id for item in applied): continue
        asset.context = {**asset.context, **rule_context, 'applied_rules': applied}
        for record in db.scalars(select(Finding).where(Finding.asset_id == asset.id)):
            observed = dict(record.observed); observed['default_controls'] = controls; observed['applied_rules'] = applied
            record.observed = observed; record.revision += 1
        changed += 1
    db.add(Audit(actor_id=user.id, action='asset_rule.applied', entity='asset_rule', entity_id=id, details={'assets': changed}))
    db.commit()
    return {'assets_updated': changed}

@router.get('/dashboard')
def dashboard(request: Request, user=Depends(require_user), db=Depends(get_db)):
    workspace = request.state.session.workspace
    active = or_(FindingWorkflow.status.is_(None), FindingWorkflow.status != 'Closed')
    base = (select(Finding).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
            .outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id)
            .where(Finding.workspace == workspace, active))
    total = db.scalar(select(func.count()).select_from(Finding).outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id).where(Finding.workspace == workspace, active)) or 0
    methodology = active_methodology(db)
    severity_value = func.coalesce(Finding.observed['severity'].as_string(), Vulnerability.technical['severity'].as_string())
    severity_counts = dict(db.execute(select(severity_value, func.count()).select_from(Finding).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id).outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id).where(Finding.workspace == workspace, active).group_by(severity_value)).all())
    # Dashboard summaries must remain fast for six-figure finding volumes.  Join the
    # most recent assessment in one query instead of calling detail() for every row.
    latest = (select(Assessment.instance_id.label('finding_id'), func.max(Assessment.revision).label('revision'))
              .join(Finding, Assessment.instance_id == Finding.id)
              .where(Finding.workspace == workspace).group_by(Assessment.instance_id).subquery())
    assessment_rows = db.execute(
        select(Finding.id, Finding.revision.label('finding_revision'), Assessment.revision.label('assessment_revision'),
               Assessment.methodology_id, Assessment.status, RiskScore.result)
        .join(latest, latest.c.finding_id == Finding.id)
        .join(Assessment, (Assessment.instance_id == latest.c.finding_id) & (Assessment.revision == latest.c.revision))
        .outerjoin(RiskScore, RiskScore.assessment_id == Assessment.id)
        .outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id)
        .where(Finding.workspace == workspace, active)
    ).all()
    draft_statuses = {'Assessment In Progress', 'Context Required', 'Pending Validation'}
    current_scores = [row for row in assessment_rows if row.result is not None and row.status not in draft_statuses
                      and row.assessment_revision == row.finding_revision and row.methodology_id == methodology.id]
    rank = case((severity_value == 'Critical', 4), (severity_value == 'High', 3), (severity_value == 'Medium', 2), (severity_value == 'Low', 1), else_=0)
    vpr = cast(Finding.observed['vpr'].as_string(), Float)
    cvss = cast(Finding.observed['cvss'].as_string(), Float)
    candidates = db.scalars(base.order_by(rank.desc(), vpr.desc(), cvss.desc()).limit(100)).all()
    highest_scored = sorted(current_scores, key=lambda row: float(row.result.get('residual', 0)), reverse=True)[:6]
    priority_ids = {finding.id for finding in candidates} | {row.id for row in highest_scored}
    priority_findings = db.scalars(select(Finding).where(Finding.id.in_(priority_ids))).all() if priority_ids else []
    by_id = {finding.id: finding for finding in priority_findings}
    priority = sorted((detail(db, finding) for finding in by_id.values()), key=lambda row: row['score']['residual'], reverse=True)[:6]
    levels = ['Critical', 'High', 'Medium', 'Low']
    now = datetime.now(timezone.utc)
    due_rows = db.execute(select(FindingWorkflow.remediation_due_at).join(Finding, Finding.id == FindingWorkflow.finding_id).where(
        Finding.workspace == workspace, FindingWorkflow.status != 'Closed', FindingWorkflow.remediation_due_at.is_not(None))).scalars().all()
    due_dates = [value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value for value in due_rows]
    overdue = sum(value < now for value in due_dates)
    due_soon = sum(now <= value <= now + timedelta(days=7) for value in due_dates)
    return {'total': total, 'severity': {s: severity_counts.get(s, 0) for s in levels},
            'pending': total - len(current_scores), 'completed': len(current_scores), 'exceptions': sum(row.status == 'Exception Requested' for row in assessment_rows),
            'remediation': {'overdue': overdue, 'due_soon': due_soon, 'scheduled': len(due_dates)},
            'above': sum(bool(row.result.get('above_appetite')) for row in current_scores), 'within': sum(not row.result.get('above_appetite') for row in current_scores),
            'distribution': [{'name': s, 'value': sum(row.result.get('residual_level') == s for row in current_scores)} for s in levels],
            'priority': priority,
            'methodology': {'version': methodology.version, 'appetite': methodology.configuration['appetite']}}

@router.get('/methodologies')
def methodologies(user=Depends(require_user), db=Depends(get_db)):
    return [{'id': m.id, 'version': m.version, 'configuration': m.configuration, 'created_at': m.created_at.isoformat()} for m in db.scalars(select(Methodology).order_by(Methodology.id.desc()))]

@router.post('/methodologies', status_code=201)
def add_methodology(data: MethodologyCreate, user=Depends(admin), db=Depends(get_db)):
    if db.scalar(select(Methodology).where(Methodology.version == data.version)):
        raise HTTPException(409, 'Version already exists')
    method = Methodology(version=data.version, configuration=data.configuration.model_dump(exclude_none=True), created_by=user.id)
    db.add(method)
    db.flush()
    db.add(Audit(actor_id=user.id, action='methodology.published', entity='methodology', entity_id=method.id, details={'version': method.version}))
    db.commit()
    return {'id': method.id, 'version': method.version}

@router.get('/audit')
def audit(request: Request, user=Depends(require_user), db=Depends(get_db)):
    from ..campaigns import visible_campaigns
    workspace = request.state.session.workspace
    visible_ids = visible_campaigns(workspace, user).with_only_columns(ReviewCampaign.id)
    scope = Audit.details['workspace'].as_string()
    query = (select(Audit, User.username).outerjoin(User, User.id == Audit.actor_id)
             .where(or_(scope == workspace, scope.is_(None)),
                    or_(Audit.entity != 'review_campaign', Audit.entity_id.in_(visible_ids)))
             .order_by(Audit.id.desc()).limit(500))
    return [{'id': a.id, 'actor': actor or 'System', 'action': a.action, 'entity': a.entity,
             'entity_id': a.entity_id, 'details': a.details, 'date': a.created_at.isoformat()}
            for a, actor in db.execute(query)]

@router.get('/users')
def users(user=Depends(admin), db=Depends(get_db)):
    return [{'id': u.id, 'username': u.username, 'role': u.role, 'active': u.active} for u in db.scalars(select(User))]

@router.post('/users', status_code=201)
def add_user(data: UserCreate, user=Depends(admin), db=Depends(get_db)):
    if db.scalar(select(User).where(User.username == data.username)):
        raise HTTPException(409, 'Username already exists')
    new = User(username=data.username, password_hash=passwords.hash(data.password), role=data.role)
    db.add(new)
    db.flush()
    db.add(Audit(actor_id=user.id, action='user.created', entity='user', entity_id=new.id, details={'role': new.role}))
    db.commit()
    return {'id': new.id, 'username': new.username, 'role': new.role}

@router.patch('/users/{user_id}/role')
def change_user_role(user_id: int, data: UserRoleUpdate, user=Depends(admin), db=Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, 'User not found')
    before = target.role
    if before == data.role:
        return {'id': target.id, 'username': target.username, 'role': target.role, 'active': target.active}
    if before == 'Administrator' and data.role != 'Administrator':
        administrator_count = db.scalar(select(func.count(User.id)).where(User.role == 'Administrator', User.active == True)) or 0
        if administrator_count <= 1:
            raise HTTPException(409, 'Keep at least one active Administrator account')
    target.role = data.role
    db.add(Audit(actor_id=user.id, action='user.role_changed', entity='user', entity_id=target.id,
                 details={'username': target.username, 'before': before, 'after': data.role}))
    db.commit()
    return {'id': target.id, 'username': target.username, 'role': target.role, 'active': target.active}
