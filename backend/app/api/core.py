from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, update, func, case, cast, Float
from sqlalchemy.exc import IntegrityError
from ..db import get_db
from ..auth import require_user, writer, admin, passwords
from ..models import *
from ..schemas import FindingCreate, AssessmentInput, MethodologyCreate, UserCreate, AssetUpdate, AssetRuleInput, SavedFilterInput
from ..asset_rules import ASSET_CONTEXT_KEYS, resolve_rules
from ..services import active_methodology, ingest, get_finding, detail, latest_assessment
from ..risk.engine import calculate

router = APIRouter(tags=['Workbench'])

@router.get('/saved-filters')
def saved_filters(request: Request, user=Depends(require_user), db=Depends(get_db)):
    rows = db.scalars(select(SavedFilter).where(SavedFilter.workspace == request.state.session.workspace,
                                                 SavedFilter.user_id == user.id).order_by(SavedFilter.name)).all()
    return [{'id': row.id, 'name': row.name, 'filters': row.filters} for row in rows]

@router.post('/saved-filters', status_code=201)
def save_filter(data: SavedFilterInput, request: Request, user=Depends(require_user), db=Depends(get_db)):
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
def findings(request: Request, q: str = '', severity: str = '', source: str = '', status: str = '', residual: str = '', inherent: str = '', appetite: str = '', business: str = '', classification: str = '', regulatory: str = '', limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0), user=Depends(require_user), db=Depends(get_db)):
    statement = select(Finding).join(Asset).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id).where(Finding.workspace == request.state.session.workspace).order_by(Finding.id)
    if source:
        statement = statement.where(Finding.source == source)
    if q:
        statement = statement.where((Asset.hostname.ilike(f'%{q}%')) | (Vulnerability.name.ilike(f'%{q}%')) | (Vulnerability.plugin_id.ilike(f'%{q}%')) | (Vulnerability.cves.cast(Text).ilike(f'%{q}%')))
    if severity:
        statement = statement.where(func.coalesce(Finding.observed['severity'].as_string(), Vulnerability.technical['severity'].as_string()) == severity)
    # Apply contextual and saved-score filters in SQL. This keeps a deliberate
    # Search action responsive even with tens of thousands of findings.
    if any((status, residual, inherent, appetite)):
        latest_ids = (select(Assessment.instance_id, func.max(Assessment.id).label('assessment_id'))
                      .group_by(Assessment.instance_id).subquery())
        statement = (statement.outerjoin(latest_ids, latest_ids.c.instance_id == Finding.id)
                      .outerjoin(Assessment, Assessment.id == latest_ids.c.assessment_id)
                      .outerjoin(RiskScore, RiskScore.assessment_id == Assessment.id))
        if status:
            statement = statement.where(Assessment.id.is_(None) if status == 'Not Assessed' else Assessment.status == status)
        if residual: statement = statement.where(RiskScore.result['residual_level'].as_string() == residual)
        if inherent: statement = statement.where(RiskScore.result['inherent_level'].as_string() == inherent)
        if appetite: statement = statement.where(RiskScore.result['above_appetite'].as_boolean() == (appetite == 'Above'))
    if business: statement = statement.where(Asset.context['business_criticality'].as_string() == business)
    if classification: statement = statement.where(Asset.context['data_classification'].as_string() == classification)
    if regulatory: statement = statement.where(Asset.context['regulatory'].cast(Text).ilike(f'%"{regulatory}"%'))
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

@router.get('/assets')
def assets(request: Request, user=Depends(require_user), db=Depends(get_db)):
    return [{'id': a.id, 'hostname': a.hostname, 'ip': a.ip, 'os': a.os, 'tags': a.tags, 'context': a.context}
            for a in db.scalars(select(Asset).where(Asset.workspace == request.state.session.workspace).order_by(Asset.hostname))]

@router.put('/assets/{id}')
def update_asset(id: int, data: AssetUpdate, request: Request, user=Depends(writer), db=Depends(get_db)):
    asset = db.get(Asset, id)
    if not asset or asset.workspace != request.state.session.workspace: raise HTTPException(404, 'Asset not found')
    before = dict(asset.context)
    changes = data.model_dump(exclude_none=True)
    if 'tags' in changes:
        asset.tags = list(dict.fromkeys(changes.pop('tags')))[:100]
    asset.context = {**asset.context, **changes}
    findings = db.scalars(select(Finding).where(Finding.asset_id == id, Finding.workspace == request.state.session.workspace)).all()
    for record in findings: record.revision += 1
    db.add(Audit(actor_id=user.id, action='asset.context_updated', entity='asset', entity_id=id,
                 details={'before': before, 'after': asset.context, 'findings_flagged': len(findings)}))
    db.commit()
    return {'id': asset.id, 'context': asset.context, 'findings_flagged': len(findings)}

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
    base = select(Finding).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id).where(Finding.workspace == workspace)
    total = db.scalar(select(func.count()).select_from(Finding).where(Finding.workspace == workspace)) or 0
    severity_value = func.coalesce(Finding.observed['severity'].as_string(), Vulnerability.technical['severity'].as_string())
    severity_counts = dict(db.execute(select(severity_value, func.count()).select_from(Finding).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id).where(Finding.workspace == workspace).group_by(severity_value)).all())
    assessed_ids = db.scalars(
        select(Assessment.instance_id)
        .join(Finding, Assessment.instance_id == Finding.id)
        .where(Finding.workspace == workspace)
        .distinct()
    ).all()
    assessed_findings = db.scalars(select(Finding).where(Finding.id.in_(assessed_ids))).all() if assessed_ids else []
    assessed_rows = [detail(db, finding) for finding in assessed_findings]
    assessed = [r for r in assessed_rows if r['saved_score'] is not None and r['status'] not in ('Assessment In Progress', 'Context Required', 'Pending Validation') and not r['reassessment_required']]
    rank = case((severity_value == 'Critical', 4), (severity_value == 'High', 3), (severity_value == 'Medium', 2), (severity_value == 'Low', 1), else_=0)
    vpr = cast(Finding.observed['vpr'].as_string(), Float)
    cvss = cast(Finding.observed['cvss'].as_string(), Float)
    candidates = db.scalars(base.order_by(rank.desc(), vpr.desc(), cvss.desc()).limit(100)).all()
    by_id = {finding.id: finding for finding in [*candidates, *assessed_findings]}
    priority = sorted((detail(db, finding) for finding in by_id.values()), key=lambda row: row['score']['residual'], reverse=True)[:6]
    levels = ['Critical', 'High', 'Medium', 'Low']
    return {'total': total, 'severity': {s: severity_counts.get(s, 0) for s in levels},
            'pending': total - len(assessed), 'completed': len(assessed), 'exceptions': sum(r['status'] == 'Exception Requested' for r in assessed_rows),
            'above': sum(r['score']['above_appetite'] for r in assessed), 'within': sum(not r['score']['above_appetite'] for r in assessed),
            'distribution': [{'name': s, 'value': sum(r['score']['residual_level'] == s for r in assessed)} for s in levels],
            'priority': priority,
            'methodology': {'version': active_methodology(db).version, 'appetite': active_methodology(db).configuration['appetite']}}

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
def audit(user=Depends(require_user), db=Depends(get_db)):
    return [{'id': a.id, 'actor': db.get(User, a.actor_id).username if a.actor_id else 'System', 'action': a.action, 'entity': a.entity, 'entity_id': a.entity_id, 'details': a.details, 'date': a.created_at.isoformat()} for a in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(500))]

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
