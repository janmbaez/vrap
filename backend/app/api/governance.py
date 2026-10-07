from datetime import datetime, timezone, timedelta
from io import BytesIO, StringIO
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy import select, func, case, update, delete
from ..db import get_db
from ..auth import require_user, writer, admin
from ..models import (User, Asset, Vulnerability, Finding, Assessment, AssessmentControl, RiskScore, Audit, ImportBatch,
                      ImportRow, SyncJob, PluginAssessmentTemplate, FindingWorkflow, RiskException, ControlLibrary,
                      ReviewCampaign, CampaignReviewer, CampaignFinding, CampaignFindingTag, CampaignEvidence, CampaignAuditEvent)
from ..schemas import PluginTemplateInput, PluginBulkAssessmentInput, WorkflowInput, ExceptionInput, ExceptionDecision, ControlLibraryInput, DataCleanupRequest, DuplicateCleanupRequest, AssessmentInput
from ..services import active_methodology, cleanup_tenable_duplicates, detail, tenable_duplicate_summary
from ..risk.engine import calculate

router = APIRouter(tags=['Governance'])

def _workspace(request): return request.state.session.workspace

def _plugin(db, vulnerability_id, workspace):
    item = db.get(Vulnerability, vulnerability_id)
    exists = db.scalar(select(Finding.id).where(Finding.vulnerability_id == vulnerability_id, Finding.workspace == workspace).limit(1))
    if not item or not exists: raise HTTPException(404, 'Plugin group not found')
    return item

def _owner(db, owner_id):
    if owner_id is None: return None
    user = db.get(User, owner_id)
    if not user or not user.active: raise HTTPException(422, 'Owner is not an active user')
    return user

@router.get('/owners')
def owners(user=Depends(require_user), db=Depends(get_db)):
    return [{'id': u.id, 'username': u.username, 'role': u.role} for u in db.scalars(select(User).where(User.active == True).order_by(User.username))]

@router.get('/assessment-groups/{vulnerability_id}/template')
def get_template(vulnerability_id: int, request: Request, user=Depends(require_user), db=Depends(get_db)):
    workspace = _workspace(request); _plugin(db, vulnerability_id, workspace)
    item = db.scalar(select(PluginAssessmentTemplate).where(PluginAssessmentTemplate.workspace == workspace, PluginAssessmentTemplate.vulnerability_id == vulnerability_id))
    if not item: return None
    return {'id': item.id, 'owner_id': item.owner_id, 'owner': db.get(User, item.owner_id).username if item.owner_id else None,
            'status': item.status, 'notes': item.notes, 'justification': item.justification, 'decision': item.decision,
            'controls': item.controls, 'updated_at': item.updated_at.isoformat()}

@router.put('/assessment-groups/{vulnerability_id}/template')
def save_template(vulnerability_id: int, data: PluginTemplateInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = _workspace(request); _plugin(db, vulnerability_id, workspace); _owner(db, data.owner_id)
    method = active_methodology(db); known = {c['name'] for c in method.configuration['controls']}
    if any(c.name not in known for c in data.controls): raise HTTPException(422, 'Template contains an unknown control')
    item = db.scalar(select(PluginAssessmentTemplate).where(PluginAssessmentTemplate.workspace == workspace, PluginAssessmentTemplate.vulnerability_id == vulnerability_id))
    if not item:
        item = PluginAssessmentTemplate(workspace=workspace, vulnerability_id=vulnerability_id, updated_by=user.id); db.add(item)
    for key, value in data.model_dump(mode='json').items(): setattr(item, key, value)
    item.updated_by = user.id; item.updated_at = datetime.now(timezone.utc)
    db.add(Audit(actor_id=user.id, action='plugin_template.saved', entity='vulnerability', entity_id=vulnerability_id, details={'status': data.status, 'owner_id': data.owner_id}))
    db.commit(); return {'id': item.id, 'message': 'Plugin assessment template saved'}

@router.post('/assessment-groups/{vulnerability_id}/template/apply')
def apply_template(vulnerability_id: int, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = _workspace(request); vulnerability = _plugin(db, vulnerability_id, workspace)
    template = db.scalar(select(PluginAssessmentTemplate).where(PluginAssessmentTemplate.workspace == workspace, PluginAssessmentTemplate.vulnerability_id == vulnerability_id))
    if not template: raise HTTPException(409, 'Save a plugin template before applying it')
    if not template.justification.strip(): raise HTTPException(422, 'Template justification is required before applying')
    method = active_methodology(db); rules = {c['name']: c for c in method.configuration['controls']}; applied = 0
    for finding in db.scalars(select(Finding).where(Finding.workspace == workspace, Finding.vulnerability_id == vulnerability_id)):
        asset = db.get(Asset, finding.asset_id); controls = template.controls or []
        technical = {**vulnerability.technical, **finding.observed}
        result = calculate(technical, asset.context or {}, controls, method.configuration, datetime.now(timezone.utc).date())
        result.update({'methodology_id': method.id, 'methodology_version': method.version, 'asset_snapshot': {'id': asset.id, 'hostname': asset.hostname, 'ip': asset.ip, 'os': asset.os, 'tags': asset.tags}})
        finding.revision += 1
        assessment = Assessment(instance_id=finding.id, revision=finding.revision, methodology_id=method.id, analyst_id=user.id,
                                context=asset.context or {}, notes=template.notes, justification=template.justification,
                                decision=template.decision, status='Assessed' if template.status not in ('New','Investigating') else 'Assessment In Progress')
        db.add(assessment); db.flush()
        for control in controls:
            rule = rules.get(control['name']);
            if rule: db.add(AssessmentControl(assessment_id=assessment.id, component=rule['component'], **control))
        db.add(RiskScore(assessment_id=assessment.id, result=result))
        workflow = db.get(FindingWorkflow, finding.id)
        if not workflow:
            workflow = FindingWorkflow(finding_id=finding.id, updated_by=user.id); db.add(workflow)
        workflow.owner_id, workflow.status, workflow.updated_by = template.owner_id, template.status, user.id
        applied += 1
    db.add(Audit(actor_id=user.id, action='plugin_template.applied', entity='vulnerability', entity_id=vulnerability_id, details={'findings': applied}))
    db.commit(); return {'findings_assessed': applied}

@router.post('/assessment-groups/{vulnerability_id}/bulk-assess')
def bulk_assess_plugin(vulnerability_id: int, data: PluginBulkAssessmentInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    """Apply the complete workbench assessment once across a plugin's current finding population."""
    from .core import preview_score
    workspace = _workspace(request); vulnerability = _plugin(db, vulnerability_id, workspace); _owner(db, data.owner_id)
    findings = list(db.scalars(select(Finding).where(Finding.workspace == workspace, Finding.vulnerability_id == vulnerability_id)))
    if not findings: raise HTTPException(404, 'No findings are available for this plugin')
    if data.decision == 'Risk Accepted' or data.status == 'Risk Accepted':
        if user.role != 'Administrator': raise HTTPException(403, 'Only an Administrator can approve risk acceptance')
        if data.decision != 'Risk Accepted' or data.status != 'Risk Accepted': raise HTTPException(422, 'Risk acceptance decision and status must agree')
    methodology = active_methodology(db)
    prepared=[]
    for finding in findings:
        assessment_data = AssessmentInput(context=data.context, controls=data.controls, methodology_id=methodology.id,
            expected_revision=finding.revision, notes=data.notes, justification=data.justification, decision=data.decision, status=data.status)
        method, result = preview_score(db, finding, assessment_data)
        if data.decision == 'Within Risk Appetite' and result['above_appetite']:
            raise HTTPException(422, 'Residual risk is above appetite for one or more affected assets')
        if result['missing_required'] and data.status not in ('Context Required', 'Assessment In Progress'):
            raise HTTPException(422, 'Required context is missing: ' + ', '.join(result['missing_required']))
        prepared.append((finding, method, result))
    rules = {rule['name']: rule for rule in prepared[0][1].configuration['controls']}
    try:
        for finding, method, result in prepared:
            finding.revision += 1
            assessment = Assessment(instance_id=finding.id, revision=finding.revision, methodology_id=method.id, analyst_id=user.id,
                context=data.context.model_dump(), notes=data.notes, justification=data.justification, decision=data.decision, status=data.status)
            db.add(assessment); db.flush()
            for control in data.controls:
                db.add(AssessmentControl(assessment_id=assessment.id, component=rules[control.name]['component'], **control.model_dump()))
            asset=db.get(Asset, finding.asset_id)
            result.update({'methodology_id':method.id, 'methodology_version':method.version, 'asset_snapshot':{'id':asset.id,'hostname':asset.hostname,'ip':asset.ip,'os':asset.os,'tags':asset.tags}})
            db.add(RiskScore(assessment_id=assessment.id, result=result))
            workflow=db.get(FindingWorkflow,finding.id)
            if not workflow:
                workflow=FindingWorkflow(finding_id=finding.id,updated_by=user.id); db.add(workflow)
            workflow.owner_id, workflow.status, workflow.updated_by = data.owner_id, data.workflow_status, user.id
        db.add(Audit(actor_id=user.id, action='plugin_assessment.bulk_applied', entity='vulnerability', entity_id=vulnerability_id,
            details={'findings':len(prepared),'decision':data.decision,'status':data.status,'workflow_status':data.workflow_status,'context':data.context.model_dump()}))
        db.commit()
    except Exception:
        db.rollback(); raise
    return {'findings_assessed':len(prepared), 'assets_affected':len({finding.asset_id for finding,_,_ in prepared})}

@router.put('/findings/{finding_id}/workflow')
def update_workflow(finding_id: int, data: WorkflowInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding or finding.workspace != _workspace(request): raise HTTPException(404, 'Finding not found')
    _owner(db, data.owner_id); item = db.get(FindingWorkflow, finding_id)
    if not item: item = FindingWorkflow(finding_id=finding_id, updated_by=user.id); db.add(item)
    timestamp = datetime.now(timezone.utc)
    if data.status == 'Reviewed':
        previous = {'review_state': item.review_state, 'reviewed_at': item.reviewed_at.isoformat() if item.reviewed_at else None,
                    'reviewed_by': item.reviewed_by}
        item.review_state, item.reviewed_at, item.reviewed_by = 'Reviewed', timestamp, user.id
        item.review_decision, item.review_notes = 'No change required', 'Reviewed from the vulnerabilities worklist'
        db.add(Audit(actor_id=user.id, action='finding.reviewed', entity='finding', entity_id=finding_id,
                     details={'workspace': _workspace(request), 'before': previous, 'decision': item.review_decision}))
    else:
        item.owner_id, item.status = data.owner_id, data.status
        item.remediation_due_at = data.remediation_due_at
        item.remediation_evidence = data.remediation_evidence
        db.add(Audit(actor_id=user.id, action='workflow.updated', entity='finding', entity_id=finding_id,
                     details={**data.model_dump(mode='json'), 'workspace': _workspace(request)}))
    item.updated_by, item.updated_at = user.id, timestamp
    db.commit(); return {'finding_id': finding_id, 'status': item.status, 'owner_id': item.owner_id,
                         'remediation_due_at': item.remediation_due_at.isoformat() if item.remediation_due_at else None,
                         'remediation_evidence': item.remediation_evidence,
                         'review_state': item.review_state, 'reviewed_at': item.reviewed_at.isoformat() if item.reviewed_at else None}

@router.get('/exceptions')
def exceptions(request: Request, user=Depends(require_user), db=Depends(get_db)):
    now = datetime.now(timezone.utc); rows = db.scalars(select(RiskException).where(RiskException.workspace == _workspace(request)).order_by(RiskException.id.desc())).all()
    output=[]
    for x in rows:
        expired = x.expires_at.replace(tzinfo=timezone.utc) <= now if x.expires_at.tzinfo is None else x.expires_at <= now
        status = 'Expired' if x.status == 'Approved' and expired else x.status
        finding=db.get(Finding,x.finding_id); vulnerability=db.get(Vulnerability,finding.vulnerability_id); asset=db.get(Asset,finding.asset_id)
        output.append({'id':x.id,'finding_id':x.finding_id,'finding':vulnerability.name,'asset':asset.hostname,'justification':x.justification,'evidence':x.evidence,'status':status,'expires_at':x.expires_at.isoformat(),'review_frequency_days':x.review_frequency_days,'requested_by':db.get(User,x.requested_by).username,'approved_by':db.get(User,x.approved_by).username if x.approved_by else None})
    return output

@router.post('/findings/{finding_id}/exceptions', status_code=201)
def request_exception(finding_id:int, data:ExceptionInput, request:Request, user=Depends(writer), db=Depends(get_db)):
    finding=db.get(Finding,finding_id)
    if not finding or finding.workspace != _workspace(request): raise HTTPException(404,'Finding not found')
    expiry=data.expires_at if data.expires_at.tzinfo else data.expires_at.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc): raise HTTPException(422,'Expiration must be in the future')
    item=RiskException(workspace=_workspace(request),finding_id=finding_id,justification=data.justification,evidence=data.evidence,expires_at=expiry,review_frequency_days=data.review_frequency_days,requested_by=user.id)
    db.add(item);db.flush();db.add(Audit(actor_id=user.id,action='exception.requested',entity='exception',entity_id=item.id,details={'finding_id':finding_id,'expires_at':expiry.isoformat()}));db.commit();return {'id':item.id,'status':item.status}

@router.put('/exceptions/{id}')
def decide_exception(id:int,data:ExceptionDecision,user=Depends(admin),db=Depends(get_db)):
    item=db.get(RiskException,id)
    if not item: raise HTTPException(404,'Exception not found')
    item.status=data.status;item.approved_by=user.id;item.reviewed_at=datetime.now(timezone.utc)
    db.add(Audit(actor_id=user.id,action='exception.'+data.status.lower(),entity='exception',entity_id=id));db.commit();return {'id':id,'status':item.status}

@router.get('/controls')
def controls(request:Request,user=Depends(require_user),db=Depends(get_db)):
    rows=db.scalars(select(ControlLibrary).where(ControlLibrary.workspace==_workspace(request)).order_by(ControlLibrary.name)).all()
    return [{'id':x.id,'name':x.name,'description':x.description,'owner_id':x.owner_id,'owner':db.get(User,x.owner_id).username if x.owner_id else None,'evidence_requirements':x.evidence_requirements,'mappings':x.mappings,'design_maturity':x.design_maturity,'operating_effectiveness':x.operating_effectiveness,'last_tested_at':x.last_tested_at.isoformat() if x.last_tested_at else None,'active':x.active} for x in rows]

@router.post('/controls',status_code=201)
def create_control(data:ControlLibraryInput,request:Request,user=Depends(admin),db=Depends(get_db)):
    _owner(db,data.owner_id); item=ControlLibrary(workspace=_workspace(request),updated_by=user.id,**data.model_dump());db.add(item);db.flush();db.add(Audit(actor_id=user.id,action='control.created',entity='control',entity_id=item.id));db.commit();return {'id':item.id}

@router.put('/controls/{id}')
def update_control(id:int,data:ControlLibraryInput,request:Request,user=Depends(admin),db=Depends(get_db)):
    item=db.get(ControlLibrary,id)
    if not item or item.workspace != _workspace(request): raise HTTPException(404,'Control not found')
    _owner(db,data.owner_id)
    for key,value in data.model_dump().items(): setattr(item,key,value)
    item.updated_by=user.id;item.updated_at=datetime.now(timezone.utc);db.add(Audit(actor_id=user.id,action='control.updated',entity='control',entity_id=id));db.commit();return {'id':id}

@router.get('/data-quality')
def data_quality(request:Request,user=Depends(require_user),db=Depends(get_db)):
    workspace=_workspace(request); total_assets=db.scalar(select(func.count(Asset.id)).where(Asset.workspace==workspace)) or 0; total_findings=db.scalar(select(func.count(Finding.id)).where(Finding.workspace==workspace)) or 0
    missing_context=db.scalar(select(func.count(Asset.id)).where(Asset.workspace==workspace,func.coalesce(Asset.context['asset_criticality'].as_string(),'')=='')) or 0
    missing_ip=db.scalar(select(func.count(Asset.id)).where(Asset.workspace==workspace,Asset.ip.is_(None))) or 0
    missing_business_owner=db.scalar(select(func.count(Asset.id)).where(Asset.workspace==workspace,func.coalesce(Asset.context['business_owner'].as_string(),'')=='')) or 0
    missing_it_owner=db.scalar(select(func.count(Asset.id)).where(Asset.workspace==workspace,func.coalesce(Asset.context['it_owner'].as_string(),'')=='')) or 0
    missing_application_owner=db.scalar(select(func.count(Asset.id)).where(Asset.workspace==workspace,func.coalesce(Asset.context['application_owner'].as_string(),'')=='')) or 0
    unowned=db.scalar(select(func.count(Finding.id)).outerjoin(FindingWorkflow,FindingWorkflow.finding_id==Finding.id).where(Finding.workspace==workspace,FindingWorkflow.owner_id.is_(None))) or 0
    no_cve=db.scalar(select(func.count(Finding.id)).join(Vulnerability).where(Finding.workspace==workspace,func.json_array_length(Vulnerability.cves)==0)) or 0
    # Only completed/failed jobs represent an operational data-quality result;
    # abandoned validation previews would otherwise permanently inflate this.
    rejected=db.scalar(select(func.coalesce(func.sum(ImportBatch.counts['rejected'].as_integer()),0)).where(ImportBatch.workspace==workspace,ImportBatch.status.in_(['Imported','Failed']))) or 0
    checks=[('Missing asset criticality',missing_context,total_assets,'Classify assets or apply an asset rule'),('Missing Business Owner',missing_business_owner,total_assets,'Assign the accountable business owner'),('Missing IT Owner / Remediator',missing_it_owner,total_assets,'Assign the infrastructure or IT remediation owner'),('Missing Application Owner / Remediator',missing_application_owner,total_assets,'Assign the application support owner'),('Missing IP address',missing_ip,total_assets,'Improve scanner asset identity mapping'),('Unassigned findings',unowned,total_findings,'Assign an analyst or plugin owner'),('Findings without CVE',no_cve,total_findings,'Review valid configuration findings and source mappings'),('Rejected import rows',rejected,None,'Download the import error details and correct the source')]
    sync_running=bool(db.scalar(select(SyncJob.id).where(SyncJob.workspace==workspace,SyncJob.status.in_(['Running','Cancel requested'])).limit(1)))
    duplicates=tenable_duplicate_summary(db, workspace)
    return {'assets':total_assets,'findings':total_findings,'sync_running':sync_running,'can_clear':user.role=='Administrator','duplicates':duplicates,'checks':[{'name':n,'count':c,'percent':round(c*100/d,1) if d else None,'action':a,'status':'Good' if c==0 else 'Needs attention'} for n,c,d,a in checks]}

@router.post('/data-quality/remove-duplicates')
def remove_duplicates(data: DuplicateCleanupRequest, request: Request, user=Depends(admin), db=Depends(get_db)):
    workspace=_workspace(request)
    if db.scalar(select(SyncJob.id).where(SyncJob.workspace==workspace,SyncJob.status.in_(['Running','Cancel requested'])).limit(1)):
        raise HTTPException(409, 'Stop or wait for the active Tenable synchronization before removing duplicates')
    result=cleanup_tenable_duplicates(db, workspace)
    db.add(Audit(actor_id=user.id, action='data_quality.duplicates_removed', entity='workspace', details={'workspace':workspace, **result}))
    db.commit()
    message=f"Removed {result['duplicates_removed']:,} duplicate Tenable finding{'s' if result['duplicates_removed'] != 1 else ''}."
    if result['duplicates_protected']:
        message+=f" Retained {result['duplicates_protected']:,} record{'s' if result['duplicates_protected'] != 1 else ''} referenced by review campaigns."
    return {'message':message, **result}

@router.post('/data-quality/clear-operational-data')
def clear_operational_data(data: DataCleanupRequest, request: Request, user=Depends(admin), db=Depends(get_db)):
    """Remove one workspace's imported operational data while retaining users, policy, rules, and audit evidence."""
    workspace=_workspace(request)
    if db.scalar(select(SyncJob.id).where(SyncJob.workspace==workspace,SyncJob.status.in_(['Running','Cancel requested'])).limit(1)):
        raise HTTPException(409, 'Stop or wait for the active Tenable synchronization before clearing data')
    finding_ids=select(Finding.id).where(Finding.workspace==workspace)
    assessment_ids=select(Assessment.id).where(Assessment.instance_id.in_(finding_ids))
    import_ids=select(ImportBatch.id).where(ImportBatch.workspace==workspace)
    campaign_ids=select(ReviewCampaign.id).where(ReviewCampaign.workspace==workspace)
    counts={
        'findings': db.scalar(select(func.count()).select_from(Finding).where(Finding.workspace==workspace)) or 0,
        'assets': db.scalar(select(func.count()).select_from(Asset).where(Asset.workspace==workspace)) or 0,
        'campaigns': db.scalar(select(func.count()).select_from(ReviewCampaign).where(ReviewCampaign.workspace==workspace)) or 0,
        'imports': db.scalar(select(func.count()).select_from(ImportBatch).where(ImportBatch.workspace==workspace)) or 0,
    }
    try:
        db.execute(delete(CampaignFindingTag).where(CampaignFindingTag.campaign_id.in_(campaign_ids)))
        db.execute(delete(CampaignEvidence).where(CampaignEvidence.campaign_id.in_(campaign_ids)))
        db.execute(delete(CampaignAuditEvent).where(CampaignAuditEvent.campaign_id.in_(campaign_ids)))
        db.execute(delete(CampaignFinding).where(CampaignFinding.campaign_id.in_(campaign_ids)))
        db.execute(delete(CampaignReviewer).where(CampaignReviewer.campaign_id.in_(campaign_ids)))
        db.execute(delete(ReviewCampaign).where(ReviewCampaign.workspace==workspace))
        db.execute(delete(RiskException).where(RiskException.workspace==workspace))
        db.execute(delete(FindingWorkflow).where(FindingWorkflow.finding_id.in_(finding_ids)))
        db.execute(delete(PluginAssessmentTemplate).where(PluginAssessmentTemplate.workspace==workspace))
        db.execute(delete(AssessmentControl).where(AssessmentControl.assessment_id.in_(assessment_ids)))
        db.execute(delete(RiskScore).where(RiskScore.assessment_id.in_(assessment_ids)))
        db.execute(delete(Assessment).where(Assessment.instance_id.in_(finding_ids)))
        db.execute(delete(ImportRow).where(ImportRow.import_id.in_(import_ids)))
        db.execute(delete(ImportBatch).where(ImportBatch.workspace==workspace))
        db.execute(delete(SyncJob).where(SyncJob.workspace==workspace))
        db.execute(delete(Finding).where(Finding.workspace==workspace))
        db.execute(delete(Asset).where(Asset.workspace==workspace))
        db.add(Audit(actor_id=user.id, action='workspace.operational_data_cleared', entity='workspace', details={'workspace':workspace, **counts}))
        db.commit()
    except Exception:
        db.rollback(); raise
    return {'message':'Operational vulnerability data cleared. Users, risk methodology, asset rules, Tenable configuration, and audit history were retained.', 'cleared':counts}

@router.get('/operations')
def operations(request:Request,user=Depends(require_user),db=Depends(get_db)):
    workspace=_workspace(request); total=db.scalar(select(func.count(Finding.id)).where(Finding.workspace==workspace)) or 0
    status_rows=db.execute(select(func.coalesce(FindingWorkflow.status,'New'),func.count(Finding.id)).select_from(Finding).outerjoin(FindingWorkflow,FindingWorkflow.finding_id==Finding.id).where(Finding.workspace==workspace).group_by(FindingWorkflow.status)).all()
    owner_rows=db.execute(select(User.username,func.count(FindingWorkflow.finding_id)).select_from(FindingWorkflow).join(Finding).outerjoin(User,User.id==FindingWorkflow.owner_id).where(Finding.workspace==workspace).group_by(User.username).order_by(func.count(FindingWorkflow.finding_id).desc()).limit(10)).all()
    thirty=(datetime.now(timezone.utc)-timedelta(days=30)).date().isoformat()
    stale=db.scalar(select(func.count(Finding.id)).where(Finding.workspace==workspace,Finding.observed['last_seen'].as_string()<thirty)) or 0
    exceptions_open=db.scalar(select(func.count(RiskException.id)).where(RiskException.workspace==workspace,RiskException.status.in_(['Requested','Approved']))) or 0
    return {'total':total,'stale':stale,'open_exceptions':exceptions_open,'statuses':[{'name':s or 'New','value':c} for s,c in status_rows],'owners':[{'name':n or 'Unassigned','value':c} for n,c in owner_rows]}

def _executive_filters(request):
    allowed = ('period_start', 'period_end', 'severity', 'asset_group', 'business_owner', 'it_owner', 'application_owner', 'regulatory', 'campaign_id')
    filters = {key: request.query_params[key] for key in allowed if request.query_params.get(key)}
    if filters.get('campaign_id'):
        try:
            filters['campaign_id'] = int(filters['campaign_id'])
        except ValueError:
            raise HTTPException(422, 'Campaign ID must be an integer')
    if filters.get('severity') and filters['severity'] not in ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'):
        raise HTTPException(422, 'Invalid severity')
    return filters

@router.get('/executive-report')
def executive_report(request: Request, user=Depends(require_user), db=Depends(get_db)):
    from ..executive import executive_report_data
    return executive_report_data(db, _workspace(request), user, _executive_filters(request))

@router.get('/executive-report.pdf')
def executive_report_pdf(request: Request, user=Depends(require_user), db=Depends(get_db)):
    from fastapi.responses import Response
    from ..report_pdf import build_executive_pdf
    data = executive_report(request, user, db)
    payload = build_executive_pdf(data)
    filename = f"VRAP-Executive-Report-{data['environment']}-{data['period']['end']}.pdf"
    return Response(payload, media_type='application/pdf', headers={
        'Content-Disposition': f'attachment; filename="{filename}"',
        'Content-Length': str(len(payload)), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})

@router.get('/review-report')
def review_report(request: Request, days: int = 7, user=Depends(require_user), db=Depends(get_db)):
    workspace = _workspace(request); days = max(1, min(days, 366)); since = datetime.now(timezone.utc) - timedelta(days=days)
    total = db.scalar(select(func.count(Finding.id)).where(Finding.workspace == workspace)) or 0
    review_state = func.coalesce(FindingWorkflow.review_state, FindingWorkflow.status)
    reviewed_at = func.coalesce(FindingWorkflow.reviewed_at, FindingWorkflow.updated_at)
    reviewed = db.scalar(select(func.count(Finding.id)).join(FindingWorkflow, FindingWorkflow.finding_id == Finding.id).where(Finding.workspace == workspace, review_state == 'Reviewed', reviewed_at >= since)) or 0
    pending = total - reviewed
    rows = db.execute(select(Finding.id, Asset.hostname, Vulnerability.name, Vulnerability.plugin_id, reviewed_at).join(Asset, Asset.id == Finding.asset_id).join(Vulnerability, Vulnerability.id == Finding.vulnerability_id).join(FindingWorkflow, FindingWorkflow.finding_id == Finding.id).where(Finding.workspace == workspace, Asset.workspace == workspace, review_state == 'Reviewed', reviewed_at >= since).order_by(reviewed_at.desc())).all()
    return {'workspace': workspace, 'period_days': days, 'since': since.isoformat(), 'generated_at': datetime.now(timezone.utc).isoformat(), 'summary': {'total_findings': total, 'reviewed_in_period': reviewed, 'pending_review': pending, 'coverage_percent': round(reviewed * 100 / total, 1) if total else 0}, 'reviews': [{'finding_id': i, 'asset': h, 'vulnerability': n, 'plugin_id': p, 'reviewed_at': t.isoformat() if t else None} for i,h,n,p,t in rows]}

@router.get('/review-report.csv')
def review_report_csv(request: Request, days: int = 7, user=Depends(require_user), db=Depends(get_db)):
    from .campaign_exports import safe_csv_cell
    report = review_report(request, days, user, db); out = StringIO(); out.write('VRAP Operational Vulnerability Review Report\n'); out.write(f"Workspace,{report['workspace']}\nPeriod days,{report['period_days']}\nReviewed in period,{report['summary']['reviewed_in_period']}\nPending review,{report['summary']['pending_review']}\nCoverage percent,{report['summary']['coverage_percent']}\n\nFinding ID,Asset,Vulnerability,Plugin ID,Reviewed At\n")
    for x in report['reviews']:
        values=[safe_csv_cell(x[k]).replace('"','""') for k in ('finding_id','asset','vulnerability','plugin_id','reviewed_at')]; out.write(','.join(f'"{v}"' for v in values)+'\n')
    return StreamingResponse(iter([out.getvalue()]), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename=vrap-operational-review.csv'})
