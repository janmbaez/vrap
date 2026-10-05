from datetime import datetime, timezone, timedelta
from io import BytesIO, StringIO
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy import select, func, case, update
from ..db import get_db
from ..auth import require_user, writer, admin
from ..models import (User, Asset, Vulnerability, Finding, Assessment, AssessmentControl, RiskScore, Audit, ImportBatch,
                      PluginAssessmentTemplate, FindingWorkflow, RiskException, ControlLibrary)
from ..schemas import PluginTemplateInput, WorkflowInput, ExceptionInput, ExceptionDecision, ControlLibraryInput
from ..services import active_methodology, detail
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

@router.put('/findings/{finding_id}/workflow')
def update_workflow(finding_id: int, data: WorkflowInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding or finding.workspace != _workspace(request): raise HTTPException(404, 'Finding not found')
    _owner(db, data.owner_id); item = db.get(FindingWorkflow, finding_id)
    if not item: item = FindingWorkflow(finding_id=finding_id, updated_by=user.id); db.add(item)
    item.owner_id, item.status, item.updated_by, item.updated_at = data.owner_id, data.status, user.id, datetime.now(timezone.utc)
    db.add(Audit(actor_id=user.id, action='workflow.updated', entity='finding', entity_id=finding_id, details=data.model_dump()))
    db.commit(); return {'finding_id': finding_id, 'status': item.status, 'owner_id': item.owner_id}

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
    return {'assets':total_assets,'findings':total_findings,'checks':[{'name':n,'count':c,'percent':round(c*100/d,1) if d else None,'action':a,'status':'Good' if c==0 else 'Needs attention'} for n,c,d,a in checks]}

@router.get('/operations')
def operations(request:Request,user=Depends(require_user),db=Depends(get_db)):
    workspace=_workspace(request); total=db.scalar(select(func.count(Finding.id)).where(Finding.workspace==workspace)) or 0
    status_rows=db.execute(select(func.coalesce(FindingWorkflow.status,'New'),func.count(Finding.id)).select_from(Finding).outerjoin(FindingWorkflow,FindingWorkflow.finding_id==Finding.id).where(Finding.workspace==workspace).group_by(FindingWorkflow.status)).all()
    owner_rows=db.execute(select(User.username,func.count(FindingWorkflow.finding_id)).select_from(FindingWorkflow).join(Finding).outerjoin(User,User.id==FindingWorkflow.owner_id).where(Finding.workspace==workspace).group_by(User.username).order_by(func.count(FindingWorkflow.finding_id).desc()).limit(10)).all()
    thirty=(datetime.now(timezone.utc)-timedelta(days=30)).date().isoformat()
    stale=db.scalar(select(func.count(Finding.id)).where(Finding.workspace==workspace,Finding.observed['last_seen'].as_string()<thirty)) or 0
    exceptions_open=db.scalar(select(func.count(RiskException.id)).where(RiskException.workspace==workspace,RiskException.status.in_(['Requested','Approved']))) or 0
    return {'total':total,'stale':stale,'open_exceptions':exceptions_open,'statuses':[{'name':s or 'New','value':c} for s,c in status_rows],'owners':[{'name':n or 'Unassigned','value':c} for n,c in owner_rows]}

@router.get('/executive-report')
def executive_report(request:Request,user=Depends(require_user),db=Depends(get_db)):
    workspace=_workspace(request); generated=datetime.now(timezone.utc); total=db.scalar(select(func.count(Finding.id)).where(Finding.workspace==workspace)) or 0
    sev=func.coalesce(Finding.observed['severity'].as_string(),Vulnerability.technical['severity'].as_string())
    severity=dict(db.execute(select(sev,func.count()).select_from(Finding).join(Vulnerability).where(Finding.workspace==workspace).group_by(sev)).all())
    assessed=db.scalar(select(func.count(func.distinct(Assessment.instance_id))).select_from(Assessment).join(Finding,Finding.id==Assessment.instance_id).where(Finding.workspace==workspace)) or 0
    accepted=db.scalar(select(func.count(RiskException.id)).where(RiskException.workspace==workspace,RiskException.status=='Approved')) or 0
    latest=(select(Assessment.instance_id,func.max(Assessment.id).label('assessment_id')).join(Finding,Finding.id==Assessment.instance_id).where(Finding.workspace==workspace).group_by(Assessment.instance_id).subquery())
    scored=db.execute(select(RiskScore.result).join(Assessment,RiskScore.assessment_id==Assessment.id).join(latest,latest.c.assessment_id==Assessment.id)).scalars().all()
    residual={level:sum(1 for result in scored if result.get('residual_level')==level) for level in ['Critical','High','Medium','Low','Informational']}
    above=sum(1 for result in scored if result.get('above_appetite')); within=len(scored)-above
    reviewed=db.scalar(select(func.count(FindingWorkflow.finding_id)).join(Finding,Finding.id==FindingWorkflow.finding_id).where(Finding.workspace==workspace,FindingWorkflow.status=='Reviewed')) or 0
    top=db.execute(select(Vulnerability.name,Vulnerability.plugin_id,func.count(Finding.id)).join(Finding).where(Finding.workspace==workspace).group_by(Vulnerability.id).order_by(func.count(Finding.id).desc()).limit(10)).all()
    return {'title':'Vulnerability Risk Executive Report','environment':workspace,'generated_at':generated.isoformat(),'summary':{'total_findings':total,'affected_assets':db.scalar(select(func.count(Asset.id)).where(Asset.workspace==workspace)) or 0,'assessed':assessed,'assessment_coverage':round(assessed*100/total,1) if total else 0,'approved_exceptions':accepted,'reviewed':reviewed},'assessment_posture':{'above_appetite':above,'within_appetite':within,'unassessed':max(total-assessed,0),'residual_distribution':residual},'severity':{s:severity.get(s,0) for s in ['Critical','High','Medium','Low','Informational']},'top_exposures':[{'name':n,'plugin_id':p,'findings':c} for n,p,c in top],'statement':'Technical severity is combined with organizational context, validated controls, and the latest saved assessment. Risk acceptance requires explicit, expiring approval.'}

@router.get('/executive-report.pdf')
def executive_report_pdf(request: Request, user=Depends(require_user), db=Depends(get_db)):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

    data = executive_report(request, user, db)
    stream = BytesIO(); teal = colors.HexColor('#087f79'); navy = colors.HexColor('#173342'); muted = colors.HexColor('#667b86')
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='ReportTitle', parent=styles['Title'], fontName='Helvetica-Bold', fontSize=22, leading=26, textColor=navy, spaceAfter=5))
    styles.add(ParagraphStyle(name='Section', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=navy, spaceBefore=16, spaceAfter=8))
    styles.add(ParagraphStyle(name='SmallMuted', parent=styles['BodyText'], fontSize=8.5, leading=12, textColor=muted))
    styles.add(ParagraphStyle(name='RightMuted', parent=styles['SmallMuted'], alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name='Compact', parent=styles['BodyText'], fontSize=8.5, leading=10))

    def footer(canvas, doc):
        canvas.saveState(); canvas.setStrokeColor(colors.HexColor('#d9e3e7')); canvas.line(0.55*inch,0.48*inch,7.95*inch,0.48*inch)
        canvas.setFont('Helvetica',8); canvas.setFillColor(muted); canvas.drawString(0.55*inch,0.28*inch,'VRAP - '+data['environment']+' - Confidential')
        canvas.drawRightString(7.95*inch,0.28*inch,'Page '+str(doc.page)); canvas.restoreState()

    doc = SimpleDocTemplate(stream, pagesize=letter, rightMargin=.55*inch, leftMargin=.55*inch, topMargin=.55*inch, bottomMargin=.62*inch,
                            title=data['title'], author='VRAP')
    story = [Paragraph('VRAP / EXECUTIVE RISK REPORT', styles['SmallMuted']), Paragraph(data['title'], styles['ReportTitle']),
             Paragraph(f"{data['environment']} environment | Generated {datetime.fromisoformat(data['generated_at']).strftime('%B %d, %Y at %H:%M UTC')}", styles['SmallMuted']), Spacer(1,16)]
    summary = data['summary']
    cards = [[Paragraph('<b>Total findings</b>',styles['SmallMuted']),Paragraph('<b>Affected assets</b>',styles['SmallMuted']),Paragraph('<b>Assessment coverage</b>',styles['SmallMuted']),Paragraph('<b>Approved exceptions</b>',styles['SmallMuted'])],
             [f"{summary['total_findings']:,}",f"{summary['affected_assets']:,}",f"{summary['assessment_coverage']}%",f"{summary['approved_exceptions']:,}"]]
    card_table=Table(cards,colWidths=[1.85*inch]*4,rowHeights=[.32*inch,.44*inch]);card_table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#f3f7f8')),('BOX',(0,0),(-1,-1),.6,colors.HexColor('#d9e3e7')),('INNERGRID',(0,0),(-1,-1),.4,colors.HexColor('#d9e3e7')),('TEXTCOLOR',(0,1),(-1,1),navy),('FONTNAME',(0,1),(-1,1),'Helvetica-Bold'),('FONTSIZE',(0,1),(-1,1),18),('ALIGN',(0,1),(-1,1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LEFTPADDING',(0,0),(-1,-1),10)]));story.append(card_table)
    story += [Paragraph('Executive position',styles['Section']),Paragraph(data['statement']+' Current assessment coverage is '+str(summary['assessment_coverage'])+'%; unassessed findings should not be interpreted as accepted risk.',styles['BodyText']),Paragraph('Technical exposure',styles['Section'])]
    severity_colors={'Critical':'#f8dfe2','High':'#fdebd5','Medium':'#e2eef9','Low':'#e1f2ea','Informational':'#eef2f4'}
    sev_rows=[['Severity','Findings','Share']]+[[name,f"{count:,}",f"{count*100/summary['total_findings']:.1f}%" if summary['total_findings'] else '0%'] for name,count in data['severity'].items()]
    sev_table=Table(sev_rows,colWidths=[3.8*inch,1.7*inch,1.7*inch]);sev_style=[('BACKGROUND',(0,0),(-1,0),navy),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#d9e3e7')),('ALIGN',(1,1),(-1,-1),'RIGHT'),('FONTNAME',(0,1),(0,-1),'Helvetica-Bold'),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7)]
    for index,name in enumerate(data['severity'],1): sev_style.append(('BACKGROUND',(0,index),(0,index),colors.HexColor(severity_colors[name])))
    sev_table.setStyle(TableStyle(sev_style));story.append(sev_table)
    story += [Paragraph('Most widespread vulnerabilities',styles['Section'])]
    exposure_rows=[['Plugin / vulnerability','Plugin ID','Affected findings']]+[[Paragraph(x['name'],styles['Compact']),x['plugin_id'] or '-',f"{x['findings']:,}"] for x in data['top_exposures'][:6]]
    exposure=Table(exposure_rows,colWidths=[4.8*inch,1.1*inch,1.3*inch],repeatRows=1);exposure.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),teal),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,1),(-1,-1),8.5),('GRID',(0,0),(-1,-1),.35,colors.HexColor('#d9e3e7')),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f7f9fa')]),('VALIGN',(0,0),(-1,-1),'TOP'),('ALIGN',(1,1),(-1,-1),'RIGHT'),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4)]));story.append(exposure)
    story += [Spacer(1,14),KeepTogether([Paragraph('Governance interpretation',styles['Section']),Paragraph(data['statement']+' Exceptions remain time-bound and require explicit approval. Workflow ownership does not create an SLA or Jira ticket.',styles['BodyText'])])]
    posture=data['assessment_posture']; story.append(PageBreak())
    story += [Paragraph('VRAP / ASSESSMENT DASHBOARD',styles['SmallMuted']), Paragraph('Assessment posture and residual risk',styles['ReportTitle']), Paragraph('Latest saved assessment per finding · '+data['environment']+' environment',styles['SmallMuted']), Spacer(1,16)]
    dash=[[Paragraph('<b>Completed assessments</b>',styles['SmallMuted']),Paragraph('<b>Above appetite</b>',styles['SmallMuted']),Paragraph('<b>Within appetite</b>',styles['SmallMuted']),Paragraph('<b>Pending assessment</b>',styles['SmallMuted'])],[str(summary['assessed']),str(posture['above_appetite']),str(posture['within_appetite']),str(posture['unassessed'])]]
    dt=Table(dash,colWidths=[1.85*inch]*4,rowHeights=[.32*inch,.5*inch]);dt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#f3f7f8')),('BOX',(0,0),(-1,-1),.6,colors.HexColor('#d9e3e7')),('INNERGRID',(0,0),(-1,-1),.4,colors.HexColor('#d9e3e7')),('FONTNAME',(0,1),(-1,1),'Helvetica-Bold'),('FONTSIZE',(0,1),(-1,1),20),('TEXTCOLOR',(0,1),(0,1),teal),('TEXTCOLOR',(1,1),(1,1),colors.HexColor('#c7464b')),('ALIGN',(0,1),(-1,1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE')])); story.append(dt)
    story += [Paragraph('Residual risk distribution',styles['Section'])]
    residual_rows=[['Residual level','Findings','Share']]+[[k,str(v),f"{v*100/summary['assessed']:.1f}%" if summary['assessed'] else '0%'] for k,v in posture['residual_distribution'].items()]
    rt=Table(residual_rows,colWidths=[3.8*inch,1.7*inch,1.7*inch],repeatRows=1);rt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),navy),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#d9e3e7')),('ALIGN',(1,1),(-1,-1),'RIGHT'),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)])); story.append(rt)
    story += [Paragraph('Operational review coverage',styles['Section']),Paragraph(f"{summary['reviewed']} findings are marked Reviewed. This report documents review activity and assessment posture; pending items remain visible for follow-up.",styles['BodyText'])]
    doc.build(story,onFirstPage=footer,onLaterPages=footer);stream.seek(0)
    filename=f"VRAP-Executive-Report-{data['environment']}-{datetime.now(timezone.utc).date().isoformat()}.pdf"
    return StreamingResponse(stream,media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="{filename}"'})

@router.get('/review-report')
def review_report(request: Request, days: int = 7, user=Depends(require_user), db=Depends(get_db)):
    workspace = _workspace(request); days = max(1, min(days, 366)); since = datetime.now(timezone.utc) - timedelta(days=days)
    total = db.scalar(select(func.count(Finding.id)).where(Finding.workspace == workspace)) or 0
    reviewed = db.scalar(select(func.count(Finding.id)).join(FindingWorkflow, FindingWorkflow.finding_id == Finding.id).where(Finding.workspace == workspace, FindingWorkflow.status == 'Reviewed', FindingWorkflow.updated_at >= since)) or 0
    pending = total - reviewed
    rows = db.execute(select(Finding.id, Asset.hostname, Vulnerability.name, Vulnerability.plugin_id, FindingWorkflow.updated_at).join(Asset, Asset.id == Finding.asset_id).join(Vulnerability, Vulnerability.id == Finding.vulnerability_id).join(FindingWorkflow, FindingWorkflow.finding_id == Finding.id).where(Finding.workspace == workspace, FindingWorkflow.status == 'Reviewed', FindingWorkflow.updated_at >= since).order_by(FindingWorkflow.updated_at.desc())).all()
    return {'workspace': workspace, 'period_days': days, 'since': since.isoformat(), 'generated_at': datetime.now(timezone.utc).isoformat(), 'summary': {'total_findings': total, 'reviewed_in_period': reviewed, 'pending_review': pending, 'coverage_percent': round(reviewed * 100 / total, 1) if total else 0}, 'reviews': [{'finding_id': i, 'asset': h, 'vulnerability': n, 'plugin_id': p, 'reviewed_at': t.isoformat() if t else None} for i,h,n,p,t in rows]}

@router.get('/review-report.csv')
def review_report_csv(request: Request, days: int = 7, user=Depends(require_user), db=Depends(get_db)):
    report = review_report(request, days, user, db); out = StringIO(); out.write('VRAP Operational Vulnerability Review Report\n'); out.write(f"Workspace,{report['workspace']}\nPeriod days,{report['period_days']}\nReviewed in period,{report['summary']['reviewed_in_period']}\nPending review,{report['summary']['pending_review']}\nCoverage percent,{report['summary']['coverage_percent']}\n\nFinding ID,Asset,Vulnerability,Plugin ID,Reviewed At\n")
    for x in report['reviews']:
        values=[str(x[k] or '').replace('"','""') for k in ('finding_id','asset','vulnerability','plugin_id','reviewed_at')]; out.write(','.join(f'"{v}"' for v in values)+'\n')
    return StreamingResponse(iter([out.getvalue()]), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename=vrap-operational-review.csv'})
