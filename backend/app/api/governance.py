from datetime import datetime, timezone, timedelta
import hashlib
import json
import uuid
from io import BytesIO, StringIO
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Query, UploadFile, File
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy import select, func, case, update, delete, or_
from sqlalchemy.orm import aliased
from ..db import get_db
from ..auth import require_user, writer, admin
from ..models import (User, Asset, Vulnerability, Finding, Assessment, AssessmentControl, RiskScore, Audit, ImportBatch,
                      ImportRow, SyncJob, PluginAssessmentTemplate, FindingWorkflow, RiskException, ControlLibrary,
                      ReviewCampaign, CampaignReviewer, CampaignFinding, CampaignFindingTag, CampaignEvidence, CampaignAuditEvent,
                      BulkAssessmentJob, BulkAssessmentItem, SmartAssessmentCategory, PluginAssessmentTemplateRevision, RemediationPackage,
                      RemediationPackageFinding, RemediationPackageEvidence, RemediationPackageEvent, RemediationSLAPolicy)
from ..schemas import PluginTemplateInput, PluginBulkAssessmentInput, WorkflowInput, ExceptionInput, ExceptionDecision, ControlLibraryInput, DataCleanupRequest, DuplicateCleanupRequest, AssessmentInput, Context, RemediationPackageInput, RemediationPackageUpdate, RemediationEvidenceInput, RemediationSLAPolicyInput
from ..services import active_methodology, cleanup_tenable_duplicates, detail, tenable_duplicate_summary
from ..risk.engine import calculate
from ..asset_rules import PROTECTED_CONTEXT_FIELDS
from ..vulnerability_questionnaire import QUESTIONNAIRE
from ..kpis import calculate_kpis
from sqlalchemy.exc import IntegrityError

router = APIRouter(tags=['Governance'])

RACI_SHEETS = {
    'START HERE': ['TEMPLATE VERSION', 'IMPORT MODE'],
    'TEAM DIRECTORY': ['Observed team / group', 'Source tag type', 'Support Owner assets', 'Change Owner assets', 'Patching Group assets', 'Proposed function', 'Jira project (APPROVED)', 'Jira team / queue (APPROVED)', 'Accountable manager (APPROVED)', 'Approval state', 'Auto ticket enabled?', 'Approval / evidence reference', 'Notes'],
    'ROUTING RULES': ['Rule ID', 'Priority', 'Source', 'Match value', 'Technical lane', 'Device type', 'OS', 'Responsible candidate', 'Accountable role', 'Prerequisite', 'Confidence', 'Auto action', 'Approval state', 'Guardrails'],
    'ASSET OVERRIDES': ['Asset UUID', 'Asset / hostname', 'Business Service ID', 'Remediation action', 'Technical lane', 'Remediation team (approved name)', 'Support Owner', 'Change Owner', 'Patching Group', 'Accountable manager', 'Approval state', 'Approval / evidence reference', 'Notes / exception reason'],
    'PLUGIN OVERRIDES': ['Plugin ID', 'Plugin / vulnerability', 'Remediation action', 'Technical lane', 'Device type', 'OS', 'Responsible team (approved name)', 'Accountable role', 'Approval state', 'Approval / evidence reference', 'Notes / match scope'],
    'RACI MATRIX': ['ID', 'Process / Activity', 'TVM', 'Infra Ops Mgr', 'Infra Security', 'Platform Ops', 'Client Eng.', 'Database Team', 'DevOps', 'App Dev / Owner', 'GRC / Sec Leads', 'Business/Service Owner', 'Authorized Risk Owner', 'Change/CAB', 'VRAP Automation', 'Approval state'],
    'ROLE MAPPING': ['Source role', 'Proposed role', 'Reason', 'Approval needed'],
    'TECH LANES': ['Technical lane', 'Source', 'Approval state', 'Notes / guardrail']
}

def _raci_parse(data):
    from openpyxl import load_workbook
    import io
    book = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    parsed = {}
    for name in RACI_SHEETS:
        if name not in book.sheetnames: raise HTTPException(422, f'Missing required worksheet: {name}')
        rows = list(book[name].iter_rows(values_only=True)); header = None; start = 0
        for index, row in enumerate(rows):
            values = [str(v).strip() if v is not None else '' for v in row]
            if values and values[0] in RACI_SHEETS[name]: header, start = values, index + 1; break
        if not header: raise HTTPException(422, f'Missing header row in worksheet: {name}')
        items = []
        for row in rows[start:]:
            values = list(row) + [None] * (len(header) - len(row))
            if not any(v is not None and str(v).strip() for v in values): continue
            items.append({header[i]: values[i] for i in range(len(header))})
        parsed[name] = items
    return parsed

@router.get('/raci/template')
def raci_template(user=Depends(require_user)):
    from openpyxl import Workbook
    from fastapi.responses import StreamingResponse
    import io
    book = Workbook(); book.remove(book.active)
    for name, headers in RACI_SHEETS.items():
        ws = book.create_sheet(name); ws.append(headers)
    output = io.BytesIO(); book.save(output); output.seek(0)
    return StreamingResponse(output, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', headers={'Content-Disposition':'attachment; filename="VRAP_RACI_Ownership_Template.xlsx"'})

@router.post('/raci/import', status_code=201)
async def raci_import(request: Request, file: UploadFile = File(...), user=Depends(writer), db=Depends(get_db)):
    if not file.filename.lower().endswith('.xlsx'): raise HTTPException(422, 'Upload an .xlsx workbook')
    parsed = _raci_parse(await file.read()); workspace = _workspace(request)
    batch = ImportBatch(owner_id=user.id, filename=file.filename, source='RACI', headers=list(parsed), mapping=parsed, counts={k: len(v) for k,v in parsed.items()}, workspace=workspace, status='Preview')
    db.add(batch); db.add(Audit(actor_id=user.id, action='raci.imported', entity='raci_import', details=batch.counts)); db.commit(); db.refresh(batch)
    return {'id': batch.id, 'status': batch.status, 'counts': batch.counts, 'sheets': list(parsed)}

@router.get('/raci/imports')
def raci_imports(request: Request, user=Depends(require_user), db=Depends(get_db)):
    rows = db.scalars(select(ImportBatch).where(ImportBatch.workspace == _workspace(request), ImportBatch.source == 'RACI').order_by(ImportBatch.id.desc())).all()
    return [{'id': b.id, 'filename': b.filename, 'status': b.status, 'counts': b.counts, 'created_at': b.created_at.isoformat()} for b in rows]

@router.post('/raci/imports/{import_id}/approve')
def raci_approve(import_id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    batch = db.get(ImportBatch, import_id)
    if not batch or batch.workspace != _workspace(request) or batch.source != 'RACI': raise HTTPException(404, 'RACI import not found')
    batch.status = 'Approved'; db.add(Audit(actor_id=user.id, action='raci.approved', entity='raci_import', entity_id=batch.id)); db.commit()
    return {'id': batch.id, 'status': batch.status}

@router.post('/raci/imports/{import_id}/apply')
def raci_apply(import_id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    batch = db.get(ImportBatch, import_id)
    if not batch or batch.workspace != _workspace(request) or batch.source != 'RACI': raise HTTPException(404, 'RACI import not found')
    if batch.status != 'Approved': raise HTTPException(409, 'RACI import must be approved before applying')
    assets = db.scalars(select(Asset).where(Asset.workspace == batch.workspace)).all(); asset_rows = batch.mapping.get('ASSET OVERRIDES', [])
    by_uuid, by_host, by_ip, by_service = {}, {}, {}, {}
    for asset in assets:
        if asset.external_id: by_uuid.setdefault(str(asset.external_id).lower(), []).append(asset)
        if asset.hostname: by_host.setdefault(str(asset.hostname).lower(), []).append(asset)
        if asset.ip: by_ip.setdefault(str(asset.ip).lower(), []).append(asset)
        service = (asset.context or {}).get('business_service')
        if service: by_service.setdefault(str(service).lower(), []).append(asset)
    applied = updated = unchanged = conflicts = unmatched = pending_approval = 0; matched_ids = set()
    for row in asset_rows:
        candidate_lists = []
        if row.get('Asset UUID'): candidate_lists.append(by_uuid.get(str(row['Asset UUID']).lower(), []))
        if row.get('Asset / hostname'): candidate_lists.append(by_host.get(str(row['Asset / hostname']).lower(), []))
        if row.get('IP'): candidate_lists.append(by_ip.get(str(row['IP']).lower(), []))
        if row.get('Business Service ID'): candidate_lists.append(by_service.get(str(row['Business Service ID']).lower(), []))
        candidates = list({a.id: a for group in candidate_lists for a in group}.values())
        if len(candidates) > 1: conflicts += 1; continue
        if not candidates: unmatched += 1; continue
        state = str(row.get('Approval state','')).strip().lower()
        if state in ('pending approval','pending','draft',''):
            pending_approval += 1; continue
        if state in ('rejected','disabled'): continue
        if state not in ('approved','approved for use','active'):
            pending_approval += 1; continue
        asset = candidates[0]; context = dict(asset.context or {}); provenance = dict(asset.context_provenance or {}); changed = False
        for column, key in [('Support Owner','it_owner'),('Change Owner','application_owner'),('Patching Group','patching_group'),('Accountable manager','business_owner'),('Remediation team (approved name)','remediation_owner')]:
            value = row.get(column)
            if not value: continue
            existing = provenance.get(key) or {}
            if existing.get('approval_state') == 'Approved' and existing.get('source') not in ('raci','RACI'): continue
            value = str(value)
            if context.get(key) != value: context[key] = value; changed = True
            provenance[key] = {'source':'raci','approval_state':'Approved'}
        if changed:
            context['raci_enabled'] = True; context['raci_roles'] = {k: row.get(k) for k in ('Support Owner','Change Owner','Patching Group','Accountable manager') if row.get(k)}
            asset.context, asset.context_provenance, asset.context_version = context, provenance, asset.context_version + 1; updated += 1
        else: unchanged += 1
        matched_ids.add(asset.id); applied += 1
    batch.status = 'Applied'; batch.counts = {**(batch.counts or {}), 'matched': applied, 'updated': updated, 'unchanged': unchanged, 'applied': updated, 'conflicts': conflicts, 'unmatched': unmatched, 'pending_approval': pending_approval}
    batch.status = 'Applied'; batch.counts = {**(batch.counts or {}), 'applied': applied, 'conflicts': conflicts, 'unmatched': unmatched}
    db.add(Audit(actor_id=user.id, action='raci.applied', entity='raci_import', entity_id=batch.id, details=batch.counts)); db.commit()
    return {'status': batch.status, 'applied': applied, 'conflicts': conflicts, 'unmatched': unmatched}

@router.post('/raci/imports/{import_id}/reconcile')
def raci_reconcile(import_id: int, request: Request, apply: bool = Query(False), user=Depends(admin), db=Depends(get_db)):
    batch = db.get(ImportBatch, import_id)
    if not batch or batch.workspace != _workspace(request) or batch.source != 'RACI': raise HTTPException(404, 'RACI import not found')
    assets = db.scalars(select(Asset).where(Asset.workspace == batch.workspace)).all()
    candidates = [a for a in assets if (a.context or {}).get('raci_enabled') or any((v or {}).get('source') == 'raci' for v in (a.context_provenance or {}).values())]
    removable = 0; changed = 0
    for asset in candidates:
        context = dict(asset.context or {}); provenance = dict(asset.context_provenance or {}); keys = [k for k,v in provenance.items() if isinstance(v, dict) and v.get('source') == 'raci']
        if not keys and not context.get('raci_enabled'): continue
        removable += 1
        if apply:
            for key in keys: context.pop(key, None); provenance.pop(key, None)
            context.pop('raci_roles', None); context.pop('raci_enabled', None)
            asset.context, asset.context_provenance, asset.context_version = context, provenance, asset.context_version + 1; changed += 1
    result = {'dry_run': not apply, 'candidates': len(candidates), 'reversible_assignments': removable, 'updated': changed}
    if apply:
        batch.counts = {**(batch.counts or {}), 'matched': 0, 'updated': 0, 'unchanged': 0, 'applied': 0, 'pending_approval': len(batch.mapping.get('ASSET OVERRIDES', [])), 'reconciled': changed}
        result['batch_counts'] = batch.counts
        db.add(Audit(actor_id=user.id, action='raci.reconciled', entity='raci_import', entity_id=batch.id, details=result)); db.commit()
    return result

@router.post('/raci/imports/{import_id}/toggle')
def raci_toggle(import_id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    batch = db.get(ImportBatch, import_id)
    if not batch or batch.workspace != _workspace(request) or batch.source != 'RACI': raise HTTPException(404, 'RACI import not found')
    batch.status = 'Disabled' if batch.status != 'Disabled' else 'Approved'
    db.add(Audit(actor_id=user.id, action='raci.toggled', entity='raci_import', entity_id=batch.id, details={'status': batch.status})); db.commit()
    return {'id': batch.id, 'status': batch.status}

@router.get('/assets.csv')
def assets_csv(request: Request, user=Depends(require_user), db=Depends(get_db)):
    import csv
    out = StringIO(); writer = csv.writer(out); writer.writerow(['id','external_id','hostname','ip','os','business_owner','it_owner','application_owner','patching_group','remediation_owner','raci_enabled','workspace'])
    for asset in db.scalars(select(Asset).where(Asset.workspace == _workspace(request)).order_by(Asset.id)).all():
        c = asset.context or {}; writer.writerow([asset.id, asset.external_id or '', asset.hostname, asset.ip or '', asset.os or '', c.get('business_owner',''), c.get('it_owner',''), c.get('application_owner',''), c.get('patching_group',''), c.get('remediation_owner',''), c.get('raci_enabled',False), asset.workspace])
    return StreamingResponse(iter([out.getvalue()]), media_type='text/csv', headers={'Content-Disposition':'attachment; filename=vrap-assets.csv'})

@router.get('/assessment-questionnaire')
def assessment_questionnaire(user=Depends(require_user)):
    return QUESTIONNAIRE

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

def _template_applies(template, asset):
    rules = template.applicability or {}
    context = asset.context or {}
    for key, expected in rules.items():
        if key == 'tags':
            if not set(expected or []).intersection(set(asset.tags or [])): return False
        elif expected not in (None, '') and context.get(key) != expected:
            return False
    return True

# These fields belong to the asset record. A shared plugin scenario can never
# replace its criticality, regulatory memberships, or exposure context.
ASSET_AUTHORITY_FIELDS = PROTECTED_CONTEXT_FIELDS | {'production', 'publicly_accessible'}

def _bulk_context(asset, submitted):
    effective = submitted.model_dump()
    for key in ASSET_AUTHORITY_FIELDS:
        value = (asset.context or {}).get(key)
        if value not in (None, '', []):
            effective[key] = value
    # These are derived by Context from the protected environment/exposure values.
    if (asset.context or {}).get('environment') not in (None, ''):
        effective['production'] = None
    if (asset.context or {}).get('exposure') not in (None, ''):
        effective['publicly_accessible'] = None
    return Context(**effective)

def _bulk_signature(finding, context, data, effective_status=None, effective_decision=None):
    payload = {'context': context.model_dump(mode='json'),
               'controls': [c.model_dump(mode='json') for c in data.controls],
               'notes': data.notes, 'justification': data.justification,
               'decision': effective_decision or data.decision, 'status': effective_status or data.status, 'workflow_status': data.workflow_status,
               'owner_id': data.owner_id, 'questionnaire_version': data.questionnaire_version,
               'answers': data.answers, 'scenario_evidence': data.scenario_evidence,
               'scenario_notes': data.scenario_notes}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def _bulk_job_output(db, job):
    errors = [{'finding_id': row.finding_id, 'error': row.error} for row in db.scalars(
        select(BulkAssessmentItem).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Failed'))]
    outcome_rows = db.execute(select(Assessment.status, func.count(Assessment.id)).join(BulkAssessmentItem, BulkAssessmentItem.assessment_id == Assessment.id).where(BulkAssessmentItem.job_id == job.id).group_by(Assessment.status)).all()
    outcome_counts = {status: count for status, count in outcome_rows}
    return {'id': job.id, 'status': job.status, 'vulnerability_id': job.vulnerability_id,
            'correlation_id': job.correlation_id, 'total': job.total, 'processed': job.processed,
            'succeeded': job.succeeded, 'skipped': job.skipped, 'failed': job.failed,
            'pending': max(0, job.total - job.processed),
            'progress_percent': round((job.processed / job.total) * 100) if job.total else 100,
            'assessed': outcome_counts.get('Assessed', 0),
            'not_applicable': outcome_counts.get('Not Applicable', 0),
            'context_required': outcome_counts.get('Context Required', 0),
            'pending_validation': outcome_counts.get('Pending Validation', 0),
            'technical_completed': sum(outcome_counts.values()),
            'error': job.error, 'errors': errors,
            'created_at': job.created_at.isoformat(), 'started_at': job.started_at.isoformat() if job.started_at else None,
            'finished_at': job.finished_at.isoformat() if job.finished_at else None}

def run_bulk_assessment_job(job_id: int, request_db=None):
    """Process one finding per transaction so a crash can resume without duplicate revisions."""
    from .core import preview_score
    from ..db import SessionLocal
    session_context = request_db or SessionLocal()
    with session_context as db:
        job = db.get(BulkAssessmentJob, job_id)
        if not job or job.status in ('Completed', 'Cancelled'): return
        job.status, job.started_at, job.error = 'Running', job.started_at or datetime.now(timezone.utc), None
        db.commit()
        payload = dict(job.payload)
        snapshot_revisions = payload.pop('finding_revisions', {})
        payload.pop('category_plugin_ids', None)
        payload.pop('category_key', None)
        data = PluginBulkAssessmentInput(**payload)
        for item in db.scalars(select(BulkAssessmentItem).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Pending').order_by(BulkAssessmentItem.id)).all():
            db.refresh(job)
            if job.status == 'Cancel requested':
                job.status, job.finished_at = 'Cancelled', datetime.now(timezone.utc)
                db.commit(); return
            finding = db.get(Finding, item.finding_id)
            try:
                if not finding or finding.workspace != job.workspace:
                    raise ValueError('Finding is no longer available in this workspace')
                snapshot_revision = snapshot_revisions.get(str(finding.id))
                if snapshot_revision is not None and finding.revision != snapshot_revision:
                    raise ValueError('Finding changed after preflight; review conflict before retrying')
                asset = db.get(Asset, finding.asset_id)
                effective_context = _bulk_context(asset, data.context)
                is_not_applicable = data.answers.get('applicability') == 'Not applicable' or data.decision == 'Not Applicable'
                if is_not_applicable and (not data.scenario_evidence or not data.scenario_notes.strip() or not data.justification.strip()):
                    raise ValueError('Not Applicable requires evidence references, evidence notes, and rationale')
                method, result = preview_score(db, finding, AssessmentInput(context=effective_context, controls=data.controls, methodology_id=active_methodology(db).id, expected_revision=finding.revision, notes=data.notes, justification=data.justification, decision=('Not Applicable' if is_not_applicable else data.decision), status=data.status))
                if data.decision == 'Within Risk Appetite' and result['above_appetite']:
                    raise ValueError('Residual risk is above appetite; select Remediation Required, Exception Required, or Escalation Required')
                latest = db.scalar(select(Assessment).where(Assessment.instance_id == finding.id).order_by(Assessment.revision.desc()).limit(1))
                effective_status = ('Not Applicable' if is_not_applicable else
                                    'Context Required' if result['missing_required'] else
                                    'Pending Validation' if data.answers.get('applicability') == 'Needs validation' else 'Assessed')
                effective_decision = latest.decision if latest and latest.status in ('Assessed','Risk Accepted','Closed') else ('Not Applicable' if is_not_applicable else data.decision)
                signature = _bulk_signature(finding, effective_context, data, effective_status, effective_decision)
                if latest and latest.context.get('_bulk_signature') == signature and latest.revision == finding.revision:
                    item.status, job.skipped = 'Skipped', job.skipped + 1
                else:
                    finding.revision += 1
                    context_json = effective_context.model_dump(mode='json'); context_json.update({
                        '_bulk_signature': signature,
                        '_technical_investigation': {'questionnaire_version': data.questionnaire_version, 'answers': data.answers,
                            'evidence': data.scenario_evidence, 'evidence_notes': data.scenario_notes},
                    })
                    assessment = Assessment(instance_id=finding.id, revision=finding.revision, methodology_id=method.id, analyst_id=job.requested_by, context=context_json, notes=data.notes, justification=data.justification, decision=effective_decision, status=data.status)
                    assessment.status = effective_status
                    db.add(assessment); db.flush()
                    rules = {rule['name']: rule for rule in method.configuration['controls']}
                    for control in data.controls:
                        db.add(AssessmentControl(assessment_id=assessment.id, component=rules[control.name]['component'], **control.model_dump()))
                    asset_snapshot = {'id': asset.id, 'hostname': asset.hostname, 'ip': asset.ip, 'os': asset.os, 'tags': asset.tags}
                    result.update({'methodology_id': method.id, 'methodology_version': method.version, 'asset_snapshot': asset_snapshot})
                    if not is_not_applicable:
                        db.add(RiskScore(assessment_id=assessment.id, result=result))
                    workflow = db.get(FindingWorkflow, finding.id)
                    if not workflow:
                        workflow = FindingWorkflow(finding_id=finding.id, updated_by=job.requested_by); db.add(workflow)
                    # Deliberately preserve ownership and decisions unless explicitly supplied on a new workflow.
                    if workflow.owner_id is None and data.owner_id is not None: workflow.owner_id = data.owner_id
                    if workflow.status in (None, 'New'): workflow.status = data.workflow_status
                    workflow.updated_by = job.requested_by
                    item.status, item.assessment_id, job.succeeded = 'Succeeded', assessment.id, job.succeeded + 1
                item.processed_at = datetime.now(timezone.utc)
                job.processed = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status.in_(['Succeeded','Skipped','Failed']))) or 0
                db.commit()
            except Exception as exc:
                db.rollback(); job = db.get(BulkAssessmentJob, job_id); item = db.get(BulkAssessmentItem, item.id)
                item.status, item.error, item.processed_at = 'Failed', str(exc), datetime.now(timezone.utc)
                job.failed = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Failed')) or 0
                job.processed = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status.in_(['Succeeded','Skipped','Failed']))) or 0
                db.commit()
        job = db.get(BulkAssessmentJob, job_id)
        job.processed = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status.in_(['Succeeded','Skipped','Failed']))) or 0
        job.failed = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Failed')) or 0
        job.status, job.finished_at = ('Failed' if job.failed else 'Completed'), datetime.now(timezone.utc)
        db.add(Audit(actor_id=job.requested_by, action='plugin_assessment.bulk_finished', entity='bulk_assessment_job', entity_id=job.id, details={'correlation_id': job.correlation_id, 'processed': job.processed, 'succeeded': job.succeeded, 'skipped': job.skipped, 'failed': job.failed}))
        db.commit()

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
            'controls': item.controls, 'template_version': item.template_version, 'applicability': item.applicability,
            'technical_rationale': item.technical_rationale, 'updated_at': item.updated_at.isoformat(),
            'revisions': [{'version': r.version, 'created_at': r.created_at.isoformat(), 'changed_by': r.changed_by}
                          for r in db.scalars(select(PluginAssessmentTemplateRevision).where(PluginAssessmentTemplateRevision.template_id == item.id).order_by(PluginAssessmentTemplateRevision.version.desc()))]}

@router.put('/assessment-groups/{vulnerability_id}/template')
def save_template(vulnerability_id: int, data: PluginTemplateInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = _workspace(request); _plugin(db, vulnerability_id, workspace); _owner(db, data.owner_id)
    method = active_methodology(db); known = {c['name'] for c in method.configuration['controls']}
    if any(c.name not in known for c in data.controls): raise HTTPException(422, 'Template contains an unknown control')
    item = db.scalar(select(PluginAssessmentTemplate).where(PluginAssessmentTemplate.workspace == workspace, PluginAssessmentTemplate.vulnerability_id == vulnerability_id))
    if not item:
        item = PluginAssessmentTemplate(workspace=workspace, vulnerability_id=vulnerability_id, updated_by=user.id); db.add(item)
    previous = {'owner_id': item.owner_id, 'status': item.status, 'notes': item.notes, 'justification': item.justification,
                'decision': item.decision, 'controls': item.controls, 'applicability': item.applicability,
                'technical_rationale': item.technical_rationale, 'template_version': item.template_version}
    item.template_version = (item.template_version or 0) + 1
    for key in ('owner_id', 'status', 'notes', 'justification', 'decision', 'controls', 'applicability', 'technical_rationale'):
        setattr(item, key, getattr(data, key))
    item.updated_by = user.id; item.updated_at = datetime.now(timezone.utc)
    db.flush()
    db.add(PluginAssessmentTemplateRevision(template_id=item.id, workspace=workspace, vulnerability_id=vulnerability_id,
        version=item.template_version, snapshot={**previous, 'new': {key: getattr(item, key) for key in ('owner_id','status','notes','justification','decision','controls','applicability','technical_rationale','template_version')}}, changed_by=user.id))
    db.add(Audit(actor_id=user.id, action='plugin_template.saved', entity='vulnerability', entity_id=vulnerability_id, details={'status': data.status, 'owner_id': data.owner_id, 'template_version': item.template_version}))
    db.commit(); return {'id': item.id, 'message': 'Plugin assessment template saved'}

@router.post('/assessment-groups/{vulnerability_id}/template/apply')
def apply_template(vulnerability_id: int, request: Request, preview: bool = False, user=Depends(writer), db=Depends(get_db)):
    workspace = _workspace(request); vulnerability = _plugin(db, vulnerability_id, workspace)
    template = db.scalar(select(PluginAssessmentTemplate).where(PluginAssessmentTemplate.workspace == workspace, PluginAssessmentTemplate.vulnerability_id == vulnerability_id))
    if not template: raise HTTPException(409, 'Save a plugin template before applying it')
    if not template.justification.strip(): raise HTTPException(422, 'Template justification is required before applying')
    method = active_methodology(db); rules = {c['name']: c for c in method.configuration['controls']}; applied = skipped = excluded = 0; changes = []
    for finding in db.scalars(select(Finding).where(Finding.workspace == workspace, Finding.vulnerability_id == vulnerability_id)):
        asset = db.get(Asset, finding.asset_id)
        if not _template_applies(template, asset): excluded += 1; continue
        controls = template.controls or []
        technical = {**vulnerability.technical, **finding.observed}
        result = calculate(technical, asset.context or {}, controls, method.configuration, datetime.now(timezone.utc).date())
        result.update({'methodology_id': method.id, 'methodology_version': method.version, 'asset_snapshot': {'id': asset.id, 'hostname': asset.hostname, 'ip': asset.ip, 'os': asset.os, 'tags': asset.tags}})
        signature = hashlib.sha256(json.dumps({'template_id': template.id, 'template_version': template.template_version, 'context': asset.context or {}, 'controls': controls, 'rationale': template.technical_rationale}, sort_keys=True, default=str).encode()).hexdigest()
        latest = db.scalar(select(Assessment).where(Assessment.instance_id == finding.id).order_by(Assessment.revision.desc()).limit(1))
        if latest and latest.context.get('_template_signature') == signature and latest.revision == finding.revision:
            skipped += 1; continue
        changes.append({'finding_id': finding.id, 'asset_id': asset.id, 'current_revision': finding.revision})
        if preview: continue
        finding.revision += 1
        prior_workflow = db.get(FindingWorkflow, finding.id)
        decision = latest.decision if latest else template.decision
        status = latest.status if latest else ('Assessed' if template.status not in ('New','Investigating') else 'Assessment In Progress')
        context_snapshot = dict(asset.context or {}); context_snapshot['_template_signature'] = signature
        assessment = Assessment(instance_id=finding.id, revision=finding.revision, methodology_id=method.id, analyst_id=user.id,
                                context=context_snapshot, notes=template.notes, justification=template.justification,
                                decision=decision, status=status)
        db.add(assessment); db.flush()
        for control in controls:
            rule = rules.get(control['name']);
            if rule: db.add(AssessmentControl(assessment_id=assessment.id, component=rule['component'], **control))
        db.add(RiskScore(assessment_id=assessment.id, result=result))
        workflow = db.get(FindingWorkflow, finding.id)
        if not workflow:
            workflow = FindingWorkflow(finding_id=finding.id, updated_by=user.id); db.add(workflow)
        # Existing ownership/workflow/decisions remain authoritative. A template
        # can provide defaults only for an unassigned/new finding.
        if workflow.owner_id is None: workflow.owner_id = template.owner_id
        if workflow.status in (None, 'New'): workflow.status = template.status
        workflow.updated_by = user.id
        applied += 1
    if preview:
        return {'preview': True, 'template_version': template.template_version, 'changed': len(changes), 'unchanged': skipped, 'excluded': excluded, 'changes': changes}
    db.add(Audit(actor_id=user.id, action='plugin_template.applied', entity='vulnerability', entity_id=vulnerability_id, details={'findings': applied, 'skipped': skipped, 'excluded': excluded, 'template_version': template.template_version}))
    db.commit(); return {'findings_assessed': applied, 'skipped': skipped, 'excluded': excluded, 'template_version': template.template_version}

@router.post('/assessment-groups/{vulnerability_id}/bulk-assess')
def bulk_assess_plugin(vulnerability_id: int, data: PluginBulkAssessmentInput, background: BackgroundTasks, request: Request, user=Depends(writer), db=Depends(get_db)):
    """Apply the complete workbench assessment once across a plugin's current finding population."""
    from .core import preview_score
    workspace = _workspace(request); vulnerability = _plugin(db, vulnerability_id, workspace); _owner(db, data.owner_id)
    query = select(Finding).where(Finding.workspace == workspace, Finding.vulnerability_id == vulnerability_id)
    all_findings = list(db.scalars(query))
    findings = all_findings
    if data.active_only:
        findings = [finding for finding in findings if (db.get(FindingWorkflow, finding.id) or FindingWorkflow(status='New')).status != 'Closed']
    if not findings: raise HTTPException(404, 'No findings are available for this plugin')
    if data.decision == 'Risk Accepted' or data.status == 'Risk Accepted':
        raise HTTPException(422, 'Bulk assessment cannot approve risk acceptance; use the governed exception workflow')
    is_not_applicable = data.answers.get('applicability') == 'Not applicable' or data.decision == 'Not Applicable'
    if is_not_applicable and (not data.scenario_evidence or not data.scenario_notes.strip() or not data.justification.strip()):
        raise HTTPException(422, 'Not Applicable requires evidence references, evidence notes, and rationale')
    methodology = active_methodology(db)
    prepared=[]; conflicts=[]
    for finding in findings:
        asset = db.get(Asset, finding.asset_id)
        effective_context = _bulk_context(asset, data.context)
        submitted = data.context.model_dump()
        protected_conflicts = {key: {'asset': (asset.context or {}).get(key), 'requested': submitted.get(key)}
                               for key in ASSET_AUTHORITY_FIELDS
                               if submitted.get(key) not in (None, '', []) and (asset.context or {}).get(key) not in (None, '', [])
                               and submitted.get(key) != (asset.context or {}).get(key)}
        if protected_conflicts:
            conflicts.append({'finding_id': finding.id, 'asset_id': asset.id, 'fields': protected_conflicts})
        assessment_data = AssessmentInput(context=effective_context, controls=data.controls, methodology_id=methodology.id,
            expected_revision=finding.revision, notes=data.notes, justification=data.justification, decision=data.decision, status=data.status)
        method, result = preview_score(db, finding, assessment_data)
        prepared.append((finding, method, result, effective_context))
    if data.dry_run:
        latest_by_finding = {finding.id: db.scalar(select(Assessment).where(Assessment.instance_id == finding.id).order_by(Assessment.revision.desc()).limit(1)) for finding, _, _, _ in prepared}
        unchanged = changed = 0; distribution = {}; regulatory = {}
        for finding, _, result, context in prepared:
            latest = latest_by_finding[finding.id]
            effective_status = ('Not Applicable' if is_not_applicable else
                                'Context Required' if result['missing_required'] else
                                'Pending Validation' if data.answers.get('applicability') == 'Needs validation' else 'Assessed')
            effective_decision = latest.decision if latest and latest.status in ('Assessed','Risk Accepted','Closed') else ('Not Applicable' if is_not_applicable else data.decision)
            signature = _bulk_signature(finding, context, data, effective_status, effective_decision)
            if latest and latest.context.get('_bulk_signature') == signature and latest.revision == finding.revision: unchanged += 1
            else: changed += 1
            if not is_not_applicable:
                level = result.get('residual_level', 'Unknown'); distribution[level] = distribution.get(level, 0) + 1
            for scope in context.regulatory: regulatory[scope] = regulatory.get(scope, 0) + 1
        excluded = len(all_findings) - len(prepared)
        cohorts = {}
        for finding, _, _, context in prepared:
            key = '|'.join([context.environment or 'Unknown', context.exposure or 'Unknown', ','.join(sorted(context.regulatory)) or 'None'])
            cohorts[key] = cohorts.get(key, 0) + 1
        conflict_ids = {item['finding_id'] for item in conflicts}
        categories = {'ready': [], 'missing_context': [], 'above_appetite': [], 'conflicting_or_excluded': []}
        for finding, _, result, context in prepared:
            item = {'finding_id': finding.id, 'asset_id': finding.asset_id,
                    'residual_score': None if is_not_applicable else result.get('residual_score'), 'residual_level': None if is_not_applicable else result.get('residual_level'),
                    'missing_fields': result.get('missing_required', [])}
            if is_not_applicable:
                item['determination'] = 'Not Applicable; evidence-backed and no risk score created'
                categories['ready'].append(item)
            elif finding.id in conflict_ids:
                item['reason'] = 'Submitted values conflict with authoritative asset context'
                categories['conflicting_or_excluded'].append(item)
            elif result['missing_required']:
                item['permissible_actions'] = ['Complete asset classification', 'Submit as Context Required']
                categories['missing_context'].append(item)
            elif result['above_appetite']:
                item['permissible_actions'] = ['Remediation Required', 'Exception Required', 'Escalation Required']
                categories['above_appetite'].append(item)
            else:
                categories['ready'].append(item)
        for finding in all_findings:
            if finding not in findings:
                categories['conflicting_or_excluded'].append({'finding_id': finding.id, 'asset_id': finding.asset_id, 'reason': 'Closed finding excluded by active-only scope'})
        return {'dry_run': True, 'findings': len(prepared), 'assets_affected': len({finding.asset_id for finding,_,_,_ in prepared}),
                'changed': changed, 'unchanged': unchanged, 'excluded': excluded, 'conflicts': conflicts,
                'regulatory_scope': regulatory, 'cohorts': [{'name': k, 'findings': v} for k, v in cohorts.items()],
                'scope': {'total_findings': len(all_findings), 'active_findings': len(findings), 'eligible_findings': changed,
                          'existing_assessments': sum(1 for value in latest_by_finding.values() if value),
                          'excluded_findings': excluded, 'affected_assets': len({finding.asset_id for finding,_,_,_ in prepared})},
                'categories': {key: {'count': len(value), 'items': value[:100]} for key, value in categories.items()},
                'risk_preview': {'above_appetite': sum(1 for _,_,result,_ in prepared if result['above_appetite']),
                                 'missing_context': sum(1 for _,_,result,_ in prepared if result['missing_required']), 'distribution': distribution}}
    key = data.idempotency_key or str(uuid.uuid4())
    existing = db.scalar(select(BulkAssessmentJob).where(BulkAssessmentJob.workspace == workspace, BulkAssessmentJob.vulnerability_id == vulnerability_id, BulkAssessmentJob.idempotency_key == key))
    if existing:
        return _bulk_job_output(db, existing)
    finding_ids = [finding.id for finding, _, _, _ in prepared]
    payload = data.model_dump(mode='json', exclude={'dry_run', 'idempotency_key'})
    payload['finding_revisions'] = {str(f.id): f.revision for f in findings}
    job = BulkAssessmentJob(workspace=workspace, vulnerability_id=vulnerability_id, requested_by=user.id,
        idempotency_key=key, status='Queued', active_only=data.active_only, payload=payload,
        finding_ids=finding_ids, total=len(finding_ids), correlation_id=uuid.uuid4().hex)
    db.add(job); db.flush()
    db.add_all([BulkAssessmentItem(job_id=job.id, finding_id=finding_id) for finding_id in finding_ids])
    db.add(Audit(actor_id=user.id, action='plugin_assessment.bulk_started', entity='bulk_assessment_job', entity_id=job.id,
                 details={'correlation_id': job.correlation_id, 'vulnerability_id': vulnerability_id, 'active_only': data.active_only, 'total': len(finding_ids)}))
    db.commit(); db.refresh(job)
    # Tests use an isolated in-memory database that is not the application's
    # SessionLocal engine; pass that session so legacy synchronous tests remain
    # deterministic while deployed jobs use an independent worker session.
    # SQLite test/demo sessions may be isolated in-memory engines; reuse that
    # session so the request and worker see the same schema. PostgreSQL uses a
    # fresh SessionLocal worker for restart-safe execution.
    background.add_task(run_bulk_assessment_job, job.id, db if db.bind.dialect.name == 'sqlite' else None)
    return _bulk_job_output(db, job) | {'status': 'Queued'}

@router.get('/bulk-assessment-jobs/{job_id}')
def bulk_job(job_id: int, request: Request, user=Depends(require_user), db=Depends(get_db)):
    job = db.get(BulkAssessmentJob, job_id)
    if not job or job.workspace != _workspace(request): raise HTTPException(404, 'Bulk assessment job not found')
    return _bulk_job_output(db, job)

@router.post('/bulk-assessment-jobs/{job_id}/cancel')
def cancel_bulk_job(job_id: int, request: Request, user=Depends(writer), db=Depends(get_db)):
    job = db.get(BulkAssessmentJob, job_id)
    if not job or job.workspace != _workspace(request): raise HTTPException(404, 'Bulk assessment job not found')
    if job.status not in ('Queued', 'Running'): raise HTTPException(409, 'Only queued or running jobs can be cancelled')
    job.status = 'Cancel requested'; db.add(Audit(actor_id=user.id, action='plugin_assessment.bulk_cancel_requested', entity='bulk_assessment_job', entity_id=job.id, details={'correlation_id': job.correlation_id})); db.commit()
    return _bulk_job_output(db, job)

@router.post('/bulk-assessment-jobs/{job_id}/resume')
def resume_bulk_job(job_id: int, background: BackgroundTasks, request: Request, user=Depends(writer), db=Depends(get_db)):
    job = db.get(BulkAssessmentJob, job_id)
    if not job or job.workspace != _workspace(request): raise HTTPException(404, 'Bulk assessment job not found')
    if job.status not in ('Failed', 'Cancelled', 'Interrupted'): raise HTTPException(409, 'Only failed, cancelled, or interrupted jobs can resume')
    db.execute(update(BulkAssessmentItem).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Failed').values(status='Pending', error=None, processed_at=None))
    job.status = 'Queued'; job.error = None
    job.failed = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Failed')) or 0
    job.succeeded = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Succeeded')) or 0
    job.skipped = db.scalar(select(func.count(BulkAssessmentItem.id)).where(BulkAssessmentItem.job_id == job.id, BulkAssessmentItem.status == 'Skipped')) or 0
    job.processed = job.succeeded + job.skipped
    db.commit(); background.add_task(run_bulk_assessment_job, job.id, db if db.bind.dialect.name == 'sqlite' else None)
    return _bulk_job_output(db, job)

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
def decide_exception(id:int,data:ExceptionDecision,request:Request,user=Depends(admin),db=Depends(get_db)):
    item=db.get(RiskException,id)
    if not item or item.workspace != _workspace(request): raise HTTPException(404,'Exception not found')
    if item.requested_by == user.id:
        raise HTTPException(403, 'A requester cannot approve or reject their own exception')
    item.status=data.status;item.approved_by=user.id;item.reviewed_at=datetime.now(timezone.utc)
    db.add(Audit(actor_id=user.id,action='exception.'+data.status.lower(),entity='exception',entity_id=id,details={'workspace':_workspace(request)}));db.commit();return {'id':id,'status':item.status}

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

@router.get('/kpis')
def kpis(request: Request, user=Depends(require_user), db=Depends(get_db)):
    """Single denominator/as-of KPI contract for dashboards, exports and reports."""
    return calculate_kpis(db, _workspace(request))

SMART_CATEGORY_NAMES = ('Windows', 'Linux', 'Microsoft Applications', 'Databases', 'Network', 'Web Servers',
                        'TLS', 'Identity', 'Third-Party Software', 'End-of-Life', 'Cloud', 'Containers',
                        'Virtualization', 'Security Tools', 'Other / Manual Review')

def _smart_category(technical, name, plugin_id):
    text = ' '.join(str(technical.get(key, '')) for key in ('family','plugin_family','product','vendor','os','description','solution','name')).casefold()
    action = str(technical.get('remediation_action') or technical.get('solution') or '').casefold()
    if any(x in text for x in ('end of life','unsupported','obsolete','deprecated')): return 'End-of-Life'
    if any(x in text for x in ('tls','ssl','certificate','cipher')): return 'TLS'
    if any(x in text for x in ('identity','active directory','kerberos','ldap','saml','iam')): return 'Identity'
    if any(x in text for x in ('database','sql server','mysql','oracle','postgres','mongodb','redis')): return 'Databases'
    if any(x in text for x in ('web server','apache','nginx','iis','httpd')): return 'Web Servers'
    if any(x in text for x in ('windows','microsoft')): return 'Windows' if 'office' not in text and 'sql' not in text and 'exchange' not in text else 'Microsoft Applications'
    if any(x in text for x in ('linux','ubuntu','debian','red hat','rhel','centos','unix')): return 'Linux'
    if any(x in text for x in ('router','switch','firewall','network','cisco','fortinet','palo alto')): return 'Network'
    if any(x in text for x in ('aws','azure','gcp','cloud')): return 'Cloud'
    if any(x in text for x in ('docker','kubernetes','container')): return 'Containers'
    if any(x in text for x in ('vmware','virtualbox','hyper-v','virtualization')): return 'Virtualization'
    if any(x in text for x in ('security tool','antivirus','edr','scanner')): return 'Security Tools'
    if action and any(x in action for x in ('patch','upgrade','update')): return 'Third-Party Software'
    return 'Other / Manual Review'

def _smart_category_data(db, workspace):
    state = db.scalar(select(SmartAssessmentCategory).where(SmartAssessmentCategory.workspace == workspace))
    overrides = (state.overrides if state else {}) or {}; renames = (state.renames if state else {}) or {}
    rows = db.execute(select(Vulnerability, func.count(Finding.id), func.count(func.distinct(Finding.asset_id))
                             ).outerjoin(Finding, (Finding.vulnerability_id == Vulnerability.id) & (Finding.workspace == workspace))
                      .group_by(Vulnerability.id)).all()
    groups = {key: {'key': key, 'name': renames.get(key, key), 'plugin_ids': [], 'plugins': [], 'findings': 0, 'assets': 0,
                    'severity': {}, 'technical_completed': 0, 'risk_assessed': 0, 'context_required': 0, 'uncertain': key == 'Other / Manual Review'} for key in SMART_CATEGORY_NAMES}
    assessment_rows = db.execute(select(Vulnerability.plugin_id, Assessment.status, func.count(func.distinct(Assessment.instance_id)))
        .join(Finding, Finding.vulnerability_id == Vulnerability.id).join(Assessment, Assessment.instance_id == Finding.id)
        .where(Finding.workspace == workspace).group_by(Vulnerability.plugin_id, Assessment.status)).all()
    counts = {}
    for plugin_id, status, count in assessment_rows: counts.setdefault(plugin_id, {})[status] = counts.setdefault(plugin_id, {}).get(status, 0) + count
    for vuln, finding_count, asset_count in rows:
        key = overrides.get(str(vuln.plugin_id)) or _smart_category(vuln.technical or {}, vuln.name, vuln.plugin_id)
        group = groups.setdefault(key, {'key': key, 'name': renames.get(key, key), 'plugin_ids': [], 'plugins': [], 'findings': 0, 'assets': 0, 'severity': {}, 'technical_completed': 0, 'risk_assessed': 0, 'context_required': 0, 'uncertain': True})
        severity = str((vuln.technical or {}).get('severity') or 'Unknown')
        plugin_counts = counts.get(vuln.plugin_id, {})
        group['plugin_ids'].append(vuln.plugin_id); group['plugins'].append({'id': vuln.plugin_id, 'name': vuln.name, 'findings': finding_count, 'assets': asset_count, 'severity': severity})
        group['findings'] += finding_count; group['assets'] += asset_count; group['severity'][severity] = group['severity'].get(severity, 0) + finding_count
        group['technical_completed'] += sum(plugin_counts.values()); group['risk_assessed'] += sum(plugin_counts.get(s, 0) for s in ('Assessed','Above Risk Appetite','Remediation Required','Exception Requested','Risk Accepted')); group['context_required'] += plugin_counts.get('Context Required', 0)
    return [group for group in groups.values() if group['plugin_ids']]

@router.get('/assessment-categories')
def assessment_categories(request: Request, user=Depends(require_user), db=Depends(get_db)):
    groups = _smart_category_data(db, _workspace(request))
    return {'workspace': _workspace(request), 'category_count': len(groups), 'plugin_count': sum(len(g['plugin_ids']) for g in groups), 'categories': groups}

@router.patch('/assessment-categories/{category_key}')
def update_assessment_category(category_key: str, data: dict, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = _workspace(request); state = db.scalar(select(SmartAssessmentCategory).where(SmartAssessmentCategory.workspace == workspace))
    if not state: state = SmartAssessmentCategory(workspace=workspace, overrides={}, renames={}, updated_by=user.id); db.add(state); db.flush()
    target = str(data.get('merge_into') or data.get('new_category') or category_key)
    if data.get('name'): state.renames = {**(state.renames or {}), category_key: str(data['name'])[:120]}
    for plugin_id in data.get('plugin_ids', []) + data.get('split_plugin_ids', []): state.overrides = {**(state.overrides or {}), str(plugin_id): target}
    if target not in SMART_CATEGORY_NAMES and target not in set((state.renames or {}).values()):
        if len(_smart_category_data(db, workspace)) >= 20: raise HTTPException(422, 'The 20-category cap would be exceeded')
        state.renames = {**(state.renames or {}), target: target}
    state.updated_by = user.id
    db.add(Audit(actor_id=user.id, action='assessment_category.updated', entity='assessment_category', entity_id=state.id, details={'category': category_key, 'changes': data}))
    db.commit(); return {'updated': True, 'categories': _smart_category_data(db, workspace)}

@router.post('/assessment-categories/{category_key:path}/bulk-assess')
def bulk_assess_category(category_key: str, data: PluginBulkAssessmentInput, background: BackgroundTasks, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = _workspace(request); category = next((g for g in _smart_category_data(db, workspace) if g['key'] == category_key), None)
    if not category: raise HTTPException(404, 'Assessment category not found')
    plugin_ids = category['plugin_ids']; findings = db.scalars(select(Finding).where(Finding.workspace == workspace, Finding.vulnerability_id.in_(select(Vulnerability.id).where(Vulnerability.plugin_id.in_(plugin_ids))))).all()
    if data.active_only:
        findings = [f for f in findings if not (db.get(FindingWorkflow, f.id) and db.get(FindingWorkflow, f.id).status == 'Closed')]
    if not findings: raise HTTPException(404, 'No active findings are available for this category')
    if data.dry_run:
        return {'dry_run': True, 'category': category_key, 'plugin_count': len(plugin_ids), 'findings': len(findings), 'assets_affected': len({f.asset_id for f in findings}), 'changed': len(findings), 'unchanged': 0, 'categories': {'ready': [], 'missing_context': [], 'above_appetite': [], 'conflicting_or_excluded': []}}
    key = data.idempotency_key or f'category-{workspace}-{category_key}-{data.questionnaire_version}'
    existing = db.scalar(select(BulkAssessmentJob).where(BulkAssessmentJob.workspace == workspace, BulkAssessmentJob.idempotency_key == key))
    if existing: return _bulk_job_output(db, existing)
    first_vuln = db.scalar(select(Vulnerability.id).where(Vulnerability.plugin_id.in_(plugin_ids)))
    payload = data.model_dump(mode='json', exclude={'dry_run','idempotency_key'}); payload['category_key'] = category_key; payload['category_plugin_ids'] = plugin_ids; payload['finding_revisions'] = {str(f.id): f.revision for f in findings}
    job = BulkAssessmentJob(workspace=workspace, vulnerability_id=first_vuln, requested_by=user.id, idempotency_key=key, status='Queued', active_only=data.active_only, payload=payload, finding_ids=[f.id for f in findings], total=len(findings), correlation_id=uuid.uuid4().hex)
    db.add(job); db.flush(); db.add_all([BulkAssessmentItem(job_id=job.id, finding_id=f.id) for f in findings]); db.commit(); db.refresh(job)
    background.add_task(run_bulk_assessment_job, job.id, db if db.bind.dialect.name == 'sqlite' else None)
    return _bulk_job_output(db, job)

@router.get('/mission-center')
def mission_center(request: Request, queue: str = '', page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), q: str = '', owner_id: int | None = None, user=Depends(require_user), db=Depends(get_db)):
    workspace = _workspace(request)
    # Join the latest assessment once.  The previous implementation issued one
    # query per finding and then paginated the complete inventory in Python.
    latest_revision = (select(Assessment.instance_id.label('instance_id'),
                              func.max(Assessment.revision).label('revision'))
                       .group_by(Assessment.instance_id).subquery())
    LatestAssessment = aliased(Assessment)
    statement = (select(Finding, Vulnerability, Asset, FindingWorkflow, LatestAssessment)
        .join(Asset, Asset.id == Finding.asset_id).join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id)
        .outerjoin(latest_revision, latest_revision.c.instance_id == Finding.id)
        .outerjoin(LatestAssessment, (LatestAssessment.instance_id == latest_revision.c.instance_id) &
                   (LatestAssessment.revision == latest_revision.c.revision))
        .where(Finding.workspace == workspace))
    if q.strip():
        term = f'%{q.strip().lower()}%'
        statement = statement.where(or_(func.lower(Asset.hostname).like(term),
                                       func.lower(func.coalesce(Asset.ip, '')).like(term),
                                       func.lower(Vulnerability.name).like(term),
                                       func.lower(func.coalesce(Vulnerability.plugin_id, '')).like(term)))
    if owner_id is not None:
        statement = statement.where(FindingWorkflow.owner_id == owner_id)
    rows = db.execute(statement.order_by(Finding.id.desc())).all()
    queues = {key: [] for key in ('urgent_review', 'missing_context_evidence', 'automated_provisional', 'monitor_reassess')}
    today = datetime.now(timezone.utc).date()
    required_context = active_methodology(db).configuration.get('required_context', [])
    for finding, vuln, asset, workflow, assessment in rows:
        status = workflow.status if workflow else 'New'
        tech = {**(vuln.technical or {}), **(finding.observed or {}).get('technical', finding.observed or {})}
        context = asset.context or {}
        factors = []
        if tech.get('kev') is True: factors.append('CISA KEV')
        if tech.get('exploit_available') is True: factors.append('Exploit available')
        if context.get('asset_criticality') in ('Critical', 'High'): factors.append('High asset criticality')
        if context.get('exposure') == 'Internet Facing' or context.get('publicly_accessible') is True: factors.append('Internet exposed')
        overdue = bool(workflow and workflow.remediation_due_at and workflow.remediation_due_at.date() < today and status not in ('Closed', 'Accepted'))
        if overdue: factors.append('Overdue')
        missing_fields = [field for field in required_context if context.get(field) in (None, '', [])]
        missing = not assessment or bool(missing_fields)
        stale = bool(assessment and assessment.revision != finding.revision)
        severity = str(tech.get('severity') or '').lower()
        priority = (40 if tech.get('kev') else 0) + (25 if tech.get('exploit_available') else 0) + (20 if context.get('asset_criticality') in ('Critical','High') else 0) + (15 if context.get('exposure') == 'Internet Facing' else 0) + (15 if overdue else 0) + (10 if missing else 0) + (10 if stale else 0) + ({'critical':20,'high':10,'medium':4}.get(severity, 0))
        if assessment and assessment.status == 'Context Required': bucket = 'missing_context_evidence'
        elif severity in ('critical', 'high') or priority >= 45 or overdue or status in ('Assessment In Progress', 'Above Risk Appetite'): bucket = 'urgent_review'
        elif stale or (not assessment and status not in ('Closed', 'Accepted')): bucket = 'monitor_reassess' if stale else 'automated_provisional'
        elif missing: bucket = 'missing_context_evidence'
        else: bucket = 'monitor_reassess'
        item = {'finding_id': finding.id, 'name': vuln.name, 'asset': asset.hostname, 'plugin_id': vuln.plugin_id,
                'status': status, 'owner_id': workflow.owner_id if workflow else None, 'priority_score': priority,
                'missing_fields': missing_fields, 'priority_factors': factors, 'overdue': overdue, 'recommended_action':
                'Reassess changed evidence' if stale else ('Collect authoritative context/evidence' if missing else ('Address overdue remediation' if overdue else 'Open finding and complete the assessment'))}
        queues[bucket].append(item)
    for items in queues.values(): items.sort(key=lambda x: (-x['priority_score'], x['finding_id']))
    selected = {queue: queues[queue]} if queue in queues else queues
    return {'workspace': workspace, 'queues': {k: v[(page-1)*page_size:page*page_size] for k,v in selected.items()},
            'summary': {key: len(value) for key, value in selected.items()}, 'page': page, 'page_size': page_size,
            'generated_at': datetime.now(timezone.utc).isoformat()}

def _package_output(db, package):
    finding_rows = db.scalars(select(RemediationPackageFinding).where(RemediationPackageFinding.package_id == package.id)).all()
    findings = [row.finding_id for row in finding_rows]
    evidence = db.scalars(select(RemediationPackageEvidence).where(RemediationPackageEvidence.package_id == package.id).order_by(RemediationPackageEvidence.id.desc())).all()
    verified = sum(1 for row in finding_rows if row.remediation_status == 'Fixed' and row.verified_at)
    statuses = {s: sum(1 for row in finding_rows if row.remediation_status == s) for s in ('Fixed','Active','Reopened','Exception','Unknown')}
    return {'id': package.id, 'name': package.name, 'workspace': package.workspace, 'remediation_action': package.remediation_action,
            'owner_id': package.owner_id, 'jira_reference': package.jira_reference, 'due_date': package.due_date.isoformat() if package.due_date else None,
            'change_window': package.change_window, 'source': package.source, 'suggestion_key': package.suggestion_key,
            'status': package.status, 'blockers': package.blockers or [], 'finding_ids': findings,
            'finding_statuses': statuses, 'unique_assets': db.scalar(select(func.count(func.distinct(Finding.asset_id))).where(Finding.id.in_(findings))) or 0,
            'verified_findings': verified, 'closure_blockers': [f'{len(findings)-verified} findings require verified remediation evidence'] if findings and verified < len(findings) else [],
            'evidence': [{'id': e.id, 'type': e.evidence_type, 'reference': e.reference, 'verified': e.verified, 'created_at': e.created_at.isoformat()} for e in evidence]}

@router.get('/remediation-packages')
def list_remediation_packages(request: Request, user=Depends(require_user), db=Depends(get_db)):
    workspace = _workspace(request)
    return [_package_output(db, p) for p in db.scalars(select(RemediationPackage).where(RemediationPackage.workspace == workspace).order_by(RemediationPackage.updated_at.desc())).all()]

@router.post('/remediation-packages', status_code=201)
def create_remediation_package(data: RemediationPackageInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    workspace = _workspace(request)
    ids = set(data.finding_ids)
    if data.suggestion_key and not ids:
        # Resolve suggestions server-side so large Tenable estates are never
        # serialized into the browser just to create a package.
        parts = data.suggestion_key.split('|', 2)
        if len(parts) == 3:
            action_key, product_key, platform_key = parts
            matching_vulns = []
            for vuln_id, technical in db.execute(select(Vulnerability.id, Vulnerability.technical)).all():
                t = technical if isinstance(technical, dict) else {}
                action = str(t.get('remediation_action') or t.get('solution') or 'Unspecified').strip().casefold()
                product = str(t.get('product') or t.get('software_family') or t.get('plugin_family') or 'Unknown').strip().casefold()
                platform = str(t.get('os') or t.get('device_type') or 'General').strip().casefold()
                if (action, product, platform) == (action_key, product_key, platform_key): matching_vulns.append(vuln_id)
            if matching_vulns:
                ids.update(db.scalars(select(Finding.id).where(Finding.workspace == workspace, Finding.vulnerability_id.in_(matching_vulns))).all())
    if ids and len(db.scalars(select(Finding.id).where(Finding.workspace == workspace, Finding.id.in_(ids))).all()) != len(ids):
        raise HTTPException(422, 'All findings must belong to the current workspace')
    package = RemediationPackage(workspace=workspace, name=data.name, remediation_action=data.remediation_action, owner_id=data.owner_id,
        jira_reference=data.jira_reference, due_date=data.due_date, blockers=data.blockers, created_by=user.id,
        change_window=data.change_window, source=data.source, suggestion_key=data.suggestion_key)
    db.add(package); db.flush()
    for finding_id in ids: db.add(RemediationPackageFinding(package_id=package.id, finding_id=finding_id, added_by=user.id))
    db.add(RemediationPackageEvent(package_id=package.id, action='created', details={'finding_count': len(ids)}, actor_id=user.id))
    db.commit(); db.refresh(package); return _package_output(db, package)

@router.put('/remediation-packages/{package_id}')
def update_remediation_package(package_id: int, data: RemediationPackageUpdate, request: Request, user=Depends(writer), db=Depends(get_db)):
    package = db.get(RemediationPackage, package_id)
    if not package or package.workspace != _workspace(request): raise HTTPException(404, 'Remediation package not found')
    changes = data.model_dump(exclude_none=True)
    finding_ids = changes.pop('finding_ids', None)
    link_plugin_ids = changes.pop('link_plugin_ids', None); link_asset_ids = changes.pop('link_asset_ids', None); link_action = changes.pop('link_remediation_action', None); unlink_ids = changes.pop('unlink_finding_ids', None)
    if finding_ids is not None:
        ids = set(finding_ids)
        valid = set(db.scalars(select(Finding.id).where(Finding.workspace == package.workspace, Finding.id.in_(ids))).all()) if ids else set()
        if valid != ids:
            raise HTTPException(422, 'All findings must belong to the current workspace')
        existing_rows = db.scalars(select(RemediationPackageFinding).where(RemediationPackageFinding.package_id == package.id)).all()
        existing = {row.finding_id: row for row in existing_rows}
        for finding_id in ids - existing.keys():
            db.add(RemediationPackageFinding(package_id=package.id, finding_id=finding_id, added_by=user.id))
        for finding_id, row in existing.items():
            if finding_id not in ids:
                db.delete(row)
        changes['finding_ids'] = sorted(ids)
    if link_plugin_ids is not None or link_asset_ids is not None or link_action:
        query = select(Finding.id).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id).where(Finding.workspace == package.workspace)
        if link_plugin_ids: query = query.where(Vulnerability.plugin_id.in_(link_plugin_ids))
        if link_asset_ids: query = query.where(Finding.asset_id.in_(link_asset_ids))
        if link_action:
            query = query.where(or_(Vulnerability.technical['remediation_action'].as_string() == link_action, Vulnerability.technical['solution'].as_string() == link_action))
        existing_ids = set(db.scalars(select(RemediationPackageFinding.finding_id).where(RemediationPackageFinding.package_id == package.id)).all())
        for fid in set(db.scalars(query).all()) - existing_ids: db.add(RemediationPackageFinding(package_id=package.id, finding_id=fid, added_by=user.id))
        changes['linked_by_filter'] = {'plugins': link_plugin_ids or [], 'assets': link_asset_ids or [], 'action': link_action}
    if unlink_ids:
        for row in db.scalars(select(RemediationPackageFinding).where(RemediationPackageFinding.package_id == package.id, RemediationPackageFinding.finding_id.in_(unlink_ids))).all(): db.delete(row)
        changes['unlinked_finding_ids'] = unlink_ids
    if data.status == 'Verified Closed':
        rows = db.scalars(select(RemediationPackageFinding).where(RemediationPackageFinding.package_id == package.id)).all()
        if not rows or any(r.remediation_status != 'Fixed' or not r.verified_at for r in rows):
            raise HTTPException(409, 'Every linked finding requires verified remediation evidence before closure')
    for key, value in changes.items(): setattr(package, key, value)
    db.add(RemediationPackageEvent(package_id=package.id, action='updated', details=changes, actor_id=user.id)); db.commit(); db.refresh(package)
    return _package_output(db, package)

@router.post('/remediation-packages/{package_id}/evidence', status_code=201)
def add_remediation_evidence(package_id: int, data: RemediationEvidenceInput, request: Request, user=Depends(writer), db=Depends(get_db)):
    package = db.get(RemediationPackage, package_id)
    if not package or package.workspace != _workspace(request): raise HTTPException(404, 'Remediation package not found')
    row = RemediationPackageEvidence(package_id=package.id, evidence_type=data.evidence_type, reference=data.reference.strip(), verified=False, created_by=user.id)
    db.add(row); db.add(RemediationPackageEvent(package_id=package.id, action='evidence_added', details={'evidence_type': data.evidence_type}, actor_id=user.id)); db.commit(); db.refresh(row)
    return {'id': row.id, 'verified': row.verified, 'type': row.evidence_type, 'reference': row.reference}

@router.post('/remediation-packages/{package_id}/evidence/{evidence_id}/verify')
def verify_remediation_evidence(package_id: int, evidence_id: int, request: Request, user=Depends(admin), db=Depends(get_db)):
    package = db.get(RemediationPackage, package_id); row = db.get(RemediationPackageEvidence, evidence_id)
    if not package or package.workspace != _workspace(request) or not row or row.package_id != package.id: raise HTTPException(404, 'Evidence not found')
    row.verified = True
    if row.evidence_type == 'rescan':
        # A verified rescan is attached to every linked finding, while each link
        # retains its own status and verification timestamp for audit/reporting.
        for link in db.scalars(select(RemediationPackageFinding).where(RemediationPackageFinding.package_id == package_id)).all():
            link.remediation_status = 'Fixed'; link.verified_at = datetime.now(timezone.utc); link.verified_by = user.id; link.evidence_id = row.id
    db.add(RemediationPackageEvent(package_id=package.id, action='evidence_verified', details={'evidence_id': row.id}, actor_id=user.id)); db.commit()
    return {'id': row.id, 'verified': True}

@router.post('/remediation-packages/{package_id}/findings/{finding_id}/verify')
def verify_package_finding(package_id: int, finding_id: int, request: Request, evidence_id: int = Query(...), user=Depends(admin), db=Depends(get_db)):
    package = db.get(RemediationPackage, package_id); link = db.scalar(select(RemediationPackageFinding).where(RemediationPackageFinding.package_id == package_id, RemediationPackageFinding.finding_id == finding_id)); evidence = db.get(RemediationPackageEvidence, evidence_id)
    if not package or package.workspace != _workspace(request) or not link or not evidence or evidence.package_id != package_id or not evidence.verified:
        raise HTTPException(409, 'Verified package evidence is required for this finding')
    link.remediation_status = 'Fixed'; link.verified_at = datetime.now(timezone.utc); link.verified_by = user.id; link.evidence_id = evidence_id
    db.add(RemediationPackageEvent(package_id=package_id, action='finding_verified', details={'finding_id': finding_id, 'evidence_id': evidence_id}, actor_id=user.id)); db.commit()
    return _package_output(db, package)

@router.get('/remediation-packages/suggestions')
def remediation_package_suggestions(request: Request, user=Depends(require_user), db=Depends(get_db)):
    """Suggest packages only when scanner action, product/platform and approved routing agree."""
    workspace = _workspace(request); groups = {}
    # Read one row per plugin, not one row per finding. Counts are computed by
    # bounded SQL aggregates, keeping this endpoint responsive for 100k findings.
    plugins = db.execute(select(Vulnerability.id, Vulnerability.plugin_id, Vulnerability.name, Vulnerability.technical).where(
        select(Finding.id).where(Finding.vulnerability_id == Vulnerability.id, Finding.workspace == workspace).exists())).all()
    counts = db.execute(select(Finding.vulnerability_id, func.count(Finding.id), func.count(func.distinct(Finding.asset_id))).where(Finding.workspace == workspace).group_by(Finding.vulnerability_id)).all()
    count_map = {v: (int(f), int(a)) for v, f, a in counts}
    for vuln_id, plugin_id, vuln_name, technical in plugins:
        t = technical if isinstance(technical, dict) else {}; action = str(t.get('remediation_action') or t.get('solution') or 'Unspecified').strip(); product = str(t.get('product') or t.get('software_family') or t.get('plugin_family') or 'Unknown').strip(); platform = str(t.get('os') or t.get('device_type') or 'General').strip()
        key = '|'.join((action.casefold(), product.casefold(), platform.casefold())); findings, assets = count_map.get(vuln_id, (0, 0))
        group = groups.setdefault(key, {'suggestion_key': key, 'name': f'{product} · {action}', 'remediation_action': action, 'product': product, 'platform': platform, 'plugin_ids': set(), 'findings': 0, 'assets': 0})
        group['plugin_ids'].add(plugin_id or str(vuln_id)); group['findings'] += findings; group['assets'] += assets
    return [{'suggestion_key': g['suggestion_key'], 'name': g['name'], 'remediation_action': g['remediation_action'], 'product': g['product'], 'platform': g['platform'], 'plugin_ids': sorted(g['plugin_ids']), 'findings': g['findings'], 'assets': g['assets']} for g in sorted(groups.values(), key=lambda x: (-x['findings'], x['name']))]

@router.get('/remediation-sla/policies')
def list_sla_policies(request: Request, user=Depends(require_user), db=Depends(get_db)):
    return [p.__dict__ | {'effective_from': p.effective_from.isoformat(), 'effective_to': p.effective_to.isoformat() if p.effective_to else None} for p in db.scalars(select(RemediationSLAPolicy).where(RemediationSLAPolicy.workspace == _workspace(request)).order_by(RemediationSLAPolicy.version.desc())).all()]

@router.post('/remediation-sla/policies', status_code=201)
def create_sla_policy(data: RemediationSLAPolicyInput, request: Request, user=Depends(admin), db=Depends(get_db)):
    workspace = _workspace(request)
    version = (db.scalar(select(func.max(RemediationSLAPolicy.version)).where(RemediationSLAPolicy.workspace == workspace)) or 0) + 1
    row = RemediationSLAPolicy(workspace=workspace, version=version, created_by=user.id, **data.model_dump())
    db.add(row); db.commit(); db.refresh(row)
    return {'id': row.id, 'version': row.version}

@router.get('/remediation-sla/evaluate')
def evaluate_remediation_sla(request: Request, user=Depends(require_user), db=Depends(get_db)):
    workspace = _workspace(request); today = datetime.now(timezone.utc).date()
    defaults = {('PCI DSS','Critical'):30,('PCI DSS','High'):30,('PCI DSS','Medium'):90,('PCI DSS','Low'):180,('Non-PCI','Critical'):30,('Non-PCI','High'):60,('Non-PCI','Medium'):90,('Non-PCI','Low'):None}
    policies = db.scalars(select(RemediationSLAPolicy).where(RemediationSLAPolicy.workspace == workspace, RemediationSLAPolicy.approved.is_(True), RemediationSLAPolicy.effective_from <= today, (RemediationSLAPolicy.effective_to.is_(None) | (RemediationSLAPolicy.effective_to >= today)))).all()
    rows=[]
    for finding, vuln, asset, workflow in db.execute(select(Finding,Vulnerability,Asset,FindingWorkflow).join(Vulnerability,Vulnerability.id==Finding.vulnerability_id).join(Asset,Asset.id==Finding.asset_id).outerjoin(FindingWorkflow,FindingWorkflow.finding_id==Finding.id).where(Finding.workspace==workspace)).all():
        tech={**(vuln.technical or {}), **(finding.observed or {})}; severity=tech.get('severity','Low'); scopes=(asset.context or {}).get('regulatory') or []
        obligations=[(s, next((p.days for p in policies if p.regulatory_scope==s and p.severity==severity), defaults.get((s,severity), defaults.get(('Non-PCI',severity)))) ) for s in (scopes or ['Non-PCI'])]
        obligations=[x for x in obligations if x[1] is not None]; days=min((x[1] for x in obligations), default=None)
        first=(finding.source_last_seen or today); age=(today-first).days; due=first+timedelta(days=days) if days else None
        rows.append({'finding_id':finding.id,'severity':severity,'scopes':scopes,'first_seen':first.isoformat(),'age_days':age,'sla_days':days,'due_date':due.isoformat() if due else None,'overdue':bool(due and today>due),'due_soon':bool(due and not (today>due) and (due-today).days<=7),'exception':False})
    return {'workspace':workspace,'policies':'provisional defaults plus approved overrides','total':len(rows),'overdue':sum(x['overdue'] for x in rows),'due_soon':sum(x['due_soon'] for x in rows),'items':rows}

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
