import hashlib
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import delete, select, update
from .models import (Asset, Vulnerability, Finding, Methodology, Assessment,
                     AssessmentControl, RiskScore, FindingWorkflow, RiskException,
                     ImportRow, CampaignFinding, CampaignEvidence)
from .risk.engine import calculate
from .asset_rules import resolve_rules, ASSET_CONTEXT_KEYS


def active_methodology(db):
    method = db.scalar(select(Methodology).order_by(Methodology.id.desc()))
    if not method:
        raise HTTPException(503, 'Initialize the database and methodology first')
    return method

def identity(data):
    return ('plugin:' + data.plugin_id) if data.plugin_id else 'manual:' + hashlib.sha256((data.name.casefold() + '|' + ','.join(sorted(data.cves))).encode()).hexdigest()

def ingest(db, data, source='Manual', original=None, update_existing=False, workspace='Production', actor_id=None, cache=None):
    """Persist one finding, optionally reusing identities already seen in this batch."""
    cache = cache if cache is not None else {}
    assets, vulnerabilities, findings = (cache.setdefault('assets', {}), cache.setdefault('vulnerabilities', {}), cache.setdefault('findings', {}))
    asset_key = (workspace, data.external_id or data.hostname.lower())
    asset = assets.get(asset_key)
    if not asset:
        asset = db.scalar(select(Asset).where(Asset.external_id == data.external_id, Asset.workspace == workspace)) if data.external_id else None
    if not asset:
        asset = db.scalar(select(Asset).where(Asset.hostname == data.hostname.lower(), Asset.workspace == workspace))
    if not asset:
        rule_context, default_controls, applied_rules = resolve_rules(db, data.hostname, data.ip, data.asset_tags)
        supplied = {k: v for k, v in data.context.model_dump().items() if v not in (None, '', [])}
        asset = Asset(hostname=data.hostname.lower(), external_id=data.external_id, ip=data.ip, os=data.os, tags=data.asset_tags,
                      context={**rule_context, **supplied, 'applied_rules': applied_rules}, workspace=workspace)
        db.add(asset)
        db.flush()
    else:
        rule_context, default_controls, applied_rules = resolve_rules(db, asset.hostname, data.ip or asset.ip, data.asset_tags or asset.tags)
        if applied_rules:
            asset.context = {**asset.context, **rule_context, 'applied_rules': applied_rules}
    assets[asset_key] = asset
    tech = data.model_dump(mode='json', exclude={'hostname', 'ip', 'os', 'external_id', 'context', 'name', 'cves', 'plugin_id', 'asset_tags', 'port', 'protocol'})
    vulnerability_identity = identity(data)
    vuln = vulnerabilities.get(vulnerability_identity) or db.scalar(select(Vulnerability).where(Vulnerability.identity == vulnerability_identity))
    if not vuln:
        vuln = Vulnerability(identity=identity(data), name=data.name, plugin_id=data.plugin_id, cves=data.cves, technical=tech)
        db.add(vuln)
        db.flush()
    vulnerabilities[vulnerability_identity] = vuln
    finding = None
    # Tenable's finding_id is stable across lifecycle changes, including a port
    # change. Prefer it so a fixed or resurfaced finding updates its history.
    upstream_id = str(original.get('finding_id')) if source == 'Tenable' and isinstance(original, dict) and original.get('finding_id') is not None else None
    finding_key = (asset.id, vuln.id, upstream_id or data.port, data.protocol if not upstream_id else '')
    finding = findings.get(finding_key)
    if not finding and upstream_id:
        for candidate in db.scalars(select(Finding).where(Finding.asset_id == asset.id, Finding.vulnerability_id == vuln.id)):
            if str((candidate.source_record or {}).get('finding_id')) == upstream_id:
                finding = candidate
                break
    if not finding:
        finding = db.scalar(select(Finding).where(Finding.asset_id == asset.id, Finding.vulnerability_id == vuln.id, Finding.port == data.port, Finding.protocol == data.protocol))
    if finding:
        if update_existing:
            finding.observed = {**tech, 'context': data.context.model_dump(), 'name': data.name, 'cves': data.cves, 'plugin_id': data.plugin_id,
                                'default_controls': default_controls, 'applied_rules': applied_rules}
            finding.source_record = original or data.model_dump(mode='json')
            finding.revision += 1
            if source == 'Tenable' and actor_id is not None:
                lifecycle = str(data.state or '').strip().casefold()
                closed = lifecycle in {'closed', 'fixed', 'resolved'}
                workflow = db.get(FindingWorkflow, finding.id)
                if closed:
                    if not workflow:
                        workflow = FindingWorkflow(finding_id=finding.id, status='Closed', updated_by=actor_id)
                        db.add(workflow)
                    else:
                        workflow.status, workflow.updated_by = 'Closed', actor_id
                elif workflow and workflow.status == 'Closed':
                    workflow.status, workflow.updated_by = 'New', actor_id
        findings[finding_key] = finding
        return finding, False
    finding = Finding(asset_id=asset.id, vulnerability_id=vuln.id, source=source, port=data.port, protocol=data.protocol, workspace=workspace,
                      source_record=original or data.model_dump(mode='json'), observed={**tech, 'context': data.context.model_dump(), 'name': data.name, 'cves': data.cves, 'plugin_id': data.plugin_id,
                      'default_controls': default_controls, 'applied_rules': applied_rules})
    db.add(finding)
    db.flush()
    findings[finding_key] = finding
    return finding, True


def _tenable_duplicate_groups(db, workspace):
    findings = db.scalars(
        select(Finding).where(Finding.workspace == workspace, Finding.source == 'Tenable').order_by(Finding.id)
    ).all()
    groups = {}
    for finding in findings:
        source_record = finding.source_record if isinstance(finding.source_record, dict) else {}
        stable_id = source_record.get('finding_id')
        if stable_id is not None and str(stable_id).strip():
            groups.setdefault((finding.asset_id, finding.vulnerability_id, str(stable_id)), []).append(finding)
    return [duplicates for duplicates in groups.values() if len(duplicates) > 1]


def tenable_duplicate_summary(db, workspace):
    """Return the actionable duplicate count without changing live findings."""
    groups = _tenable_duplicate_groups(db, workspace)
    protected = 0
    duplicates = 0
    for group in groups:
        ids = [finding.id for finding in group]
        campaign_ids = set(db.scalars(select(CampaignFinding.finding_id).where(CampaignFinding.finding_id.in_(ids))))
        if campaign_ids:
            protected += len(group) - 1
        else:
            duplicates += len(group) - 1
    return {'duplicate_findings': duplicates, 'duplicates_protected': protected, 'duplicate_groups': len(groups)}


def cleanup_tenable_duplicates(db, workspace):
    """Merge legacy duplicate Tenable findings using Tenable's stable finding ID.

    The normal ingestion path is an upsert, but older exports could leave more
    than one row when a finding changed port.  A campaign's snapshot is audit
    evidence, so any duplicate referenced by a campaign is deliberately left
    intact rather than deleting history behind an active or completed review.
    """
    groups = _tenable_duplicate_groups(db, workspace)

    removed = protected = 0
    for duplicates in groups:
        ids = [finding.id for finding in duplicates]
        campaign_ids = set(db.scalars(select(CampaignFinding.finding_id).where(CampaignFinding.finding_id.in_(ids))))
        if campaign_ids:
            # Do not change a campaign population retroactively.  New syncs will
            # continue to update its canonical record and no further duplicates
            # will be created by ingest().
            protected += len(duplicates) - 1
            continue

        canonical = max(duplicates, key=lambda finding: (finding.revision, finding.id))
        for duplicate in (finding for finding in duplicates if finding.id != canonical.id):
            # Preserve assessment history by moving it to the canonical finding.
            next_revision = db.scalar(
                select(Assessment.revision).where(Assessment.instance_id == canonical.id).order_by(Assessment.revision.desc())
            ) or 0
            for assessment in db.scalars(
                select(Assessment).where(Assessment.instance_id == duplicate.id).order_by(Assessment.revision, Assessment.id)
            ):
                next_revision += 1
                assessment.instance_id, assessment.revision = canonical.id, next_revision

            duplicate_workflow = db.get(FindingWorkflow, duplicate.id)
            canonical_workflow = db.get(FindingWorkflow, canonical.id)
            if duplicate_workflow:
                if not canonical_workflow:
                    duplicate_workflow.finding_id = canonical.id
                elif duplicate_workflow.updated_at > canonical_workflow.updated_at:
                    canonical_workflow.status = duplicate_workflow.status
                    canonical_workflow.owner_id = duplicate_workflow.owner_id
                    canonical_workflow.updated_by = duplicate_workflow.updated_by
                    canonical_workflow.review_state = duplicate_workflow.review_state
                    canonical_workflow.reviewed_at = duplicate_workflow.reviewed_at
                    canonical_workflow.reviewed_by = duplicate_workflow.reviewed_by
                    canonical_workflow.review_decision = duplicate_workflow.review_decision
                    canonical_workflow.review_notes = duplicate_workflow.review_notes
                    db.delete(duplicate_workflow)
                else:
                    db.delete(duplicate_workflow)

            db.execute(update(RiskException).where(RiskException.finding_id == duplicate.id).values(finding_id=canonical.id))
            db.execute(update(CampaignEvidence).where(CampaignEvidence.finding_id == duplicate.id).values(finding_id=canonical.id))
            db.execute(update(ImportRow).where(ImportRow.instance_id == duplicate.id).values(instance_id=canonical.id))
            db.delete(duplicate)
            removed += 1
        db.flush()
    return {'duplicates_removed': removed, 'duplicates_protected': protected}

def get_finding(db, id):
    result = db.get(Finding, id)
    if not result:
        raise HTTPException(404, 'Finding not found')
    return result

def latest_assessment(db, id):
    return db.scalar(select(Assessment).where(Assessment.instance_id == id).order_by(Assessment.revision.desc()))

def assessment_controls(db, assessment):
    return [{'name': c.name, 'effectiveness': c.effectiveness, 'applicable': c.applicable, 'validated': c.validated,
             'evidence': c.evidence, 'notes': c.notes, 'design_maturity': c.design_maturity,
             'operating_effectiveness': c.operating_effectiveness}
            for c in db.scalars(select(AssessmentControl).where(AssessmentControl.assessment_id == assessment.id))] if assessment else []

def detail(db, finding):
    asset, vuln = db.get(Asset, finding.asset_id), db.get(Vulnerability, finding.vulnerability_id)
    assessment = latest_assessment(db, finding.id)
    workflow = db.get(FindingWorkflow, finding.id)
    method = active_methodology(db)
    technical = {**vuln.technical, **finding.observed}
    context = {**finding.observed.get('context', {}), **(assessment.context if assessment else {}),
               **{k: v for k, v in asset.context.items() if k in ASSET_CONTEXT_KEYS}}
    saved = db.scalar(select(RiskScore).where(RiskScore.assessment_id == assessment.id)) if assessment else None
    baseline = calculate(technical, {}, [], method.configuration, datetime.now(timezone.utc).date())
    saved_controls = assessment_controls(db, assessment)
    inherited_controls = finding.observed.get('default_controls', [])
    merged_controls = {c['name']: c for c in inherited_controls}
    merged_controls.update({c['name']: c for c in saved_controls})
    return {'id': finding.id, 'revision': finding.revision, 'asset': {'id': asset.id, 'hostname': asset.hostname, 'ip': asset.ip, 'os': asset.os, 'tags': asset.tags},
            'name': finding.observed.get('name', vuln.name), 'plugin_id': vuln.plugin_id, 'cves': finding.observed.get('cves', vuln.cves), 'port': finding.port, 'protocol': finding.protocol,
            'source': finding.source, 'technical': technical, 'context': context,
            'controls': list(merged_controls.values()),
            'applied_rules': finding.observed.get('applied_rules', asset.context.get('applied_rules', [])),
            'status': assessment.status if assessment else 'Not Assessed',
            'workflow_status': workflow.status if workflow else 'New',
            'remediation_due_at': workflow.remediation_due_at.isoformat() if workflow and workflow.remediation_due_at else None,
            'remediation_evidence': workflow.remediation_evidence if workflow else None,
            'decision': assessment.decision if assessment else 'Needs Further Assessment',
            'review_state': workflow.review_state if workflow else None,
            'reviewed_at': workflow.reviewed_at.isoformat() if workflow and workflow.reviewed_at else None,
            'reviewed_by': workflow.reviewed_by if workflow else None,
            'notes': assessment.notes if assessment else '', 'justification': assessment.justification if assessment else '',
            'assessed_at': assessment.created_at.isoformat() if assessment else None, 'saved_score': saved.result if saved else None,
            'score': saved.result if saved else baseline, 'baseline': baseline,
            'methodology_id': method.id, 'methodology_version': method.version,
            'reassessment_required': bool(assessment and (assessment.revision != finding.revision or assessment.methodology_id != method.id))}
