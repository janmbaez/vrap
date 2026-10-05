import hashlib
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import select
from .models import Asset, Vulnerability, Finding, Methodology, Assessment, AssessmentControl, RiskScore
from .risk.engine import calculate
from .asset_rules import resolve_rules, ASSET_CONTEXT_KEYS


def active_methodology(db):
    method = db.scalar(select(Methodology).order_by(Methodology.id.desc()))
    if not method:
        raise HTTPException(503, 'Initialize the database and methodology first')
    return method

def identity(data):
    return ('plugin:' + data.plugin_id) if data.plugin_id else 'manual:' + hashlib.sha256((data.name.casefold() + '|' + ','.join(sorted(data.cves))).encode()).hexdigest()

def ingest(db, data, source='Manual', original=None, update_existing=False, workspace='Production'):
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
    tech = data.model_dump(mode='json', exclude={'hostname', 'ip', 'os', 'external_id', 'context', 'name', 'cves', 'plugin_id', 'asset_tags', 'port', 'protocol'})
    vuln = db.scalar(select(Vulnerability).where(Vulnerability.identity == identity(data)))
    if not vuln:
        vuln = Vulnerability(identity=identity(data), name=data.name, plugin_id=data.plugin_id, cves=data.cves, technical=tech)
        db.add(vuln)
        db.flush()
    finding = db.scalar(select(Finding).where(Finding.asset_id == asset.id, Finding.vulnerability_id == vuln.id, Finding.port == data.port, Finding.protocol == data.protocol))
    if finding:
        if update_existing:
            finding.observed = {**tech, 'context': data.context.model_dump(), 'name': data.name, 'cves': data.cves, 'plugin_id': data.plugin_id,
                                'default_controls': default_controls, 'applied_rules': applied_rules}
            finding.source_record = original or data.model_dump(mode='json')
            finding.revision += 1
        return finding, False
    finding = Finding(asset_id=asset.id, vulnerability_id=vuln.id, source=source, port=data.port, protocol=data.protocol, workspace=workspace,
                      source_record=original or data.model_dump(mode='json'), observed={**tech, 'context': data.context.model_dump(), 'name': data.name, 'cves': data.cves, 'plugin_id': data.plugin_id,
                      'default_controls': default_controls, 'applied_rules': applied_rules})
    db.add(finding)
    db.flush()
    return finding, True

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
            'status': assessment.status if assessment else 'Not Assessed', 'decision': assessment.decision if assessment else 'Needs Further Assessment',
            'notes': assessment.notes if assessment else '', 'justification': assessment.justification if assessment else '',
            'assessed_at': assessment.created_at.isoformat() if assessment else None, 'saved_score': saved.result if saved else None,
            'score': saved.result if saved else baseline, 'baseline': baseline,
            'methodology_id': method.id, 'methodology_version': method.version,
            'reassessment_required': bool(assessment and (assessment.revision != finding.revision or assessment.methodology_id != method.id))}
