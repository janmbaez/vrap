"""Central KPI contract shared by operational and executive surfaces."""
from datetime import date, datetime, timezone, timedelta
from sqlalchemy import select, func
from .models import Finding, FindingWorkflow, Assessment, RiskException, ControlLibrary, Asset, Vulnerability, RemediationSLAPolicy

DEFAULT_SLA_DAYS = {
    ('PCI DSS', 'Critical'): 30, ('PCI DSS', 'High'): 30,
    ('PCI DSS', 'Medium'): 90, ('PCI DSS', 'Low'): 180,
    ('Non-PCI', 'Critical'): 30, ('Non-PCI', 'High'): 60,
    ('Non-PCI', 'Medium'): 90, ('Non-PCI', 'Low'): None,
}

def _first_seen(finding):
    value = (finding.observed or {}).get('first_seen') or (finding.source_record or {}).get('first_seen')
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None

def evaluate_sla(db, workspace, as_of=None):
    today = (as_of or datetime.now(timezone.utc)).date()
    policies = db.scalars(select(RemediationSLAPolicy).where(
        RemediationSLAPolicy.workspace == workspace, RemediationSLAPolicy.approved.is_(True),
        RemediationSLAPolicy.effective_from <= today,
        (RemediationSLAPolicy.effective_to.is_(None) | (RemediationSLAPolicy.effective_to >= today)))
        .order_by(RemediationSLAPolicy.version.desc(), RemediationSLAPolicy.id.desc())).all()
    overrides = {}
    for policy in policies:
        overrides.setdefault((policy.regulatory_scope, policy.severity), policy.days)
    rows = []
    query = (select(Finding, Vulnerability, Asset, FindingWorkflow)
             .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
             .join(Asset, Asset.id == Finding.asset_id)
             .outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id)
             .where(Finding.workspace == workspace))
    for finding, vuln, asset, workflow in db.execute(query):
        observed = finding.observed or {}
        technical = {**(vuln.technical or {}), **observed.get('technical', observed)}
        severity = technical.get('severity') or 'Low'
        scopes = (asset.context or {}).get('regulatory') or []
        applicable = ['PCI DSS' if scope == 'PCI DSS' else scope if scope in ('SOC 2', 'Non-PCI') else 'Non-PCI' for scope in scopes] or ['Non-PCI']
        days = min((value for scope in applicable if (value := overrides.get((scope, severity), DEFAULT_SLA_DAYS.get((scope, severity), DEFAULT_SLA_DAYS.get(('Non-PCI', severity))))) is not None), default=None)
        first = _first_seen(finding)
        due = first + timedelta(days=days) if first and days is not None else None
        active = not workflow or workflow.status not in ('Closed', 'Accepted')
        rows.append({'finding_id': finding.id, 'vulnerability_id': vuln.id, 'asset_id': asset.id,
                     'severity': severity, 'scopes': scopes, 'first_seen': first.isoformat() if first else None,
                     'age_days': (today - first).days if first else None, 'sla_days': days,
                     'due_date': due.isoformat() if due else None,
                     'overdue': bool(active and due and today > due),
                     'due_soon': bool(active and due and today <= due and (due - today).days <= 7),
                     'exception': False, 'monitored': days is None, 'active': active})
    applicable_rows = [row for row in rows if row['active'] and row['sla_days'] is not None and row['due_date']]
    unverifiable = sum(row['active'] and row['sla_days'] is not None and not row['due_date'] for row in rows)
    overdue = sum(row['overdue'] for row in applicable_rows)
    return {'workspace': workspace, 'policies': 'provisional defaults plus approved overrides',
            'total': len(rows), 'overdue': overdue, 'due_soon': sum(row['due_soon'] for row in rows),
            'sla_applicable': len(applicable_rows), 'sla_compliant': len(applicable_rows) - overdue,
            'sla_unverifiable': unverifiable,
            'sla_compliance_percent': round((len(applicable_rows) - overdue) / len(applicable_rows) * 100, 2) if applicable_rows else 0,
            'items': rows}

def calculate_kpis(db, workspace, as_of=None):
    as_of = as_of or datetime.now(timezone.utc)
    total = db.scalar(select(func.count(Finding.id)).where(Finding.workspace == workspace)) or 0
    vulnerabilities = db.scalar(select(func.count(func.distinct(Finding.vulnerability_id))).where(Finding.workspace == workspace)) or 0
    assets = db.scalar(select(func.count(func.distinct(Finding.asset_id))).where(Finding.workspace == workspace)) or 0
    workflows = db.execute(select(FindingWorkflow.status, FindingWorkflow.remediation_due_at, FindingWorkflow.remediation_evidence).join(Finding, Finding.id == FindingWorkflow.finding_id).where(Finding.workspace == workspace)).all()
    assessed = db.scalar(select(func.count(Assessment.id)).join(Finding, Finding.id == Assessment.instance_id).where(Finding.workspace == workspace, Assessment.revision == Finding.revision)) or 0
    overdue = due_soon = scheduled = 0
    for status, due, _ in workflows:
        if due and status not in ('Closed', 'Accepted'):
            scheduled += 1; due = due.replace(tzinfo=timezone.utc) if due.tzinfo is None else due
            overdue += due < as_of; due_soon += as_of <= due <= as_of + timedelta(days=7)
    exceptions = db.scalar(select(func.count(RiskException.id)).where(RiskException.workspace == workspace, RiskException.status.in_(['Requested','Approved']))) or 0
    expired_controls = db.scalar(select(func.count(ControlLibrary.id)).where(ControlLibrary.workspace == workspace, ControlLibrary.expires_at.is_not(None), ControlLibrary.expires_at < as_of)) or 0
    sla = evaluate_sla(db, workspace, as_of)
    return {'workspace': workspace, 'as_of': as_of.isoformat(), 'total_findings': total,
            'distinct_vulnerabilities': vulnerabilities, 'unique_affected_assets': assets, 'assessed': assessed,
            'assessment_coverage': round(assessed / total * 100, 2) if total else 0,
            'overdue': overdue, 'due_soon': due_soon, 'scheduled': scheduled,
            'verified_closure': sum(status == 'Closed' and bool(evidence) for status, _, evidence in workflows),
            'ticket_coverage': sum(bool(evidence) for _, _, evidence in workflows),
            'backlog_aging': total - sum(status in ('Closed', 'Accepted') for status, _, _ in workflows),
            'backlog_denominator': total,
            'sla_applicable': sla['sla_applicable'], 'sla_compliant': sla['sla_compliant'],
            'sla_compliance_percent': sla['sla_compliance_percent'], 'sla_overdue': sla['overdue'],
            'sla_unverifiable': sla['sla_unverifiable'],
            'open_exceptions': exceptions, 'expired_control_evidence': expired_controls}
