"""Central KPI contract shared by operational and executive surfaces."""
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func
from .models import Finding, FindingWorkflow, Assessment, RiskScore, RiskException, ControlLibrary

def calculate_kpis(db, workspace, as_of=None):
    as_of = as_of or datetime.now(timezone.utc)
    total = db.scalar(select(func.count(Finding.id)).where(Finding.workspace == workspace)) or 0
    workflows = db.execute(select(FindingWorkflow.status, FindingWorkflow.remediation_due_at, FindingWorkflow.remediation_evidence).join(Finding, Finding.id == FindingWorkflow.finding_id).where(Finding.workspace == workspace)).all()
    assessed = db.scalar(select(func.count(Assessment.id)).join(Finding, Finding.id == Assessment.instance_id).where(Finding.workspace == workspace, Assessment.revision == Finding.revision)) or 0
    overdue = due_soon = scheduled = 0
    for _, due, _ in workflows:
        if due:
            scheduled += 1; due = due.replace(tzinfo=timezone.utc) if due.tzinfo is None else due
            overdue += due < as_of; due_soon += as_of <= due <= as_of + timedelta(days=7)
    exceptions = db.scalar(select(func.count(RiskException.id)).where(RiskException.workspace == workspace, RiskException.status.in_(['Requested','Approved']))) or 0
    expired_controls = db.scalar(select(func.count(ControlLibrary.id)).where(ControlLibrary.workspace == workspace, ControlLibrary.expires_at.is_not(None), ControlLibrary.expires_at < as_of)) or 0
    return {'workspace': workspace, 'as_of': as_of.isoformat(), 'total_findings': total, 'assessed': assessed,
            'assessment_coverage': round(assessed / total * 100, 2) if total else 0,
            'overdue': overdue, 'due_soon': due_soon, 'scheduled': scheduled,
            'verified_closure': sum(status == 'Closed' and bool(evidence) for status, _, evidence in workflows),
            'ticket_coverage': sum(bool(evidence) for _, _, evidence in workflows),
            'backlog_aging': sum(status in ('New','Investigating','Remediation Planned','Risk Review') for status, _, _ in workflows),
            'open_exceptions': exceptions, 'expired_control_evidence': expired_controls}
