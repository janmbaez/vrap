"""Environment-scoped campaign evidence exports through the shared PDF engine."""
import csv
import json
from datetime import datetime, timezone
from io import StringIO
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from ..auth import require_user
from ..db import get_db
from ..models import CampaignFinding, CampaignReviewer, CampaignEvidence, CampaignAuditEvent, User
from ..campaigns import get_campaign, campaign_metrics
from ..report_pdf import build_campaign_pdf

router = APIRouter(tags=['Review campaign evidence'])


def safe_csv_cell(value):
    """Neutralize spreadsheet formulas including prefixes hidden behind whitespace."""
    cell = '' if value is None else str(value)
    return "'" + cell if cell.lstrip().startswith(('=', '+', '-', '@')) else cell


def campaign_evidence_data(db, campaign, metrics):
    generated = datetime.now(timezone.utc)
    reviewers = db.scalars(select(User.username).join(CampaignReviewer, CampaignReviewer.user_id == User.id)
                          .where(CampaignReviewer.campaign_id == campaign.id).order_by(User.username)).all()
    data = {'id': campaign.id, 'name': campaign.name, 'description': campaign.description,
            'environment': campaign.workspace, 'status': campaign.status, 'frequency': campaign.frequency,
            'period_start': campaign.period_start.isoformat(), 'period_end': campaign.period_end.isoformat(),
            'start_date': campaign.start_date.isoformat(), 'due_date': campaign.due_date.isoformat(),
            'activated_at': campaign.activated_at.isoformat() if campaign.activated_at else None,
            'completed_at': campaign.completed_at.isoformat() if campaign.completed_at else None,
            'generated_at': generated.isoformat(), 'scope_text': json.dumps(campaign.scope, sort_keys=True, ensure_ascii=False),
            'reviewers': reviewers, 'metrics': metrics}
    columns = [column for column in CampaignFinding.__table__.columns if column.name != 'campaign_id']
    rows = db.execute(select(*columns, User.username.label('reviewer')).outerjoin(User, User.id == CampaignFinding.reviewer_id)
                      .where(CampaignFinding.campaign_id == campaign.id).order_by(CampaignFinding.finding_id))
    findings = []
    for row in rows.mappings():
        record = dict(row)
        record['reviewed_at'] = record['reviewed_at'].isoformat() if record['reviewed_at'] else None
        findings.append(record)
    evidence = [{'finding_id': row.finding_id, 'reference': row.reference, 'notes': row.notes,
                 'actor': actor, 'created_at': row.created_at.isoformat()}
                for row, actor in db.execute(select(CampaignEvidence, User.username).join(User, User.id == CampaignEvidence.created_by)
                .where(CampaignEvidence.campaign_id == campaign.id).order_by(CampaignEvidence.created_at, CampaignEvidence.id))]
    audit = [{'actor': actor, 'action': row.action, 'created_at': row.created_at.isoformat(),
              'details_text': json.dumps(row.details, sort_keys=True, ensure_ascii=False)}
             for row, actor in db.execute(select(CampaignAuditEvent, User.username).join(User, User.id == CampaignAuditEvent.actor_id)
             .where(CampaignAuditEvent.campaign_id == campaign.id).order_by(CampaignAuditEvent.created_at, CampaignAuditEvent.id))]
    return data, findings, evidence, audit


def campaign_csv(data, findings, evidence, audit):
    stream = StringIO(newline=''); writer = csv.writer(stream)
    def row(values): writer.writerow([safe_csv_cell(value) for value in values])
    row(['VRAP review campaign evidence']); row(['Campaign ID', data['id']]); row(['Campaign', data['name']])
    for key in ('environment', 'status', 'frequency', 'period_start', 'period_end', 'start_date', 'due_date', 'activated_at', 'completed_at', 'generated_at', 'scope_text'):
        row([key, data[key]])
    row(['Assigned reviewers', ', '.join(data['reviewers'])])
    for key in ('total', 'reviewed', 'pending', 'skipped', 'review_coverage', 'processed_coverage'):
        row([key, data['metrics'].get(key) if data['metrics'].get(key) is not None else 'No data'])
    row(['Review coverage formula', 'Reviewed / Total x 100; skipped is excluded'])
    row([]); row(['Frozen population and review decisions'])
    keys = ['finding_id', 'snapshot_asset_id', 'snapshot_asset', 'snapshot_vulnerability', 'snapshot_plugin_id',
            'snapshot_severity', 'snapshot_risk', 'snapshot_risk_level', 'snapshot_business_owner', 'snapshot_it_owner',
            'snapshot_application_owner', 'snapshot_asset_group', 'snapshot_tags', 'snapshot_regulatory',
            'status', 'reviewer_id', 'reviewer', 'reviewed_at', 'decision', 'skip_reason', 'notes', 'evidence_references']
    row(keys)
    for item in findings:
        row([json.dumps(item.get(key), ensure_ascii=False) if isinstance(item.get(key), (list, dict)) else item.get(key) for key in keys])
    row([]); row(['Campaign evidence']); row(['finding_id', 'reference', 'notes', 'actor', 'created_at'])
    for item in evidence: row([item.get(key) for key in ('finding_id', 'reference', 'notes', 'actor', 'created_at')])
    row([]); row(['Campaign audit trail']); row(['actor', 'created_at', 'action', 'details'])
    for item in audit: row([item[key] for key in ('actor', 'created_at', 'action', 'details_text')])
    return stream.getvalue().encode('utf-8-sig')


def _export(campaign_id, request, user, db, kind):
    campaign = get_campaign(db, campaign_id, request.state.session.workspace, user)
    metrics = campaign_metrics(db, campaign_id)
    data, findings, evidence, audit = campaign_evidence_data(db, campaign, metrics)
    payload = campaign_csv(data, findings, evidence, audit) if kind == 'csv' else build_campaign_pdf(data, findings, evidence, audit)
    db.add(CampaignAuditEvent(campaign_id=campaign.id, actor_id=user.id, action='campaign.exported',
                              details={'format': kind, 'population': metrics['total'], 'environment': campaign.workspace}))
    db.commit()
    return Response(payload, media_type='text/csv; charset=utf-8' if kind == 'csv' else 'application/pdf',
                    headers={'Content-Disposition': f'attachment; filename="VRAP-Campaign-{campaign.id}-{campaign.workspace}.{kind}"',
                             'Content-Length': str(len(payload)), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@router.get('/review-campaigns/{campaign_id}/export/csv')
def export_campaign_csv(campaign_id: int, request: Request, user=Depends(require_user), db=Depends(get_db)):
    return _export(campaign_id, request, user, db, 'csv')


@router.get('/review-campaigns/{campaign_id}/export/pdf')
def export_campaign_pdf(campaign_id: int, request: Request, user=Depends(require_user), db=Depends(get_db)):
    return _export(campaign_id, request, user, db, 'pdf')
