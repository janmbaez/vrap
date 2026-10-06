"""One source of truth for executive JSON, screen charts and PDF.

Live exposure is an as-of snapshot; period governance uses frozen campaign populations.
A current score requires the latest completed assessment, matching revision and policy.
"""
from datetime import date, datetime, timedelta, timezone
from sqlalchemy import and_, case, func, select, Text
from fastapi import HTTPException
from .models import Asset, Assessment, Finding, FindingWorkflow, Methodology, RiskException, RiskScore, Vulnerability

SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown')
COMPLETED_ASSESSMENTS = ('Assessed', 'Above Risk Appetite', 'Exception Requested', 'Risk Accepted', 'Remediation Required', 'Closed')
ATTENTION_THRESHOLDS = {'review_coverage': 80, 'owner_min_population': 5, 'group_min_population': 5,
                        'skipped_share': 10, 'coverage_drop_points': 10}


def percent(n, d):
    return n * 100 / d if d else None


def reporting_period(filters, today=None):
    today = today or datetime.now(timezone.utc).date()
    def parse(key, default):
        try:
            return date.fromisoformat(str(filters[key])) if filters.get(key) else default
        except ValueError:
            raise HTTPException(422, f'{key} must be an ISO date')
    end = parse('period_end', today)
    start = parse('period_start', end - timedelta(days=6))
    if start > end or (end - start).days > 366:
        raise HTTPException(422, 'Reporting period must be ordered and at most 367 days')
    return start, end


def _live_query(db, workspace, filters):
    latest = select(Assessment.instance_id, func.max(Assessment.revision).label('revision')).group_by(Assessment.instance_id).subquery()
    query = (select(Finding.id.label('finding_id'), Finding.asset_id, Finding.revision,
                    Vulnerability.name, Vulnerability.plugin_id,
                    func.coalesce(Finding.observed['severity'].as_string(), Vulnerability.technical['severity'].as_string(), 'Unknown').label('severity'),
                    Assessment.id.label('assessment_id'), Assessment.revision.label('assessment_revision'), Assessment.methodology_id,
                    Assessment.status.label('assessment_status'), RiskScore.result,
                    func.coalesce(FindingWorkflow.review_state, case((FindingWorkflow.status == 'Reviewed', 'Reviewed'), else_='Pending')).label('review_state'))
             .select_from(Finding).join(Asset, Asset.id == Finding.asset_id).join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
             .outerjoin(latest, latest.c.instance_id == Finding.id)
             .outerjoin(Assessment, and_(Assessment.instance_id == Finding.id, Assessment.revision == latest.c.revision))
             .outerjoin(RiskScore, RiskScore.assessment_id == Assessment.id)
             .outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id)
             .where(Finding.workspace == workspace, Asset.workspace == workspace,
                    func.coalesce(FindingWorkflow.status, Assessment.status, 'New') != 'Closed'))
    from .query import finding_query
    scope = {key: filters[key] for key in ('severity', 'business_owner', 'it_owner', 'application_owner', 'asset_group', 'regulatory') if filters.get(key)}
    if scope.get('severity') == 'Unknown':
        scope.pop('severity')
        query = query.where(func.coalesce(Finding.observed['severity'].as_string(), Vulnerability.technical['severity'].as_string(), 'Unknown') == 'Unknown')
    matching_ids = finding_query(db, workspace, scope).with_only_columns(Finding.id)
    query = query.where(Finding.id.in_(matching_ids))
    if filters.get('campaign_id'):
        from .models import CampaignFinding
        query = query.where(Finding.id.in_(select(CampaignFinding.finding_id).where(CampaignFinding.campaign_id == filters['campaign_id'])))
    return query


def live_exposure(db, workspace, filters, generated):
    method = db.scalar(select(Methodology).order_by(Methodology.id.desc()))
    base = _live_query(db, workspace, filters).subquery()
    # JSON risk values are projected once; aggregates remain portable on SQLite/Postgres.
    valid = and_(base.c.assessment_status.in_(COMPLETED_ASSESSMENTS), base.c.assessment_revision == base.c.revision,
                 base.c.methodology_id == (method.id if method else -1), base.c.result.is_not(None))
    stale = and_(base.c.assessment_id.is_not(None),
                 (base.c.assessment_revision != base.c.revision) | (base.c.methodology_id != (method.id if method else -1)))
    reviewed = base.c.review_state == 'Reviewed'
    count = lambda condition: func.coalesce(func.sum(case((condition, 1), else_=0)), 0)
    result = db.execute(select(func.count().label('total'), func.count(func.distinct(base.c.asset_id)).label('assets'),
                              count(valid).label('assessed'), count(stale).label('stale'),
                              count(and_(base.c.assessment_id.is_not(None), ~valid, ~stale)).label('draft'),
                              count(reviewed).label('reviewed'),
                              count(and_(valid, base.c.result['above_appetite'].as_boolean().is_(True))).label('above'),
                              count(and_(valid, base.c.result['above_appetite'].as_boolean().is_(False))).label('within'),
                              func.avg(case((valid, base.c.result['residual'].as_float()), else_=None)).label('risk_exposure'))).one()
    severity = {s: 0 for s in SEVERITIES}
    for name, value in db.execute(select(base.c.severity, func.count()).group_by(base.c.severity)):
        severity[name if name in severity else 'Unknown'] += value
    residual = {s: 0 for s in SEVERITIES}
    for name, value in db.execute(select(base.c.result['residual_level'].as_string(), func.count()).where(valid).group_by(base.c.result['residual_level'].as_string())):
        residual[name if name in residual else 'Unknown'] += value
    approved = db.scalar(select(func.count(RiskException.id)).where(RiskException.workspace == workspace,
                         RiskException.status == 'Approved', RiskException.expires_at > generated,
                         RiskException.finding_id.in_(select(base.c.finding_id)))) or 0
    top = db.execute(select(base.c.name, base.c.plugin_id, func.count().label('findings'),
                            count(base.c.severity.in_(['Critical', 'High'])).label('critical_high'),
                            count(~reviewed).label('pending_reviews'), count(valid).label('scored'),
                            func.avg(case((valid, base.c.result['residual'].as_float()), else_=None)).label('risk'))
                     .group_by(base.c.name, base.c.plugin_id).order_by(func.count().desc(), base.c.name).limit(10)).all()
    total_assets = db.scalar(select(func.count(Asset.id)).where(Asset.workspace == workspace)) or 0
    summary = {'total_findings': result.total, 'active_findings': result.total, 'affected_assets': result.assets,
               'assessed': result.assessed, 'assessment_coverage': percent(result.assessed, result.total),
               'approved_exceptions': approved, 'reviewed': result.reviewed, 'pending_live_reviews': result.total - result.reviewed,
               'risk_exposure': result.risk_exposure, 'scored_findings': result.assessed,
               'asset_coverage': percent(result.assets, total_assets), 'inventory_assets': total_assets}
    posture = {'above_appetite': result.above, 'within_appetite': result.within,
               'unassessed': result.total - result.assessed, 'draft_assessments': result.draft,
               'stale_assessments': result.stale, 'never_assessed': result.total - result.assessed - result.draft - result.stale,
               'residual_distribution': residual}
    return summary, posture, severity, [{'name': r.name, 'plugin_id': r.plugin_id, 'findings': r.findings,
             'critical_high': r.critical_high, 'pending_reviews': r.pending_reviews,
             'scored': r.scored, 'risk': r.risk} for r in top], {
                 'version': method.version if method else None,
                 'appetite': method.configuration.get('appetite') if method else None}


def comparison(key, label, current, previous, higher_is_better, unit='count'):
    delta = current - previous if current is not None and previous is not None else None
    direction = 'n/a' if delta is None else 'unchanged' if delta == 0 else 'improved' if (delta > 0) == higher_is_better else 'deteriorated'
    return {'key': key, 'label': label, 'current': current, 'previous': previous, 'change': delta,
            'direction': direction, 'arrow': 'up' if delta is not None and delta > 0 else 'down' if delta is not None and delta < 0 else None,
            'unit': unit}


def management_attention(governance, comparisons):
    """Documented rules; changing thresholds never changes review/remediation state."""
    summary = governance['summary']; attention = []
    def add(level, code, text, campaign_id=None, query=''):
        attention.append({'severity': level, 'code': code, 'text': text,
                          'link': f'/review-campaigns/{campaign_id}' if campaign_id else '/review-campaigns' + query})
    if summary.get('overdue_campaigns', 0):
        add('Critical', 'overdue', f"{summary['overdue_campaigns']} campaigns are overdue and need a documented review decision.", query='?overdue=true')
    if summary.get('critical_pending', 0):
        add('Critical', 'critical_pending', f"{summary['critical_pending']} critical campaign findings are pending review.", query='?severity=Critical')
    for campaign in governance.get('campaigns', []):
        metrics = campaign.get('metrics') or campaign
        coverage = metrics.get('review_coverage')
        if coverage is not None and coverage < ATTENTION_THRESHOLDS['review_coverage']:
            add('High', 'campaign_coverage', f"{campaign['name']}: {coverage:.1f}% reviewed against the 80% attention threshold ({metrics.get('reviewed', 0)} / {metrics.get('total', 0)}).", campaign['id'])
    for dimension, label in [('business_owner', 'Business owner'), ('it_owner', 'IT owner'), ('application_owner', 'Application owner'), ('asset_group', 'Asset group')]:
        for group in governance.get('breakdowns', {}).get(dimension, []):
            coverage = group.get('review_coverage')
            if group.get('total', 0) >= 5 and coverage is not None and coverage < 80:
                from urllib.parse import urlencode
                add('High', dimension + '_coverage', f"{label} {group['name']}: {group['pending']} pending, {coverage:.1f}% reviewed across {group['total']} population entries.", query='?' + urlencode({dimension: group['name']}))
    skipped_share = percent(summary.get('skipped', 0), summary.get('total', 0))
    if skipped_share is not None and skipped_share > 10:
        add('Medium', 'skipped_share', f'{skipped_share:.1f}% of the campaign population was skipped; confirm reasons and evidence.')
    coverage = next((r for r in comparisons if r['key'] == 'review_coverage'), None)
    if coverage and coverage['change'] is not None and coverage['change'] <= -10:
        add('High', 'coverage_drop', f"Review coverage fell {abs(coverage['change']):.1f} percentage points versus the previous equal-length period.")
    rank = {'Critical': 0, 'High': 1, 'Medium': 2}
    return sorted(attention, key=lambda x: (rank[x['severity']], x['code'], x['text']))


def executive_report_data(db, workspace, user, filters=None, generated=None):
    from .campaigns import governance_analytics, get_campaign
    filters = dict(filters or {}); generated = generated or datetime.now(timezone.utc)
    start, end = reporting_period(filters, generated.date())
    filters.update(period_start=start.isoformat(), period_end=end.isoformat())
    if filters.get('campaign_id'):
        get_campaign(db, filters['campaign_id'], workspace, user)
    current = governance_analytics(db, workspace, user=user, filters=filters)
    days = (end - start).days + 1
    previous_start, previous_end = start - timedelta(days=days), start - timedelta(days=1)
    previous_filters = {**filters, 'period_start': previous_start.isoformat(), 'period_end': previous_end.isoformat(),
                        'exclude_campaign_ids': [campaign['id'] for campaign in current.get('campaigns', [])]}
    # A specific campaign has no artificial previous campaign; period comparison is n/a.
    previous = governance_analytics(db, workspace, user=user, filters=previous_filters)
    previous_summary = previous['summary'] if previous.get('campaigns') else {}
    current_summary = current['summary']
    from .campaigns import snapshot_query, SNAPSHOT_FILTER_KEYS
    from .models import CampaignFinding
    scope = {key: value for key, value in filters.items() if key in SNAPSHOT_FILTER_KEYS}
    def snapshot_exposure(campaigns):
        ids = [campaign['id'] for campaign in campaigns]
        conditions = snapshot_query(db, ids, scope)._where_criteria
        r = db.execute(select(func.count(CampaignFinding.id).label('total'),
             func.count(CampaignFinding.snapshot_risk).label('scored'),
             func.avg(CampaignFinding.snapshot_risk).label('risk'),
             func.coalesce(func.sum(case((CampaignFinding.snapshot_severity.in_(['Critical', 'High']), 1), else_=0)), 0).label('critical_high')).where(*conditions)).one()
        return {'total': r.total, 'scored': r.scored, 'risk_exposure': r.risk, 'critical_high': r.critical_high,
                'score_coverage': percent(r.scored, r.total)}
    current['snapshot_exposure'] = snapshot_exposure(current.get('campaigns', []))
    previous_exposure = snapshot_exposure(previous.get('campaigns', []))
    from .models import ReviewCampaign
    conditions = snapshot_query(db, [campaign['id'] for campaign in current.get('campaigns', [])], scope)._where_criteria
    risk_rows = db.execute(select(ReviewCampaign.period_start.label('period'), func.count(CampaignFinding.id).label('total'),
        func.count(CampaignFinding.snapshot_risk).label('scored'), func.avg(CampaignFinding.snapshot_risk).label('risk'))
        .join(CampaignFinding, CampaignFinding.campaign_id == ReviewCampaign.id).where(*conditions)
        .group_by(ReviewCampaign.period_start).order_by(ReviewCampaign.period_start)).all()
    current['risk_trends'] = [{'period': row.period.isoformat(), 'total': row.total, 'scored': row.scored,
        'risk_exposure': row.risk, 'score_coverage': percent(row.scored, row.total)} for row in risk_rows]
    metrics = [('review_coverage', 'Review coverage', True, 'percent'),
               ('processed_coverage', 'Processed coverage', True, 'percent'),
               ('campaign_completion_rate', 'Campaign completion rate', True, 'percent'),
               ('critical_pending', 'Critical findings pending review', False, 'count'),
               ('overdue_campaigns', 'Overdue campaigns', False, 'count')]
    comparisons = [comparison(key, label, current_summary.get(key), previous_summary.get(key), good, unit)
                   for key, label, good, unit in metrics]
    comparisons.append(comparison('skipped_share', 'Skipped share', percent(current_summary.get('skipped', 0), current_summary.get('total', 0)),
                       percent(previous_summary.get('skipped', 0), previous_summary.get('total', 0)), False, 'percent'))
    comparisons += [comparison('snapshot_risk', 'Campaign snapshot average residual risk', current['snapshot_exposure']['risk_exposure'], previous_exposure['risk_exposure'], False, 'score'),
                    comparison('snapshot_critical_high', 'Critical / High snapshot entries', current['snapshot_exposure']['critical_high'] if current['snapshot_exposure']['total'] else None, previous_exposure['critical_high'] if previous_exposure['total'] else None, False)]
    summary, posture, severity, top, method = live_exposure(db, workspace, filters, generated)
    attention = management_attention(current, comparisons)
    narrative = [f"{summary['total_findings']:,} active findings affect {summary['affected_assets']:,} assets; {severity['Critical']:,} are Critical and {severity['High']:,} High by technical severity.",
                 f"{summary['assessed']:,} findings have a current completed assessment. {posture['unassessed']:,} require assessment or reassessment, including {posture['draft_assessments']:,} drafts and {posture['stale_assessments']:,} stale assessments."]
    if current_summary.get('total'):
        narrative.append(f"{current_summary['reviewed']:,} of {current_summary['total']:,} campaign population entries were reviewed ({current_summary['review_coverage']:.1f}%). {current_summary['pending']:,} remain pending and {current_summary['skipped']:,} were skipped.")
    else:
        narrative.append('No activated review campaigns match this reporting period and scope; review coverage is not available.')
    if summary['risk_exposure'] is not None:
        narrative.append(f"Average residual risk is {summary['risk_exposure']:.1f} across {summary['scored_findings']:,} current assessed findings; unassessed, draft and stale scores are excluded.")
    else:
        narrative.append('Residual risk exposure is not available because there are no current completed scored assessments.')
    narrative.append(f"{len(attention)} management attention conditions were triggered by documented thresholds." if attention else 'No management attention threshold was triggered in the selected campaign data.')
    return {'title': 'Vulnerability Risk Executive Report', 'environment': workspace, 'generated_at': generated.isoformat(),
            'period': {'start': start.isoformat(), 'end': end.isoformat(), 'previous_start': previous_start.isoformat(), 'previous_end': previous_end.isoformat()},
            'filters': filters, 'methodology': method, 'summary': summary, 'assessment_posture': posture,
            'severity': severity, 'top_exposures': top, 'governance': current, 'comparisons': comparisons,
            'management_attention': attention, 'attention_thresholds': ATTENTION_THRESHOLDS, 'narrative': narrative,
            'statement': 'Live exposure is the current estate snapshot. Period review governance uses frozen campaign populations. Skipped entries are never counted as reviewed. Review decisions do not change remediation status or approve risk acceptance.',
            'history_statement': 'Historical vulnerability risk is not reconstructed. Any saved campaign snapshot risk describes only the assessed population at activation, not a continuous estate risk trend.'}
