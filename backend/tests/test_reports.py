"""Report correctness, frozen review evidence and download security regressions."""
from datetime import date, datetime, timedelta, timezone
from io import BytesIO
import csv
from sqlalchemy import select
from app.models import (Asset, Vulnerability, Finding, FindingWorkflow, Assessment, RiskScore, Methodology,
                        ReviewCampaign, CampaignFinding, CampaignReviewer, CampaignEvidence, CampaignAuditEvent, User)
from app.executive import executive_report_data, management_attention
from app.api.campaign_exports import campaign_csv, campaign_evidence_data, safe_csv_cell
from app.campaigns import campaign_metrics
from app.report_pdf import build_executive_pdf, build_campaign_pdf
from conftest import login


NOW = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)


def add_finding(db, workspace='Production', severity='Critical', owner='Security business', group='Servers'):
    index = (db.scalar(select(Finding.id).order_by(Finding.id.desc())) or 0) + 1
    asset = Asset(hostname=f'{workspace.lower()}-host-{index}', context={'business_owner': owner, 'asset_group': group, 'regulatory': ['SOC 2']}, tags=['group:'+group], workspace=workspace)
    vulnerability = Vulnerability(identity=f'test-{workspace}-{index}', name=f'Plugin {index}', plugin_id=str(index), technical={'severity': severity}, cves=[])
    db.add_all([asset, vulnerability]); db.flush()
    finding = Finding(asset_id=asset.id, vulnerability_id=vulnerability.id, workspace=workspace, source='Manual', observed={'severity': severity}, revision=1)
    db.add(finding); db.flush(); return finding, asset


def add_assessment(db, finding, status='Assessed', revision=1, score=75, method_id=1):
    assessment = Assessment(instance_id=finding.id, revision=revision, methodology_id=method_id, analyst_id=1,
        context={}, notes='', justification='Validated risk context', decision='Remediate', status=status)
    db.add(assessment); db.flush()
    db.add(RiskScore(assessment_id=assessment.id, result={'residual': score, 'residual_level': 'Critical', 'above_appetite': True}))
    db.flush(); return assessment


def add_campaign(db, finding, workspace='Production', status='Active', period_start=date(2026,10,1), period_end=date(2026,10,7), review_status='Pending', name='Weekly review', risk=None):
    campaign = ReviewCampaign(workspace=workspace, name=name, period_start=period_start, period_end=period_end, start_date=period_start,
                due_date=period_end, created_by=1, status=status, scope={}, activated_at=NOW)
    db.add(campaign);db.flush()
    db.add(CampaignReviewer(campaign_id=campaign.id,user_id=1))
    db.add(CampaignFinding(campaign_id=campaign.id, finding_id=finding.id, snapshot_asset_id=finding.asset_id,
           snapshot_asset='Snapshot asset', snapshot_vulnerability='Snapshot vulnerability', snapshot_plugin_id='1000', snapshot_severity='Critical',
           snapshot_risk=risk, snapshot_risk_level='High' if risk else None, snapshot_business_owner='Security business', snapshot_it_owner='Infrastructure',
           snapshot_application_owner='Apps', snapshot_asset_group='Servers', snapshot_tags=['Production'], snapshot_regulatory=['SOC 2'],
           status=review_status, reviewer_id=1 if review_status!='Pending' else None, reviewed_at=NOW if review_status!='Pending' else None,
           decision='No change required' if review_status=='Reviewed' else None, skip_reason='Duplicate' if review_status=='Skipped' else None))
    db.flush();return campaign


def test_latest_assessments_exclude_drafts_stale_closed_and_old_method(db):
    current,_=add_finding(db);add_assessment(db,current,score=60)
    draft,_=add_finding(db);add_assessment(db,draft,status='Assessment In Progress',score=95)
    stale,_=add_finding(db);add_assessment(db,stale,score=95);stale.revision=2
    never,_=add_finding(db)
    closed,_=add_finding(db);add_assessment(db,closed);db.add(FindingWorkflow(finding_id=closed.id,status='Closed',updated_by=1))
    demo,_=add_finding(db,workspace='Demo');add_assessment(db,demo)
    db.flush()
    report=executive_report_data(db,'Production',db.get(User,1),generated=NOW)
    assert report['summary']['total_findings']==4
    assert report['summary']['assessed']==1
    assert report['summary']['risk_exposure']==60
    assert report['assessment_posture']['draft_assessments']==1
    assert report['assessment_posture']['stale_assessments']==1
    assert report['assessment_posture']['never_assessed']==1
    assert report['assessment_posture']['residual_distribution']['Critical']==1
    method=db.get(Methodology,1)
    db.add(Methodology(version='new',configuration=method.configuration));db.flush()
    report=executive_report_data(db,'Production',db.get(User,1),generated=NOW)
    assert report['summary']['assessed']==0 and report['summary']['risk_exposure'] is None
    assert report['assessment_posture']['stale_assessments']==3


def test_report_comparison_direction_and_no_previous_population(db):
    finding,_=add_finding(db)
    add_campaign(db,finding,status='Completed',review_status='Reviewed',risk=40)
    report=executive_report_data(db,'Production',db.get(User,1),generated=NOW)
    assert report['governance']['summary']['review_coverage']==100
    assert all(r['previous'] is None and r['direction']=='n/a' for r in report['comparisons'])
    add_campaign(db,finding,period_start=date(2026,9,24),period_end=date(2026,9,30),review_status='Pending',risk=80)
    report=executive_report_data(db,'Production',db.get(User,1),generated=NOW)
    coverage=next(r for r in report['comparisons'] if r['key']=='review_coverage')
    assert coverage['previous']==0 and coverage['change']==100 and coverage['direction']=='improved' and coverage['arrow']=='up'
    risk=next(r for r in report['comparisons'] if r['key']=='snapshot_risk')
    assert risk['current']==40 and risk['previous']==80 and risk['direction']=='improved' and risk['arrow']=='down'


def test_spanning_campaign_not_compared_against_itself(db):
    finding,_=add_finding(db)
    add_campaign(db,finding,period_start=date(2026,9,1),period_end=date(2026,10,31),review_status='Reviewed')
    report=executive_report_data(db,'Production',db.get(User,1),generated=NOW)
    assert report['governance']['summary']['total']==1
    assert all(r['previous'] is None for r in report['comparisons'])


def test_reports_filters_and_viewer_environment_isolation(db,client):
    finding,_=add_finding(db);production=add_campaign(db,finding,review_status='Reviewed')
    add_campaign(db,finding,status='Completed',review_status='Skipped')
    demo,_=add_finding(db,workspace='Demo');demo_campaign=add_campaign(db,demo,workspace='Demo',status='Completed',review_status='Reviewed')
    db.commit();login(client,'viewer')
    response=client.get('/api/executive-report?period_start=2026-10-01&period_end=2026-10-07&environment=Demo')
    assert response.status_code==200
    data=response.json();assert data['environment']=='Production' and data['governance']['summary']['total']==1
    assert data['governance']['summary']['skipped']==1 and data['governance']['summary']['reviewed']==0
    assert client.get(f'/api/executive-report?campaign_id={production.id}').status_code==404
    assert client.get(f'/api/executive-report?campaign_id={demo_campaign.id}').status_code==404
    assert client.get(f'/api/review-campaigns/{production.id}/export/csv').status_code==404
    assert client.get(f'/api/review-campaigns/{demo_campaign.id}/export/pdf').status_code==404
    login(client,'admin')
    data=client.get('/api/executive-report?period_start=2026-10-01&period_end=2026-10-07&severity=High&business_owner=Security%20business').json()
    assert data['summary']['total_findings']==0 and data['governance']['summary']['total']==0
    assert data['summary']['assessment_coverage'] is None and data['governance']['summary']['review_coverage'] is None


def test_export_snapshot_csv_formulas_and_long_pdf(db,client):
    finding,asset=add_finding(db);campaign=add_campaign(db,finding,review_status='Reviewed',name='<b>Evidence & accountability</b>')
    record=db.scalar(select(CampaignFinding).where(CampaignFinding.campaign_id==campaign.id))
    record.snapshot_asset='=HYPERLINK("bad")'; record.snapshot_vulnerability='<img src="file:///etc/passwd" /> & preserved text'
    record.snapshot_business_owner='Very long owner name & business accountability ' * 10
    record.notes='@dangerous formula';record.evidence_references=['https://example.test/evidence']
    db.add(CampaignAuditEvent(campaign_id=campaign.id,actor_id=1,action='review',details={'previous':'Pending','new':'Reviewed'}))
    db.add(CampaignEvidence(campaign_id=campaign.id,finding_id=finding.id,reference='+malicious',notes='Audit evidence',created_by=1))
    db.flush()
    data,rows,evidence,audit=campaign_evidence_data(db,campaign,campaign_metrics(db,campaign.id))
    payload=campaign_csv(data,rows,evidence,audit).decode('utf-8-sig')
    assert "'=HYPERLINK" in payload and "'@dangerous" in payload and "'+malicious" in payload
    assert 'Snapshot vulnerability' not in payload and 'Very long owner' in payload
    assert safe_csv_cell(' \t=1+1')=="' \t=1+1"
    assert safe_csv_cell('-100')=="'-100" and safe_csv_cell('ordinary')=='ordinary'
    pdf=build_campaign_pdf(data,rows,evidence,audit);assert pdf.startswith(b'%PDF-')
    asset.hostname='live-renamed';db.flush()
    data,rows,_,_=campaign_evidence_data(db,campaign,campaign_metrics(db,campaign.id))
    assert rows[0]['snapshot_asset']=='=HYPERLINK("bad")'
    db.commit();login(client)
    response=client.get(f'/api/review-campaigns/{campaign.id}/export/pdf')
    assert response.status_code==200 and int(response.headers['content-length'])==len(response.content)
    response=client.get(f'/api/review-campaigns/{campaign.id}/export/csv')
    assert response.status_code==200 and int(response.headers['content-length'])==len(response.content)


def test_no_data_pdf_and_content_length_download(client):
    login(client)
    data=client.get('/api/executive-report?period_start=2026-10-01&period_end=2026-10-07').json()
    assert data['summary']['total_findings']==0 and data['summary']['risk_exposure'] is None
    response=client.get('/api/executive-report.pdf')
    assert response.status_code==200 and response.content.startswith(b'%PDF-')
    assert int(response.headers['content-length'])==len(response.content)
    assert response.headers['cache-control']=='no-store'


def test_management_attention_deterministic_thresholds():
    group={'name':'Owner & group','total':5,'reviewed':3,'pending':2,'skipped':0,'review_coverage':60}
    governance={'summary':{'overdue_campaigns':1,'critical_pending':2,'skipped':2,'total':10},
                'campaigns':[{'id':4,'name':'Weekly','metrics':{'total':10,'reviewed':5,'review_coverage':50}}],
                'breakdowns':{'business_owner':[group],'it_owner':[{**group,'total':4}],'asset_group':[group]}}
    comparison=[{'key':'review_coverage','change':-10}]
    output=management_attention(governance,comparison)
    assert output==management_attention(governance,comparison)
    assert [r['severity'] for r in output][:2]==['Critical','Critical']
    assert len(output)==7
    assert not any(r['code']=='it_owner_coverage' for r in output)
    assert any(r['code']=='coverage_drop' for r in output)


def test_executive_golden_population_charts_and_snapshot_stability(db):
    from sqlalchemy import insert
    first,asset=add_finding(db)
    findings=[first]
    for i in range(1,500):
        item=Finding(asset_id=asset.id,vulnerability_id=first.vulnerability_id,workspace='Production',source='Manual',port=i,protocol='tcp',observed={'severity':'Critical'},revision=1)
        db.add(item);findings.append(item)
    db.flush()
    campaign=ReviewCampaign(workspace='Production',name='500 golden',period_start=date(2026,10,1),period_end=date(2026,10,7),start_date=date(2026,10,1),due_date=date(2026,10,7),created_by=1,status='In Progress',scope={},activated_at=NOW)
    db.add(campaign);db.flush()
    db.execute(insert(CampaignFinding),[{'campaign_id':campaign.id,'finding_id':f.id,'snapshot_asset_id':asset.id,'snapshot_asset':'Frozen asset','snapshot_vulnerability':'Frozen plugin','snapshot_plugin_id':'500',
        'snapshot_severity':'Critical' if i<250 else 'High','snapshot_risk':20 if i<200 else None,'snapshot_business_owner':'Business','snapshot_it_owner':'IT','snapshot_application_owner':'App','snapshot_asset_group':'Servers','snapshot_tags':[],
        'snapshot_regulatory':[],'status':'Reviewed' if i<420 else 'Pending' if i<470 else 'Skipped','reviewer_id':1 if i<420 or i>=470 else None,'reviewed_at':NOW if i<420 or i>=470 else None,'notes':'','evidence_references':[]}
        for i,f in enumerate(findings)])
    db.flush()
    report=executive_report_data(db,'Production',db.get(User,1),generated=NOW)
    metrics=report['governance']['summary']
    assert (metrics['total'],metrics['reviewed'],metrics['pending'],metrics['skipped'])==(500,420,50,30)
    assert metrics['review_coverage']==84 and metrics['processed_coverage']==90
    assert metrics['critical_pending']==0 and metrics['campaign_completion_rate']==0
    assert report['governance']['snapshot_exposure']=={'total':500,'scored':200,'risk_exposure':20,'critical_high':500,'score_coverage':40}
    assert report['governance']['trends'][0]['reviewed']==420 and report['governance']['trends'][0]['incomplete'] in (0,1)
    assert report['governance']['risk_trends']==[{'period':'2026-10-01','total':500,'scored':200,'risk_exposure':20,'score_coverage':40}]
    groups=report['governance']['breakdowns']
    assert [r['name'] for r in groups['severity']]==['Critical','High']
    assert groups['severity'][0]['review_coverage']==100 and groups['severity'][1]['review_coverage']==68
    assert groups['business_owner'][0]['total']==500 and groups['business_owner'][0]['review_coverage']==84
    for finding in findings[:100]: db.add(FindingWorkflow(finding_id=finding.id,status='Closed',updated_by=1))
    asset.context={'business_owner':'Changed live owner'};asset.tags=[];db.flush()
    changed=executive_report_data(db,'Production',db.get(User,1),generated=NOW)
    assert changed['summary']['total_findings']==400 and changed['governance']['summary']['total']==500
    assert changed['governance']['breakdowns']['business_owner'][0]['name']=='Business'
