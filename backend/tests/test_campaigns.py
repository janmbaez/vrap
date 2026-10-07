from datetime import date,timedelta
import os
from time import perf_counter
import pytest
from fastapi import HTTPException
from sqlalchemy import select,insert,update,func,event,create_engine,inspect
from app.models import (User,Asset,Vulnerability,Finding,FindingWorkflow,ReviewCampaign,CampaignFinding,
                        CampaignAuditEvent,CampaignEvidence,Assessment,RiskScore)
from app.campaigns import (campaign_metrics,activate,review_rows,get_campaign,transition,
                          governance_analytics,set_reviewers,shifted_date)
from app.campaign_schemas import ReviewInput,BulkReview
from app.query import finding_query
from conftest import login

TODAY=date.today()

def populate(db,n=1,workspace='Production',owner='Finance',tags=None):
    asset=Asset(hostname=f'{workspace}-{n}-{owner}',workspace=workspace,tags=tags or ['group:Servers','location:East'],
                context={'business_owner':owner,'it_owner':'IT Operations','application_owner':'Payments',
                         'asset_group':'Servers','regulatory':['SOC 2']})
    vuln=Vulnerability(identity=f'{workspace}-{n}-{owner}',plugin_id='test-plugin',name='Example vulnerability',
                       technical={'severity':'Critical'},cves=[])
    db.add_all([asset,vuln]);db.flush()
    rows=db.execute(insert(Finding).returning(Finding.id),[{'asset_id':asset.id,'vulnerability_id':vuln.id,
                 'workspace':workspace,'port':i,'protocol':'tcp','source':'Manual','observed':{},
                 'source_record':{},'revision':0} for i in range(n)]).all()
    db.commit()
    return [r.id for r in rows],asset

def make_campaign(db,workspace='Production',creator=1,reviewer=2,scope=None,status='Draft'):
    campaign=ReviewCampaign(name='Weekly review',description='Operational requirement',frequency='weekly',
        workspace=workspace,period_start=TODAY-timedelta(days=6),period_end=TODAY,
        start_date=TODAY-timedelta(days=6),due_date=TODAY+timedelta(days=1),created_by=creator,
        scope=scope or {},status=status)
    db.add(campaign);db.flush();set_reviewers(db,campaign,[reviewer]);db.commit()
    return campaign

def payload(**changes):
    base={'name':'Weekly review','frequency':'weekly','period_start':str(TODAY-timedelta(days=6)),
          'period_end':str(TODAY),'start_date':str(TODAY-timedelta(days=6)),
          'due_date':str(TODAY+timedelta(days=1)),'scope':{},'reviewer_ids':[2]}
    return {**base,**changes}

def test_golden_metrics_and_stable_population(db):
    ids,asset=populate(db,500);campaign=make_campaign(db);admin=db.get(User,1)
    activate(db,campaign,admin);db.commit()
    review_rows(db,campaign,admin,BulkReview(status='Reviewed',decision='No change required',ids=ids[:420]),ids[:420])
    review_rows(db,campaign,admin,BulkReview(status='Skipped',skip_reason='Awaiting validation',ids=ids[420:450]),ids[420:450])
    db.commit();metric=campaign_metrics(db,campaign.id)
    assert (metric['total'],metric['reviewed'],metric['pending'],metric['skipped'])==(500,420,50,30)
    assert metric['review_coverage']==84 and metric['processed_coverage']==90
    db.execute(update(Finding).where(Finding.id.in_(ids[:100])).values(observed={'state':'Fixed','severity':'Low'}))
    asset.context={'business_owner':'Changed owner'};asset.tags=['new-tag'];db.commit()
    metric=campaign_metrics(db,campaign.id)
    assert metric['total']==500
    assert metric['breakdowns']['severity'][0]['name']=='Critical'
    assert metric['breakdowns']['business_owner'][0]['name']=='Finance'
    assert metric['breakdowns']['asset_tag'][0]['total']==500

def test_live_review_does_not_change_remediation_and_audits_previous(db):
    ids,_=populate(db,2);campaign=make_campaign(db);admin=db.get(User,1)
    db.add(FindingWorkflow(finding_id=ids[0],status='In Remediation',owner_id=2,updated_by=2))
    db.commit();activate(db,campaign,admin);db.commit()
    review_rows(db,campaign,admin,ReviewInput(status='Reviewed',decision='Remediation follow-up',notes='Evidence checked',
                                           evidence_references=['https://evidence.example/123']),ids[:1]);db.commit()
    db.expire_all();live=db.get(FindingWorkflow,ids[0])
    assert live.status=='In Remediation' and live.owner_id==2
    assert live.review_state=='Reviewed' and live.reviewed_by==1 and live.reviewed_at
    review_rows(db,campaign,admin,ReviewInput(status='Skipped',skip_reason='Other',notes='Waiting for owner'),ids[:1]);db.commit()
    audits=db.scalars(select(CampaignAuditEvent).where(CampaignAuditEvent.action=='finding_review').order_by(CampaignAuditEvent.id)).all()
    assert audits[-1].details['before'][0]['decision']=='Remediation follow-up'
    assert audits[-1].details['live_review_before'][0]['review_decision']=='Remediation follow-up'
    assert db.scalar(select(func.count(CampaignEvidence.id)))==1

def test_unauthorized_invalid_and_cross_environment_api(client,db):
    ids,_=populate(db,2);campaign=make_campaign(db,creator=1);login(client,'analyst')
    assert client.post(f'/api/review-campaigns/{campaign.id}/activate').status_code==403
    login(client);assert client.post(f'/api/review-campaigns/{campaign.id}/activate').status_code==200
    login(client,'analyst')
    assert client.patch(f'/api/review-campaigns/{campaign.id}/findings/{ids[0]}',json={
        'status':'Reviewed','decision':'No change required'}).status_code==200
    assert client.post(f'/api/review-campaigns/{campaign.id}/complete').status_code==403
    login(client,'viewer')
    assert client.get(f'/api/review-campaigns/{campaign.id}').status_code==404
    assert client.get('/api/review-campaigns').json()['total']==0
    assert client.post('/api/review-campaigns/preview',json={'scope':{}}).status_code==403
    assert client.post('/api/review-campaigns',json=payload()).status_code==403
    login(client,environment='Demo')
    for route in ('','/metrics','/findings','/audit','/evidence'):
        assert client.get(f'/api/review-campaigns/{campaign.id}{route}').status_code==404
    assert client.post('/api/review-campaigns/preview',json={'scope':{}}).json()['total']==0
    assert client.get('/api/review-campaigns/analytics').json()['summary']['total']==0
    assert client.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={
        'selection':'matching','status':'Reviewed','decision':'No change required'}).status_code==404

def test_transitions_validation_and_clone_api(client,db):
    ids,_=populate(db,2);login(client)
    assert client.post('/api/review-campaigns',json=payload(name=' ')).status_code==422
    assert client.post('/api/review-campaigns',json=payload(period_end=str(TODAY-timedelta(days=10)))).status_code==422
    assert client.post('/api/review-campaigns',json=payload(reviewer_ids=[3])).status_code==422
    assert client.post('/api/review-campaigns/preview',json={'scope':{'unknown':'value'}}).status_code==422
    created=client.post('/api/review-campaigns',json=payload());assert created.status_code==201,created.text
    cid=created.json()['id']
    assert client.post(f'/api/review-campaigns/{cid}/complete').status_code==409
    assert client.post(f'/api/review-campaigns/{cid}/activate').status_code==200
    assert client.post(f'/api/review-campaigns/{cid}/activate').status_code==409
    updated=client.patch(f'/api/review-campaigns/{cid}',json={'name':'Updated active review','scope':{}})
    assert updated.status_code==200 and updated.json()['population_unchanged'] is True
    assert client.get(f'/api/review-campaigns/{cid}/findings').json()['total']==2
    assert client.post(f'/api/review-campaigns/{cid}/complete').status_code==409
    assert client.patch(f'/api/review-campaigns/{cid}/findings/{ids[0]}',json={'status':'Reviewed'}).status_code==422
    assert client.patch(f'/api/review-campaigns/{cid}/findings/{ids[0]}',json={'status':'Skipped','skip_reason':'Other'}).status_code==422
    result=client.post(f'/api/review-campaigns/{cid}/bulk-review',json={'selection':'matching','status':'Reviewed',
                         'decision':'No change required','filters':{}})
    assert result.status_code==200,result.text
    assert result.json()['updated']==2
    assert client.post(f'/api/review-campaigns/{cid}/complete').status_code==200
    login(client,'viewer');assert client.get(f'/api/review-campaigns/{cid}').status_code==200
    assert client.get(f'/api/review-campaigns/{cid}/findings').json()['total']==2
    assert client.get('/api/review-campaigns/analytics').json()['summary']['total']==2
    login(client,'analyst');assert client.post(f'/api/review-campaigns/{cid}/reopen',json={'reason':'Recheck evidence'}).status_code==403
    login(client);assert client.post(f'/api/review-campaigns/{cid}/reopen',json={'reason':' '}).status_code==422
    assert client.post(f'/api/review-campaigns/{cid}/reopen',json={'reason':'Recheck evidence'}).status_code==200
    assert client.post(f'/api/review-campaigns/{cid}/archive').status_code==409
    assert client.post(f'/api/review-campaigns/{cid}/complete').status_code==200
    clone=client.post(f'/api/review-campaigns/{cid}/clone',json={});assert clone.status_code==201,clone.text
    assert clone.json()['status']=='Draft' and clone.json()['metrics']['total']==0
    assert clone.json()['period_start']==str(TODAY+timedelta(days=1))
    assert client.post(f'/api/review-campaigns/{cid}/archive').status_code==200
    assert client.post(f'/api/review-campaigns/{cid}/reopen',json={'reason':'Recheck'}).status_code==409

def test_bulk_atomic_matching_scope_and_csrf(client,db):
    ids,_=populate(db,3);campaign=make_campaign(db);login(client)
    assert client.post(f'/api/review-campaigns/{campaign.id}/activate').status_code==200
    result=client.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={
        'selection':'selected','ids':[ids[0],999999],'status':'Reviewed','decision':'No change required'})
    assert result.status_code==404
    assert campaign_metrics(db,campaign.id)['reviewed']==0
    result=client.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={
        'selection':'matching','filters':{'asset_group':'Servers','business_owner':'Finance'},
        'status':'Skipped','skip_reason':'Awaiting validation'})
    assert result.status_code==200,result.text
    assert result.json()['metrics']['review_coverage']==0
    assert result.json()['metrics']['processed_coverage']==100
    client.headers.pop('X-CSRF-Token')
    assert client.post(f'/api/review-campaigns/{campaign.id}/complete').status_code==403

def test_unassigned_analyst_idor_and_evidence_rbac(client,db):
    from app.auth import passwords
    other=User(username='other-analyst',role='Security Analyst',password_hash=passwords.hash('Test-password-123!'))
    db.add(other);db.commit()
    ids,_=populate(db,2);campaign=make_campaign(db);another=make_campaign(db,workspace='Demo')
    login(client);assert client.post(f'/api/review-campaigns/{campaign.id}/activate').status_code==200
    login(client,'other-analyst')
    action={'status':'Reviewed','decision':'No change required'}
    assert client.patch(f'/api/review-campaigns/{campaign.id}/findings/{ids[0]}',json=action).status_code==403
    assert client.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={**action,'ids':ids}).status_code==403
    assert client.post(f'/api/review-campaigns/{campaign.id}/evidence',json={'notes':'Unauthorized'}).status_code==403
    assert client.patch(f'/api/review-campaigns/{campaign.id}',json={'name':'Unauthorized'}).status_code==403
    assert client.post(f'/api/review-campaigns/{campaign.id}/clone',json={}).status_code==403
    assert client.post(f'/api/review-campaigns/{campaign.id}/complete').status_code==403
    login(client,'analyst')
    assert client.post(f'/api/review-campaigns/{campaign.id}/evidence',json={'finding_id':999999,'reference':'doc123'}).status_code==404
    created=client.post(f'/api/review-campaigns/{campaign.id}/evidence',json={'finding_id':ids[0],'reference':'doc123'})
    assert created.status_code==201
    assert client.get(f'/api/review-campaigns/{campaign.id}/evidence').json()['total']==1
    login(client,'viewer')
    for route in ('findings','metrics','audit','evidence','export/csv','export/pdf'):
        assert client.get(f'/api/review-campaigns/{campaign.id}/{route}').status_code==404
    login(client);client.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={**action,'ids':ids})
    assert client.post(f'/api/review-campaigns/{campaign.id}/complete').status_code==200
    login(client,'viewer')
    for route in ('findings','metrics','audit','evidence','export/csv','export/pdf'):
        response=client.get(f'/api/review-campaigns/{campaign.id}/{route}')
        assert response.status_code==200,(route,response.text)
    login(client,'viewer',environment='Demo')
    for route in ('findings','metrics','audit','evidence','export/csv','export/pdf'):
        assert client.get(f'/api/review-campaigns/{campaign.id}/{route}').status_code==404

def test_scope_exact_tags_and_and_filters(db):
    ids,_=populate(db,3,tags=[{'category':'Location','value':'East'},'group:Servers'])
    assert len(db.scalars(finding_query(db,'Production',{'asset_tag':'location:East','asset_group':'Servers',
                      'business_owner':'Finance','severity':'Critical','regulatory':'SOC 2'})).all())==3
    assert not db.scalars(finding_query(db,'Production',{'asset_tag':'location:Eas'})).all()
    assert not db.scalars(finding_query(db,'Production',{'severity':'High','business_owner':'Finance'})).all()
    assert not db.scalars(finding_query(db,'Demo',{})).all()

def test_snapshot_unassigned_filter_and_sort_whitelist_api(client,db):
    ids,asset=populate(db,3);asset.context={'business_owner':'','asset_group':None};db.commit()
    campaign=make_campaign(db);login(client)
    assert client.post(f'/api/review-campaigns/{campaign.id}/activate').status_code==200
    metrics=client.get(f'/api/review-campaigns/{campaign.id}/metrics').json()
    assert metrics['breakdowns']['business_owner'][0]['name']=='Unassigned'
    assert client.get(f'/api/review-campaigns/{campaign.id}/findings?business_owner=Unassigned').json()['total']==3
    sorted_rows=client.get(f'/api/review-campaigns/{campaign.id}/findings?sort=finding_id&direction=desc').json()['items']
    assert [r['finding_id'] for r in sorted_rows]==list(reversed(ids))
    assert client.get(f'/api/review-campaigns/{campaign.id}/findings?sort=secret_sql').status_code==422
    assert client.get('/api/review-campaigns?sort=secret_sql').status_code==422

def test_snapshot_and_bulk_limits_do_not_partially_mutate(client,db,monkeypatch):
    import app.campaigns as service
    ids,_=populate(db,3);campaign=make_campaign(db);login(client)
    monkeypatch.setattr(service,'MAX_SNAPSHOT',2)
    assert client.post(f'/api/review-campaigns/{campaign.id}/activate').status_code==422
    assert campaign_metrics(db,campaign.id)['total']==0
    assert db.get(ReviewCampaign,campaign.id).status=='Draft'
    monkeypatch.setattr(service,'MAX_SNAPSHOT',100000)
    assert client.post(f'/api/review-campaigns/{campaign.id}/activate').status_code==200
    monkeypatch.setattr(service,'MAX_BULK',2)
    assert client.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={
        'selection':'matching','status':'Reviewed','decision':'No change required'}).status_code==422
    assert campaign_metrics(db,campaign.id)['reviewed']==0
    assert db.get(ReviewCampaign,campaign.id).status=='Active'

def test_unassessed_stale_and_inprogress_snapshot_risk_null(db):
    ids,_=populate(db,3);admin=db.get(User,1);campaign=make_campaign(db)
    first=Assessment(instance_id=ids[0],revision=0,methodology_id=1,analyst_id=1,status='Assessed',
                     context={},justification='Saved',decision='Remediation Required')
    stale=Assessment(instance_id=ids[1],revision=0,methodology_id=1,analyst_id=1,status='Assessed',
                     context={},justification='Saved',decision='Remediation Required')
    draft=Assessment(instance_id=ids[2],revision=0,methodology_id=1,analyst_id=1,status='Assessment In Progress',
                     context={},justification='Saved',decision='Remediation Required')
    db.add_all([first,stale,draft]);db.flush()
    for assessment in (first,stale,draft): db.add(RiskScore(assessment_id=assessment.id,result={'residual':74.5,'residual_level':'High'}))
    db.execute(update(Finding).where(Finding.id==ids[1]).values(revision=1));db.commit()
    activate(db,campaign,admin);db.commit()
    rows=db.scalars(select(CampaignFinding).order_by(CampaignFinding.finding_id)).all()
    assert rows[0].snapshot_risk==74.5 and rows[0].snapshot_risk_level=='High'
    assert rows[1].snapshot_risk is None and rows[2].snapshot_risk is None

def test_empty_analytics_no_fake_percent_and_calendar_shift(db):
    metrics=campaign_metrics(db,123)
    assert metrics['total']==0 and metrics['review_coverage'] is None and metrics['processed_coverage'] is None
    analytics=governance_analytics(db,'Production')
    assert analytics['summary']['average_review_coverage'] is None
    assert analytics['summary']['campaign_completion_rate'] is None
    assert analytics['trends']==[]
    assert shifted_date(date(2028,1,31),'monthly')==date(2028,2,29)
    assert shifted_date(date(2026,12,5),'monthly')==date(2027,1,5)

def test_ten_thousand_findings_sql_performance(client,db):
    ids,_=populate(db,10000);campaign=make_campaign(db);admin=db.get(User,1)
    start=perf_counter();activate(db,campaign,admin);db.commit();activation=perf_counter()-start
    calls=[]
    def record(*args): calls.append(args[2])
    event.listen(db.bind,'before_cursor_execute',record)
    try:
        start=perf_counter();metrics=campaign_metrics(db,campaign.id);elapsed_metrics=perf_counter()-start
        assert metrics['total']==10000
        assert len(calls)==8  # total + seven dimensions, independent of population size
    finally: event.remove(db.bind,'before_cursor_execute',record)
    login(client);start=perf_counter()
    listing=client.get('/api/review-campaigns');elapsed_list=perf_counter()-start
    assert listing.status_code==200 and len(listing.json()['items'])==1
    start=perf_counter();report=client.get('/api/executive-report');elapsed_report=perf_counter()-start
    assert report.status_code==200
    print(f'10k SQLite timings: activate={activation:.3f}s list={elapsed_list:.3f}s metrics={elapsed_metrics:.3f}s executive={elapsed_report:.3f}s')

@pytest.mark.skipif(not os.environ.get('VRAP_CAMPAIGN_DATABASE_URL'),reason='Requires a fresh disposable PostgreSQL campaign database')
def test_postgresql_campaign_query_activation_bulk_api():
    from sqlalchemy.orm import sessionmaker
    from fastapi.testclient import TestClient
    from app.db import Base,get_db
    from app.main import app
    from app.auth import passwords
    from app.models import Methodology
    from app.risk.policy import DEFAULT
    from test_migrations import upgrade
    engine=create_engine(os.environ['VRAP_CAMPAIGN_DATABASE_URL'])
    assert not inspect(engine).get_table_names(),'Campaign PostgreSQL smoke requires a fresh disposable database'
    with engine.connect() as connection: upgrade(connection,'head')
    with sessionmaker(engine,expire_on_commit=False)() as session:
        for name,role in [('admin','Administrator'),('analyst','Security Analyst'),('viewer','Viewer')]:
            session.add(User(username=name,role=role,password_hash=passwords.hash('Test-password-123!')))
        session.add(Methodology(version='1.0',configuration=DEFAULT));session.commit()
        ids,asset=populate(session,10000,tags=[{'category':'Location','value':'East'},'group:Servers'])
        # Exact normalized dict tags and fallback group tags use PostgreSQL JSONB functions.
        assert len(session.scalars(finding_query(session,'Production',{'asset_tag':'location:East',
            'asset_group':'Servers','business_owner':'Finance','regulatory':'SOC 2'})).all())==10000
        assert not session.scalars(finding_query(session,'Production',{'asset_tag':'location:Eas'})).all()
        campaign=make_campaign(session);admin=session.get(User,1)
        def override(): yield session
        app.dependency_overrides[get_db]=override
        try:
            with TestClient(app) as testclient:
                login(testclient)
                started=perf_counter()
                result=testclient.post(f'/api/review-campaigns/{campaign.id}/activate')
                elapsed_activation=perf_counter()-started
                assert result.status_code==200,result.text
                assert result.json()['metrics']['total']==10000
                initial=session.scalar(select(func.count(CampaignFinding.id)))
                # Invalid all-or-none selected IDs must leave every evidence/review state intact.
                result=testclient.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={
                    'status':'Reviewed','decision':'No change required','ids':[ids[0],999999]})
                assert result.status_code==404
                assert campaign_metrics(session,campaign.id)['reviewed']==0
                started=perf_counter()
                result=testclient.post(f'/api/review-campaigns/{campaign.id}/bulk-review',json={
                    'status':'Reviewed','decision':'No change required','selection':'matching',
                    'filters':{'asset_tag':'location:East','asset_group':'Servers'}})
                elapsed_bulk=perf_counter()-started
                assert result.status_code==200,result.text
                assert result.json()['metrics']['reviewed']==10000
                assert session.scalar(select(func.count(CampaignFinding.id)))==initial
                started=perf_counter();listing=testclient.get('/api/review-campaigns?sort=due_date&direction=asc')
                elapsed_list=perf_counter()-started
                assert listing.status_code==200 and listing.json()['total']==1
                assert testclient.get(f'/api/review-campaigns/{campaign.id}/findings?sort=risk&direction=desc').status_code==200
                started=perf_counter();metrics=testclient.get(f'/api/review-campaigns/{campaign.id}/metrics')
                elapsed_metrics=perf_counter()-started
                assert metrics.status_code==200 and metrics.json()['processed_coverage']==100
                started=perf_counter();executive=testclient.get('/api/executive-report')
                elapsed_report=perf_counter()-started
                assert executive.status_code==200,executive.text
                print(f'10k PostgreSQL timings: activate={elapsed_activation:.3f}s bulk={elapsed_bulk:.3f}s list={elapsed_list:.3f}s metrics={elapsed_metrics:.3f}s executive={elapsed_report:.3f}s')
        finally: app.dependency_overrides.clear()
    engine.dispose()
