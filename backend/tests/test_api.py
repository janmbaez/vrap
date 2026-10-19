from copy import deepcopy
from time import monotonic
import pytest
from sqlalchemy import select
from cryptography.fernet import Fernet
from app.config import settings
from app.models import Assessment,Asset,AssetRegulatoryScope,Audit,Finding,FindingWorkflow,ImportRow,IntegrationSettings,SyncJob,User,Vulnerability,RiskScore,Methodology,now
from app.api.tenable import recover_stale_syncs
from app.risk.policy import DEFAULT
from conftest import login
DATA={'hostname':'TEST-01','name':'Synthetic RCE','plugin_id':'test-100','severity':'Critical','cvss':9.8,'vpr':9.4}
CONTEXT={'asset_criticality':'Critical','business_criticality':'High','data_classification':'Confidential','regulatory':['SOC 2'],'environment':'Production','exposure':'Internal'}
def create(client):
    r=client.post('/api/findings',json=DATA); assert r.status_code==201,r.text
    return r.json()
def body(f): return {'expected_revision':f['revision'],'methodology_id':f['methodology_id'],'context':CONTEXT,'controls':[],'justification':'Reviewed business context','decision':'Remediation Required','status':'Assessed'}
def test_api_security_headers_are_restrictive(client):
    response = client.get('/api/health')
    assert response.headers['content-security-policy'] == "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    assert response.headers['cross-origin-opener-policy'] == 'same-origin'
    assert response.headers['cross-origin-resource-policy'] == 'same-site'
    assert response.headers['permissions-policy'] == 'camera=(), geolocation=(), microphone=()'
    assert response.headers['x-permitted-cross-domain-policies'] == 'none'


def test_auth_rbac_csrf(client):
    assert client.get('/api/findings').status_code==401
    login(client,'viewer'); assert client.get('/api/findings').status_code==200
    assert client.post('/api/findings',json=DATA).status_code==403
    assert client.get('/api/users').status_code==403
    login(client); client.headers.pop('X-CSRF-Token')
    assert client.post('/api/findings',json=DATA).status_code==403
    assert client.post('/api/auth/login',headers={'Origin':'https://evil.example'},json={'username':'admin','password':'Test-password-123!'}).status_code==403

def test_stale_tenable_job_is_recovered_without_touching_active_job(db):
    from datetime import timedelta
    stale = SyncJob(kind='vulnerabilities', workspace='Production', started_at=now()-timedelta(hours=2))
    active = SyncJob(kind='assets', workspace='Production', started_at=now())
    db.add_all([stale, active]); db.commit()
    recovered = recover_stale_syncs(db, 'Production')
    assert [job.id for job in recovered] == [stale.id]
    db.refresh(stale); db.refresh(active)
    assert stale.status == 'Failed' and stale.counts['recovered_stale_job'] is True
    assert active.status == 'Running'

def test_administrator_can_change_role_and_audit_it(client, db):
    login(client)
    analyst = client.get('/api/users').json()[1]
    changed = client.patch(f"/api/users/{analyst['id']}/role", json={'role':'Viewer'})
    assert changed.status_code == 200 and changed.json()['role'] == 'Viewer'
    audit = db.scalar(select(Audit).where(Audit.action == 'user.role_changed'))
    assert audit.details['before'] == 'Security Analyst' and audit.details['after'] == 'Viewer'
    login(client, 'viewer')
    assert client.patch(f"/api/users/{analyst['id']}/role", json={'role':'Administrator'}).status_code == 403

def test_administrator_can_clear_workspace_operational_data(client, db):
    login(client)
    create(client)
    assert client.get('/api/data-quality').json()['findings'] == 1
    assert client.post('/api/data-quality/clear-operational-data', json={'confirmation':'CLEAR'}).status_code == 422
    cleared = client.post('/api/data-quality/clear-operational-data', json={'confirmation':'CLEAR DATA'})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()['cleared']['findings'] == 1
    quality = client.get('/api/data-quality').json()
    assert quality['findings'] == 0 and quality['assets'] == 0 and quality['can_clear'] is True
    assert db.scalar(select(Audit).where(Audit.action == 'workspace.operational_data_cleared')) is not None

def test_administrator_can_run_duplicate_cleanup_from_data_quality(client, db):
    login(client)
    assert client.get('/api/data-quality').json()['duplicates'] == {
        'duplicate_findings': 0, 'duplicates_protected': 0, 'duplicate_groups': 0,
    }
    assert client.post('/api/data-quality/remove-duplicates', json={'confirmation':'REMOVE'}).status_code == 422
    response = client.post('/api/data-quality/remove-duplicates', json={'confirmation':'REMOVE DUPLICATES'})
    assert response.status_code == 200, response.text
    assert response.json()['duplicates_removed'] == 0
    assert db.scalar(select(Audit).where(Audit.action == 'data_quality.duplicates_removed')) is not None

def test_closed_workflow_is_visible_and_excluded_from_active_dashboard(client):
    login(client)
    finding = create(client)
    closed = client.put(f"/api/findings/{finding['id']}/workflow", json={'owner_id':None, 'status':'Closed'})
    assert closed.status_code == 200, closed.text
    listed = client.get('/api/findings?status=Closed').json()
    assert listed['total'] == 1 and listed['items'][0]['workflow_status'] == 'Closed'
    assert client.get('/api/dashboard').json()['total'] == 0

def test_final_administrator_cannot_be_demoted(client, db):
    db.query(User).filter_by(username='analyst').update({'role':'Viewer'})
    db.commit(); login(client)
    admin_id = client.get('/api/users').json()[0]['id']
    assert client.patch(f"/api/users/{admin_id}/role", json={'role':'Viewer'}).status_code == 409

def test_atomic_revision_and_replay(client,db):
    login(client); f=create(client); payload=body(f)
    preview=client.post(f"/api/findings/{f['id']}/preview",json=payload); assert preview.status_code==200,preview.text
    saved=client.post(f"/api/findings/{f['id']}/assessments",json=payload); assert saved.status_code==201,saved.text
    assert saved.json()['revision']==1
    assert client.post(f"/api/findings/{f['id']}/assessments",json=payload).status_code==409
    assert len(db.scalars(select(Assessment)).all())==1
    h=client.get(f"/api/findings/{f['id']}/history").json()
    assert h[0]['score']['residual']==preview.json()['residual']
    assert h[0]['score']['inputs']['technical']['cvss']==9.8
    assert db.scalar(select(Audit).where(Audit.action=='assessment.saved'))

def test_dashboard_and_executive_report_share_current_assessment_definition(client):
    login(client)
    finding=create(client)
    assert client.post(f"/api/findings/{finding['id']}/assessments",json=body(finding)).status_code==201
    dashboard=client.get('/api/dashboard').json()
    report=client.get('/api/executive-report').json()
    assert dashboard['completed']==1 and report['summary']['assessed']==1
    config=deepcopy(DEFAULT); config['appetite']='Critical'
    assert client.post('/api/methodologies',json={'version':'currentness-test','configuration':config}).status_code==201
    dashboard=client.get('/api/dashboard').json()
    report=client.get('/api/executive-report').json()
    assert dashboard['completed']==0 and report['summary']['assessed']==0
    assert report['assessment_posture']['stale_assessments']==1

def test_methodology_immutable(client):
    login(client);f=create(client);payload=body(f)
    assert client.post(f"/api/findings/{f['id']}/assessments",json=payload).status_code==201
    old=client.get(f"/api/findings/{f['id']}/history").json(); config=deepcopy(DEFAULT);config['appetite']='Critical'
    assert client.post('/api/methodologies',json={'version':'2.0','configuration':config}).status_code==201
    assert client.post(f"/api/findings/{f['id']}/preview",json=payload).status_code==409
    assert client.get(f"/api/findings/{f['id']}/history").json()==old
    assert client.get(f"/api/findings/{f['id']}").json()['reassessment_required']
def test_missing_context_and_acceptance(client):
    login(client,'analyst');f=create(client);payload=body(f);payload['context']={}
    assert client.post(f"/api/findings/{f['id']}/assessments",json=payload).status_code==422
    payload['context']=CONTEXT;payload.update(decision='Risk Accepted',status='Risk Accepted')
    assert client.post(f"/api/findings/{f['id']}/assessments",json=payload).status_code==403

def test_import_duplicates_validation_audit(client,db):
    login(client);content=b'Host,Plugin,CVSS\nserver-a,RCE,9.8\nserver-a,RCE,9.8\nserver-b,RCE,44\n'
    r=client.post('/api/imports/preview',files={'file':('data.csv',content,'text/csv')});assert r.status_code==200,r.text
    id=r.json()['id'];payload={'mapping':{'hostname':'Host','name':'Plugin','cvss':'CVSS'}}
    r=client.post(f'/api/imports/{id}/validate',json=payload);assert r.status_code==200,r.text
    assert r.json()['counts']=={'detected':3,'valid':1,'rejected':1,'duplicates':1}
    r=client.post(f'/api/imports/{id}/commit',json=payload);assert r.status_code==200,r.text
    assert r.json()['counts']['imported']==1
    assert client.post(f'/api/imports/{id}/commit',json=payload).status_code==409
    row=db.scalar(select(ImportRow).where(ImportRow.instance_id.is_not(None)))
    assert row.original=={'Host':'server-a','Plugin':'RCE','CVSS':'9.8'}

def test_tenable_csv_headers_auto_map(client):
    login(client)
    headers='asset.display_ipv4_address,asset.host_name,asset.name,definition.cve,definition.exploitability_ease,definition.id,definition.name,definition.vpr.drivers_on_cisa_kev,definition.vpr.score,first_observed,last_seen,port,protocol,severity\n'
    row='10.0.0.1,,server-1,CVE-2026-1,AVAILABLE,123,Finding,false,8.4,2026-09-29T08:06:52.386Z,2026-09-30T04:18:20.359Z,443,TCP,High\n'
    response=client.post('/api/imports/preview',files={'file':('tenable.csv',(headers+row).encode(),'text/csv')})
    assert response.status_code==200,response.text
    mapping=response.json()['mapping']
    assert mapping['hostname']=='asset.name' and mapping['name']=='definition.name'
    assert mapping['plugin_id']=='definition.id' and mapping['first_seen']=='first_observed'
    assert mapping['last_seen']=='last_seen' and mapping['protocol']=='protocol'
def test_bad_upload_logout(client):
    login(client)
    # Multipart requests above 60 MiB are allowed through the request gate;
    # the deliberately invalid content is then rejected by the file parser.
    over_sixty=client.post('/api/imports/preview',headers={'Content-Length':str(61*1024*1024)},files={'file':('bad.csv',b'x','text/csv')})
    assert over_sixty.status_code==200 and '105 MiB' not in over_sixty.text
    assert client.post('/api/imports/preview',headers={'Content-Length':str(106*1024*1024)},files={'file':('bad.csv',b'x','text/csv')}).status_code==413
    assert client.post('/api/imports/preview',files={'file':('evil.exe',b'x','application/octet-stream')}).status_code==422
    assert client.post('/api/auth/logout').status_code==200
    assert client.get('/api/findings').status_code==401

def test_assessment_group_detail_does_not_leak_between_workspaces(client):
    login(client, environment='Production')
    finding=create(client)
    group_id=next(item for item in client.get('/api/assessment-groups').json()['items'] if item['plugin_id']=='test-100')['id']
    assert group_id == finding['id'] or group_id > 0
    assert client.post('/api/auth/logout').status_code==200
    login(client, environment='Demo')
    assert client.get(f'/api/assessment-groups/{group_id}').status_code==404

def test_environment_isolation(client):
    login(client, environment='Demo'); demo=create(client)
    assert client.get('/api/auth/me').json()['environment']=='Demo'
    assert client.get('/api/findings').json()['total']==1
    assert client.post('/api/auth/logout').status_code==200
    login(client, environment='Production')
    assert client.get('/api/findings').json()['total']==0
    production=create(client)
    assert production['id'] != demo['id']
    assert client.get('/api/findings').json()['total']==1

def test_asset_rule_applies_context_and_default_controls(client):
    login(client)
    rule={
        'name':'Critical data center subnet','priority':10,'active':True,'match_type':'CIDR','match_value':'10.44.0.0/16',
        'context':{'asset_criticality':'Critical','business_criticality':'Critical','data_classification':'Restricted','regulatory':['SOX'],
                   'business_owner':'Finance','it_owner':'Infrastructure Operations','application_owner':'ERP Support'},
        'controls':[{'name':'Network segmentation','effectiveness':.35,'applicable':True,'validated':False,'evidence':'','notes':'Inherited baseline','design_maturity':3,'operating_effectiveness':3}],
    }
    assert client.post('/api/asset-rules',json=rule).status_code==201
    created=client.post('/api/findings',json={**DATA,'hostname':'rule-target','ip':'10.44.2.10','plugin_id':'rule-1'}).json()
    assert created['context']['asset_criticality']=='Critical'
    assert created['context']['data_classification']=='Restricted'
    assert created['context']['business_owner']=='Finance'
    assert created['context']['it_owner']=='Infrastructure Operations'
    assert created['context']['application_owner']=='ERP Support'
    assert created['controls'][0]['name']=='Network segmentation'
    assert created['controls'][0]['validated'] is False
    assert created['applied_rules'][0]['name']=='Critical data center subnet'

def test_asset_rule_hostname_prefix_matches_wildcard_or_plain_prefix(client):
    login(client)
    rule={'name':'AWS servers','priority':10,'active':True,'match_type':'Hostname prefix','match_value':'aws*',
          'context':{'environment':'Production','asset_type':'Cloud server'},'controls':[]}
    assert client.post('/api/asset-rules',json=rule).status_code==201
    matching=client.post('/api/findings',json={**DATA,'hostname':'aws-api-01','ip':'10.44.2.10','plugin_id':'aws-prefix'}).json()
    non_matching=client.post('/api/findings',json={**DATA,'hostname':'prod-aws-api-01','ip':'10.44.2.11','plugin_id':'aws-prefix-other'}).json()
    assert matching['context']['environment']=='Production'
    assert matching['context']['asset_type']=='Cloud server'
    assert not non_matching['applied_rules']

def test_disabling_or_deleting_rule_removes_its_inherited_effects(client):
    login(client)
    rule={'name':'AWS inherited context','priority':10,'active':True,'match_type':'Hostname prefix','match_value':'aws',
          'context':{'environment':'Production','asset_type':'Cloud server'},'controls':[]}
    created_rule=client.post('/api/asset-rules',json=rule).json()
    finding=client.post('/api/findings',json={**DATA,'hostname':'aws-api-02','ip':'10.44.2.12','plugin_id':'aws-cleanup'}).json()
    assert finding['context']['environment']=='Production'
    disabled={**rule,'active':False}
    response=client.put(f"/api/asset-rules/{created_rule['id']}",json=disabled)
    assert response.status_code==200 and response.json()['assets_reconciled']==1
    cleaned=client.get(f"/api/findings/{finding['id']}").json()
    assert cleaned['context'].get('environment') is None
    assert cleaned['context'].get('asset_type') is None
    assert cleaned['applied_rules']==[]
    # Deleting an active rule performs the same reconciliation.
    replacement={**rule,'name':'AWS inherited context replacement'}
    replacement_id=client.post('/api/asset-rules',json=replacement).json()['id']
    assert client.post(f"/api/asset-rules/{replacement_id}/apply").status_code==200
    deleted=client.delete(f"/api/asset-rules/{replacement_id}")
    assert deleted.status_code==200 and deleted.json()['assets_reconciled']==1
    assert client.get(f"/api/findings/{finding['id']}").json()['applied_rules']==[]

def test_disabling_rule_preserves_a_manual_context_value(client):
    login(client)
    rule={'name':'Production AWS','priority':10,'active':True,'match_type':'Hostname prefix','match_value':'aws',
          'context':{'environment':'Production','regulatory':['PCI DSS']},'controls':[]}
    rule_id=client.post('/api/asset-rules',json=rule).json()['id']
    finding=client.post('/api/findings',json={**DATA,'hostname':'aws-finance-01','ip':'10.44.2.20','plugin_id':'aws-finance'}).json()
    asset_id=finding['asset']['id']
    changed=client.put(f'/api/assets/{asset_id}',json={'environment':'Production','regulatory':['PCI DSS','SOC 2']})
    assert changed.status_code==200
    assert changed.json()['context_provenance']['regulatory']['source_system']=='asset_management'
    disabled=client.put(f'/api/asset-rules/{rule_id}',json={**rule,'active':False})
    assert disabled.status_code==200
    refreshed=client.get(f"/api/findings/{finding['id']}").json()
    assert refreshed['context']['environment']=='Production'
    assert refreshed['context']['regulatory']==['PCI DSS','SOC 2']

def test_asset_context_is_authoritative_and_flags_reassessment(client):
    login(client); finding=create(client); payload=body(finding)
    saved=client.post(f"/api/findings/{finding['id']}/assessments",json=payload).json()
    changed=client.put(f"/api/assets/{saved['asset']['id']}",json={'asset_criticality':'Low','regulatory':['SOX']})
    assert changed.status_code==200 and changed.json()['findings_flagged']==1
    refreshed=client.get(f"/api/findings/{finding['id']}").json()
    assert refreshed['context']['asset_criticality']=='Low'
    assert refreshed['context']['regulatory']==['SOX']
    assert refreshed['reassessment_required'] is True

def test_regulatory_scope_memberships_are_additive_and_governed(client, db):
    login(client)
    created = client.post('/api/assets', json={
        'hostname': 'scope-asset', 'regulatory': ['PCI DSS'],
    })
    assert created.status_code == 201, created.text
    asset_id = created.json()['id']
    membership = db.scalar(select(AssetRegulatoryScope).where(
        AssetRegulatoryScope.asset_id == asset_id,
        AssetRegulatoryScope.scope == 'PCI DSS',
    ))
    assert membership and membership.active and membership.source_system == 'asset_management'

    expanded = client.put(f'/api/assets/{asset_id}', json={
        'regulatory': ['PCI DSS', 'SOC 2'],
    })
    assert expanded.status_code == 200, expanded.text
    assert expanded.json()['context']['regulatory'] == ['PCI DSS', 'SOC 2']
    assert db.scalar(select(AssetRegulatoryScope).where(
        AssetRegulatoryScope.asset_id == asset_id,
        AssetRegulatoryScope.scope == 'SOC 2',
        AssetRegulatoryScope.active.is_(True),
    )) is not None

    removed = client.put(f'/api/assets/{asset_id}', json={'regulatory': ['PCI DSS']})
    assert removed.status_code == 409
    assert 'governed classification change request' in removed.json()['detail']


def test_assets_are_paginated_searchable_and_support_crud(client):
    login(client)
    first = create(client)
    second = client.post('/api/findings', json={**DATA, 'hostname':'TEST-02', 'ip':'10.0.0.2'}).json()
    page = client.get('/api/assets?limit=1&offset=0').json()
    assert page['total'] == 2 and len(page['items']) == 1
    assert client.get('/api/assets?q=10.0.0.2&limit=50').json()['items'][0]['hostname'] == 'test-02'
    changed = client.put(f"/api/assets/{first['asset']['id']}", json={'hostname':'RENAMED-01','ip':'10.0.0.10','os':'Linux','tags':['tier:1'],'business_owner':'Risk'} )
    assert changed.status_code == 200, changed.text
    assert changed.json()['hostname'] == 'renamed-01' and changed.json()['ip'] == '10.0.0.10'
    added = client.post('/api/assets', json={'hostname':'MANUAL-01','ip':'10.0.0.99','os':'Appliance','tags':['manual']})
    assert added.status_code == 201, added.text
    removed = client.delete(f"/api/assets/{second['asset']['id']}")
    assert removed.status_code == 200 and removed.json()['findings_deleted'] == 1
    assert client.get(f"/api/findings/{second['id']}").status_code == 404

def test_assessment_groups_plugin_assets_and_bulk_context(client):
    login(client)
    first=create(client)
    second=client.post('/api/findings',json={**DATA,'hostname':'TEST-02'}).json()
    other=client.post('/api/findings',json={**DATA,'hostname':'TEST-01','plugin_id':'test-other','name':'Other finding'}).json()
    groups=client.get('/api/assessment-groups').json()
    group=next(item for item in groups['items'] if item['plugin_id']=='test-100')
    assert group['assets']==2 and group['findings']==2 and group['assessed']==0
    detail=client.get(f"/api/assessment-groups/{group['id']}").json()
    assert {item['finding_id'] for item in detail['items']}=={first['id'],second['id']}
    protected=client.put(f"/api/assessment-groups/{group['id']}/assets",json={'asset_criticality':'Critical'})
    assert protected.status_code==422
    updated=client.put(f"/api/assessment-groups/{group['id']}/assets",json={'asset_group':'Windows fleet'})
    assert updated.status_code==200 and updated.json()=={'assets_updated':2,'findings_flagged':3}
    assert client.get(f"/api/findings/{other['id']}").json()['context']['asset_group']=='Windows fleet'

def test_assessment_recommendations_are_bounded_and_workspace_scoped(client):
    login(client)
    create(client)
    client.post('/api/findings', json={**DATA, 'hostname': 'TEST-02', 'plugin_id': 'test-101', 'name': 'Another finding'})
    response = client.get('/api/assessment-recommendations?limit=20')
    assert response.status_code == 200
    payload = response.json()
    assert len(payload['groups']) <= 20
    assert payload['target_groups'] == len(payload['groups'])
    assert payload['total_compatible_groups'] >= 1
    assert all(group['findings'] >= 1 and group['plugins'] for group in payload['groups'])

def test_assessment_recommendations_large_dataset_is_bounded_and_fast(client, db):
    """Acceptance guard for the recommendation query at the expected plugin scale."""
    login(client)
    assets = [Asset(hostname=f'PERF-{index:04d}', workspace='Production') for index in range(2725)]
    db.add_all(assets)
    db.flush()
    vulnerabilities = [Vulnerability(identity=f'perf-{index}', plugin_id=f'perf-{index}',
                                      name=f'Performance plugin {index}',
                                      technical={'severity': 'Medium', 'remediation_action': f'Action {index % 10}',
                                                 'software_family': f'Family {index % 5}', 'technical_lane': 'server'})
                       for index in range(2725)]
    db.add_all(vulnerabilities)
    db.flush()
    findings = [Finding(asset_id=assets[index].id, vulnerability_id=vulnerabilities[index].id,
                        source='synthetic', observed={'severity': 'Medium'}, workspace='Production')
                for index in range(2725)]
    db.add_all(findings)
    db.commit()
    started = monotonic()
    response = client.get('/api/assessment-recommendations?limit=20')
    elapsed = monotonic() - started
    assert response.status_code == 200, response.text
    payload = response.json()
    assert len(payload['groups']) <= 20
    assert payload['total_compatible_groups'] == 10
    assert elapsed < 3.0
    categories = client.get('/api/assessment-categories')
    assert categories.status_code == 200
    category_payload = categories.json()
    assert category_payload['plugin_count'] == 2725
    assert category_payload['category_count'] <= 20
    assert sum(len(category['plugin_ids']) for category in category_payload['categories']) == 2725

def test_smart_category_bulk_questionnaire_supports_outcomes_and_multiple_plugins(client):
    login(client)
    first = create(client)
    second = client.post('/api/findings', json={**DATA, 'hostname':'TEST-02', 'plugin_id':'test-101'}).json()
    category = next(c for c in client.get('/api/assessment-categories').json()['categories'] if first['plugin_id'] in c['plugin_ids'] and second['plugin_id'] in c['plugin_ids'])
    technical = {'applicability':'Applicable','attack_prerequisite':'Low','exploit_validation':'Not observed','remediation_feasibility':'Available','internet_exposure':'None'}
    common = {'context':{},'controls':[],'owner_id':None,'workflow_status':'Investigating','status':'Assessed','decision':'Remediation Required','justification':'Reviewed evidence','active_only':True,'questionnaire_version':'1.0-provisional','answers':technical,'scenario_evidence':['scan://category'],'scenario_notes':'Shared evidence validated for the category'}
    preview = client.post(f"/api/assessment-categories/{category['key']}/bulk-assess", json={**common,'dry_run':True})
    assert preview.status_code == 200 and preview.json()['findings'] >= 2 and preview.json()['plugin_count'] >= 2
    not_applicable = {**common,'answers':{'applicability':'Not applicable'},'decision':'Not Applicable','status':'Not Applicable','scenario_evidence':['ticket://na'],'scenario_notes':'Evidence confirms this is not applicable','justification':'Governed determination','dry_run':True}
    assert client.post(f"/api/assessment-categories/{category['key']}/bulk-assess", json=not_applicable).status_code == 200
    needs_validation = {**common,'answers':{'applicability':'Needs validation'},'decision':'Needs Further Assessment','status':'Pending Validation','dry_run':True}
    assert client.post(f"/api/assessment-categories/{category['key']}/bulk-assess", json=needs_validation).status_code == 200
    confirmed = client.post(f"/api/assessment-categories/{category['key']}/bulk-assess", json={**common,'dry_run':False,'idempotency_key':'category-multi-plugin-test'})
    assert confirmed.status_code == 200 and confirmed.json()['total'] >= 2

def test_protected_asset_context_rejects_a_stale_editor_version(client):
    login(client)
    finding=create(client)
    asset_id=finding['asset']['id']
    first=client.put(f'/api/assets/{asset_id}',json={'asset_criticality':'High','expected_context_version':1})
    assert first.status_code==200 and first.json()['context_version']==2
    stale=client.put(f'/api/assets/{asset_id}',json={'asset_criticality':'Critical','expected_context_version':1})
    assert stale.status_code==409
    current=client.get('/api/assets').json()['items'][0]
    assert current['context']['asset_criticality']=='High' and current['context_version']==2

def test_rules_and_ingest_cannot_overwrite_existing_asset_classification(client):
    login(client)
    first=create(client)
    asset_id=first['asset']['id']
    protected=client.put(f'/api/assets/{asset_id}',json={'asset_criticality':'Critical','regulatory':['PCI DSS','SOC 2'],'environment':'Production'})
    assert protected.status_code==200
    assert protected.json()['context_version']==2
    assert protected.json()['context_provenance']['regulatory']['source_system']=='asset_management'
    rule={'name':'Unsafe source proposal','priority':1,'active':True,'match_type':'Hostname prefix','match_value':'test-',
          'context':{'asset_criticality':'Low','regulatory':['None'],'environment':'Development'},'controls':[]}
    assert client.post('/api/asset-rules',json=rule).status_code==201
    second=client.post('/api/findings',json={**DATA,'plugin_id':'test-rule-proposal','name':'Rule proposal'}).json()
    assert second['context']['asset_criticality']=='Critical'
    assert second['context']['regulatory']==['PCI DSS','SOC 2']
    assert second['context']['environment']=='Production'

def test_tenable_configuration_is_encrypted_and_redacted(client,db):
    login(client)
    payload={'enabled':True,'access_key':'access-private','secret_key':'secret-private','base_url':'https://cloud.tenable.com'}
    response=client.put('/api/tenable',json=payload)
    assert response.status_code==200,response.text
    state=db.get(IntegrationSettings,1)
    assert 'access-private' not in state.access_key_encrypted
    assert 'secret-private' not in state.secret_key_encrypted
    encrypted=Fernet(settings().credential_encryption_key.encode())
    assert encrypted.decrypt(state.access_key_encrypted.encode()).decode()=='access-private'
    status=client.get('/api/tenable').json()
    assert status['configured'] and status['access_key_set'] and status['secret_key_set']
    assert 'access_key' not in status and 'secret_key' not in status

def test_governance_workflow_template_exception_control_and_reporting(client):
    login(client); first=create(client)
    second=client.post('/api/findings',json={**DATA,'hostname':'TEST-02'}).json()
    group=next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    template={'owner_id':1,'status':'Investigating','notes':'Use the vendor remediation guidance','justification':'Shared plugin behavior reviewed across affected assets','decision':'Remediation Required','controls':[]}
    assert client.put(f"/api/assessment-groups/{group['id']}/template",json=template).status_code==200
    applied=client.post(f"/api/assessment-groups/{group['id']}/template/apply",json={})
    assert applied.status_code==200 and applied.json()['findings_assessed']==2
    assert client.get(f"/api/findings/{first['id']}").json()['status']=='Assessment In Progress'
    workflow=client.put(f"/api/findings/{second['id']}/workflow",json={'owner_id':2,'status':'Remediation Planned'})
    assert workflow.status_code==200 and workflow.json()['owner_id']==2
    login(client,'analyst')
    exception=client.post(f"/api/findings/{first['id']}/exceptions",json={'justification':'Temporary operational dependency requires documented acceptance','evidence':'Change record CAB-42','expires_at':'2030-01-01T00:00:00Z','review_frequency_days':30})
    assert exception.status_code==201
    login(client)
    assert client.put(f"/api/exceptions/{exception.json()['id']}",json={'status':'Approved'}).status_code==200
    control=client.post('/api/controls',json={'name':'Privileged access review','description':'Quarterly review','evidence_requirements':'Approved review record','mappings':{'NIST':['PR.AA-05']},'design_maturity':3,'operating_effectiveness':4,'active':True})
    assert control.status_code==201
    assert client.get('/api/controls').json()[0]['name']=='Privileged access review'
    assert client.get('/api/data-quality').status_code==200
    assert client.get('/api/operations').status_code==200
    report=client.get('/api/executive-report')
    assert report.status_code==200 and report.json()['summary']['total_findings']==2
    pdf=client.get('/api/executive-report.pdf')
    assert pdf.status_code==200 and pdf.headers['content-type']=='application/pdf'
    assert pdf.content.startswith(b'%PDF-') and len(pdf.content)>3000

def test_plugin_template_versions_preview_and_preserve_workflow(client):
    login(client); finding = create(client)
    group=next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    saved=client.put(f"/api/assessment-groups/{group['id']}/template",json={
        'owner_id':2,'status':'Closed','notes':'Shared rationale','justification':'Template review completed',
        'decision':'Remediation Required','technical_rationale':'Same vendor remediation applies',
        'applicability':{},'controls':[]})
    assert saved.status_code == 200
    template=client.get(f"/api/assessment-groups/{group['id']}/template").json()
    assert template['template_version']==1 and len(template['revisions'])==1
    assert client.put(f"/api/findings/{finding['id']}/workflow",json={'owner_id':3,'status':'Investigating'}).status_code==200
    preview=client.post(f"/api/assessment-groups/{group['id']}/template/apply?preview=true")
    assert preview.status_code==200 and preview.json()['changed'] + preview.json()['unchanged'] >= 1
    applied=client.post(f"/api/assessment-groups/{group['id']}/template/apply")
    assert applied.status_code==200
    detail=client.get(f"/api/findings/{finding['id']}").json()
    assert detail['workflow_status']=='Investigating' and detail['asset']['hostname']
    replay=client.post(f"/api/assessment-groups/{group['id']}/template/apply")
    assert replay.status_code==200 and replay.json()['skipped'] >= 1
def test_bulk_plugin_assessment_preserves_asset_authoritative_context(client):
    login(client)
    first=create(client)
    second=client.post('/api/findings',json={**DATA,'hostname':'TEST-02'}).json()
    first_asset=client.get(f"/api/findings/{first['id']}").json()['asset']['id']
    second_asset=client.get(f"/api/findings/{second['id']}").json()['asset']['id']
    assert client.put(f'/api/assets/{first_asset}',json={'asset_criticality':'Critical','regulatory':['PCI DSS','SOC 2'],'environment':'Production'}).status_code==200
    assert client.put(f'/api/assets/{second_asset}',json={'asset_criticality':'Low','regulatory':['SOC 2'],'environment':'Test'}).status_code==200
    group=next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    submitted={**CONTEXT,'asset_criticality':'Low','regulatory':['None'],'environment':'Development'}
    response=client.post(f"/api/assessment-groups/{group['id']}/bulk-assess",json={
        'context':submitted,'controls':[],'owner_id':1,'workflow_status':'Risk Review','notes':'Shared technical scenario',
        'justification':'Preserve approved asset context','decision':'Remediation Required','status':'Assessed'})
    assert response.status_code==200,response.text
    first_assessment=client.get(f"/api/findings/{first['id']}/history").json()[0]
    second_assessment=client.get(f"/api/findings/{second['id']}/history").json()[0]
    assert first_assessment['score']['inputs']['context']['asset_criticality']=='Critical'
    assert first_assessment['score']['inputs']['context']['regulatory']==['PCI DSS','SOC 2']
    assert second_assessment['score']['inputs']['context']['asset_criticality']=='Low'
    assert second_assessment['score']['inputs']['context']['environment']=='Test'

def test_mission_center_returns_prioritized_operational_queues(client):
    login(client)
    create(client)
    response = client.get('/api/mission-center')
    assert response.status_code == 200
    body = response.json()
    assert set(body['queues']) == {'urgent_review','missing_context_evidence','automated_provisional','monitor_reassess'}
    assert body['summary']['urgent_review'] == 1

def test_remediation_package_requires_verified_rescan_before_closure(client):
    login(client); finding = create(client)
    package = client.post('/api/remediation-packages', json={'name':'Patch wave','remediation_action':'Patch and rescan','finding_ids':[finding['id']]})
    assert package.status_code == 201, package.text
    pid = package.json()['id']
    assert client.put(f'/api/remediation-packages/{pid}', json={'status':'Verified Closed'}).status_code == 409
    evidence = client.post(f'/api/remediation-packages/{pid}/evidence', json={'evidence_type':'rescan','reference':'scan-1'})
    assert evidence.status_code == 201
    assert client.post(f"/api/remediation-packages/{pid}/evidence/{evidence.json()['id']}/verify").status_code == 200
    assert client.put(f'/api/remediation-packages/{pid}', json={'status':'Verified Closed'}).status_code == 200
    reopened = client.put(f'/api/remediation-packages/{pid}', json={'status':'Reopened','finding_ids':[finding['id'],finding['id']]})
    assert reopened.status_code == 200
    assert reopened.json()['finding_ids'] == [finding['id']]

def test_remediation_package_pagination_filters_and_clears_fields(client, db):
    login(client)
    for index in range(52):
        response = client.post('/api/remediation-packages', json={'name': f'Wave {index:02}', 'remediation_action': 'Patch'})
        assert response.status_code == 201, response.text
    first = client.get('/api/remediation-packages?page=1&page_size=50&include_archived=true&view=All').json()
    second = client.get('/api/remediation-packages?page=2&page_size=50&include_archived=true&view=All').json()
    assert first['total'] == 52 and len(first['items']) == 50 and len(second['items']) == 2
    assert not {row['id'] for row in first['items']} & {row['id'] for row in second['items']}
    match = client.get('/api/remediation-packages?page=1&page_size=50&include_archived=true&view=All&q=Wave%2000').json()
    assert match['total'] == 1 and match['items'][0]['name'] == 'Wave 00'
    package_id = first['items'][0]['id']
    saved = client.put(f'/api/remediation-packages/{package_id}', json={'jira_reference': 'TASK-1', 'change_window': 'Friday', 'owner_id': 1})
    assert saved.status_code == 200, saved.text
    cleared = client.put(f'/api/remediation-packages/{package_id}', json={'jira_reference': None, 'change_window': None, 'owner_id': None})
    assert cleared.status_code == 200, cleared.text
    assert all(cleared.json()[key] is None for key in ('jira_reference', 'change_window', 'owner_id'))
    archived = client.post(f'/api/remediation-packages/{package_id}/archive').json()
    assert archived['archived'] is True
    assert client.get('/api/remediation-packages?page=1&include_archived=true&view=Archived').json()['total'] == 1
    assert client.get('/api/remediation-packages?page=1&include_archived=true&view=Active').json()['total'] == 51

def test_remediation_package_closure_uses_final_links_and_preserves_history(client, db):
    from app.models import RemediationPackageEvent
    login(client)
    first = create(client)
    second_data = {**DATA, 'hostname': 'SECOND'}
    second = client.post('/api/findings', json=second_data).json()
    package = client.post('/api/remediation-packages', json={'name': 'Closure check', 'remediation_action': 'Patch', 'finding_ids': [first['id']]}).json()
    package_id = package['id']
    evidence = client.post(f'/api/remediation-packages/{package_id}/evidence', json={'evidence_type': 'rescan', 'reference': 'scan'}).json()
    assert client.post(f"/api/remediation-packages/{package_id}/evidence/{evidence['id']}/verify").status_code == 200
    rejected = client.put(f'/api/remediation-packages/{package_id}', json={'finding_ids': [first['id'], second['id']], 'status': 'Verified Closed'})
    assert rejected.status_code == 409
    assert client.get(f'/api/remediation-packages/{package_id}').json()['finding_ids'] == [first['id']]
    assert client.put(f'/api/remediation-packages/{package_id}', json={'status': 'Verified Closed'}).status_code == 200
    assert client.put(f'/api/remediation-packages/{package_id}', json={'finding_ids': [first['id'], second['id']]}).status_code == 409
    reopened = client.put(f'/api/remediation-packages/{package_id}', json={'status': 'Reopened', 'finding_ids': [first['id'], second['id']]})
    assert reopened.status_code == 200 and set(reopened.json()['finding_ids']) == {first['id'], second['id']}
    assert db.query(RemediationPackageEvent).filter_by(package_id=package_id).count() >= 4

def test_remediation_package_filters_preserve_workspace_and_writer_roles(client):
    login(client)
    package = client.post('/api/remediation-packages', json={'name': 'Production package', 'remediation_action': 'Patch'}).json()
    login(client, 'viewer')
    assert client.get('/api/remediation-packages?page=1&view=All&include_archived=true').json()['total'] == 1
    assert client.post('/api/remediation-packages', json={'name': 'Denied', 'remediation_action': 'Patch'}).status_code == 403
    assert client.put(f"/api/remediation-packages/{package['id']}", json={'name': 'Denied'}).status_code == 403
    login(client, environment='Demo')
    assert client.get('/api/remediation-packages?page=1&view=All&include_archived=true').json()['total'] == 0
    assert client.get(f"/api/remediation-packages/{package['id']}").status_code == 404

def test_remediation_package_2_suggests_compatible_work_and_tracks_progress(client):
    login(client); finding = create(client)
    suggestions = client.get('/api/remediation-packages/suggestions')
    assert suggestions.status_code == 200 and suggestions.json()
    suggestion = suggestions.json()[0]
    package = client.post('/api/remediation-packages', json={
        'name': 'Suggested patch wave', 'remediation_action': suggestion['remediation_action'],
        'finding_ids': [finding['id']], 'source': 'suggested', 'suggestion_key': suggestion['suggestion_key'],
        'change_window': 'Saturday 02:00 UTC'})
    assert package.status_code == 201
    body = package.json(); assert body['unique_assets'] == 1 and body['finding_statuses']['Unknown'] == 1
    evidence = client.post(f"/api/remediation-packages/{body['id']}/evidence", json={'evidence_type':'rescan','reference':'verified-scan-2'}).json()
    assert client.post(f"/api/remediation-packages/{body['id']}/evidence/{evidence['id']}/verify").status_code == 200
    refreshed = client.get('/api/remediation-packages').json()[0]
    assert refreshed['finding_statuses']['Fixed'] == 1 and refreshed['verified_findings'] == 1

def test_remediation_package_linking_and_empty_package_lifecycle(client):
    login(client); finding = create(client)
    package = client.post('/api/remediation-packages', json={'name':'Empty coordination','remediation_action':'Configure and verify'}).json()
    pid = package['id']; assert package['finding_ids'] == []
    linked = client.put(f'/api/remediation-packages/{pid}', json={'link_asset_ids':[finding['asset']['id']], 'status':'In Progress'})
    assert linked.status_code == 200 and finding['id'] in linked.json()['finding_ids']
    edited = client.put(f'/api/remediation-packages/{pid}', json={'status':'Pending Verification','change_window':'CAB-42'})
    assert edited.status_code == 200 and edited.json()['change_window'] == 'CAB-42'
    removed = client.put(f'/api/remediation-packages/{pid}', json={'unlink_finding_ids':[finding['id']]})
    assert removed.status_code == 200 and removed.json()['finding_ids'] == []

def test_remediation_package_archive_restore_and_guarded_delete(client):
    login(client)
    empty = client.post('/api/remediation-packages', json={'name':'Archive me','remediation_action':'Coordinate change'}).json()
    pid = empty['id']
    archived = client.post(f'/api/remediation-packages/{pid}/archive')
    assert archived.status_code == 200 and archived.json()['archived'] is True
    listing = client.get('/api/remediation-packages?include_archived=true').json()
    assert listing['total'] >= 1 and any(row['id'] == pid and row['archived'] for row in listing['items'])
    restored = client.post(f'/api/remediation-packages/{pid}/restore')
    assert restored.status_code == 200 and restored.json()['archived'] is False
    assert client.delete(f'/api/remediation-packages/{pid}').status_code == 409

def test_smart_assessment_context_required_bulk_classification_is_governed(client, db):
    login(client); finding = create(client)
    asset_id = finding['asset']['id']
    method = db.scalar(select(Methodology))
    db.add(Assessment(instance_id=finding['id'], revision=1, methodology_id=method.id,
                      analyst_id=1, context={}, justification='Technical investigation complete',
                      decision='Remediation Required', status='Context Required'))
    db.commit()
    response = client.get('/api/smart-assessment/context-required?limit=10')
    assert response.status_code == 200 and response.json()['assets_total'] == 1
    payload = {'asset_ids': [asset_id], 'changes': {'environment': 'Production'},
               'justification': 'Validated by CMDB owner', 'evidence': 'CMDB-123'}
    preview = client.post('/api/smart-assessment/context-required/bulk-classify', json={**payload, 'dry_run': True})
    assert preview.status_code == 202, preview.text
    submitted = client.post('/api/smart-assessment/context-required/bulk-classify', json={
        **payload, 'confirmed': True, 'preview_token': preview.json()['preview_token']})
    assert submitted.status_code == 202, submitted.text
    assert submitted.json()['status'] == 'Awaiting Approval'
    rejected = client.post('/api/smart-assessment/context-required/bulk-classify', json={'asset_ids': [asset_id], 'changes': {'environment': 'Test'}})
    assert rejected.status_code == 422

def test_kpi_contract_is_workspace_scoped_and_has_consistent_denominator(client):
    login(client); create(client)
    response = client.get('/api/kpis')
    assert response.status_code == 200
    body = response.json()
    assert body['total_findings'] >= 1 and body['assessment_coverage'] >= 0
    assert body['workspace'] == 'Production' and body['as_of']

def test_dashboard_exposes_governance_and_remediation_metrics(client):
    login(client)
    create(client)
    dashboard = client.get('/api/dashboard')
    assert dashboard.status_code == 200
    remediation = dashboard.json()['remediation']
    assert {'verified_closure','ticket_coverage','backlog_aging'} <= set(remediation)

def test_plugin_bulk_dry_run_reports_conflicts_without_mutation(client):
    login(client)
    finding = create(client)
    asset_id = client.get(f"/api/findings/{finding['id']}").json()['asset']['id']
    assert client.put(f'/api/assets/{asset_id}', json={'asset_criticality':'Critical','regulatory':['PCI DSS']}).status_code == 200
    group = next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    response = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json={
        'context': {**CONTEXT, 'asset_criticality':'Low', 'regulatory':['None']},
        'justification':'Preview only', 'dry_run':True, 'active_only':True,
    })
    assert response.status_code == 200, response.text
    assert response.json()['dry_run'] is True and response.json()['findings'] == 1
    assert response.json()['conflicts']
    assert client.get(f"/api/findings/{finding['id']}/history").json() == []

def test_workspace_idor_is_blocked_for_exceptions_and_imports(client):
    login(client)
    finding=create(client)
    exception=client.post(f"/api/findings/{finding['id']}/exceptions",json={'justification':'Production exception for isolation test','evidence':'CAB-77','expires_at':'2030-01-01T00:00:00Z','review_frequency_days':30}).json()
    csv=b'hostname,name,plugin_id\nimport-host,Import test,import-plugin\n'
    batch=client.post('/api/imports/preview',files={'file':('production.csv',csv,'text/csv')}).json()['id']
    login(client,environment='Demo')
    assert client.put(f"/api/exceptions/{exception['id']}",json={'status':'Approved'}).status_code==404
    assert client.post(f'/api/imports/{batch}/validate',json={'mapping':{}}).status_code==404

def test_exception_requester_cannot_self_approve(client):
    login(client)
    finding=create(client)
    exception=client.post(f"/api/findings/{finding['id']}/exceptions",json={'justification':'Self approval must be blocked','evidence':'CAB-88','expires_at':'2030-01-01T00:00:00Z','review_frequency_days':30}).json()
    assert client.put(f"/api/exceptions/{exception['id']}",json={'status':'Approved'}).status_code==403

def test_plugin_bulk_assessment_applies_full_workbench_context(client):
    login(client); first=create(client)
    second=client.post('/api/findings',json={**DATA,'hostname':'TEST-02'}).json()
    group=next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    response=client.post(f"/api/assessment-groups/{group['id']}/bulk-assess",json={
        'context':CONTEXT,'controls':[],'owner_id':1,'workflow_status':'Risk Review',
        'notes':'Shared validation completed','justification':'The plugin has the same exposure across this asset group',
        'decision':'Remediation Required','status':'Assessed'})
    assert response.status_code==200,response.text
    body = response.json()
    assert body['total'] == 2 and body['status'] in ('Queued', 'Running') and body['correlation_id']
    body = client.get(f"/api/bulk-assessment-jobs/{body['id']}").json()
    assert body['succeeded'] == 2 and body['processed'] == 2 and body['failed'] == 0
    for finding in (first,second):
        detail=client.get(f"/api/findings/{finding['id']}").json()
        assert detail['status']=='Assessed' and detail['context']['asset_criticality']=='Critical'

def test_plugin_bulk_job_is_idempotent_and_reports_progress(client):
    login(client); create(client)
    group=next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    payload={'context':CONTEXT,'controls':[],'owner_id':1,'workflow_status':'Risk Review',
             'notes':'Idempotent job','justification':'Retry-safe bulk assessment',
             'decision':'Remediation Required','status':'Assessed','idempotency_key':'bulk-test-key-001'}
    first=client.post(f"/api/assessment-groups/{group['id']}/bulk-assess",json=payload)
    assert first.status_code == 200
    original=first.json()
    original=client.get(f"/api/bulk-assessment-jobs/{original['id']}").json()
    assert original['status']=='Completed' and original['progress_percent']==100
    retry=client.post(f"/api/assessment-groups/{group['id']}/bulk-assess",json=payload)
    assert retry.status_code == 200
    assert retry.json()['id'] == original['id']
    assert retry.json()['succeeded'] == original['succeeded']
    status=client.get(f"/api/bulk-assessment-jobs/{original['id']}")
    assert status.status_code == 200 and status.json()['correlation_id'] == original['correlation_id']
    assert status.json()['processed'] <= status.json()['total']

def test_vulnerability_questionnaire_and_preview_explain_cohorts(client):
    login(client); create(client)
    questionnaire = client.get('/api/assessment-questionnaire')
    assert questionnaire.status_code == 200 and questionnaire.json()['version'] == '1.0-provisional'
    group=next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    response=client.post(f"/api/assessment-groups/{group['id']}/bulk-assess",json={
        'context':CONTEXT,'controls':[],'justification':'Preview scenario evidence and cohorts',
        'answers':{'applicability':'Applicable','attack_prerequisite':'Low','exploit_validation':'Observed',
                   'remediation_feasibility':'Available','internet_exposure':'All affected assets'},
        'scenario_evidence':['TENABLE-PLUGIN-100'],'scenario_notes':'Shared synthetic evidence',
        'decision':'Remediation Required','status':'Assessed','dry_run':True})
    body=response.json()
    assert response.status_code == 200
    assert {'changed','unchanged','excluded','conflicts','regulatory_scope','cohorts'} <= body.keys()
    assert 'distribution' in body['risk_preview']

def test_bulk_preview_returns_missing_context_and_job_retains_investigation(client):
    login(client); finding = create(client)
    group = next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id'] == 'test-100')
    payload = {'context':{}, 'controls':[], 'justification':'Validated shared technical investigation',
        'answers':{'applicability':'Applicable','attack_prerequisite':'Low','exploit_validation':'Observed',
                   'remediation_feasibility':'Available','internet_exposure':'All affected assets'},
        'scenario_evidence':['SCAN-100'], 'scenario_notes':'Scanner output reviewed',
        'decision':'Remediation Required','status':'Assessed'}
    preview = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json={**payload,'dry_run':True})
    assert preview.status_code == 200, preview.text
    assert preview.json()['categories']['missing_context']['count'] == 1
    queued = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json=payload)
    assert queued.status_code == 200, queued.text
    finished = client.get(f"/api/bulk-assessment-jobs/{queued.json()['id']}").json()
    assert finished['succeeded'] == 1 and finished['processed'] == finished['total']
    detail = client.get(f"/api/findings/{finding['id']}").json()
    assert detail['status'] == 'Context Required'
    assert detail['context']['_technical_investigation']['answers']['applicability'] == 'Applicable'

def test_bulk_not_applicable_requires_evidence_and_creates_no_risk_score(client, db):
    login(client)
    finding = create(client)
    group = next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id'] == 'test-100')
    base = {'context': CONTEXT, 'controls': [], 'justification': 'Evidence confirms the plugin is not applicable to this service.',
            'answers': {'applicability': 'Not applicable'}, 'scenario_evidence': ['APP-NA-001'],
            'scenario_notes': 'Service inventory and vendor validation reviewed.', 'decision': 'Not Applicable', 'status': 'Assessed'}
    response = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json={**base, 'dry_run': True})
    assert response.status_code == 200, response.text
    assert response.json()['risk_preview']['distribution'] == {}
    queued = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json=base)
    assert queued.status_code == 200, queued.text
    finished = client.get(f"/api/bulk-assessment-jobs/{queued.json()['id']}").json()
    assert finished['not_applicable'] == 1 and finished['assessed'] == 0 and finished['failed'] == 0
    detail = client.get(f"/api/findings/{finding['id']}").json()
    assert detail['status'] == 'Not Applicable' and detail['saved_score'] is None
    assert db.scalar(select(RiskScore).join(Assessment).where(Assessment.instance_id == finding['id'])) is None

def test_approved_asset_context_recalculates_completed_investigation(client, db):
    login(client); finding = create(client)
    group = next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id'] == 'test-100')
    payload = {'context': {}, 'controls': [], 'justification': 'Technical investigation completed pending authoritative classification.',
               'answers': {'applicability': 'Applicable', 'attack_prerequisite': 'Low', 'exploit_validation': 'Observed',
                           'remediation_feasibility': 'Available', 'internet_exposure': 'All affected assets'},
               'scenario_evidence': ['SCAN-CONTEXT-1'], 'scenario_notes': 'Scanner evidence reviewed.',
               'decision': 'Remediation Required', 'status': 'Assessed'}
    queued = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json=payload)
    assert queued.status_code == 200
    assert client.get(f"/api/findings/{finding['id']}").json()['status'] == 'Context Required'
    asset = client.get('/api/assets').json()['items'][0]
    login(client, 'analyst')
    request = client.post(f"/api/assets/{asset['id']}/classification-change-requests", json={
        'expected_context_version': asset['context_version'], 'changes': CONTEXT,
        'justification': 'BIA and service inventory approved.', 'evidence': 'BIA-CONTEXT-1'})
    assert request.status_code == 201
    login(client)
    approved = client.put(f"/api/classification-change-requests/{request.json()['id']}", json={
        'status': 'Approved', 'justification': 'GRC approved authoritative context.'})
    assert approved.status_code == 200, approved.text
    detail = client.get(f"/api/findings/{finding['id']}").json()
    assert detail['status'] == 'Assessed' and detail['saved_score'] is not None

def test_bulk_preview_and_job_handle_one_thousand_mixed_findings(client, db):
    login(client)
    vulnerability = Vulnerability(identity='mixed-1000', plugin_id='mixed-1000', name='Mixed bulk population', cves=[],
                                  technical={'severity':'High','cvss':8.0,'vpr':7.5})
    db.add(vulnerability); db.flush()
    findings = []
    for index in range(1000):
        asset = Asset(hostname=f'MIXED-{index:04d}', context=CONTEXT if index % 4 else {}, workspace='Production')
        db.add(asset); db.flush()
        finding = Finding(asset_id=asset.id, vulnerability_id=vulnerability.id, source='Manual', workspace='Production')
        db.add(finding); db.flush(); findings.append(finding)
        if index < 50: db.add(FindingWorkflow(finding_id=finding.id, status='Closed', updated_by=1))
        elif index < 60: db.add(Assessment(instance_id=finding.id, revision=0, methodology_id=1, analyst_id=1,
                                             context={}, justification='Existing assessment', decision='Exception Required', status='Assessed'))
    db.commit()
    group = next(x for x in client.get('/api/assessment-groups?limit=100').json()['items'] if x['plugin_id'] == 'mixed-1000')
    payload = {'context':{},'controls':[],'justification':'Mixed population investigation',
        'answers':{'applicability':'Applicable','attack_prerequisite':'Low','exploit_validation':'Observed',
                   'remediation_feasibility':'Available','internet_exposure':'All affected assets'},
        'scenario_evidence':['SCAN-MIXED-1000'],'scenario_notes':'Validated synthetic evidence',
        'decision':'Remediation Required','status':'Assessed'}
    preview = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json={**payload,'dry_run':True})
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body['scope']['total_findings'] == 1000 and body['scope']['active_findings'] == 950
    assert body['scope']['excluded_findings'] == 50 and body['scope']['existing_assessments'] == 10
    assert body['categories']['missing_context']['count'] > 0
    queued = client.post(f"/api/assessment-groups/{group['id']}/bulk-assess", json=payload)
    finished = client.get(f"/api/bulk-assessment-jobs/{queued.json()['id']}").json()
    assert finished['processed'] == 950 and finished['processed'] <= finished['total'] and finished['failed'] == 0
    preserved = db.scalar(select(Assessment).where(Assessment.instance_id == findings[55].id).order_by(Assessment.revision.desc()).limit(1))
    assert preserved.decision == 'Exception Required'
def test_saved_filters_are_personal_and_workspace_scoped(client):
    login(client)
    created=client.post('/api/saved-filters',json={'name':'Critical unassessed','filters':{'severity':'Critical','status':'Not Assessed','q':''}})
    assert created.status_code==201 and created.json()['filters']=={'severity':'Critical','status':'Not Assessed'}
    saved=client.get('/api/saved-filters').json(); assert len(saved)==1
    updated=client.post('/api/saved-filters',json={'name':'Critical unassessed','filters':{'severity':'High'}})
    assert updated.status_code==201 and client.get('/api/saved-filters').json()[0]['filters']=={'severity':'High'}
    assert client.delete(f"/api/saved-filters/{saved[0]['id']}").status_code==200
    assert client.get('/api/saved-filters').json()==[]

def test_classification_change_request_requires_independent_approval(client, db):
    login(client)
    asset = client.post('/api/assets', json={
        'hostname': 'governed-scope-asset', 'regulatory': ['PCI DSS', 'SOC 2'],
    }).json()
    asset_id = asset['id']

    login(client, 'analyst')
    request = client.post(f'/api/assets/{asset_id}/classification-change-requests', json={
        'expected_context_version': asset['context_version'],
        'changes': {'regulatory': ['SOC 2']},
        'justification': 'The PCI system was decommissioned and scope was validated.',
        'evidence': 'Approved decommission record DC-001.',
    })
    assert request.status_code == 201, request.text
    change = request.json()
    assert change['before_context']['regulatory'] == ['PCI DSS', 'SOC 2']
    assert change['proposed_context']['regulatory'] == ['SOC 2']
    assert client.put(f"/api/classification-change-requests/{change['id']}", json={
        'status': 'Approved', 'justification': 'Self approval must be blocked.',
    }).status_code == 403

    login(client)
    approved = client.put(f"/api/classification-change-requests/{change['id']}", json={
        'status': 'Approved', 'justification': 'GRC evidence reviewed and approved.',
    })
    assert approved.status_code == 200, approved.text
    assert approved.json()['status'] == 'Approved' and approved.json()['applied_at']
    saved = client.get('/api/assets').json()['items'][0]
    assert saved['context']['regulatory'] == ['SOC 2']
    memberships = db.scalars(select(AssetRegulatoryScope).where(
        AssetRegulatoryScope.asset_id == asset_id,
    )).all()
    by_scope = {row.scope: row for row in memberships}
    assert by_scope['PCI DSS'].active is False
    assert by_scope['SOC 2'].active is True
    assert by_scope['SOC 2'].approval_state == 'Approved'

    # Re-add the approved scope and remove it again: membership identity must
    # remain stable while the audit lifecycle records both transitions.
    current = db.get(Asset, asset_id)
    login(client, 'analyst')
    readd = client.post(f'/api/assets/{asset_id}/classification-change-requests', json={
        'expected_context_version': current.context_version, 'changes': {'regulatory': ['PCI DSS', 'SOC 2']},
        'justification': 'PCI scope restored after approved system change.', 'evidence': 'GRC-RESTORE-1',
    }).json()
    login(client)
    assert client.put(f"/api/classification-change-requests/{readd['id']}", json={'status':'Approved','justification':'GRC approved restoration.'}).status_code == 200
    restored = {row.scope: row for row in db.scalars(select(AssetRegulatoryScope).where(AssetRegulatoryScope.asset_id == asset_id)).all()}
    pci_id = restored['PCI DSS'].id
    assert restored['PCI DSS'].active is True and restored['PCI DSS'].approval_state == 'Approved'
    current = db.get(Asset, asset_id)
    login(client, 'analyst')
    remove_again = client.post(f'/api/assets/{asset_id}/classification-change-requests', json={
        'expected_context_version': current.context_version, 'changes': {'regulatory': ['SOC 2']},
        'justification': 'PCI scope removed again with approved evidence.', 'evidence': 'GRC-REMOVE-2',
    }).json()
    login(client)
    assert client.put(f"/api/classification-change-requests/{remove_again['id']}", json={'status':'Approved','justification':'GRC approved removal.'}).status_code == 200
    db.expire_all(); final = db.scalar(select(AssetRegulatoryScope).where(AssetRegulatoryScope.id == pci_id))
    assert final.active is False and final.id == pci_id and final.removed_at is not None


def test_classification_change_request_is_workspace_scoped(client):
    login(client, environment='Production')
    asset = client.post('/api/assets', json={'hostname': 'production-governed-asset'}).json()
    change = client.post(f"/api/assets/{asset['id']}/classification-change-requests", json={
        'expected_context_version': asset['context_version'],
        'changes': {'asset_criticality': 'High'},
        'justification': 'Business impact review.',
    }).json()
    assert client.post('/api/auth/logout').status_code == 200
    login(client, environment='Demo')
    assert client.put(f"/api/classification-change-requests/{change['id']}", json={
        'status': 'Approved', 'justification': 'Guessed ID.'
    }).status_code == 404


def test_classification_mission_draft_is_resumable_and_workspace_scoped(client):
    login(client, environment='Production')
    asset = client.post('/api/assets', json={'hostname': 'mission-asset'}).json()
    saved = client.put(f"/api/assets/{asset['id']}/classification-mission", json={
        'questionnaire_version': '1.0-provisional', 'current_step': 3,
        'responses': {'identity_owner': 'Infrastructure', 'data_scope': 'PCI DSS'},
    })
    assert saved.status_code == 200, saved.text
    assert saved.json()['status'] == 'Draft' and saved.json()['current_step'] == 3
    resumed = client.get(f"/api/assets/{asset['id']}/classification-mission")
    assert resumed.status_code == 200 and resumed.json()['responses']['data_scope'] == 'PCI DSS'
    assert client.post('/api/auth/logout').status_code == 200
    login(client, environment='Demo')
    assert client.get(f"/api/assets/{asset['id']}/classification-mission").status_code == 404

def test_classification_change_request_can_govern_owner_assignment(client):
    login(client)
    asset = client.post('/api/assets', json={'hostname': 'owner-governed-asset'}).json()
    assert client.post('/api/auth/logout').status_code == 200
    login(client, 'analyst')
    assert client.put(f"/api/assets/{asset['id']}/classification-mission", json={'current_step': 1, 'responses': {}}).status_code == 200
    request = client.post(f"/api/assets/{asset['id']}/classification-change-requests", json={
        'expected_context_version': asset['context_version'],
        'changes': {'business_owner': 'Payments leadership', 'it_owner': 'Endpoint engineering'},
        'justification': 'Owner attestation completed.', 'evidence': 'BIA-123',
    })
    assert request.status_code == 201, request.text
    assert client.get(f"/api/assets/{asset['id']}/classification-mission").json()['status'] == 'Pending Owner Validation'
    assert client.post('/api/auth/logout').status_code == 200
    login(client)
    approved = client.put(f"/api/classification-change-requests/{request.json()['id']}", json={
        'status': 'Approved', 'justification': 'Attestation verified.',
    })
    assert approved.status_code == 200
    current = next(item for item in client.get('/api/assets').json()['items'] if item['id'] == asset['id'])
    assert current['context']['business_owner'] == 'Payments leadership'
    assert current['context']['it_owner'] == 'Endpoint engineering'

def test_classification_mission_tracks_review_decision(client):
    login(client)
    asset = client.post('/api/assets', json={'hostname': 'mission-decision-asset'}).json()
    assert client.put(f"/api/assets/{asset['id']}/classification-mission", json={
        'current_step': 4, 'responses': {'classification': {'context': {'asset_criticality': 'High'}}},
    }).status_code == 200
    assert client.post('/api/auth/logout').status_code == 200
    login(client, 'analyst')
    request = client.post(f"/api/assets/{asset['id']}/classification-change-requests", json={
        'expected_context_version': asset['context_version'], 'changes': {'asset_criticality': 'High'},
        'justification': 'BIA completed.',
    })
    assert request.status_code == 201
    pending = client.get(f"/api/assets/{asset['id']}/classification-mission").json()
    assert pending['status'] == 'Pending GRC Approval' and pending['current_step'] == 5
    assert client.post('/api/auth/logout').status_code == 200
    login(client)
    assert client.put(f"/api/classification-change-requests/{request.json()['id']}", json={
        'status': 'Rejected', 'justification': 'Evidence is incomplete.',
    }).status_code == 200
    assert client.get(f"/api/assets/{asset['id']}/classification-mission").json()['status'] == 'Rejected'

def test_classification_mission_validates_version_and_answer_contract(client):
    login(client)
    asset = client.post('/api/assets', json={'hostname': 'mission-validation-asset'}).json()
    bad_version = client.put(f"/api/assets/{asset['id']}/classification-mission", json={
        'questionnaire_version': '0.1-old', 'current_step': 1, 'responses': {},
    })
    assert bad_version.status_code == 409
    bad_answer = client.put(f"/api/assets/{asset['id']}/classification-mission", json={
        'questionnaire_version': '1.0-provisional', 'current_step': 2,
        'responses': {'business.criticality': 'Extreme'},
    })
    assert bad_answer.status_code == 422
    good = client.put(f"/api/assets/{asset['id']}/classification-mission", json={
        'questionnaire_version': '1.0-provisional', 'current_step': 2,
        'responses': {'business.criticality': 'High', 'scope.regulatory': ['PCI DSS']},
    })
    assert good.status_code == 200

def test_classification_questionnaire_uses_stable_versioned_ids(client):
    login(client)
    questionnaire = client.get('/api/classification-questionnaire').json()
    assert questionnaire['version'] == '1.0-provisional'
    question_ids = [question['id'] for step in questionnaire['steps'] for question in step['questions']]
    assert len(question_ids) == len(set(question_ids))
    assert {'identity.business_owner', 'scope.regulatory', 'exposure.network'} <= set(question_ids)

def test_classification_mission_history_is_workspace_scoped_and_resumable(client):
    login(client, environment='Production')
    asset = client.post('/api/assets', json={'hostname': 'mission-history-asset'}).json()
    saved = client.put(f"/api/assets/{asset['id']}/classification-mission", json={
        'current_step': 2, 'responses': {'business.criticality': 'High'},
    })
    assert saved.status_code == 200
    history = client.get(f"/api/assets/{asset['id']}/classification-mission/history")
    assert history.status_code == 200 and history.json()[0]['action'] == 'draft_saved'
    login(client, environment='Demo')
    assert client.get(f"/api/assets/{asset['id']}/classification-mission/history").status_code == 404

def test_classification_evidence_requires_mission_and_is_workspace_scoped(client):
    login(client, environment='Production')
    asset = client.post('/api/assets', json={'hostname': 'evidence-asset'}).json()
    payload = {'evidence_type': 'BIA', 'reference': 'BIA-77', 'notes': 'Business impact assessment.'}
    assert client.post(f"/api/assets/{asset['id']}/classification-mission/evidence", json=payload).status_code == 409
    assert client.put(f"/api/assets/{asset['id']}/classification-mission", json={'current_step': 2, 'responses': {}}).status_code == 200
    added = client.post(f"/api/assets/{asset['id']}/classification-mission/evidence", json=payload)
    assert added.status_code == 201, added.text
    evidence = client.get(f"/api/assets/{asset['id']}/classification-mission/evidence").json()
    assert evidence[0]['reference'] == 'BIA-77' and evidence[0]['evidence_type'] == 'BIA'
    assert client.post('/api/auth/logout').status_code == 200
    login(client, environment='Demo')
    assert client.get(f"/api/assets/{asset['id']}/classification-mission/evidence").status_code == 404

def test_raci_template_and_preview_import(client):
    pytest.importorskip('openpyxl')
    from io import BytesIO
    from openpyxl import Workbook
    login(client)
    response = client.get('/api/raci/template')
    assert response.status_code == 200
    book = Workbook(); book.remove(book.active)
    sheets = {
        'START HERE':['TEMPLATE VERSION', 'IMPORT MODE'],
        'TEAM DIRECTORY':['Observed team / group'], 'ROUTING RULES':['Rule ID'],
        'ASSET OVERRIDES':['Asset UUID'], 'PLUGIN OVERRIDES':['Plugin ID'],
        'RACI MATRIX':['ID'], 'ROLE MAPPING':['Source role'], 'TECH LANES':['Technical lane']}
    for name, headers in sheets.items(): book.create_sheet(name).append(headers)
    output = BytesIO(); book.save(output); output.seek(0)
    upload = client.post('/api/raci/import', files={'file':('raci.xlsx', output.getvalue(), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')})
    assert upload.status_code == 201
    assert upload.json()['status'] == 'Preview'

def test_mission_center_sql_order_filter_pages_and_workspace(client, db):
    from sqlalchemy import event
    login(client)
    vuln = Vulnerability(identity='mission-fixture', plugin_id='mission', name='Mission fixture', technical={'severity': 'Low'})
    db.add(vuln); db.flush()
    for i in range(120):
        asset = Asset(hostname=f'mission-{i:03}', workspace='Production', context={'asset_criticality': 'Low'})
        db.add(asset); db.flush()
        db.add(Finding(asset_id=asset.id, vulnerability_id=vuln.id, source='test', workspace='Production',
                       observed={'technical': {'severity': 'Low', 'kev': i >= 110}}, revision=0))
    other = Asset(hostname='mission-secret', workspace='Development', context={})
    db.add(other); db.flush()
    db.add(Finding(asset_id=other.id, vulnerability_id=vuln.id, source='test', workspace='Development', observed={'technical': {'severity': 'Critical'}}))
    db.commit()
    statements = []
    def track(_conn, _cursor, statement, _params, _context, _executemany):
        if 'vulnerability_instances' in statement:
            statements.append(statement)
    event.listen(db.bind, 'before_cursor_execute', track)
    try:
        first = client.get('/api/mission-center?queue=urgent_review&page_size=3').json()
        second = client.get('/api/mission-center?queue=urgent_review&page_size=3&page=2').json()
        filtered = client.get('/api/mission-center?q=mission-000').json()
        owned = client.get('/api/mission-center?owner_id=999').json()
    finally:
        event.remove(db.bind, 'before_cursor_execute', track)
    assert first['summary'] == {'urgent_review': 10}
    ids1 = [row['finding_id'] for row in first['queues']['urgent_review']]
    ids2 = [row['finding_id'] for row in second['queues']['urgent_review']]
    assert len(ids1) == len(ids2) == 3 and ids1 == sorted(ids1) and max(ids1) < min(ids2)
    assert filtered['summary']['automated_provisional'] == 1
    assert sum(owned['summary'].values()) == 0
    assert all(row['asset'] != 'mission-secret' for row in filtered['queues']['automated_provisional'])
    assert len(statements) <= 12
