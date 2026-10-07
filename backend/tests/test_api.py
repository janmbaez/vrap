from copy import deepcopy
from sqlalchemy import select
from cryptography.fernet import Fernet
from app.config import settings
from app.models import Assessment,Audit,ImportRow,IntegrationSettings,User
from app.risk.policy import DEFAULT
from conftest import login
DATA={'hostname':'TEST-01','name':'Synthetic RCE','plugin_id':'test-100','severity':'Critical','cvss':9.8,'vpr':9.4}
CONTEXT={'asset_criticality':'Critical','business_criticality':'High','data_classification':'Confidential','regulatory':['SOC 2'],'environment':'Production','exposure':'Internal'}
def create(client):
    r=client.post('/api/findings',json=DATA); assert r.status_code==201,r.text
    return r.json()
def body(f): return {'expected_revision':f['revision'],'methodology_id':f['methodology_id'],'context':CONTEXT,'controls':[],'justification':'Reviewed business context','decision':'Remediation Required','status':'Assessed'}
def test_auth_rbac_csrf(client):
    assert client.get('/api/findings').status_code==401
    login(client,'viewer'); assert client.get('/api/findings').status_code==200
    assert client.post('/api/findings',json=DATA).status_code==403
    assert client.get('/api/users').status_code==403
    login(client); client.headers.pop('X-CSRF-Token')
    assert client.post('/api/findings',json=DATA).status_code==403
    assert client.post('/api/auth/login',headers={'Origin':'https://evil.example'},json={'username':'admin','password':'Test-password-123!'}).status_code==403

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

def test_asset_context_is_authoritative_and_flags_reassessment(client):
    login(client); finding=create(client); payload=body(finding)
    saved=client.post(f"/api/findings/{finding['id']}/assessments",json=payload).json()
    changed=client.put(f"/api/assets/{saved['asset']['id']}",json={'asset_criticality':'Low','regulatory':['SOX']})
    assert changed.status_code==200 and changed.json()['findings_flagged']==1
    refreshed=client.get(f"/api/findings/{finding['id']}").json()
    assert refreshed['context']['asset_criticality']=='Low'
    assert refreshed['context']['regulatory']==['SOX']
    assert refreshed['reassessment_required'] is True

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
    updated=client.put(f"/api/assessment-groups/{group['id']}/assets",json={'asset_criticality':'Critical'})
    assert updated.status_code==200 and updated.json()=={'assets_updated':2,'findings_flagged':3}
    assert client.get(f"/api/findings/{other['id']}").json()['context']['asset_criticality']=='Critical'

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
    exception=client.post(f"/api/findings/{first['id']}/exceptions",json={'justification':'Temporary operational dependency requires documented acceptance','evidence':'Change record CAB-42','expires_at':'2030-01-01T00:00:00Z','review_frequency_days':30})
    assert exception.status_code==201
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

def test_plugin_bulk_assessment_applies_full_workbench_context(client):
    login(client); first=create(client)
    second=client.post('/api/findings',json={**DATA,'hostname':'TEST-02'}).json()
    group=next(x for x in client.get('/api/assessment-groups').json()['items'] if x['plugin_id']=='test-100')
    response=client.post(f"/api/assessment-groups/{group['id']}/bulk-assess",json={
        'context':CONTEXT,'controls':[],'owner_id':1,'workflow_status':'Risk Review',
        'notes':'Shared validation completed','justification':'The plugin has the same exposure across this asset group',
        'decision':'Remediation Required','status':'Assessed'})
    assert response.status_code==200,response.text
    assert response.json()=={'findings_assessed':2,'assets_affected':2}
    for finding in (first,second):
        detail=client.get(f"/api/findings/{finding['id']}").json()
        assert detail['status']=='Assessed' and detail['context']['asset_criticality']=='Critical'

def test_saved_filters_are_personal_and_workspace_scoped(client):
    login(client)
    created=client.post('/api/saved-filters',json={'name':'Critical unassessed','filters':{'severity':'Critical','status':'Not Assessed','q':''}})
    assert created.status_code==201 and created.json()['filters']=={'severity':'Critical','status':'Not Assessed'}
    saved=client.get('/api/saved-filters').json(); assert len(saved)==1
    updated=client.post('/api/saved-filters',json={'name':'Critical unassessed','filters':{'severity':'High'}})
    assert updated.status_code==201 and client.get('/api/saved-filters').json()[0]['filters']=={'severity':'High'}
    assert client.delete(f"/api/saved-filters/{saved[0]['id']}").status_code==200
    assert client.get('/api/saved-filters').json()==[]
