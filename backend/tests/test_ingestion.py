import asyncio,io
from types import SimpleNamespace
import httpx,pytest
from openpyxl import Workbook
from app.integrations.tenable import normalize,TenableClient,TenableError,MAX_TENABLE_CHUNK_BYTES,normalized_asset_tags
from app.services import ingest
from app.models import FindingWorkflow
from app.api.tenable import MAX_ACTIONABLE_VULNERABILITIES, sync_summary
from app.imports.parser import parse_file, normalize as normalize_import, MAX_BYTES, MAX_ROWS

def test_missing_fields():
    d=normalize({'asset':{'uuid':'123','hostname':['asset']},'plugin':{'id':123,'name':'Test'},'port':{'port':443,'protocol':'TCP'}})
    assert d.kev is None and d.cvss is None and d.vpr is None
    assert d.hostname=='asset' and d.port==443

def test_tenable_chunk_limit_matches_import_limit():
    assert MAX_TENABLE_CHUNK_BYTES == 100 * 1024 * 1024
    assert MAX_ACTIONABLE_VULNERABILITIES == 500000

def test_tenable_sync_summary_is_human_readable():
    job = SimpleNamespace(status='Running', counts={
        'received': 5185, 'created': 5185, 'updated': 0,
        'informational_skipped': 43214, 'batches_processed': 7,
        'progress_percent': 7,
    })
    assert sync_summary(job) == ('5,185 actionable findings processed · 5,185 new · '
                                '43,214 informational skipped · 7 batches complete · 7% in progress')

def test_tenable_info_severity_is_normalized():
    data = normalize({'asset': {'uuid': '123', 'hostname': ['asset']},
                      'plugin': {'id': 123, 'name': 'Test'},
                      'severity': 'Info'})
    assert data.severity == 'Informational'

def test_tenable_asset_tag_objects_are_normalized():
    assert normalized_asset_tags([{'category':'Patching Group','value':'Windows Servers'}, {'category_name':'Application','value_name':'VRAP'}]) == ['patching_group:Windows Servers', 'application:VRAP']

def test_tenable_cvss_vector_object_is_accepted():
    data = normalize({'asset': {'uuid': '123', 'hostname': ['asset']},
                      'plugin': {'id': 123, 'name': 'Test',
                                 'cvss3_vector': {'version': '3.1', 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}}})
    assert data.cvss_vector == 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

def test_export_chunks_safe_errors():
    config=SimpleNamespace(tenable_base_url='https://cloud.tenable.com',tenable_allowed_hosts='cloud.tenable.com',tenable_access_key='PRIVATE',tenable_secret_key='SECRET')
    def respond(request):
        if request.method=='POST':
            assert b'"since":0' in request.content
            assert b'"num_assets":100' in request.content
            return httpx.Response(200,json={'export_uuid':'abc-123'})
        if request.url.path.endswith('/status'):return httpx.Response(200,json={'status':'FINISHED','chunks_available':[3,1]})
        return httpx.Response(200,json=[{'chunk':request.url.path[-1]}])
    async def run():
        c=TenableClient(config,httpx.MockTransport(respond));chunks=[chunk async for chunk in c.export('vulnerabilities')]
        assert chunks==[[{'chunk':'3'}],[{'chunk':'1'}]];await c.close()
        c=TenableClient(config,httpx.MockTransport(lambda _:httpx.Response(403,text='SECRET')))
        with pytest.raises(TenableError) as exc:await c.test()
        assert 'SECRET' not in str(exc.value);await c.close()
    asyncio.run(run())
def test_reject_host():
    c=SimpleNamespace(tenable_base_url='http://127.0.0.1',tenable_allowed_hosts='cloud.tenable.com',tenable_access_key='x',tenable_secret_key='y')
    with pytest.raises(TenableError):TenableClient(c)
def test_xlsx_formulas():
    w=Workbook();s=w.active;s.append(['Host','Plugin']);s.append(['server','Test']);b=io.BytesIO();w.save(b)
    h,r=parse_file('a.xlsx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',b.getvalue());assert len(r)==1
    s.append(['server','=1+1']);b=io.BytesIO();w.save(b)
    with pytest.raises(ValueError,match='Formulas'):parse_file('a.xlsx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',b.getvalue())
def test_csv_limits():
    assert MAX_BYTES == 100 * 1024 * 1024 and MAX_BYTES > 60 * 1024 * 1024
    assert MAX_ROWS == 100000
    with pytest.raises(ValueError):parse_file('a.csv','text/csv',b'Host,Host\na,b')
    with pytest.raises(ValueError):parse_file('a.csv','application/octet-stream',b'Host,Plugin\na,b')

def test_tenable_csv_value_normalization():
    mapping={'hostname':'asset.name','ip':'asset.display_ipv4_address','name':'definition.name',
             'exploit_available':'definition.exploitability_ease','kev':'definition.vpr.drivers_on_cisa_kev',
             'first_seen':'first_observed','last_seen':'last_seen','protocol':'protocol'}
    base={'asset.name':'server-1','asset.display_ipv4_address':'10.0.0.1','definition.name':'Finding',
          'definition.vpr.drivers_on_cisa_kev':'false','first_observed':'2026-09-29T08:06:52.386Z',
          'last_seen':'2026-09-30T04:18:20.359Z','protocol':'TCP'}
    available=normalize_import({**base,'definition.exploitability_ease':'AVAILABLE'},mapping)
    assert available.exploit_available is True and available.kev is False
    assert available.first_seen.isoformat()=='2026-09-29' and available.last_seen.isoformat()=='2026-09-30'
    assert available.protocol=='tcp'
    not_required=normalize_import({**base,'definition.exploitability_ease':'NOT_REQUIRED'},mapping)
    assert not_required.exploit_available is None
    many_cves=normalize_import({**base,'definition.exploitability_ease':'NOT_AVAILABLE',
                                'definition.cve':', '.join(f'CVE-2026-{i:04}' for i in range(628))},
                               {**mapping,'cves':'definition.cve'})
    assert len(many_cves.cves)==628

def test_tenable_asset_tags_are_normalized_for_rules():
    data=normalize_import({'asset.name':'server-1','asset.tags':'[{"category":"Location","value":"OWB - Data Center"},{"category":"Patching Group","value":"Windows_Server_Prod_A"},{"category":"Application","value":"JCOM"}]'}, {'hostname':'asset.name','asset_tags':'asset.tags','name':'asset.name'})
    assert data.asset_tags==['location:OWB - Data Center','patching_group:Windows_Server_Prod_A','application:JCOM']

def test_tenable_lifecycle_updates_one_finding_and_preserves_review(db):
    original={'finding_id':'stable-1'}
    active=normalize({'asset':{'uuid':'asset-1','hostname':['server']},'plugin':{'id':1,'name':'Finding'},'port':{'port':443,'protocol':'tcp'},'severity':'High','state':'ACTIVE','finding_id':'stable-1'})
    finding,created=ingest(db,active,'Tenable',original,update_existing=True,actor_id=1)
    assert created
    db.add(FindingWorkflow(finding_id=finding.id,status='Reviewed',review_state='Reviewed',updated_by=1,reviewed_by=1)); db.flush()
    closed=normalize({'asset':{'uuid':'asset-1','hostname':['server']},'plugin':{'id':1,'name':'Finding'},'port':{'port':0,'protocol':'tcp'},'severity':'High','state':'FIXED','finding_id':'stable-1'})
    same,created=ingest(db,closed,'Tenable',{'finding_id':'stable-1'},update_existing=True,actor_id=1)
    assert same.id == finding.id and not created
    assert db.get(FindingWorkflow,finding.id).status == 'Closed'
    assert db.get(FindingWorkflow,finding.id).review_state == 'Reviewed'
    reopened=normalize({'asset':{'uuid':'asset-1','hostname':['server']},'plugin':{'id':1,'name':'Finding'},'port':{'port':0,'protocol':'tcp'},'severity':'High','state':'ACTIVE','finding_id':'stable-1'})
    same,created=ingest(db,reopened,'Tenable',{'finding_id':'stable-1'},update_existing=True,actor_id=1)
    assert same.id == finding.id and not created and db.get(FindingWorkflow,finding.id).status == 'New'

def test_ingest_cache_prevents_duplicate_findings(db):
    cache = {}
    data = normalize({'asset':{'uuid':'asset-1','hostname':['server']},'plugin':{'id':1,'name':'Finding'},'port':{'port':443,'protocol':'tcp'},'severity':'High','finding_id':'stable-1'})
    first, created = ingest(db, data, 'Tenable', {'finding_id':'stable-1'}, update_existing=True, actor_id=1, cache=cache)
    second, created_again = ingest(db, data, 'Tenable', {'finding_id':'stable-1'}, update_existing=True, actor_id=1, cache=cache)
    assert created and not created_again and first.id == second.id
