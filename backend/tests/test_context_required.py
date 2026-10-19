"""Cohort parity, confirmation, workspace and approval boundaries through the API."""
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import select, func, event

from app.models import (Asset, Finding, Vulnerability, Assessment, Methodology, Audit, User,
                        AssetClassificationChangeRequest, AssetRegulatoryScope, AssetClassificationMission)
from conftest import login

URL = '/api/smart-assessment/context-required'


def add_asset(db, name='host', os=None, technical=None, context=None, tags=None, workspace='Production', findings=1):
    asset = Asset(hostname=name, os=os, context=context or {}, tags=tags or [], workspace=workspace)
    db.add(asset); db.flush()
    method = db.scalar(select(Methodology))
    analyst = db.scalar(select(User).where(User.username == 'analyst'))
    for n in range(findings):
        vuln = Vulnerability(identity=f'{workspace}-{name}-{n}', plugin_id=f'{name}-{n}',
                             name='Investigated vulnerability', technical=technical or {})
        db.add(vuln); db.flush()
        finding = Finding(asset_id=asset.id, vulnerability_id=vuln.id, workspace=workspace,
                          port=443+n, protocol='tcp', source='Manual', source_record={}, observed={}, revision=1)
        db.add(finding); db.flush()
        db.add(Assessment(instance_id=finding.id, revision=1, methodology_id=method.id, analyst_id=analyst.id,
                          context={}, justification='Verified technical evidence', decision='Remediation Required', status='Context Required'))
    db.commit()
    return asset


def payload(**extra):
    return {'selection': {}, 'changes': {'business_criticality': 'High'},
            'justification': 'Owner CMDB evidence reviewed', 'evidence': 'CMDB-123', **extra}


def preview(client, body):
    result = client.post(URL+'/bulk-classify', json={**body, 'dry_run': True})
    assert result.status_code == 202, result.text
    return result.json()


def submit(client, body, checked):
    return client.post(URL+'/bulk-classify', json={**body, 'confirmed': True, 'preview_token': checked['preview_token']})


@pytest.mark.parametrize('category,os,tech', [
    ('Windows Servers', 'Windows Datacenter', {}),
    ('Windows Workstations', 'Windows 11', {}),
    ('Linux Servers', None, {'os': 'Debian 12'}),
    ('Network Devices', None, {'device_type': 'network switch'}),
    ('Storage', None, {'product': 'PowerScale'}),
    ('Databases', None, {'software_family': 'PostgreSQL database'}),
    ('Cloud', None, {'product': 'AWS service'}),
    ('Applications', None, {'product': 'Business service'}),
    ('Unknown', None, {}),
])
def test_every_subcategory_is_filtered_before_pagination_and_shared_by_preview(client, db, category, os, tech):
    login(client, 'analyst')
    add_asset(db, name='000-nonmatching', os='Ubuntu')
    target = add_asset(db, name='zzz-target', os=os, technical=tech, findings=2)
    filters = {'subcategory': category, 'q': 'target'}
    result = client.get(URL, params={**filters, 'limit': 1, 'offset': 1})
    assert result.status_code == 200, result.text
    assert result.json()['total'] == 2 and result.json()['assets_total'] == 1
    assert len(result.json()['items']) == 1
    assert result.json()['items'][0]['category'] == category
    body = payload(selection=result.json()['filters'])
    checked = preview(client, body)
    assert (checked['findings_selected'], checked['assets_selected']) == (2, 1)
    result = submit(client, body, checked)
    assert result.status_code == 202, result.text
    assert db.scalar(select(AssetClassificationChangeRequest.asset_id)) == target.id


@pytest.mark.parametrize('filters', [
    {'missing_field': 'business_criticality'}, {'os': 'debian'}, {'raci_owner': 'Alice'},
    {'environment': 'QA'}, {'tag': 'blue'}, {'tag': 'service_tier:gold'},
    {'regulatory': 'PCI DSS'}, {'device_type': 'server'},
    {'q': '10.1.2.3'},
    {'subcategory': 'Linux Servers', 'missing_field': 'business_criticality', 'os': 'Debian',
     'raci_owner': 'Alice', 'environment': 'QA', 'regulatory': 'PCI DSS', 'tag': 'blue'},
])
def test_filter_contract_has_identical_list_count_preview_and_submission(client, db, filters):
    login(client, 'analyst')
    add_asset(db, 'aaa-nonmatching', os='Windows Server', context={'business_criticality': 'Low'}, tags=['blueish'])
    asset = add_asset(db, 'zzz-matching', technical={'os': 'Debian', 'device_type': 'server'},
                      context={'business_owner': 'Alice', 'environment': 'QA'},
                      tags=['blue', {'category': 'Service Tier', 'value': 'gold'}], findings=2)
    asset.ip = '10.1.2.3'
    db.add(AssetRegulatoryScope(asset_id=asset.id, scope='PCI DSS', active=True))
    db.commit()
    listed = client.get(URL, params={**filters, 'limit': 1}).json()
    assert (listed['total'], listed['assets_total']) == (2, 1)
    assert listed['items'][0]['asset']['id'] == asset.id
    body = payload(selection=filters)
    checked = preview(client, body)
    assert (checked['findings_selected'], checked['assets_selected']) == (2, 1)
    assert submit(client, body, checked).json()['requests_created'] == 1


def test_regulatory_and_tags_use_exact_membership_not_substrings(client, db):
    login(client)
    target = add_asset(db, 'target', context={'regulatory': ['SOC 2', 'PCI DSS']}, tags=['blue', 'green'])
    add_asset(db, 'other', context={'regulatory': ['SOC 2']}, tags=['blueish'])
    listed = client.get(URL, params={'regulatory': 'PCI DSS', 'tag': 'blue'}).json()
    assert listed['assets_total'] == 1 and listed['items'][0]['asset']['id'] == target.id
    assert client.get(URL, params={'regulatory': 'SOC'}).status_code == 422
    assert client.get(URL, params={'regulatory': 'PCI DSS', 'tag': 'bl'}).json()['total'] == 0


def test_persisted_regulatory_scope_is_authoritative_for_missing_fields_and_review_diff(client, db):
    login(client, 'analyst')
    asset = add_asset(db)
    db.add(AssetRegulatoryScope(asset_id=asset.id, scope='PCI DSS', active=True, approval_state='Approved'))
    db.commit()
    assert client.get(URL, params={'missing_field':'regulatory'}).json()['total'] == 0
    assert 'regulatory' not in client.get(URL).json()['items'][0]['missing_fields']
    body = payload(changes={'regulatory':['SOC 2']})
    checked = preview(client, body)
    assert checked['approval_conflicts'] == 1
    result = submit(client, body, checked)
    item = db.get(AssetClassificationChangeRequest, result.json()['request_ids'][0])
    assert item.before_context == {'regulatory':['PCI DSS']}
    assert item.proposed_context == {'regulatory':['SOC 2']}
    assert db.scalar(select(AssetRegulatoryScope.active)) is True


def test_missing_field_and_subcategory_reject_unknown_filters(client, db):
    login(client)
    add_asset(db)
    for filters in ({'missing_field': 'made_up'}, {'subcategory': 'made_up'}, {'unknown': 'silently ignored'}):
        assert client.get(URL, params=filters).status_code == 422
        assert client.post(URL+'/bulk-classify', json=payload(selection=filters, dry_run=True)).status_code == 422


def test_missing_field_preserves_false_and_respects_active_methodology(client, db):
    login(client)
    method = db.scalar(select(Methodology))
    method.configuration = {**method.configuration, 'required_context': ['privileged']}
    db.commit()
    add_asset(db, 'known-false', context={'privileged':False})
    target = add_asset(db, 'unknown')
    listed = client.get(URL, params={'missing_field':'privileged'}).json()
    assert listed['total'] == 1 and listed['items'][0]['asset']['id'] == target.id
    assert listed['items'][0]['missing_fields'] == ['privileged']


@pytest.mark.parametrize('field', ['business_owner','it_owner','application_owner','remediation_owner'])
def test_raci_owner_matches_each_role_and_unassigned_means_no_owner(client, db, field):
    login(client)
    target = add_asset(db, 'assigned', context={field:'Alice'})
    empty = add_asset(db, 'unassigned')
    assert client.get(URL, params={'raci_owner':' Alice '}).json()['items'][0]['asset']['id'] == target.id
    result = client.get(URL, params={'raci_owner':'Unassigned'}).json()
    assert result['assets_total'] == 1 and result['items'][0]['asset']['id'] == empty.id


def test_explicit_selection_deduplicates_assets_and_enforces_current_cohort(client, db):
    login(client, 'analyst')
    target = add_asset(db, findings=3)
    other = add_asset(db, 'other')
    body = payload(selection=None, asset_ids=[target.id, target.id])
    checked = preview(client, body)
    assert checked['findings_selected'] == 3 and checked['assets_selected'] == 1
    assert submit(client, body, checked).json()['requests_created'] == 1
    assert db.scalar(select(func.count()).select_from(AssetClassificationChangeRequest)) == 1
    assert client.post(URL+'/bulk-classify', json=payload(selection={}, asset_ids=[other.id], dry_run=True)).status_code == 422
    assert client.post(URL+'/bulk-classify', json=payload(selection=None, asset_ids=[99999], dry_run=True)).status_code == 422


@pytest.mark.parametrize('change', ['filter','values','context','approval','new_match','assessment','expiry','tamper','actor','workspace','evidence'])
def test_stale_or_mismatched_preview_never_creates_requests(client, db, change):
    login(client, 'analyst')
    asset = add_asset(db)
    body = payload()
    checked = preview(client, body)
    if change == 'filter': body['selection'] = {'q': 'host'}
    elif change == 'values': body['changes'] = {'business_criticality': 'Low'}
    elif change == 'evidence': body['evidence'] = 'different-evidence'
    elif change == 'context': asset.context = {'business_criticality': 'Low'}; asset.context_version += 1
    elif change == 'approval':
        db.add(AssetClassificationChangeRequest(asset_id=asset.id, workspace='Production', requested_by=1,
            expected_context_version=1, before_context={}, proposed_context={'business_criticality':'Low'},
            justification='Conflicting review', evidence='BIA-456'))
    elif change == 'new_match': add_asset(db, 'new-host')
    elif change == 'assessment':
        old = db.scalar(select(Assessment))
        db.add(Assessment(instance_id=old.instance_id, revision=2, methodology_id=old.methodology_id,
                          analyst_id=old.analyst_id, context={}, justification='Updated', decision='Pending Validation', status='Context Required'))
    elif change == 'expiry':
        audit = db.get(Audit, int(checked['preview_token'].split('.')[0])); audit.created_at = datetime.now(timezone.utc)-timedelta(minutes=16)
    elif change == 'tamper': checked['preview_token'] += 'wrong'
    elif change == 'actor': login(client)
    elif change == 'workspace':
        add_asset(db, 'demo-host', workspace='Demo'); login(client, 'analyst', environment='Demo')
    db.commit()
    response = submit(client, body, checked)
    assert response.status_code == 409, response.text
    if change != 'approval':
        assert db.scalar(select(func.count()).select_from(AssetClassificationChangeRequest)) == 0


def test_confirmation_is_required_and_single_use(client, db):
    login(client, 'analyst'); add_asset(db)
    body = payload()
    checked = preview(client, body)
    assert client.post(URL+'/bulk-classify', json=body).status_code == 422
    assert client.post(URL+'/bulk-classify', json={**body,'preview_token':checked['preview_token']}).status_code == 422
    assert submit(client, body, checked).status_code == 202
    assert submit(client, body, checked).status_code == 409
    assert db.scalar(select(func.count()).select_from(AssetClassificationChangeRequest)) == 1


def test_no_matches_workspace_and_rbac(client, db):
    login(client, 'analyst')
    foreign = add_asset(db, workspace='Demo')
    assert client.get(URL).json()['total'] == 0
    assert client.post(URL+'/bulk-classify', json=payload(dry_run=True)).status_code == 422
    local = add_asset(db, 'local')
    assert client.post(URL+'/bulk-classify', json=payload(selection=None, asset_ids=[local.id, foreign.id], dry_run=True)).status_code == 409
    login(client, 'viewer')
    assert client.get(URL).json()['assets_total'] == 1
    assert client.post(URL+'/bulk-classify', json=payload(dry_run=True)).status_code == 403


def test_pending_conflicts_block_submission_and_approved_values_are_preserved(client, db):
    login(client, 'analyst')
    asset = add_asset(db, context={'business_criticality':'Critical'})
    asset.context_provenance = {'business_criticality': {'approval_state':'Approved'}}
    pending = AssetClassificationChangeRequest(asset_id=asset.id, workspace='Production', requested_by=1,
        expected_context_version=1, before_context={}, proposed_context={'business_criticality':'Low'},
        justification='Existing review', evidence='BIA-456')
    db.add(pending); db.commit()
    body = payload()
    checked = preview(client, body)
    assert checked['approval_conflicts'] == 1 and checked['pending_conflicts'] == 1
    assert submit(client, body, checked).status_code == 409
    pending.status = 'Rejected'; db.commit()
    checked = preview(client, body)
    result = submit(client, body, checked)
    assert result.status_code == 202, result.text
    db.refresh(asset)
    assert asset.context['business_criticality'] == 'Critical' and asset.context_version == 1
    audits = db.scalars(select(Audit).where(Audit.action == 'asset.classification_change_requested.bulk')).all()
    assert audits[0].details['before'] == {'business_criticality':'Critical'}
    assert audits[0].details['proposed'] == {'business_criticality':'High'}


@pytest.mark.parametrize('derived_flags', [False, True])
def test_bulk_requires_distinct_analyst_assigned_owner_and_assigned_grc(client, db, derived_flags):
    login(client, 'analyst')
    context = {'business_criticality':'Low', 'asset_criticality':'High', 'data_classification':'Internal',
               'regulatory':['SOC 2'], 'environment':'QA', 'production':False,
               'exposure':'Internal', 'publicly_accessible':False}
    asset = add_asset(db, context=context)
    if derived_flags:
        asset.context = {**context, 'regulatory': []}
        db.add(AssetRegulatoryScope(asset_id=asset.id, scope='SOC 2', active=True, approval_state='Approved'))
    assessment = db.scalar(select(Assessment)); assessment.context = {'_technical_investigation': {'evidence':'CMDB-123'}}
    db.commit()
    body = payload(changes={'business_criticality':'High', **({'environment':'Production','exposure':'Internet Facing'} if derived_flags else {})})
    checked = preview(client, body)
    rid = submit(client, body, checked).json()['request_ids'][0]
    analyst = db.scalar(select(User).where(User.username == 'analyst'))
    admin = db.scalar(select(User).where(User.username == 'admin'))
    owner = User(username='owner', role='Security Analyst', password_hash=analyst.password_hash)
    db.add(owner); db.commit()
    assert client.get(URL+'/reviews').json()['total'] == 1
    owner_input = {'justification':'Owner validates the classification', 'evidence':'Owner attestation 123'}
    decision = {'status':'Approved','justification':'GRC independent approval'}
    assert client.post(f'/api/classification-change-requests/{rid}/owner-validation', json=owner_input).status_code == 403
    login(client)
    assert client.put(f'/api/classification-change-requests/{rid}', json=decision).status_code == 403
    for role, uid in [('owner',owner.id),('grc',admin.id)]:
        assert client.put(f'/api/assets/{asset.id}/classification-mission/reviewers', json={'role':role,'user_id':uid}).status_code == 200
    assert not client.get(URL+'/reviews').json()['items'][0]['owner_validated']
    login(client, 'owner')
    assert client.get(URL+'/reviews').json()['total'] == 1
    assert client.post(f'/api/classification-change-requests/{rid}/owner-validation', json=owner_input).status_code == 200
    assert client.put(f'/api/classification-change-requests/{rid}', json=decision).status_code == 403
    login(client)
    assert client.get(URL+'/reviews').json()['items'][0]['owner_validated']
    assert client.put(f'/api/classification-change-requests/{rid}', json=decision).status_code == 200
    db.refresh(asset)
    assert asset.context['business_criticality'] == 'High' and asset.context_version == 2
    if derived_flags:
        assert asset.context['production'] is True and asset.context['publicly_accessible'] is True
    assert db.scalar(select(Assessment).order_by(Assessment.id.desc())).status == 'Assessed'
    validated = db.scalar(select(Audit).where(Audit.action=='asset.classification_owner_validated'))
    assert validated.actor_id == owner.id and validated.details['evidence'] == owner_input['evidence']
    assert client.get(URL+'/reviews').json()['total'] == 0


def test_admin_bulk_request_cannot_self_validate_or_self_approve_or_use_job_bypass(client, db):
    from app.api.classification_jobs import process_one
    login(client); asset = add_asset(db)
    body = payload(); checked = preview(client, body)
    rid = submit(client, body, checked).json()['request_ids'][0]
    mission = db.scalar(select(AssetClassificationMission)); mission.owner_reviewer_id = 1; mission.grc_reviewer_id = 1
    db.commit()
    assert client.post(f'/api/classification-change-requests/{rid}/owner-validation', json={'justification':'Self review','evidence':'CMDB'}).status_code == 403
    assert client.put(f'/api/classification-change-requests/{rid}', json={'status':'Approved','justification':'Self approval'}).status_code == 403
    response = client.post('/api/classification-decision-jobs', json={'request_ids':[rid],'status':'Approved','justification':'Bypass attempt','idempotency_key':'cannot-bypass-owner-grc'})
    assert response.status_code == 403
    assert 'different GRC administrator' in response.json()['detail']
    assert not process_one(db)
    assert db.scalar(select(func.count()).select_from(ClassificationDecisionJob)) == 0
    db.refresh(asset)
    assert asset.context == {}
    login(client,'analyst',environment='Demo')
    assert client.get(URL+'/reviews').json()['total'] == 0
    assert client.post(f'/api/classification-change-requests/{rid}/owner-validation', json={'justification':'Other workspace','evidence':'CMDB'}).status_code == 404


def test_select_all_over_1000_assets_has_no_pagination_or_n_plus_one_dependency(client, db):
    login(client, 'analyst')
    method = db.scalar(select(Methodology)); analyst = db.scalar(select(User).where(User.username=='analyst'))
    vulnerability = Vulnerability(identity='bulk-linux', plugin_id='bulk-linux', name='Linux issue', technical={})
    db.add(vulnerability); db.flush()
    assets = [Asset(hostname=f'bulk-{i:04}', workspace='Production', os='Debian', context={}) for i in range(1005)]
    db.add_all(assets); db.flush()
    findings = [Finding(asset_id=a.id, vulnerability_id=vulnerability.id, workspace='Production', port=443,
                        protocol='tcp', source='Manual', source_record={}, observed={}, revision=1) for a in assets]
    # Two investigations on one asset must still produce one classification request.
    findings.append(Finding(asset_id=assets[0].id, vulnerability_id=vulnerability.id, workspace='Production', port=8443,
                            protocol='tcp', source='Manual', source_record={}, observed={}, revision=1))
    db.add_all(findings); db.flush()
    db.add_all([Assessment(instance_id=f.id, revision=1, methodology_id=method.id, analyst_id=analyst.id,
                           context={}, justification='Technical review', decision='Remediation Required', status='Context Required') for f in findings])
    db.commit()
    filters = {'subcategory':'Linux Servers','missing_field':'business_criticality'}
    page = client.get(URL, params={**filters,'offset':1000,'limit':100}).json()
    assert page['total'] == 1006 and page['assets_total'] == 1005 and len(page['items']) == 6
    queries = []
    def count_reads(conn, cursor, statement, *args):
        if statement.lstrip().upper().startswith('SELECT'): queries.append(statement)
    event.listen(db.bind, 'before_cursor_execute', count_reads)
    try:
        checked = preview(client, payload(selection=filters))
    finally:
        event.remove(db.bind, 'before_cursor_execute', count_reads)
    assert len(queries) < 20, len(queries)
    assert checked['assets_selected'] == 1005 and checked['findings_selected'] == 1006
    result = submit(client, payload(selection=filters), checked)
    assert result.status_code == 202, result.text
    assert result.json()['requests_created'] == 1005
    assert db.scalar(select(func.count()).select_from(AssetClassificationChangeRequest)) == 1005
