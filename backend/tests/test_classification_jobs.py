from conftest import login
from app.api.classification_jobs import process_one
from app.models import Asset, AssetClassificationChangeRequest, ClassificationDecisionJob

def test_durable_approval_replay_isolation_and_checkpoint(client, db):
    login(client)
    asset=Asset(hostname='job-test',workspace='Production',context={},tags=[])
    db.add(asset);db.flush()
    request=AssetClassificationChangeRequest(asset_id=asset.id,workspace='Production',requested_by=1,expected_context_version=asset.context_version,before_context={},proposed_context={'environment':'Production'},justification='Inventory evidence',evidence='CMDB')
    db.add(request);db.commit()
    body={'request_ids':[request.id], 'status':'Approved','justification':'Reviewed inventory','idempotency_key':'test-replay'}
    response=client.post('/api/classification-decision-jobs',json=body)
    assert response.status_code==202,response.text
    job_id=response.json()['id']
    assert request.status=='Requested'
    assert client.post('/api/classification-decision-jobs',json=body).json()['id']==job_id
    assert process_one(db)
    assert request.status=='Approved'
    assert asset.context['environment']=='Production'
    assert not process_one(db)
    result=client.get(f'/api/classification-decision-jobs/{job_id}').json()
    assert result['processed']==result['succeeded']==1
    assert result['status']=='Completed'
    login(client,environment='Demo')
    assert client.get(f'/api/classification-decision-jobs/{job_id}').status_code==404
    login(client,'analyst')
    assert client.post('/api/classification-decision-jobs',json=body).status_code==403

def test_conflict_does_not_block_later_requests(client, db):
    login(client)
    asset=Asset(hostname='conflict',workspace='Production',context={},tags=[])
    db.add(asset);db.flush()
    ids=[]
    for version in (999,asset.context_version):
        row=AssetClassificationChangeRequest(asset_id=asset.id,workspace='Production',requested_by=1,expected_context_version=version,before_context={},proposed_context={'environment':'Production'},justification='Inventory',evidence='CMDB')
        db.add(row);db.flush();ids.append(row.id)
    db.commit()
    response=client.post('/api/classification-decision-jobs',json={'request_ids':ids,'status':'Approved','justification':'Reviewed inventory','idempotency_key':'mixed'})
    assert response.status_code==202
    process_one(db)
    db.expire_all()  # simulate reopening a persisted checkpoint
    process_one(db)
    result=client.get(f"/api/classification-decision-jobs/{response.json()['id']}").json()
    assert result['processed']==2 and result['failed']==1 and result['succeeded']==1
    assert db.get(AssetClassificationChangeRequest,ids[0]).status=='Requested'

def test_all_pending_snapshot_is_workspace_scoped_paginated_and_retryable(client, db):
    login(client)
    asset=Asset(hostname='bulk-selection',workspace='Production',context={},tags=[])
    other=Asset(hostname='other-workspace',workspace='Demo',context={},tags=[])
    db.add_all([asset,other]); db.flush()
    rows=[AssetClassificationChangeRequest(asset_id=asset.id,workspace='Production',requested_by=1,expected_context_version=asset.context_version,before_context={},proposed_context={'environment':'Production'},justification='Evidence',evidence='CMDB') for _ in range(205)]
    rows.append(AssetClassificationChangeRequest(asset_id=other.id,workspace='Demo',requested_by=1,expected_context_version=other.context_version,before_context={},proposed_context={'environment':'Production'},justification='Evidence',evidence='CMDB'))
    db.add_all(rows);db.commit()
    page=client.get('/api/classification-change-requests?status=Requested&limit=100&offset=100').json()
    assert page['total']==205 and len(page['items'])==100
    body={'all_pending':True,'excluded_ids':[rows[0].id],'through_id':rows[-2].id,'status':'Rejected','justification':'Reviewed','idempotency_key':'snapshot'}
    result=client.post('/api/classification-decision-jobs',json=body)
    assert result.status_code==202 and result.json()['total']==204
    job=db.get(ClassificationDecisionJob,result.json()['id'])
    assert rows[0].id not in job.request_ids and rows[-1].id not in job.request_ids
    rows[1].status='Rejected'; db.commit()
    assert client.post('/api/classification-decision-jobs',json=body).json()['id']==job.id

def test_large_selection_uses_one_server_job(client, db):
    login(client)
    asset=Asset(hostname='large-selection',workspace='Production',context={},tags=[])
    db.add(asset); db.flush()
    db.bulk_insert_mappings(AssetClassificationChangeRequest, [dict(asset_id=asset.id, workspace='Production', requested_by=1, expected_context_version=asset.context_version, before_context={}, proposed_context={'environment':'Production'}, justification='Inventory', evidence='CMDB') for _ in range(37558)])
    db.commit()
    page=client.get('/api/classification-change-requests?status=Requested&limit=100').json()
    assert page['total']==37558 and len(page['items'])==100
    result=client.post('/api/classification-decision-jobs',json={'all_pending':True,'through_id':page['max_id'],'status':'Rejected','justification':'Reviewed','idempotency_key':'large-selection'})
    assert result.status_code==202 and result.json()['total']==37558
    assert process_one(db)
    assert client.get(f"/api/classification-decision-jobs/{result.json()['id']}").json()['processed']==1
