from sqlalchemy import select
from app.models import FindingWorkflow, User, ReviewCampaign, Audit
from app.campaigns import activate
from conftest import login
from test_campaigns import populate, make_campaign


def test_standalone_review_preserves_remediation_and_owner(client, db):
    ids, _ = populate(db)
    db.add(FindingWorkflow(finding_id=ids[0], status='In Remediation', owner_id=2, updated_by=2))
    db.commit()
    login(client)
    result = client.put(f'/api/findings/{ids[0]}/workflow', json={'status': 'Reviewed', 'owner_id': None})
    assert result.status_code == 200, result.text
    db.expire_all()
    workflow = db.get(FindingWorkflow, ids[0])
    assert workflow.status == 'In Remediation' and workflow.owner_id == 2
    assert workflow.review_state == 'Reviewed' and workflow.reviewed_by == 1 and workflow.reviewed_at
    detail = client.get(f'/api/findings/{ids[0]}').json()
    assert detail['review_state'] == 'Reviewed' and detail['reviewed_at']
    weekly = client.get('/api/review-report?days=7').json()
    assert weekly['summary']['reviewed_in_period'] == 1
    assert weekly['reviews'][0]['finding_id'] == ids[0]


def test_global_audit_honors_campaign_visibility_and_environment(client, db):
    populate(db)
    production = make_campaign(db)
    demo = make_campaign(db, workspace='Demo')
    for campaign in (production, demo):
        db.add(Audit(actor_id=1, entity='review_campaign', entity_id=campaign.id,
                     action='campaign.created', details={'workspace': campaign.workspace}))
    db.commit()
    login(client)
    rows = client.get('/api/audit').json()
    assert {r['entity_id'] for r in rows if r['entity'] == 'review_campaign'} == {production.id}
    login(client, 'viewer')
    assert not [r for r in client.get('/api/audit').json() if r['entity'] == 'review_campaign']
    production.status = 'Completed'
    db.commit()
    assert {r['entity_id'] for r in client.get('/api/audit').json() if r['entity'] == 'review_campaign'} == {production.id}


def test_saved_scope_and_live_findings_use_same_and_query(client, db):
    ids, _ = populate(db, 3)
    login(client)
    scope = {'business_owner': 'Finance', 'asset_group': 'Servers', 'asset_tag': 'location:East', 'severity': 'Critical'}
    saved = client.post('/api/saved-filters', json={'name': 'Finance review scope', 'filters': scope})
    assert saved.status_code == 201, saved.text
    preview = client.post('/api/review-campaigns/preview', json={'scope': saved.json()['filters']})
    listing = client.get('/api/findings', params=scope)
    assert preview.status_code == listing.status_code == 200
    assert preview.json()['total'] == listing.json()['total'] == 3
    assert {r['id'] for r in listing.json()['items']} == set(ids)
