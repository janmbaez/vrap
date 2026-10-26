"""Disposable PostgreSQL proof of large-job blocking and restart recovery."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import (Asset, AssetClassificationChangeRequest as Change,
                        AssetClassificationMission as Mission, Audit,
                        ClassificationDecisionJob as Job, Methodology, User)
from app.api.classification_jobs import process_one
from app.risk.policy import DEFAULT


@pytest.mark.skipif(not os.environ.get('VRAP_TEST_DATABASE_URL'), reason='Disposable PostgreSQL test URL required')
def test_postgresql_thousand_request_preflight_restart_and_independent_approval():
    source = make_url(os.environ['VRAP_TEST_DATABASE_URL'])
    assert source.drivername.startswith('postgresql') and 'test' in source.database
    assert source.host in ('127.0.0.1', 'localhost')
    temporary_name = f'vrap_approval_test_{uuid4().hex[:12]}'
    maintenance = create_engine(source.set(database='postgres'), isolation_level='AUTOCOMMIT')
    with maintenance.connect() as connection:
        connection.exec_driver_sql(f'CREATE DATABASE {temporary_name}')
    engine = create_engine(source.set(database=temporary_name))
    try:
        Base.metadata.create_all(engine)
        Session = sessionmaker(engine, expire_on_commit=False)
        with Session() as db:
            db.add_all([User(id=1, username='grc', password_hash='test', role='Administrator'),
                        User(id=2, username='analyst', password_hash='test', role='Security Analyst'),
                        User(id=3, username='owner', password_hash='test', role='Security Analyst'),
                        Methodology(version='1.0', configuration=DEFAULT)])
            db.flush()
            assets = [Asset(hostname=f'pg-{n:04d}', workspace='Production', context={}) for n in range(1000)]
            db.add_all(assets);db.flush()
            requests = [Change(asset_id=asset.id, workspace='Production', requested_by=2,
                expected_context_version=asset.context_version, before_context={},
                proposed_context={'business_criticality':'High'},
                justification='CMDB review', evidence='CMDB-123') for asset in assets]
            db.add_all(requests);db.flush()
            db.add_all([Audit(actor_id=2, action='asset.classification_change_requested.bulk',
                entity='asset', entity_id=asset.id,
                details={'workspace':'Production', 'request_id':item.id})
                for asset, item in zip(assets, requests)])
            job = Job(workspace='Production', requested_by=1, idempotency_key='old-1000',
                status='Queued', payload={'status':'Approved', 'justification':'GRC'},
                request_ids=[item.id for item in requests])
            db.add(job);db.commit()
            assert process_one(db)
            db.refresh(job)
            assert (job.status, job.processed, job.succeeded, job.failed) == ('Blocked', 0, 0, 0)
            assert db.scalar(select(Change.status).where(Change.id == requests[0].id)) == 'Requested'
        # Reopen the checkpoint as a restarted worker would. A blocked job stays idle.
        with Session() as db:
            assert not process_one(db)
            first = db.get(Change, requests[0].id)
            mission = Mission(asset_id=first.asset_id, workspace='Production', created_by=2,
                updated_by=3, owner_reviewer_id=3, grc_reviewer_id=1)
            db.add(mission)
            db.add(Audit(actor_id=3, action='asset.classification_owner_validated',
                entity='classification_change_request', entity_id=first.id,
                details={'workspace':'Production', 'context_version':first.expected_context_version,
                         'proposed':first.proposed_context, 'evidence':'Owner attestation',
                         'justification':'I verified the asset'}))
            ready = Job(workspace='Production', requested_by=1, idempotency_key='ready-one',
                status='Queued', payload={'status':'Approved', 'justification':'Independent GRC review'},
                request_ids=[first.id])
            db.add(ready);db.commit()
            assert process_one(db)
            db.refresh(ready);db.refresh(first)
            assert ready.status == 'Completed' and ready.succeeded == 1
            assert first.status == 'Approved'
            assert db.get(Asset, first.asset_id).context['business_criticality'] == 'High'
            assert db.get(Job, job.id).status == 'Blocked'
    finally:
        engine.dispose()
        with maintenance.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE {temporary_name} WITH (FORCE)')
        maintenance.dispose()
