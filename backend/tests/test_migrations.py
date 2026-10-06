"""Real Alembic upgrade proof, never pointed at an application database."""
from pathlib import Path
import os
import subprocess
import sys

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, inspect, text

ROOT = Path(__file__).resolve().parents[1]

def upgrade(connection, revision):
    configuration = Config(str(ROOT / 'alembic.ini'))
    configuration.set_main_option('script_location', str(ROOT / 'migrations'))
    configuration.attributes['connection'] = connection
    command.upgrade(configuration, revision)
    connection.commit()

def preservation_check(engine):
    with engine.connect() as connection:
        upgrade(connection, '0004')
        assert 'reviewed_at' not in {column['name'] for column in inspect(connection).get_columns('finding_workflows')}
        existing_tables = set(inspect(connection).get_table_names())
        connection.execute(text("INSERT INTO users (id,username,password_hash,role,active) VALUES (910001,'migration-check','test-only','Administrator',true)"))
        connection.execute(text("INSERT INTO assets (id,hostname,workspace,tags,context) VALUES (910001,'preserved-host','Production','[]','{\"business_owner\":\"Preserved owner\"}')"))
        connection.execute(text("INSERT INTO vulnerabilities (id,identity,name,cves,technical) VALUES (910001,'migration-check','Preserved vulnerability','[]','{}')"))
        connection.execute(text("INSERT INTO vulnerability_instances (id,asset_id,vulnerability_id,port,protocol,source,source_record,observed,revision,workspace) VALUES (910001,910001,910001,443,'tcp','Manual','{}','{}',5,'Production')"))
        connection.execute(text("INSERT INTO finding_workflows (finding_id,owner_id,status,updated_by,updated_at) VALUES (910001,910001,'Remediation Planned',910001,CURRENT_TIMESTAMP)"))
        connection.commit()
        before = {}
        for table in ('users', 'assets', 'vulnerabilities', 'vulnerability_instances', 'finding_workflows'):
            before[table] = [dict(row) for row in connection.execute(text(f'SELECT * FROM {table}')).mappings()]
        upgrade(connection, 'head')
        upgrade(connection, 'head')  # restart/idempotence
        assert existing_tables <= set(inspect(connection).get_table_names())
        for table, rows in before.items():
            after = [dict(row) for row in connection.execute(text(f'SELECT * FROM {table}')).mappings()]
            assert [{k: row[k] for k in rows[0]} for row in after] == rows
        assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0005'
        assert 'review_campaigns' in inspect(connection).get_table_names()
        assert 'reviewed_at' in {column['name'] for column in inspect(connection).get_columns('finding_workflows')}

def test_additive_migration_preserves_pre_feature_data(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path}/migration-only.db')
    try:
        preservation_check(engine)
    finally:
        engine.dispose()

@pytest.mark.skipif(not os.environ.get('VRAP_TEST_DATABASE_URL'), reason='Requires a fresh disposable PostgreSQL test database')
def test_postgresql_additive_migration():
    engine = create_engine(os.environ['VRAP_TEST_DATABASE_URL'])
    # Refuse nonempty databases, including existing application volumes.
    assert not inspect(engine).get_table_names(), 'PostgreSQL test must use a fresh disposable database'
    try:
        preservation_check(engine)
    finally:
        engine.dispose()

def test_concurrent_startup_and_restart_do_not_duplicate_seed(tmp_path):
    url = f'sqlite:///{tmp_path}/startup-only.db'
    environment = {**os.environ, 'DATABASE_URL': url, 'PYTHONPATH': str(ROOT),
                   'BOOTSTRAP_USER': 'startup-test', 'BOOTSTRAP_PASSWORD': 'Test-only-startup-password!'}
    args = [sys.executable, '-m', 'app.bootstrap', '--demo']
    processes = [subprocess.Popen(args, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr.decode()
    assert subprocess.run(args, env=environment, capture_output=True, timeout=30).returncode == 0
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT COUNT(*) FROM users')) == 1
            assert connection.scalar(text('SELECT COUNT(*) FROM vulnerability_instances')) == 20
            assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0005'
    finally:
        engine.dispose()
