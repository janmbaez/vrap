"""Initial VRAP schema.

Revision ID: 0001
"""
from alembic import op
from app.db import Base
from app import models
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Initial tables only: later additive revisions own their own tables.
    # This prevents importing current models from creating future schema early.
    names = ('users', 'sessions', 'assets', 'vulnerabilities',
             'vulnerability_instances', 'risk_methodologies', 'assessments',
             'assessment_controls', 'risk_scores', 'audit_log', 'imports',
             'import_rows', 'tenable_sync_history', 'integration_settings')
    Base.metadata.create_all(bind=op.get_bind(), tables=[Base.metadata.tables[n] for n in names])

def downgrade():
    Base.metadata.drop_all(bind=op.get_bind())
