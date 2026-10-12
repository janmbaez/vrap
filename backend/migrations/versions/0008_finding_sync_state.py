"""Separate source freshness and evidence revisions for findings.

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import sqlalchemy as sa

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    existing = {column['name'] for column in sa.inspect(bind).get_columns('vulnerability_instances')}
    if 'source_last_seen' not in existing:
        op.add_column('vulnerability_instances', sa.Column('source_last_seen', sa.Date(), nullable=True))
    if 'evidence_fingerprint' not in existing:
        op.add_column('vulnerability_instances', sa.Column('evidence_fingerprint', sa.String(length=64), nullable=True))
    if 'lifecycle_revision' not in existing:
        op.add_column('vulnerability_instances', sa.Column('lifecycle_revision', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    # Additive audit/freshness fields intentionally remain available after rollback.
    pass
