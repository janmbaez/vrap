"""Add versioned provenance storage for authoritative asset context.

Revision ID: 0007
"""
from alembic import op
import sqlalchemy as sa

revision='0007'; down_revision='0006'; branch_labels=None; depends_on=None

def upgrade():
    bind=op.get_bind(); existing={c['name'] for c in sa.inspect(bind).get_columns('assets')}
    if 'context_version' not in existing:
        op.add_column('assets', sa.Column('context_version', sa.Integer(), nullable=False, server_default='1'))
    if 'context_provenance' not in existing:
        op.add_column('assets', sa.Column('context_provenance', sa.JSON(), nullable=False, server_default=sa.text("'{}'")))

def downgrade():
    # Deliberately additive: provenance remains available for audit after rollback.
    pass
