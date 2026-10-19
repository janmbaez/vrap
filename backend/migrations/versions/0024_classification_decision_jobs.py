"""Durable classification decisions with atomic per-request checkpoints."""
from alembic import op
import sqlalchemy as sa
revision = '0024'
down_revision = '0023'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('classification_decision_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('workspace', sa.String(20), nullable=False),
        sa.Column('requested_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('idempotency_key', sa.String(120), nullable=False),
        sa.Column('status', sa.String(30), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('request_ids', sa.JSON(), nullable=False),
        sa.Column('processed', sa.Integer(), nullable=False),
        sa.Column('succeeded', sa.Integer(), nullable=False),
        sa.Column('skipped', sa.Integer(), nullable=False),
        sa.Column('failed', sa.Integer(), nullable=False),
        sa.Column('errors', sa.JSON(), nullable=False),
        sa.UniqueConstraint('workspace', 'idempotency_key'))
    op.create_index('ix_classification_decision_jobs_workspace', 'classification_decision_jobs', ['workspace'])

def downgrade():
    op.drop_table('classification_decision_jobs')
