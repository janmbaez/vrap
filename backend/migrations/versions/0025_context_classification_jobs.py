"""Durable, resumable context classification submissions."""
from alembic import op
import sqlalchemy as sa

revision = '0025'
down_revision = '0024'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('context_classification_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('workspace', sa.String(20), nullable=False),
        sa.Column('preview_id', sa.Integer(), sa.ForeignKey('audit_log.id'), nullable=False),
        sa.Column('requested_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(30), nullable=False),
        sa.Column('asset_ids', sa.JSON(), nullable=False),
        sa.Column('total_assets', sa.Integer(), nullable=False),
        sa.Column('proposals', sa.JSON(), nullable=False),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('processed', sa.Integer(), nullable=False),
        sa.Column('awaiting_approval', sa.Integer(), nullable=False),
        sa.Column('unchanged', sa.Integer(), nullable=False),
        sa.Column('conflicted', sa.Integer(), nullable=False),
        sa.Column('failed', sa.Integer(), nullable=False),
        sa.Column('errors', sa.JSON(), nullable=False),
        sa.Column('retry_ids', sa.JSON(), nullable=False),
        sa.UniqueConstraint('workspace', 'preview_id'))
    op.create_index('ix_context_classification_jobs_workspace', 'context_classification_jobs', ['workspace'])


def downgrade():
    op.drop_table('context_classification_jobs')
