"""Add resumable bulk assessment jobs."""
from alembic import op
import sqlalchemy as sa

revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None

def upgrade():
    inspector = sa.inspect(op.get_bind())
    if 'bulk_assessment_jobs' not in inspector.get_table_names():
        op.create_table('bulk_assessment_jobs',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('workspace', sa.String(20), nullable=False),
            sa.Column('vulnerability_id', sa.Integer(), sa.ForeignKey('vulnerabilities.id'), nullable=False),
            sa.Column('requested_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('idempotency_key', sa.String(120), nullable=False),
            sa.Column('status', sa.String(30), nullable=False, server_default='Queued'),
            sa.Column('active_only', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('payload', sa.JSON(), nullable=False),
            sa.Column('finding_ids', sa.JSON(), nullable=False),
            sa.Column('total', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('processed', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('succeeded', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('skipped', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('failed', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('correlation_id', sa.String(64), nullable=False, unique=True),
            sa.Column('error', sa.Text()),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('started_at', sa.DateTime(timezone=True)),
            sa.Column('finished_at', sa.DateTime(timezone=True)),
            sa.UniqueConstraint('workspace', 'vulnerability_id', 'idempotency_key'),
        )
        op.create_index('ix_bulk_assessment_jobs_workspace', 'bulk_assessment_jobs', ['workspace'])
        op.create_index('ix_bulk_assessment_jobs_status', 'bulk_assessment_jobs', ['status'])
    if 'bulk_assessment_items' not in inspector.get_table_names():
        op.create_table('bulk_assessment_items',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('job_id', sa.Integer(), sa.ForeignKey('bulk_assessment_jobs.id'), nullable=False),
            sa.Column('finding_id', sa.Integer(), sa.ForeignKey('vulnerability_instances.id'), nullable=False),
            sa.Column('status', sa.String(30), nullable=False, server_default='Pending'),
            sa.Column('error', sa.Text()),
            sa.Column('assessment_id', sa.Integer(), sa.ForeignKey('assessments.id')),
            sa.Column('processed_at', sa.DateTime(timezone=True)),
            sa.UniqueConstraint('job_id', 'finding_id'),
        )
        op.create_index('ix_bulk_assessment_items_job', 'bulk_assessment_items', ['job_id'])

def downgrade():
    pass
