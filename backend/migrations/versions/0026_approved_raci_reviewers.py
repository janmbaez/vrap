"""Approved, workspace-scoped RACI team to owner-validator delegation."""
from alembic import op
import sqlalchemy as sa

revision = '0026'
down_revision = '0025'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('approved_raci_reviewer_mappings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('workspace', sa.String(20), nullable=False),
        sa.Column('owner_name', sa.String(200), nullable=False),
        sa.Column('validator_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('approved_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('workspace', 'owner_name'))
    op.create_index('ix_approved_raci_reviewer_mappings_workspace',
                    'approved_raci_reviewer_mappings', ['workspace'])


def downgrade():
    op.drop_table('approved_raci_reviewer_mappings')
