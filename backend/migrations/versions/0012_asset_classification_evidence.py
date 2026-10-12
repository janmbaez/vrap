"""Add classification mission evidence lineage.

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa
revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None

def upgrade():
    if 'asset_classification_evidence' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('asset_classification_evidence',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('mission_id', sa.Integer(), sa.ForeignKey('asset_classification_missions.id'), nullable=False),
            sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), nullable=False),
            sa.Column('workspace', sa.String(length=20), nullable=False, server_default='Production'),
            sa.Column('evidence_type', sa.String(length=60), nullable=False),
            sa.Column('reference', sa.Text(), nullable=False),
            sa.Column('notes', sa.Text(), nullable=False, server_default=''),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        )
        op.create_index('ix_asset_classification_evidence_mission', 'asset_classification_evidence', ['mission_id'])

def downgrade():
    # Evidence is retained as audit material on application rollback.
    pass
