"""Add immutable classification mission history.

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import sqlalchemy as sa

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None

def upgrade():
    if 'asset_classification_mission_history' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('asset_classification_mission_history',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('mission_id', sa.Integer(), sa.ForeignKey('asset_classification_missions.id'), nullable=False),
            sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), nullable=False),
            sa.Column('workspace', sa.String(length=20), nullable=False, server_default='Production'),
            sa.Column('action', sa.String(length=50), nullable=False),
            sa.Column('status', sa.String(length=50), nullable=False),
            sa.Column('current_step', sa.Integer(), nullable=False),
            sa.Column('responses', sa.JSON(), nullable=False),
            sa.Column('actor_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        )
        op.create_index('ix_asset_classification_mission_history_mission', 'asset_classification_mission_history', ['mission_id', 'created_at'])

def downgrade():
    pass
