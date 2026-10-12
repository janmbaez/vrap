"""Add governed asset classification change requests.

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade():
    if 'asset_classification_change_requests' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            'asset_classification_change_requests',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), nullable=False),
            sa.Column('workspace', sa.String(length=20), nullable=False, server_default='Production'),
            sa.Column('requested_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('approved_by', sa.Integer(), sa.ForeignKey('users.id')),
            sa.Column('status', sa.String(length=30), nullable=False, server_default='Requested'),
            sa.Column('expected_context_version', sa.Integer(), nullable=False),
            sa.Column('before_context', sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column('proposed_context', sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column('justification', sa.Text(), nullable=False),
            sa.Column('evidence', sa.Text(), nullable=False, server_default=''),
            sa.Column('decision_justification', sa.Text(), nullable=False, server_default=''),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('reviewed_at', sa.DateTime(timezone=True)),
            sa.Column('applied_at', sa.DateTime(timezone=True)),
        )
        op.create_index('ix_asset_classification_change_requests_workspace_status',
                        'asset_classification_change_requests', ['workspace', 'status'])


def downgrade():
    # Requests are durable governance/audit evidence and intentionally retained.
    pass
