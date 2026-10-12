"""Add resumable asset classification mission drafts.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade():
    if 'asset_classification_missions' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            'asset_classification_missions',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), nullable=False),
            sa.Column('workspace', sa.String(length=20), nullable=False, server_default='Production'),
            sa.Column('questionnaire_version', sa.String(length=50), nullable=False, server_default='1.0-provisional'),
            sa.Column('status', sa.String(length=40), nullable=False, server_default='Draft'),
            sa.Column('current_step', sa.Integer(), nullable=False, server_default='1'),
            sa.Column('responses', sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('updated_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.UniqueConstraint('workspace', 'asset_id'),
        )


def downgrade():
    # Questionnaire drafts are governance evidence and are intentionally retained.
    pass
