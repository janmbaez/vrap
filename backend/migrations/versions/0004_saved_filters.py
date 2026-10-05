"""Saved vulnerability filters.

Revision ID: 0004
"""
from alembic import op
import sqlalchemy as sa
revision='0004'; down_revision='0003'; branch_labels=None; depends_on=None

def upgrade():
    op.create_table('saved_filters',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('workspace',sa.String(20),nullable=False),
        sa.Column('user_id',sa.Integer(),sa.ForeignKey('users.id'),nullable=False),
        sa.Column('name',sa.String(100),nullable=False),
        sa.Column('filters',sa.JSON(),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.UniqueConstraint('workspace','user_id','name'))

def downgrade(): op.drop_table('saved_filters')
