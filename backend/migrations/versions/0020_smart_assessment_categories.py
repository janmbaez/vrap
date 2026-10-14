"""Persist analyst overrides for deterministic smart assessment categories."""
from alembic import op
import sqlalchemy as sa
revision='0020'; down_revision='0019'; branch_labels=None; depends_on=None
def upgrade():
    if 'smart_assessment_categories' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('smart_assessment_categories',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('workspace', sa.String(20), nullable=False, unique=True),
            sa.Column('overrides', sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column('renames', sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column('updated_by', sa.Integer()),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')))
def downgrade():
    pass
