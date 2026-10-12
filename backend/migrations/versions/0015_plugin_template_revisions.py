"""Version plugin assessment templates and preserve revisions."""
from alembic import op
import sqlalchemy as sa

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None

def upgrade():
    inspector = sa.inspect(op.get_bind())
    columns = {c['name'] for c in inspector.get_columns('plugin_assessment_templates')}
    if 'template_version' not in columns: op.add_column('plugin_assessment_templates', sa.Column('template_version', sa.Integer(), nullable=False, server_default='1'))
    if 'applicability' not in columns: op.add_column('plugin_assessment_templates', sa.Column('applicability', sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    if 'technical_rationale' not in columns: op.add_column('plugin_assessment_templates', sa.Column('technical_rationale', sa.Text(), nullable=False, server_default=''))
    if 'plugin_assessment_template_revisions' not in inspector.get_table_names():
        op.create_table('plugin_assessment_template_revisions',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('template_id', sa.Integer(), sa.ForeignKey('plugin_assessment_templates.id'), nullable=False),
            sa.Column('workspace', sa.String(20), nullable=False),
            sa.Column('vulnerability_id', sa.Integer(), sa.ForeignKey('vulnerabilities.id'), nullable=False),
            sa.Column('version', sa.Integer(), nullable=False),
            sa.Column('snapshot', sa.JSON(), nullable=False),
            sa.Column('changed_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        )
        op.create_index('ix_plugin_assessment_template_revisions_template', 'plugin_assessment_template_revisions', ['template_id'])

def downgrade():
    pass
