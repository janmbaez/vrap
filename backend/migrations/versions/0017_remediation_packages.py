"""Create governed remediation work packages."""
from alembic import op
import sqlalchemy as sa
revision = '0017'
down_revision = '0016'
branch_labels = None
depends_on = None
def upgrade():
    if 'remediation_packages' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('remediation_packages', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('workspace', sa.String(20), nullable=False), sa.Column('name', sa.String(200), nullable=False), sa.Column('remediation_action', sa.Text(), nullable=False), sa.Column('owner_id', sa.Integer()), sa.Column('jira_reference', sa.String(300)), sa.Column('due_date', sa.Date()), sa.Column('status', sa.String(30), nullable=False, server_default='Open'), sa.Column('blockers', sa.JSON(), nullable=False, server_default=sa.text("'[]'")), sa.Column('created_by', sa.Integer(), nullable=False), sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')), sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')))
    if 'remediation_package_findings' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('remediation_package_findings', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('package_id', sa.Integer(), nullable=False), sa.Column('finding_id', sa.Integer(), nullable=False), sa.Column('added_by', sa.Integer(), nullable=False), sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')), sa.UniqueConstraint('package_id','finding_id'))
    if 'remediation_package_evidence' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('remediation_package_evidence', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('package_id', sa.Integer(), nullable=False), sa.Column('evidence_type', sa.String(50), nullable=False), sa.Column('reference', sa.Text(), nullable=False), sa.Column('verified', sa.Boolean(), nullable=False, server_default=sa.text('false')), sa.Column('created_by', sa.Integer(), nullable=False), sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')))
    if 'remediation_package_events' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('remediation_package_events', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('package_id', sa.Integer(), nullable=False), sa.Column('action', sa.String(50), nullable=False), sa.Column('details', sa.JSON(), nullable=False, server_default=sa.text("'{}'")), sa.Column('actor_id', sa.Integer(), nullable=False), sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')))
def downgrade():
    pass
