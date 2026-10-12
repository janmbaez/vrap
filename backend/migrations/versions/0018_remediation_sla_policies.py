"""Add effective-dated remediation SLA policies."""
from alembic import op
import sqlalchemy as sa
revision='0018'; down_revision='0017'; branch_labels=None; depends_on=None
def upgrade():
    if 'remediation_sla_policies' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('remediation_sla_policies', sa.Column('id',sa.Integer(),primary_key=True),sa.Column('workspace',sa.String(20),nullable=False),sa.Column('version',sa.Integer(),nullable=False,server_default='1'),sa.Column('name',sa.String(160),nullable=False),sa.Column('regulatory_scope',sa.String(40),nullable=False),sa.Column('severity',sa.String(20),nullable=False),sa.Column('days',sa.Integer()),sa.Column('effective_from',sa.Date(),nullable=False),sa.Column('effective_to',sa.Date()),sa.Column('approved',sa.Boolean(),nullable=False,server_default=sa.text('false')),sa.Column('created_by',sa.Integer(),nullable=False),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.text('CURRENT_TIMESTAMP')))
def downgrade(): pass
