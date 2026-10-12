"""Add methodology lifecycle and control validation metadata."""
from alembic import op
import sqlalchemy as sa
revision='0019'; down_revision='0018'; branch_labels=None; depends_on=None
def upgrade():
    b=op.get_bind(); i=sa.inspect(b)
    m={c['name'] for c in i.get_columns('risk_methodologies')}; c={x['name'] for x in i.get_columns('control_library')}
    for n,col in [('lifecycle_status',sa.String(30)),('approved_by',sa.Integer()),('approved_at',sa.DateTime(timezone=True))]:
        if n not in m: op.add_column('risk_methodologies',sa.Column(n,col,nullable=True))
    for n,col in [('version',sa.Integer()),('validator_id',sa.Integer()),('expires_at',sa.DateTime(timezone=True)),('recertification_days',sa.Integer())]:
        if n not in c: op.add_column('control_library',sa.Column(n,col,nullable=True))
def downgrade(): pass
