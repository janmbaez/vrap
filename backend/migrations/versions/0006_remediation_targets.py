"""Add remediation ownership evidence and target dates.

Revision ID: 0006
"""
from alembic import op
import sqlalchemy as sa

revision='0006'; down_revision='0005'; branch_labels=None; depends_on=None

def upgrade():
    bind=op.get_bind(); existing={c['name'] for c in sa.inspect(bind).get_columns('finding_workflows')}
    for column in (sa.Column('remediation_due_at',sa.DateTime(timezone=True),nullable=True),sa.Column('remediation_evidence',sa.Text(),nullable=True)):
        if column.name not in existing: op.add_column('finding_workflows',column)

def downgrade():
    pass
