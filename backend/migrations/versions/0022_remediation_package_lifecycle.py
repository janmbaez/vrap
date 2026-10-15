"""Add archive lifecycle fields to remediation packages."""
from alembic import op
import sqlalchemy as sa

revision = '0023'
down_revision = '0022'
branch_labels = None
depends_on = None

def upgrade():
    cols = {c['name'] for c in sa.inspect(op.get_bind()).get_columns('remediation_packages')}
    if 'archived_at' not in cols:
        op.add_column('remediation_packages', sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True))
    if 'archived_by' not in cols:
        op.add_column('remediation_packages', sa.Column('archived_by', sa.Integer(), nullable=True))
    op.create_index('ix_remediation_packages_archived_at', 'remediation_packages', ['archived_at'], if_not_exists=True)

def downgrade():
    pass
