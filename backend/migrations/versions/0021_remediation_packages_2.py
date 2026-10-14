"""Add remediation coordination and per-finding verification state."""
from alembic import op
import sqlalchemy as sa

revision = '0021'
down_revision = '0020'
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind(); inspector = sa.inspect(bind)
    cols = {c['name'] for c in inspector.get_columns('remediation_packages')}
    for name, typ in [('change_window', sa.String(120)), ('source', sa.String(30)), ('suggestion_key', sa.String(300))]:
        if name not in cols:
            op.add_column('remediation_packages', sa.Column(name, typ, nullable=True))
    cols = {c['name'] for c in inspector.get_columns('remediation_package_findings')}
    additions = [('remediation_status', sa.String(30), 'Unknown'), ('verified_at', sa.DateTime(timezone=True), None), ('verified_by', sa.Integer(), None), ('evidence_id', sa.Integer(), None)]
    for name, typ, default in additions:
        if name not in cols:
            op.add_column('remediation_package_findings', sa.Column(name, typ, nullable=True, server_default=default if default else None))
    op.create_index('ix_remediation_package_finding_status', 'remediation_package_findings', ['remediation_status'], if_not_exists=True)

def downgrade():
    pass
