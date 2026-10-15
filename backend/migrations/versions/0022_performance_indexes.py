"""Indexes for bounded remediation and workspace-scoped reads."""
from alembic import op
import sqlalchemy as sa
revision = '0022'; down_revision = '0021'; branch_labels = None; depends_on = None
def upgrade():
    op.create_index('ix_finding_workspace_vulnerability', 'vulnerability_instances', ['workspace','vulnerability_id'], if_not_exists=True)
    op.create_index('ix_finding_workspace_asset', 'vulnerability_instances', ['workspace','asset_id'], if_not_exists=True)
    op.create_index('ix_workflow_status_owner', 'finding_workflows', ['status','owner_id'], if_not_exists=True)
def downgrade():
    pass
