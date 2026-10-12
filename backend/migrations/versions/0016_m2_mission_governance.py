"""Add M2 mission reviewer assignment and evidence expiry metadata."""
from alembic import op
import sqlalchemy as sa

revision = '0016'
down_revision = '0015'
branch_labels = None
depends_on = None

def upgrade():
    inspector = sa.inspect(op.get_bind())
    mission = {c['name'] for c in inspector.get_columns('asset_classification_missions')}
    evidence = {c['name'] for c in inspector.get_columns('asset_classification_evidence')}
    if 'owner_reviewer_id' not in mission:
        op.add_column('asset_classification_missions', sa.Column('owner_reviewer_id', sa.Integer(), nullable=True))
    if 'grc_reviewer_id' not in mission:
        op.add_column('asset_classification_missions', sa.Column('grc_reviewer_id', sa.Integer(), nullable=True))
    if 'expires_at' not in evidence:
        op.add_column('asset_classification_evidence', sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True))

def downgrade():
    pass
