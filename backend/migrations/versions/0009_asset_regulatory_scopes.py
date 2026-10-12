"""Add governed asset regulatory scope memberships.

Revision ID: 0009
Revises: 0008
"""
import json
from alembic import op
import sqlalchemy as sa

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    if 'asset_regulatory_scopes' not in sa.inspect(bind).get_table_names():
        op.create_table('asset_regulatory_scopes',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id'), nullable=False),
            sa.Column('scope', sa.String(length=40), nullable=False),
            sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
            sa.Column('source_system', sa.String(length=80), nullable=False, server_default='legacy'),
            sa.Column('source_record_id', sa.String(length=200)),
            sa.Column('approval_state', sa.String(length=40), nullable=False, server_default='Pending verification'),
            sa.Column('verified_by', sa.Integer(), sa.ForeignKey('users.id')),
            sa.Column('verified_at', sa.DateTime(timezone=True)),
            sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
            sa.Column('removed_at', sa.DateTime(timezone=True)),
            sa.UniqueConstraint('asset_id', 'scope'),
        )
    rows = bind.execute(sa.text('SELECT id, context FROM assets')).mappings()
    for row in rows:
        context = row['context']
        if isinstance(context, str):
            try: context = json.loads(context)
            except ValueError: context = {}
        for scope in (context or {}).get('regulatory', []):
            if scope and scope != 'None':
                exists = bind.execute(sa.text('SELECT 1 FROM asset_regulatory_scopes WHERE asset_id = :asset_id AND scope = :scope'), {'asset_id': row['id'], 'scope': str(scope)}).scalar()
                if not exists:
                    bind.execute(sa.text("INSERT INTO asset_regulatory_scopes (asset_id, scope, active, source_system, approval_state, valid_from) VALUES (:asset_id, :scope, 1, 'legacy', 'Pending verification', CURRENT_TIMESTAMP)"), {'asset_id': row['id'], 'scope': str(scope)})

def downgrade():
    # Membership history is retained for audit even if application code is rolled back.
    pass
