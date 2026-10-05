"""Environment isolation, asset rules, stored integration configuration and GRC maturity.

Revision ID: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def _columns(inspector, table):
    return {column['name'] for column in inspector.get_columns(table)}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    additions = {
        'sessions': [('workspace', sa.String(20), 'Production')],
        'assets': [('workspace', sa.String(20), 'Production')],
        'vulnerability_instances': [('workspace', sa.String(20), 'Production')],
        'imports': [('workspace', sa.String(20), 'Production')],
        'tenable_sync_history': [('workspace', sa.String(20), 'Production')],
        'assessment_controls': [('design_maturity', sa.Integer(), None), ('operating_effectiveness', sa.Integer(), None)],
        'integration_settings': [
            ('access_key_encrypted', sa.Text(), None),
            ('secret_key_encrypted', sa.Text(), None),
            ('base_url', sa.String(500), 'https://cloud.tenable.com'),
        ],
    }
    for table, columns in additions.items():
        existing = _columns(inspector, table)
        for name, type_, default in columns:
            if name not in existing:
                op.add_column(table, sa.Column(name, type_, nullable=default is None, server_default=default))

    if 'asset_rules' not in set(inspector.get_table_names()):
        op.create_table(
            'asset_rules',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('name', sa.String(200), nullable=False, unique=True),
            sa.Column('priority', sa.Integer(), nullable=False),
            sa.Column('active', sa.Boolean(), nullable=False),
            sa.Column('match_type', sa.String(30), nullable=False),
            sa.Column('match_value', sa.String(300), nullable=False),
            sa.Column('context', sa.JSON(), nullable=False),
            sa.Column('controls', sa.JSON(), nullable=False),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        )

    # Replace the original global asset uniqueness with workspace-local identity.
    inspector = sa.inspect(bind)
    uniques = inspector.get_unique_constraints('assets')
    singles = [item for item in uniques if item.get('column_names') in (['hostname'], ['external_id'])]
    composites = {tuple(item.get('column_names') or []) for item in uniques}
    if bind.dialect.name == 'postgresql':
        for item in singles:
            if item.get('name'):
                op.drop_constraint(item['name'], 'assets', type_='unique')
        if ('workspace', 'hostname') not in composites:
            op.create_unique_constraint('uq_assets_workspace_hostname', 'assets', ['workspace', 'hostname'])
        if ('workspace', 'external_id') not in composites:
            op.create_unique_constraint('uq_assets_workspace_external_id', 'assets', ['workspace', 'external_id'])

    op.execute("UPDATE vulnerability_instances SET workspace='Demo' WHERE source='Demo'")
    op.execute("UPDATE assets SET workspace='Demo' WHERE id IN (SELECT asset_id FROM vulnerability_instances WHERE source='Demo')")


def downgrade():
    op.drop_table('asset_rules')
    for table, columns in [
        ('integration_settings', ['base_url', 'secret_key_encrypted', 'access_key_encrypted']),
        ('assessment_controls', ['operating_effectiveness', 'design_maturity']),
        ('tenable_sync_history', ['workspace']), ('imports', ['workspace']),
        ('vulnerability_instances', ['workspace']), ('assets', ['workspace']), ('sessions', ['workspace']),
    ]:
        for column in columns:
            op.drop_column(table, column)
