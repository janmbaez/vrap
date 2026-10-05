"""Plugin templates, workflow, exceptions and control library.

Revision ID: 0003
"""
from alembic import op
import sqlalchemy as sa
revision='0003'; down_revision='0002'; branch_labels=None; depends_on=None

def upgrade():
    op.create_table('plugin_assessment_templates',sa.Column('id',sa.Integer(),primary_key=True),sa.Column('workspace',sa.String(20),nullable=False),sa.Column('vulnerability_id',sa.Integer(),sa.ForeignKey('vulnerabilities.id'),nullable=False),sa.Column('owner_id',sa.Integer(),sa.ForeignKey('users.id')),sa.Column('status',sa.String(40),nullable=False),sa.Column('notes',sa.Text(),nullable=False),sa.Column('justification',sa.Text(),nullable=False),sa.Column('decision',sa.String(60),nullable=False),sa.Column('controls',sa.JSON(),nullable=False),sa.Column('updated_by',sa.Integer(),sa.ForeignKey('users.id'),nullable=False),sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False),sa.UniqueConstraint('workspace','vulnerability_id'))
    op.create_table('finding_workflows',sa.Column('finding_id',sa.Integer(),sa.ForeignKey('vulnerability_instances.id'),primary_key=True),sa.Column('owner_id',sa.Integer(),sa.ForeignKey('users.id')),sa.Column('status',sa.String(40),nullable=False),sa.Column('updated_by',sa.Integer(),sa.ForeignKey('users.id'),nullable=False),sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False))
    op.create_table('risk_exceptions',sa.Column('id',sa.Integer(),primary_key=True),sa.Column('workspace',sa.String(20),nullable=False),sa.Column('finding_id',sa.Integer(),sa.ForeignKey('vulnerability_instances.id'),nullable=False),sa.Column('justification',sa.Text(),nullable=False),sa.Column('evidence',sa.Text(),nullable=False),sa.Column('status',sa.String(30),nullable=False),sa.Column('requested_by',sa.Integer(),sa.ForeignKey('users.id'),nullable=False),sa.Column('approved_by',sa.Integer(),sa.ForeignKey('users.id')),sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),sa.Column('review_frequency_days',sa.Integer(),nullable=False),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),sa.Column('reviewed_at',sa.DateTime(timezone=True)))
    op.create_table('control_library',sa.Column('id',sa.Integer(),primary_key=True),sa.Column('workspace',sa.String(20),nullable=False),sa.Column('name',sa.String(100),nullable=False),sa.Column('description',sa.Text(),nullable=False),sa.Column('owner_id',sa.Integer(),sa.ForeignKey('users.id')),sa.Column('evidence_requirements',sa.Text(),nullable=False),sa.Column('mappings',sa.JSON(),nullable=False),sa.Column('design_maturity',sa.Integer()),sa.Column('operating_effectiveness',sa.Integer()),sa.Column('last_tested_at',sa.DateTime(timezone=True)),sa.Column('active',sa.Boolean(),nullable=False),sa.Column('updated_by',sa.Integer(),sa.ForeignKey('users.id'),nullable=False),sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False),sa.UniqueConstraint('workspace','name'))

def downgrade():
    for name in ('control_library','risk_exceptions','finding_workflows','plugin_assessment_templates'): op.drop_table(name)
