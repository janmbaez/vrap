"""Add immutable campaign populations and separate live review fields.

Revision ID: 0005
"""
from alembic import op
import sqlalchemy as sa
from app.models import (ReviewCampaign,CampaignReviewer,CampaignFinding,CampaignFindingTag,
                        CampaignEvidence,CampaignAuditEvent)

revision='0005';down_revision='0004';branch_labels=None;depends_on=None

def upgrade():
    bind=op.get_bind()
    # Initial migration imports current metadata, so fresh and pre-feature installs both work.
    existing={c['name'] for c in sa.inspect(bind).get_columns('finding_workflows')}
    columns=[sa.Column('review_state',sa.String(30),nullable=True),
             sa.Column('reviewed_at',sa.DateTime(timezone=True),nullable=True),
             sa.Column('reviewed_by',sa.Integer(),nullable=True),
             sa.Column('review_decision',sa.String(80),nullable=True),
             sa.Column('review_notes',sa.Text(),nullable=True)]
    for column in columns:
        if column.name not in existing: op.add_column('finding_workflows',column)
    # PostgreSQL enforces reviewer identity on an existing table; SQLite's additive ALTER
    # cannot add FK constraints without rebuilding, which this migration deliberately avoids.
    if bind.dialect.name=='postgresql':
        foreign_keys=sa.inspect(bind).get_foreign_keys('finding_workflows')
        if not any(fk['constrained_columns']==['reviewed_by'] for fk in foreign_keys):
            op.create_foreign_key('fk_workflow_reviewed_by','finding_workflows','users',['reviewed_by'],['id'])
    for model in (ReviewCampaign,CampaignReviewer,CampaignFinding,CampaignFindingTag,CampaignEvidence,CampaignAuditEvent):
        model.__table__.create(bind,checkfirst=True)

def downgrade():
    # Production rollback changes the image, keeping the compatible additive schema and evidence.
    pass
