from datetime import date, datetime, timezone
from sqlalchemy import String, Integer, JSON, ForeignKey, Text, Boolean, DateTime, Date, UniqueConstraint, Float, Index, text
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(30))
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class Session(Base):
    __tablename__ = 'sessions'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    workspace: Mapped[str] = mapped_column(String(20), default='Production')

class Asset(Base):
    __tablename__ = 'assets'
    __table_args__ = (UniqueConstraint('workspace', 'hostname'), UniqueConstraint('workspace', 'external_id'))
    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str | None] = mapped_column(String(200))
    hostname: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(60))
    os: Mapped[str | None] = mapped_column(String(200))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    # Context is versioned so a later classification workflow can reject stale writes.
    context_version: Mapped[int] = mapped_column(Integer, default=1, server_default='1')
    context_provenance: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'"))
    workspace: Mapped[str] = mapped_column(String(20), default='Production')

class AssetRegulatoryScope(Base):
    __tablename__ = 'asset_regulatory_scopes'
    __table_args__ = (UniqueConstraint('asset_id', 'scope'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'))
    scope: Mapped[str] = mapped_column(String(40))
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default='1')
    source_system: Mapped[str] = mapped_column(String(80), default='legacy')
    source_record_id: Mapped[str | None] = mapped_column(String(200))
    approval_state: Mapped[str] = mapped_column(String(40), default='Pending verification')
    verified_by: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class AssetClassificationChangeRequest(Base):
    __tablename__ = 'asset_classification_change_requests'
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'))
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    requested_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    status: Mapped[str] = mapped_column(String(30), default='Requested')
    expected_context_version: Mapped[int] = mapped_column(Integer)
    before_context: Mapped[dict] = mapped_column(JSON, default=dict)
    proposed_context: Mapped[dict] = mapped_column(JSON, default=dict)
    justification: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text, default='')
    decision_justification: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class AssetClassificationMission(Base):
    __tablename__ = 'asset_classification_missions'
    __table_args__ = (UniqueConstraint('workspace', 'asset_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'))
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    questionnaire_version: Mapped[str] = mapped_column(String(50), default='1.0-provisional')
    status: Mapped[str] = mapped_column(String(40), default='Draft')
    current_step: Mapped[int] = mapped_column(Integer, default=1)
    responses: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    updated_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

class AssetClassificationMissionHistory(Base):
    __tablename__ = 'asset_classification_mission_history'
    __table_args__ = (Index('ix_asset_classification_mission_history_mission', 'mission_id', 'created_at'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    mission_id: Mapped[int] = mapped_column(ForeignKey('asset_classification_missions.id'), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), index=True)
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    action: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50))
    current_step: Mapped[int] = mapped_column(Integer)
    responses: Mapped[dict] = mapped_column(JSON, default=dict)
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class AssetClassificationEvidence(Base):
    __tablename__ = 'asset_classification_evidence'
    id: Mapped[int] = mapped_column(primary_key=True)
    mission_id: Mapped[int] = mapped_column(ForeignKey('asset_classification_missions.id'))
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'))
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    evidence_type: Mapped[str] = mapped_column(String(60))
    reference: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text, default='')
    created_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id: Mapped[int] = mapped_column(primary_key=True)
    identity: Mapped[str] = mapped_column(String(300), unique=True)
    plugin_id: Mapped[str | None] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(300))
    cves: Mapped[list] = mapped_column(JSON, default=list)
    technical: Mapped[dict] = mapped_column(JSON)

class Finding(Base):
    __tablename__ = 'vulnerability_instances'
    __table_args__ = (UniqueConstraint('asset_id', 'vulnerability_id', 'port', 'protocol'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'))
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey('vulnerabilities.id'))
    port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(20), default='tcp')
    source: Mapped[str] = mapped_column(String(20))
    source_record: Mapped[dict] = mapped_column(JSON, default=dict)
    observed: Mapped[dict] = mapped_column(JSON, default=dict)
    # Scanner freshness and lifecycle are distinct from the assessment revision.
    source_last_seen: Mapped[date | None] = mapped_column(Date)
    evidence_fingerprint: Mapped[str | None] = mapped_column(String(64))
    lifecycle_revision: Mapped[int] = mapped_column(Integer, default=0, server_default='0')
    revision: Mapped[int] = mapped_column(Integer, default=0)
    workspace: Mapped[str] = mapped_column(String(20), default='Production')

class Methodology(Base):
    __tablename__ = 'risk_methodologies'
    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[str] = mapped_column(String(50), unique=True)
    configuration: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Assessment(Base):
    __tablename__ = 'assessments'
    __table_args__ = (UniqueConstraint('instance_id', 'revision'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey('vulnerability_instances.id'))
    revision: Mapped[int] = mapped_column(Integer)
    methodology_id: Mapped[int] = mapped_column(ForeignKey('risk_methodologies.id'))
    analyst_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    context: Mapped[dict] = mapped_column(JSON)
    notes: Mapped[str] = mapped_column(Text, default='')
    justification: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(String(60))
    status: Mapped[str] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class AssessmentControl(Base):
    __tablename__ = 'assessment_controls'
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey('assessments.id'))
    name: Mapped[str] = mapped_column(String(100))
    component: Mapped[str] = mapped_column(String(30))
    effectiveness: Mapped[float] = mapped_column(Float)
    validated: Mapped[bool] = mapped_column(Boolean)
    applicable: Mapped[bool] = mapped_column(Boolean)
    evidence: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text)
    design_maturity: Mapped[int | None] = mapped_column(Integer)
    operating_effectiveness: Mapped[int | None] = mapped_column(Integer)

class RiskScore(Base):
    __tablename__ = 'risk_scores'
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey('assessments.id'), unique=True)
    result: Mapped[dict] = mapped_column(JSON)

class Audit(Base):
    __tablename__ = 'audit_log'
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String(100))
    entity: Mapped[str] = mapped_column(String(60))
    entity_id: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ImportBatch(Base):
    __tablename__ = 'imports'
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    filename: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(20))
    headers: Mapped[list] = mapped_column(JSON)
    mapping: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default='Preview')
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    workspace: Mapped[str] = mapped_column(String(20), default='Production')

class ImportRow(Base):
    __tablename__ = 'import_rows'
    __table_args__ = (UniqueConstraint('import_id', 'row_number'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    import_id: Mapped[int] = mapped_column(ForeignKey('imports.id'))
    row_number: Mapped[int] = mapped_column(Integer)
    original: Mapped[dict] = mapped_column(JSON)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    instance_id: Mapped[int | None] = mapped_column(ForeignKey('vulnerability_instances.id'))

class SyncJob(Base):
    __tablename__ = 'tenable_sync_history'
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default='Running')
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    workspace: Mapped[str] = mapped_column(String(20), default='Production')

class IntegrationSettings(Base):
    __tablename__ = 'integration_settings'
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    access_key_encrypted: Mapped[str | None] = mapped_column(Text)
    secret_key_encrypted: Mapped[str | None] = mapped_column(Text)
    base_url: Mapped[str] = mapped_column(String(500), default='https://cloud.tenable.com')

class AssetRule(Base):
    __tablename__ = 'asset_rules'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    match_type: Mapped[str] = mapped_column(String(30))
    match_value: Mapped[str] = mapped_column(String(300))
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    controls: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class PluginAssessmentTemplate(Base):
    __tablename__ = 'plugin_assessment_templates'
    __table_args__ = (UniqueConstraint('workspace', 'vulnerability_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey('vulnerabilities.id'))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    status: Mapped[str] = mapped_column(String(40), default='New')
    notes: Mapped[str] = mapped_column(Text, default='')
    justification: Mapped[str] = mapped_column(Text, default='')
    decision: Mapped[str] = mapped_column(String(60), default='Needs Further Assessment')
    controls: Mapped[list] = mapped_column(JSON, default=list)
    template_version: Mapped[int] = mapped_column(Integer, default=1)
    applicability: Mapped[dict] = mapped_column(JSON, default=dict)
    technical_rationale: Mapped[str] = mapped_column(Text, default='')
    updated_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

class PluginAssessmentTemplateRevision(Base):
    __tablename__ = 'plugin_assessment_template_revisions'
    id: Mapped[int] = mapped_column(primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey('plugin_assessment_templates.id'), index=True)
    workspace: Mapped[str] = mapped_column(String(20))
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey('vulnerabilities.id'))
    version: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict] = mapped_column(JSON)
    changed_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class BulkAssessmentJob(Base):
    __tablename__ = 'bulk_assessment_jobs'
    __table_args__ = (UniqueConstraint('workspace', 'vulnerability_id', 'idempotency_key'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace: Mapped[str] = mapped_column(String(20), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey('vulnerabilities.id'), index=True)
    requested_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    idempotency_key: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(30), default='Queued', index=True)
    active_only: Mapped[bool] = mapped_column(Boolean, default=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    total: Mapped[int] = mapped_column(Integer, default=0)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    succeeded: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    correlation_id: Mapped[str] = mapped_column(String(64), unique=True)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class BulkAssessmentItem(Base):
    __tablename__ = 'bulk_assessment_items'
    __table_args__ = (UniqueConstraint('job_id', 'finding_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey('bulk_assessment_jobs.id'), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey('vulnerability_instances.id'), index=True)
    status: Mapped[str] = mapped_column(String(30), default='Pending', index=True)
    error: Mapped[str | None] = mapped_column(Text)
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey('assessments.id'))
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class FindingWorkflow(Base):
    __tablename__ = 'finding_workflows'
    finding_id: Mapped[int] = mapped_column(ForeignKey('vulnerability_instances.id'), primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    status: Mapped[str] = mapped_column(String(40), default='New')
    updated_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    # Review evidence is separate from remediation status and ownership.
    review_state: Mapped[str | None] = mapped_column(String(30))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    review_decision: Mapped[str | None] = mapped_column(String(80))
    review_notes: Mapped[str | None] = mapped_column(Text)
    remediation_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    remediation_evidence: Mapped[str | None] = mapped_column(Text)

class RiskException(Base):
    __tablename__ = 'risk_exceptions'
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    finding_id: Mapped[int] = mapped_column(ForeignKey('vulnerability_instances.id'))
    justification: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String(30), default='Requested')
    requested_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    review_frequency_days: Mapped[int] = mapped_column(Integer, default=90)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class ControlLibrary(Base):
    __tablename__ = 'control_library'
    __table_args__ = (UniqueConstraint('workspace', 'name'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default='')
    owner_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    evidence_requirements: Mapped[str] = mapped_column(Text, default='')
    mappings: Mapped[dict] = mapped_column(JSON, default=dict)
    design_maturity: Mapped[int | None] = mapped_column(Integer)
    operating_effectiveness: Mapped[int | None] = mapped_column(Integer)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

class SavedFilter(Base):
    __tablename__ = 'saved_filters'
    __table_args__ = (UniqueConstraint('workspace', 'user_id', 'name'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace: Mapped[str] = mapped_column(String(20), default='Production')
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    name: Mapped[str] = mapped_column(String(100))
    filters: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ReviewCampaign(Base):
    __tablename__ = 'review_campaigns'
    __table_args__ = (Index('ix_campaign_workspace_status', 'workspace', 'status'),
                     Index('ix_campaign_workspace_period', 'workspace', 'period_start', 'period_end'))
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default='')
    frequency: Mapped[str] = mapped_column(String(20), default='one-time')
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    start_date: Mapped[date] = mapped_column(Date)
    due_date: Mapped[date] = mapped_column(Date)
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(30), default='Draft')
    created_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class CampaignReviewer(Base):
    __tablename__ = 'campaign_reviewers'
    __table_args__ = (UniqueConstraint('campaign_id', 'user_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey('review_campaigns.id'), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))

class CampaignFinding(Base):
    __tablename__ = 'campaign_findings'
    __table_args__ = (UniqueConstraint('campaign_id', 'finding_id'),
                     Index('ix_campaign_finding_status', 'campaign_id', 'status'),
                     Index('ix_campaign_finding_severity', 'campaign_id', 'snapshot_severity'),
                     Index('ix_campaign_finding_business_owner', 'campaign_id', 'snapshot_business_owner'),
                     Index('ix_campaign_finding_it_owner', 'campaign_id', 'snapshot_it_owner'),
                     Index('ix_campaign_finding_app_owner', 'campaign_id', 'snapshot_application_owner'),
                     Index('ix_campaign_finding_group', 'campaign_id', 'snapshot_asset_group'))
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey('review_campaigns.id'))
    # Historical populations survive remediation; deleting referenced live findings is restricted.
    finding_id: Mapped[int] = mapped_column(ForeignKey('vulnerability_instances.id', ondelete='RESTRICT'))
    snapshot_plugin_id: Mapped[str | None] = mapped_column(String(100))
    snapshot_vulnerability: Mapped[str] = mapped_column(String(300))
    snapshot_asset_id: Mapped[int] = mapped_column(Integer)
    snapshot_asset: Mapped[str] = mapped_column(String(255))
    snapshot_severity: Mapped[str] = mapped_column(String(30))
    snapshot_risk: Mapped[float | None] = mapped_column(Float)
    snapshot_risk_level: Mapped[str | None] = mapped_column(String(30))
    snapshot_business_owner: Mapped[str | None] = mapped_column(String(200))
    snapshot_it_owner: Mapped[str | None] = mapped_column(String(200))
    snapshot_application_owner: Mapped[str | None] = mapped_column(String(200))
    snapshot_asset_group: Mapped[str | None] = mapped_column(String(200))
    snapshot_tags: Mapped[list] = mapped_column(JSON, default=list)
    snapshot_regulatory: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default='Pending')
    reviewer_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision: Mapped[str | None] = mapped_column(String(80))
    skip_reason: Mapped[str | None] = mapped_column(String(50))
    notes: Mapped[str] = mapped_column(Text, default='')
    evidence_references: Mapped[list] = mapped_column(JSON, default=list)

class CampaignFindingTag(Base):
    """Normalized snapshot tags support portable SQL filtering and aggregate joins."""
    __tablename__ = 'campaign_finding_tags'
    __table_args__ = (UniqueConstraint('campaign_finding_id', 'tag'),
                     Index('ix_campaign_finding_tag', 'campaign_id', 'tag'))
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey('review_campaigns.id'))
    campaign_finding_id: Mapped[int] = mapped_column(ForeignKey('campaign_findings.id'))
    tag: Mapped[str] = mapped_column(String(500))

class CampaignEvidence(Base):
    __tablename__ = 'campaign_evidence'
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey('review_campaigns.id'), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey('vulnerability_instances.id'))
    reference: Mapped[str] = mapped_column(String(2000), default='')
    notes: Mapped[str] = mapped_column(Text, default='')
    created_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class CampaignAuditEvent(Base):
    __tablename__ = 'campaign_audit_events'
    __table_args__ = (Index('ix_campaign_audit_time', 'campaign_id', 'created_at'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey('review_campaigns.id'))
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
