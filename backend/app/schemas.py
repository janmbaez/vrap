from typing import Literal, Any
from datetime import date, datetime
from ipaddress import ip_address
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator

class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)

class Login(Strict):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)
    environment: Literal['Demo', 'Production'] = 'Production'

class UserCreate(Login):
    password: str = Field(min_length=14, max_length=256)
    role: Literal['Administrator', 'Security Analyst', 'Viewer']

class UserRoleUpdate(Strict):
    role: Literal['Administrator', 'Security Analyst', 'Viewer']

class Context(Strict):
    asset_criticality: Literal['Low', 'Medium', 'High', 'Critical'] | None = None
    business_criticality: Literal['Low', 'Medium', 'High', 'Critical'] | None = None
    data_classification: Literal['Public', 'Internal', 'Confidential', 'Restricted'] | None = None
    regulatory: list[Literal['PCI DSS', 'SOC 2', 'SOX', 'HIPAA', 'GDPR', 'Other', 'None']] = Field(default_factory=list, max_length=7)
    environment: Literal['Development', 'Test', 'QA', 'Staging', 'Production'] | None = None
    exposure: Literal['Internet Facing', 'Internal', 'Restricted Network', 'Isolated'] | None = None
    production: bool | None = None
    publicly_accessible: bool | None = None
    sensitive_data: bool | None = None
    critical_process: bool | None = None
    privileged: bool | None = None
    authentication_required: bool | None = None
    web_applicable: bool | None = None
    threat_intelligence: Literal['Low', 'Medium', 'High', 'Critical'] | None = None
    business_owner: str | None = Field(default=None, max_length=200)
    it_owner: str | None = Field(default=None, max_length=200)
    application_owner: str | None = Field(default=None, max_length=200)
    asset_group: str | None = Field(default=None, max_length=200)
    inherent_likelihood_override: int | None = Field(default=None, ge=1, le=5)
    inherent_impact_override: int | None = Field(default=None, ge=1, le=5)
    other_controls: str = Field(default='', max_length=5000)
    additional_factors: dict[str, Any] = Field(default_factory=dict, max_length=30)

    @model_validator(mode='after')
    def consistent(self):
        if 'None' in self.regulatory and len(self.regulatory) > 1:
            raise ValueError('None cannot be combined with regulatory scopes')
        if self.environment is not None:
            expected = self.environment == 'Production'
            if self.production is not None and self.production != expected:
                raise ValueError('Production must agree with environment')
            self.production = expected
        if self.exposure is not None:
            expected = self.exposure == 'Internet Facing'
            if self.publicly_accessible is not None and self.publicly_accessible != expected:
                raise ValueError('Public accessibility must agree with exposure')
            self.publicly_accessible = expected
        if any(k in type(self).model_fields for k in self.additional_factors):
            raise ValueError('Additional factors cannot override built-in context')
        return self

    def engine_values(self):
        d = self.model_dump()
        d.update(d.pop('additional_factors'))
        return d

class FindingCreate(Strict):
    hostname: str = Field(min_length=1, max_length=255)
    ip: str | None = Field(default=None, max_length=60)
    os: str | None = Field(default=None, max_length=200)
    external_id: str | None = Field(default=None, max_length=200)
    plugin_id: str | None = Field(default=None, max_length=100)
    name: str = Field(min_length=1, max_length=300)
    # Tenable definition-level findings can legitimately aggregate hundreds of CVEs.
    cves: list[str] = Field(default_factory=list, max_length=1000)
    severity: Literal['Informational', 'Low', 'Medium', 'High', 'Critical'] | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    vpr: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=300)
    exploit_available: bool | None = None
    kev: bool | None = None
    exploit_maturity: str | None = Field(default=None, max_length=200)
    first_seen: date | None = None
    last_seen: date | None = None
    published: date | None = None
    modified: date | None = None
    family: str | None = Field(default=None, max_length=200)
    description: str = Field(default='', max_length=30000)
    solution: str = Field(default='', max_length=30000)
    plugin_output: str = Field(default='', max_length=100000)
    state: str | None = Field(default=None, max_length=100)
    service: str | None = Field(default=None, max_length=200)
    tags: list = Field(default_factory=list, max_length=100)
    asset_tags: list = Field(default_factory=list, max_length=100)
    port: int = Field(default=0, ge=0, le=65535)
    protocol: Literal['tcp', 'udp', 'icmp', 'other'] = 'tcp'
    context: Context = Field(default_factory=Context)

    @field_validator('hostname', 'name')
    @classmethod
    def no_blank(cls, value):
        if not value.strip():
            raise ValueError('Must not be blank')
        return value.strip()

    @field_validator('ip')
    @classmethod
    def valid_ip(cls, value):
        if value:
            ip_address(value)
        return value or None

class Control(Strict):
    name: str = Field(min_length=1, max_length=100)
    effectiveness: float = Field(ge=0, le=1)
    applicable: bool = False
    validated: bool = False
    evidence: str = Field(default='', max_length=4000)
    notes: str = Field(default='', max_length=4000)
    design_maturity: int | None = Field(default=None, ge=1, le=5)
    operating_effectiveness: int | None = Field(default=None, ge=1, le=5)

class AssessmentInput(Strict):
    context: Context
    controls: list[Control] = Field(default_factory=list, max_length=50)
    methodology_id: int
    expected_revision: int = Field(ge=0)
    notes: str = Field(default='', max_length=10000)
    justification: str = Field(default='', max_length=5000)
    decision: Literal['Needs Further Assessment', 'Within Risk Appetite', 'Remediation Required', 'Risk Acceptance Required', 'Exception Required', 'Escalation Required', 'Risk Accepted'] = 'Needs Further Assessment'
    status: Literal['Assessment In Progress', 'Context Required', 'Assessed', 'Pending Validation', 'Above Risk Appetite', 'Exception Requested', 'Risk Accepted', 'Remediation Required', 'Closed'] = 'Assessment In Progress'

    @model_validator(mode='after')
    def unique_controls(self):
        if len({c.name for c in self.controls}) != len(self.controls):
            raise ValueError('Duplicate controls are not allowed')
        return self

class Threshold(Strict):
    name: Literal['Low', 'Medium', 'High', 'Critical']
    min: float = Field(ge=0, lt=100)

class Factor(Strict):
    key: str = Field(pattern=r'^[a-z][a-z_0-9]{0,79}$')
    component: Literal['likelihood', 'impact']
    weight: float = Field(gt=0, le=100)
    kind: Literal['technical', 'boolean', 'mapping', 'multi', 'linear']
    values: dict[str, float] | None = None
    true_score: float | None = Field(default=None, ge=0, le=100)
    false_score: float | None = Field(default=None, ge=0, le=100)
    scale: float | None = Field(default=None, gt=0)

    @model_validator(mode='after')
    def parameters(self):
        if self.kind in ('mapping', 'multi') and (not self.values or any(v < 0 or v > 100 for v in self.values.values())):
            raise ValueError('Mapping values must be between 0 and 100')
        if self.kind == 'boolean' and (self.true_score is None or self.false_score is None):
            raise ValueError('Boolean factors require true and false scores')
        if self.kind == 'linear' and self.scale is None:
            raise ValueError('Linear factors require scale')
        if self.kind == 'technical' and self.key != 'technical':
            raise ValueError('Technical factors must use technical key')
        return self

class ControlRule(Strict):
    name: str = Field(min_length=1, max_length=100)
    component: Literal['likelihood', 'impact']
    max_effectiveness: float = Field(ge=0, le=0.95)
    requires: str | None = None

class Policy(Strict):
    engine_version: Literal['1.0']
    appetite: Literal['Low', 'Medium', 'High', 'Critical']
    unknown_score: float = Field(ge=0, le=100)
    thresholds: list[Threshold] = Field(min_length=4, max_length=4)
    technical_weights: dict[Literal['cvss', 'vpr'], float]
    severity_map: dict[str, float]
    max_control_reduction: float = Field(ge=0, le=0.95)
    required_context: list[str] = Field(max_length=50)
    factors: list[Factor] = Field(min_length=2, max_length=100)
    controls: list[ControlRule] = Field(max_length=50)
    grc_matrix: dict[str, Any]

    @model_validator(mode='after')
    def valid_policy(self):
        if [t.name for t in self.thresholds] != ['Low', 'Medium', 'High', 'Critical'] or self.thresholds[0].min != 0 or any(a.min >= b.min for a, b in zip(self.thresholds, self.thresholds[1:])):
            raise ValueError('Thresholds must be ordered Low/Medium/High/Critical, beginning at 0')
        if not self.technical_weights or sum(self.technical_weights.values()) <= 0 or any(w < 0 or w > 100 for w in self.technical_weights.values()):
            raise ValueError('Invalid technical weights')
        if any(v < 0 or v > 100 for v in self.severity_map.values()):
            raise ValueError('Invalid severity score')
        if set(f.component for f in self.factors) != {'likelihood', 'impact'}:
            raise ValueError('Both risk components require factors')
        if len({(f.component, f.key) for f in self.factors}) != len(self.factors) or len({c.name for c in self.controls}) != len(self.controls):
            raise ValueError('Duplicate factor/control definitions')
        matrix = self.grc_matrix
        if not isinstance(matrix.get('authorized_tolerance'), (int, float)) or not 1 <= matrix['authorized_tolerance'] <= 25:
            raise ValueError('GRC authorized tolerance must be between 1 and 25')
        expected = {str(i) for i in range(2, 11)}
        factors = matrix.get('remaining_risk_factors', {})
        if set(factors) != expected or any(not 0 <= float(v) <= 1 for v in factors.values()):
            raise ValueError('GRC remaining risk factors must define control strengths 2 through 10')
        keys = set(Context.model_fields) | {f.key for f in self.factors}
        if any(k not in keys for k in self.required_context):
            raise ValueError('Unknown required context key')
        return self

class MethodologyCreate(Strict):
    version: str = Field(pattern=r'^[A-Za-z0-9._-]{1,50}$')
    configuration: Policy

class MappingInput(Strict):
    mapping: dict[str, str] = Field(max_length=50)

class AssetUpdate(Strict):
    tags: list[str] | None = Field(default=None, max_length=100)
    asset_criticality: Literal['Low', 'Medium', 'High', 'Critical'] | None = None
    business_criticality: Literal['Low', 'Medium', 'High', 'Critical'] | None = None
    data_classification: Literal['Public', 'Internal', 'Confidential', 'Restricted'] | None = None
    regulatory: list[Literal['PCI DSS', 'SOC 2', 'SOX', 'HIPAA', 'GDPR', 'Other', 'None']] | None = None
    environment: Literal['Development', 'Test', 'QA', 'Staging', 'Production'] | None = None
    exposure: Literal['Internet Facing', 'Internal', 'Restricted Network', 'Isolated'] | None = None
    business_owner: str | None = Field(default=None, max_length=200)
    it_owner: str | None = Field(default=None, max_length=200)
    application_owner: str | None = Field(default=None, max_length=200)
    asset_group: str | None = Field(default=None, max_length=200)

class SavedFilterInput(Strict):
    name: str = Field(min_length=1, max_length=100)
    filters: dict[str, str] = Field(max_length=20)

    @field_validator('filters')
    @classmethod
    def valid_filters(cls, value):
        allowed = {'q','severity','residual','inherent','appetite','status','source','business','classification','regulatory',
                   'plugin_id','asset_group','asset_tag','business_owner','it_owner','application_owner'}
        if set(value) - allowed or any(len(str(v)) > 300 for v in value.values()):
            raise ValueError('Saved filter contains unsupported fields')
        return {k: v for k, v in value.items() if v}

class PluginTemplateInput(Strict):
    owner_id: int | None = None
    status: Literal['New', 'Investigating', 'Remediation Planned', 'Risk Review', 'Reviewed', 'Accepted', 'Closed'] = 'New'
    notes: str = Field(default='', max_length=10000)
    justification: str = Field(default='', max_length=5000)
    decision: Literal['Needs Further Assessment', 'Within Risk Appetite', 'Remediation Required', 'Risk Acceptance Required', 'Exception Required', 'Escalation Required'] = 'Needs Further Assessment'
    controls: list[Control] = Field(default_factory=list, max_length=50)

class WorkflowInput(Strict):
    owner_id: int | None = None
    status: Literal['New', 'Investigating', 'Remediation Planned', 'Risk Review', 'Reviewed', 'Accepted', 'Closed']

class ExceptionInput(Strict):
    justification: str = Field(min_length=10, max_length=5000)
    evidence: str = Field(default='', max_length=10000)
    expires_at: datetime
    review_frequency_days: int = Field(default=90, ge=1, le=365)

class ExceptionDecision(Strict):
    status: Literal['Approved', 'Rejected', 'Revoked']

class ControlLibraryInput(Strict):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default='', max_length=5000)
    owner_id: int | None = None
    evidence_requirements: str = Field(default='', max_length=5000)
    mappings: dict[str, list[str]] = Field(default_factory=dict)
    design_maturity: int | None = Field(default=None, ge=1, le=5)
    operating_effectiveness: int | None = Field(default=None, ge=1, le=5)
    last_tested_at: datetime | None = None
    active: bool = True

class RuleControl(Control):
    validated: bool = False
    applicable: bool = True

class AssetRuleInput(Strict):
    name: str = Field(min_length=1, max_length=200)
    priority: int = Field(default=100, ge=1, le=10000)
    active: bool = True
    match_type: Literal['CIDR', 'Hostname suffix', 'Tag', 'All assets']
    match_value: str = Field(default='', max_length=300)
    context: AssetUpdate = Field(default_factory=AssetUpdate)
    controls: list[RuleControl] = Field(default_factory=list, max_length=50)

    @model_validator(mode='after')
    def valid_match(self):
        if self.match_type != 'All assets' and not self.match_value.strip():
            raise ValueError('A match value is required')
        if self.match_type == 'CIDR':
            from ipaddress import ip_network
            ip_network(self.match_value, strict=False)
        return self

class TenableConfiguration(Strict):
    enabled: bool
    access_key: str | None = Field(default=None, max_length=500)
    secret_key: str | None = Field(default=None, max_length=500)
    base_url: str = Field(default='https://cloud.tenable.com', max_length=500)
