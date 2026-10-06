from datetime import date
from typing import Literal
from pydantic import Field, model_validator, field_validator
from .schemas import Strict
from .query import validate_filters

Frequency = Literal['one-time','weekly','monthly']
ReviewDecision = Literal['Further assessment required','Remediation follow-up','Risk decision documented','No change required']
SkipReason = Literal['Duplicate','False positive','Asset decommissioned','Not applicable','Awaiting validation','Other']

class CampaignInput(Strict):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default='', max_length=10000)
    frequency: Frequency = 'one-time'
    period_start: date
    period_end: date
    start_date: date
    due_date: date
    scope: dict[str, str] = Field(default_factory=dict, max_length=20)
    reviewer_ids: list[int] = Field(default_factory=list, max_length=100)

    @field_validator('name')
    @classmethod
    def name_required(cls,value):
        if not value.strip(): raise ValueError('Name is required')
        return value.strip()

    @field_validator('scope')
    @classmethod
    def scope_supported(cls,value): return validate_filters(value)

    @model_validator(mode='after')
    def dates(self):
        if self.period_end < self.period_start: raise ValueError('Reporting period end must follow its start')
        if self.due_date < self.start_date: raise ValueError('Due date must follow start date')
        if any(x <= 0 for x in self.reviewer_ids): raise ValueError('Invalid reviewer id')
        self.reviewer_ids = list(dict.fromkeys(self.reviewer_ids))
        return self

class CampaignPatch(Strict):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    frequency: Frequency | None = None
    period_start: date | None = None
    period_end: date | None = None
    start_date: date | None = None
    due_date: date | None = None
    scope: dict[str,str] | None = None
    reviewer_ids: list[int] | None = Field(default=None, max_length=100)

class ScopePreview(Strict):
    scope: dict[str,str] = Field(default_factory=dict, max_length=20)

class ReviewInput(Strict):
    status: Literal['Reviewed','Skipped']
    decision: ReviewDecision | None = None
    skip_reason: SkipReason | None = None
    notes: str = Field(default='', max_length=10000)
    evidence_references: list[str] = Field(default_factory=list, max_length=20)

    @field_validator('evidence_references')
    @classmethod
    def references(cls,values):
        if any(not value.strip() or len(value)>2000 for value in values): raise ValueError('Evidence references must be nonblank and at most 2000 characters')
        return list(dict.fromkeys(value.strip() for value in values))

    @model_validator(mode='after')
    def valid_action(self):
        if self.status == 'Reviewed' and not self.decision: raise ValueError('A review decision is required')
        if self.status == 'Skipped' and not self.skip_reason: raise ValueError('A skip reason is required')
        if self.status == 'Skipped' and self.skip_reason == 'Other' and not self.notes.strip(): raise ValueError('Explain Other in notes')
        if self.status == 'Reviewed': self.skip_reason = None
        else: self.decision = None
        return self

class BulkReview(ReviewInput):
    selection: Literal['selected','matching'] = 'selected'
    ids: list[int] = Field(default_factory=list,max_length=10000)
    filters: dict[str,str] = Field(default_factory=dict,max_length=20)

    @model_validator(mode='after')
    def valid_selection(self):
        if self.selection == 'selected' and (not self.ids or any(i<=0 for i in self.ids)): raise ValueError('Select at least one finding')
        if self.selection == 'matching' and self.ids: raise ValueError('Matching selections use server filters, not IDs')
        self.ids = list(dict.fromkeys(self.ids))
        return self

class ReopenInput(Strict):
    reason: str = Field(min_length=1,max_length=10000)

    @field_validator('reason')
    @classmethod
    def nonblank(cls,value):
        if not value.strip(): raise ValueError('A reopen reason is required')
        return value.strip()

class EvidenceInput(Strict):
    finding_id: int | None = Field(default=None,gt=0)
    reference: str = Field(default='',max_length=2000)
    notes: str = Field(default='',max_length=10000)

    @model_validator(mode='after')
    def required(self):
        if not self.reference.strip() and not self.notes.strip(): raise ValueError('An evidence reference or note is required')
        return self

class CloneInput(Strict):
    name: str | None = Field(default=None,min_length=1,max_length=200)
    period_start: date | None = None
    period_end: date | None = None
    start_date: date | None = None
    due_date: date | None = None
