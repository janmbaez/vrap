"""Assessment currency rules shared by live worklists, campaigns, and reports.

A completed assessment is current only when it is the finding's latest revision,
uses the currently selected methodology, and has a saved risk score.  Workflow
closure is intentionally separate: closed findings are excluded by callers.
"""
from sqlalchemy import and_, func, select
from .models import Assessment

COMPLETED_ASSESSMENT_STATUSES = frozenset({
    'Assessed', 'Above Risk Appetite', 'Exception Requested', 'Risk Accepted',
    'Remediation Required', 'Closed',
})


def latest_assessment_revision():
    """Return one revision number per finding; `Assessment` enforces uniqueness."""
    return (select(Assessment.instance_id.label('finding_id'),
                   func.max(Assessment.revision).label('revision'))
            .group_by(Assessment.instance_id).subquery())


def current_assessment_columns(status, assessment_revision, finding_revision, methodology_id, active_methodology_id, score_result=None):
    """Portable SQL predicate for an already-projected latest assessment."""
    terms = [status.in_(COMPLETED_ASSESSMENT_STATUSES),
             assessment_revision == finding_revision,
             methodology_id == active_methodology_id]
    if score_result is not None:
        terms.append(score_result.is_not(None))
    return and_(*terms)


def current_assessment_condition(assessment, finding, methodology_id, score=None):
    return current_assessment_columns(assessment.status, assessment.revision, finding.revision,
                                      assessment.methodology_id, methodology_id,
                                      score.result if score is not None else None)


def stale_assessment_columns(assessment_id, assessment_revision, finding_revision, methodology_id, active_methodology_id):
    """An assessment exists but was invalidated by evidence or methodology change."""
    return and_(assessment_id.is_not(None),
                (assessment_revision != finding_revision) |
                (methodology_id != active_methodology_id))


def stale_assessment_condition(assessment, finding, methodology_id):
    return stale_assessment_columns(assessment.id, assessment.revision, finding.revision,
                                    assessment.methodology_id, methodology_id)


def assessment_currency(*, assessment_id, assessment_revision, finding_revision,
                         methodology_id, active_methodology_id, status, score_present):
    """Classify a latest assessment for response payloads without inventing state."""
    if assessment_id is None:
        return 'Never Assessed'
    if assessment_revision != finding_revision or methodology_id != active_methodology_id:
        return 'Stale'
    if status in COMPLETED_ASSESSMENT_STATUSES and score_present:
        return 'Current'
    return 'Draft'
