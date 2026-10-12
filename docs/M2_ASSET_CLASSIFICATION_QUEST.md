# M2 — Asset Classification Quest

**Status:** In progress — protected-change request and reviewer flow delivered locally on 2026-10-12.

## Delivered first slice

- The Assets page provides a request form for protected asset classification values: asset and business criticality, data classification, environment, exposure, and independent regulatory memberships.
- It prefills the current operative context and submits only fields that changed, with required business justification and optional evidence references.
- Administrators receive a workspace-scoped review queue showing the before/proposed diff, submitter rationale and evidence. Every approval or rejection requires a reviewer rationale.
- The FastAPI API remains authoritative: approval is independent, checks the workspace and context version, atomically publishes approved changes, updates scope memberships, preserves history, and flags linked findings for reassessment.

## Deliberate limits

This is a governed request/review flow, not yet the full five-stage accessible questionnaire. It does not claim a mere request or completed form is an approved classification. The next slice needs versioned question definitions, drafts/resume, assignments, evidence lifecycle, change-request statuses beyond requested/approved/rejected, and keyboard-focused wizard verification.

## Validation and rollback

- Backend: `PYTHONPATH=backend .venv/bin/pytest backend/tests -q` — 89 passed, 2 skipped.
- Frontend: `npm --prefix frontend run build` — passed; Vite continues to report the pre-existing >500 kB bundle advisory.
- Rollback: UI rollback leaves the request API/audit data intact. Application rollback keeps migrations additive; do not delete request or scope-history tables.
