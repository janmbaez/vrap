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

## Resumable draft slice

- Migration `0011` adds one workspace-scoped, versioned classification mission draft per asset. It stores the questionnaire version, current step, responses, creator/updater and timestamps separately from operative asset context.
- The protected-change form restores its prior draft and offers **Save draft**. Draft persistence never modifies the asset, scope memberships, finding scores or approval state.
- API tests verify draft retrieval and Demo/Production isolation. A full stepper, branching question bank, explicit owner validation, evidence objects and accessibility test suite remain subsequent M2 slices.

## Guided quest slice

The protected classification form is now a five-stage flow: identity, business context, data/regulatory scope, exposure, and review. Each forward step persists a resumable draft. The final stage presents the proposed context and submits a governed approval request; it does not publish a classification directly.

The identity stage now supports governed proposals for business, IT and application owners plus asset group. Owner assignments are never created as verified merely by completing the quest; they become operative only after the existing independent review decision.

Quest drafts now transition to **Pending GRC Approval** when their protected change request is submitted, and to **Approved** or **Rejected** with the independent decision. These states remain distinct from the operative asset context and from vulnerability-review status.

## Versioned questionnaire contract

`GET /api/classification-questionnaire` exposes the source-controlled `1.0-provisional` question bank. Each question has a stable ID, field mapping, response type, allowed values where applicable, and supported evidence-source types. Quest drafts persist an `answers` map keyed by these IDs. Later questionnaire versions must add new IDs rather than reinterpret saved answers.
