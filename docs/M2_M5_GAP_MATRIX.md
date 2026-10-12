# VRAP M2–M5 functional acceptance matrix

Evidence basis: backend suite and frontend production build on the current branch, plus direct API acceptance tests using synthetic findings.

| Area | Status | Evidence / test | Remaining acceptance |
|---|---|---|---|
| M2 mission persistence, isolation, immutable history | Complete | Existing mission draft/history tests | Browser accessibility/offline recovery coverage remains. |
| M2 conditional Q&A and evidence expiry | Partial | Conditional contract validation, expiry metadata, migration `0016` | Frontend branching/smart skips and approval-time evidence enforcement remain. |
| M2 owner/GRC separation | Partial | SoD tests and reviewer assignment API | Full analyst→owner→GRC UI workflow remains. |
| M3 durable bulk jobs/idempotency/context preservation | Complete | Bulk job/idempotency, active-only and protected-context tests | 1,000+ asset browser performance fixture remains. |
| M4 Mission Center prioritization | Partial | Priority queue test and server pagination | Assignment, progress mutation, saved filters and governed batch actions remain. |
| M4 remediation Work Packages | Partial | Verified-rescan closure test; migration `0017`, APIs and page | Finding selection/edit UI, Jira sync, automated rescan linkage and reopen detection remain. |
| M4 configurable SLA engine | Partial | Migration `0018`, SLA APIs, provisional defaults and strictest overlap evaluator | Exception pauses, SOC 2 admin UI and dashboard integration remain. |
| M5 methodology lifecycle | Partial | Migration `0019`, approval endpoint with SoD | Golden-case calibration, delegated roles and version lock enforcement remain. |
| M5 Control Library currency | Partial | Expiry metadata and risk-engine rejection of expired evidence | Version FK, validator workflow and recertification UI remain. |
| M5 centralized KPI contract | Partial | `app/kpis.py`, `/api/kpis`, KPI contract regression test | Dashboard, Mission Center, campaigns, PDF and CSV migration plus trends remain. |
| M5 role-specific reporting | Missing | Existing outputs remain separate aggregations | Tailored Analyst, Vulnerability Manager, GRC and Executive trend views remain. |

## Acceptance result

Backend: 105 passed, 2 skipped. Frontend production build passed. No unrelated security hardening or deployment was performed.

Highest remaining blockers: frontend M2 branching/evidence workflow, governed Mission Center actions, full Work Package operations, and migration of every report surface to the centralized KPI contract.
