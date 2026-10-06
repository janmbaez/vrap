# Review campaigns implementation plan

## Discovery

- React/TypeScript/Vite and Recharts: `frontend/src/App.tsx`, `frontend/package.json`, `frontend/src/pages/Dashboard.tsx`.
- FastAPI, SQLAlchemy and Alembic: `backend/app/main.py`, `backend/app/db.py`, `backend/migrations/`.
- Finding, FindingWorkflow, Audit and SavedFilter: `backend/app/models.py`; existing Reviewed action: `backend/app/api/governance.py` and `frontend/src/pages/Findings.tsx`.
- Cookie auth, CSRF, role checks and server-selected environment: `backend/app/auth.py`; scoped finding SQL and saved filters: `backend/app/api/core.py`.
- Executive JSON and ReportLab PDF: `backend/app/api/governance.py`; live risk: `backend/app/services.py`.
- Docker image startup: `backend/Dockerfile`; publication: `.github/workflows/publish.yml`; volume: `docker-compose.yml` (must not change).
- Tests: `backend/tests/conftest.py` creates isolated SQLite databases and authenticated TestClients; PostgreSQL migration/performance checks will use a fresh disposable container only.

## Decisions and reasons

1. Activation takes one transactional snapshot of references and audit-relevant scalar values, normalized tags and regulatory scope; the denominator must survive later remediation and changes to asset owners/tags.
2. A campaign finding is unique per campaign and live finding, but a finding may appear in many campaigns; repeated weekly reviews need independent evidence.
3. Keep remediation `FindingWorkflow.status` and owner intact; add nullable live review fields and retain campaign-specific decisions, timestamps and append-only audit history, so review is not mistaken for remediation or acceptance.
4. Refactor the existing finding SQL into a shared validated AND-filter builder; saved views and campaign preview/activation must select the same population.
5. Add optional asset group in existing context JSON and use existing owner strings/tags; business, IT and application owners remain independent of app users.
6. Derive overdue from UTC date after due date for unfinished, non-archived campaigns; clocks must not create stale stored statuses or remediation tickets.
7. Draft -> Active on snapshot, Active -> In Progress on first review, In Progress/Active/Reopened -> Completed only with no pending findings, Completed -> Reopened (administrator with reason), Reopened -> In Progress on next review, Completed -> Archived; invalid transitions return conflicts.
8. Administrators manage all scoped campaigns; analyst creators manage their campaigns and assigned active analysts review them; viewers read only Completed/Archived results. All object access also checks session workspace.
9. Aggregate campaign metrics on demand with SQL counts/grouping and indexed snapshot columns; 10k populations do not require a second aggregate store that could drift.
10. Normalize snapshot tags in a small child table for portable SQL tag breakdowns; never copy scanner source payloads or credentials.
11. Recurrence uses an explicit clone-next-period action (weekly or calendar monthly); it is predictable without adding a scheduler to this in-process application.
12. Bulk review uses a validated server-side filter or bounded selected IDs and set-based writes in one transaction; one audit record stores prior/new decisions and the affected snapshot references, bounded at 10,000.
13. Evidence contains references/notes, not uploaded files; avoid introducing an upload/security subsystem.
14. Central campaign metrics feed dashboard, CSV, PDF and executive review governance; Reviewed/Total and (Reviewed+Skipped)/Total remain distinct, and empty denominator returns null/No data.
15. Executive report live exposure uses latest saved risk with assessment freshness disclosed; campaign review trends use frozen campaign populations. No historical exposure backfill or invented prior period.
16. Deterministic management attention thresholds: any overdue campaign, any critical pending reviews, campaign coverage below 80%, owner/group below 80% with at least 5 population rows, skipped share over 10%, and coverage drop >=10 points; ordered by severity with supporting links.
17. Export PDF through the existing ReportLab engine with vector charts and content-length responses; preview every page and escape user text.
18. Replace stamping-on-start with Alembic upgrade under a PostgreSQL advisory lock (local file lock for SQLite) and retain additive schema on rollback; never touch Compose volume declarations.
19. CI gates publishing on backend tests, SQLite/PostgreSQL additive migration validation and actual frontend build; failed checks must not publish an image.

## Delivery and proof

- Record exact full-suite, migration, Docker, performance, browser and PDF checks in `docs/review-campaigns-verification.md`.
- Golden population: 500 / 420 reviewed / 50 pending / 30 skipped = 84% review coverage and 90% processed coverage.
- Change 100 live findings after activation; campaign denominator and snapshot owners/severity/risk remain 500 and unchanged.
- Test roles, CSRF, cross-environment and cross-campaign IDs for preview, activation, bulk, metrics, evidence and exports.
- Before first production upgrade, recommend a `pg_dump` from the existing DB; do not automate it or alter its volume. Roll back by prior immutable image tag with additive schema retained.
