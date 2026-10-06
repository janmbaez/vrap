# Review campaigns delivery and verification

Verification date: 2026-10-06. Deployment status is recorded separately below; local verification does not imply a production deployment.

## 1. Architecture and decisions

This extends the existing React/TypeScript/Vite UI, FastAPI API, SQLAlchemy models, Alembic migrations, Recharts UI charts and ReportLab PDF engine. The discovery and rationale are in [review-campaigns-plan.md](review-campaigns-plan.md).

- `backend/app/query.py` shares AND scope matching between findings, saved filters and campaign preview/activation.
- `backend/app/campaigns.py` freezes a compact population at activation. References plus severity, scored risk, three owners, group, tags and regulatory scope preserve the historical denominator without duplicating scanner payloads.
- `FindingWorkflow` remains live remediation state. Separate nullable review fields record the latest review; campaign snapshots and append-only audit events preserve campaign-specific decisions. Review does not change remediation status or assign ownership.
- Overdue is derived from due date and completion; next weekly/monthly periods use an explicit clone action. SQL aggregation avoids a second materialized metrics store.

## 2. Database

`backend/migrations/versions/0005_review_campaigns.py` adds `review_campaigns`, `campaign_reviewers`, `campaign_findings`, `campaign_finding_tags`, `campaign_evidence`, and `campaign_audit_events`. Five nullable review columns extend `finding_workflows`. Indexes cover campaign status, finding uniqueness, severity, each owner, group, environment/status and campaign audit time. Existing data columns are not dropped or rewritten.

`backend/app/bootstrap.py` runs Alembic under a PostgreSQL session advisory lock; local SQLite uses a file lock. Lock scope includes idempotent demo seeding. `backend/migrations/env.py` accepts that same connection. Initial revision creation is restricted to its original tables so fresh databases cannot accidentally pre-create future schema.

## 3. Backend

`backend/app/api/campaigns.py` provides create/list/get/patch, scope preview, reviewer assignment, activate/complete/reopen/archive/clone, paginated and filtered findings, individual/bulk review, metrics, evidence and audit. Input enums and dates live in `campaign_schemas.py`. The shared campaign service enforces transitions and review authorization.

`backend/app/api/campaign_exports.py` provides campaign CSV/PDF evidence. Existing executive JSON/PDF endpoints in `api/governance.py` use `executive.py` and `report_pdf.py`. The legacy weekly review CSV now recognizes the new live review fields while preserving old review records.

## 4. Frontend

`frontend/src/pages/ReviewCampaigns.tsx` adds the dashboard, six-step creation wizard, history, filters, charts and explicit next-period cloning. `CampaignDetail.tsx` provides paginated findings, snapshot inspection, individual and selected/all-matching bulk review, evidence, audit and insights. `components/campaignShared.tsx` and `campaigns.css` share accessible controls and styling.

`pages/ExecutiveReport.tsx` adds report filters, exposure and governance visuals, comparison directions and supporting links. Navigation is in `App.tsx`. `Management.tsx` exposes asset groups alongside existing independent business, IT and application owner properties.

## 5. Executive report

The report distinguishes current estate exposure from campaign review obligations. A finding in two campaigns represents two obligations. Current risk includes only current completed assessments under the current methodology; drafts, stale and unassessed findings are disclosed and excluded from scored averages.

- KPIs: active findings, Critical, High, affected assets, current assessments, average residual risk, reviewed population entries, review coverage, processed coverage, campaign completion, overdue campaigns, pending, skipped, approved/unexpired exceptions and inventory coverage.
- Dashboard on PDF page two: severity counts, assessment posture, above/within appetite, assessment backlog and residual-risk distribution.
- Charts/details: technical severity, residual risk, review status distribution, coverage by severity, owners and asset groups, review coverage trend, reviewed entries over time, campaign completion trend and saved campaign snapshot risk.
- Comparison: current/equal-length previous period, percentage-point changes, metric-specific improvement/deterioration arrows and colors. Missing previous population is n/a; no historical estate risk is reconstructed.
- Supporting tables: three owners, asset groups, plugins, campaign population and completed/overdue/incomplete counts.
- Deterministic attention rules in `executive.py`: any overdue campaign, any critical pending review, coverage below 80%, owner/group coverage below 80% with at least five entries, skipped share above 10%, coverage decline of at least 10 percentage points. Items link to supporting campaign populations.
- Empty denominators show No data. PDF text is escaped; vector charts remain sharp; tables repeat headers and paginate. Campaign finding entries stay together where possible.

## 6. Security

Campaign queries and exports are scoped by the server-selected session environment. Administrators manage all scoped campaigns; analyst creators manage their campaigns and assigned analysts review them; viewers read Completed/Archived results only. Object-level checks cover finding, evidence and campaign IDs. Cookie mutations require CSRF. Bulk actions are transactional and record prior/new state plus affected references. CSV cells neutralize formula prefixes; PDF paragraphs escape markup. No credential fields enter snapshots or exports. Docker build contexts exclude local credentials and databases.

## 7. Tests and observed results

From the repository root, using a fresh disposable PostgreSQL 17 container with a tmpfs data directory (no production volume):

```sh
VRAP_TEST_DATABASE_URL=postgresql+psycopg://vrap_test@127.0.0.1:52172/vrap_migration_release \
VRAP_CAMPAIGN_DATABASE_URL=postgresql+psycopg://vrap_test@127.0.0.1:52172/vrap_campaign_release \
PYTHONPATH=backend .venv/bin/pytest -q -s backend/tests
npm --prefix frontend run build
git diff --check
```

Result: **60 passed, 0 failed**, 11.88 seconds. One Starlette/httpx deprecation warning. Frontend build passed; Vite reports a non-failing large-bundle warning (869 kB before gzip). The final PDF pagination-only adjustment was followed by `PYTHONPATH=backend .venv/bin/pytest -q backend/tests/test_reports.py`: **8 passed, 0 failed**.

The optional PostgreSQL tests require empty databases. A normal local run without those variables produced 58 passed and two explicitly skipped PostgreSQL checks.

Evidence covered:

- Golden population 500 / 420 reviewed / 50 pending / 30 skipped: 84% review coverage and 90% processed coverage. Closing/changing 100 live findings leaves the snapshot population and attributes unchanged.
- Additive upgrade of a pre-feature schema with sample rows on SQLite and PostgreSQL; second upgrade is idempotent and preserves all original sampled columns.
- Role/object/environment isolation, CSRF, invalid transitions, filter whitelists, bulk limits and transaction rollback, recurrence calendar boundaries, previous-period math and deterministic attention.
- 10,000 findings, PostgreSQL: activation 1.230 s; bulk review 1.732 s; list 0.006 s; metrics 0.023 s; executive JSON 0.112 s. SQLite: activation 0.222 s; list 0.004 s; metrics 0.023 s; executive JSON 0.053 s. Metrics used eight queries independent of population. These are local smoke benchmarks, not production load guarantees.
- Both Docker images built for `linux/amd64`. Isolated Docker web/API/PostgreSQL stack: health, cookie login, campaign activation/bulk, executive JSON and complete PDF HTTP responses passed. PDF bytes began `%PDF` and ended `%%EOF`; Content-Length matched. Two additional bootstrap runs preserved 20 findings, one user and migration 0005.
- Browser: six-step wizard, scope preview, activation, review decision with evidence reference, completion, snapshot/evidence views, campaign charts and executive report rendered successfully in the local demo. Screenshot evidence is under ignored `output/ui/`.
- Every final PDF page was rendered and visually inspected: executive demo (8), executive no-data (7), campaign evidence (13). Long owner names, no-data states, charts, comparison colors, tables and audit pagination were checked.

Not tested: production-scale concurrent reviewer load, 100,000-row PDF generation, a restored production backup, browser download completion tracking (HTTP PDF completion was tested), mobile browser matrix, live Tenable synchronization. No new penetration-test claim is made for this feature release.

## 8. Known limitations

Activation is synchronous, bounded at 100,000 findings; a bulk operation is bounded at 10,000. Large evidence PDFs are generated in-process. Recurrence is a clone action, not a scheduled generator. Evidence stores references/notes only. Historical campaign populations can differ; snapshot risk is not a continuous estate trend. Notifications and scheduled delivery of exports are not part of this release. Frontend route splitting is a future performance improvement.

## 9. Deployment and rollback

`.github/workflows/publish.yml` gates publication on backend tests (including isolated PostgreSQL migration/performance checks) and frontend build. Passing builds publish `shyhotboy/vrap-api` and `shyhotboy/vrap-web` with `latest` and immutable commit-SHA tags. Existing GitHub secret patterns remain; the optional webhook step is unchanged.

For the existing Portainer/ZimaBoard stack:

1. Recommend a `pg_dump` backup from the existing database before the first upgrade; retain it outside the live volume and verify it is readable. Backup/restore automation is outside this change.
2. Record current application image digests and the database container/mount before updating.
3. Pull the new API and web images after the passing publication job. Redeploy those app services in the existing stack, retaining environment variables and the exact existing volume block. Do not delete the stack or volumes.
4. API startup runs the locked, additive migration before serving requests. Confirm health, login, campaigns and executive export.
5. Confirm the same database container/mount and compare pre/post existing-row counts/content checksums.
6. Rollback: select the recorded previous API/web image digests or immutable tags and redeploy only app services. Keep additive schema at 0005; do not run downgrade or restore over the live database as an app rollback.

No repository Compose file or volume definition was changed. The real Portainer inspection confirmed volume `vrap_db_clean_20261005` and an identical volume-block hash. The existing stopped web container was started successfully. No database volume was deleted, renamed, recreated or reset by this work. Before release deployment, LAN access became unavailable again; production upgrade and final login remain pending and must not be inferred from local checks.

## 10. Next features and architecture

- Asset inventory reconciliation: ingest authoritative inventory into separate source/staging tables, match stable asset identifiers, and expose missing/duplicate/retired candidates for human confirmation before changing live assets.
- Risk trend history: append dated environment-scoped risk snapshots with methodology and population identifiers. Record new observations prospectively; do not backfill invented historical values.
- Backup and restore verification: a least-privilege scheduled backup job with encrypted retention plus a disposable restore validation job checking schema, counts and sample integrity. Never restore a test over production.
- Notifications: an environment-scoped outbox with deduplication, retry state and delivery preferences. Emit events for failed imports/syncs, overdue campaigns and documented coverage gaps; avoid sending credentials or raw scanner payloads.

## 11. Acceptance criteria

| Criterion | Status | Evidence |
|---|---|---|
| Existing regression suite and new feature tests pass | Verified | 60 tests, including real PostgreSQL |
| Additive schema preserves pre-feature sample data | Verified | SQLite/PostgreSQL upgrade twice |
| Snapshot population survives live remediation | Verified | 500 population, 100 live changes |
| Correct coverage and skipped distinction | Verified | Golden 84% / 90% |
| Campaign transitions, review, bulk and evidence | Verified | API tests and browser workflow |
| Environment isolation, RBAC, CSRF and IDOR | Verified | Cross-environment/object tests |
| Shared AND scope and saved filters | Verified | Finding/preview matching test |
| Audit and safe CSV/PDF exports | Verified | API tests and complete HTTP PDFs |
| Executive dashboard, governance and comparisons | Verified | Report tests plus browser/PDF inspection |
| 10k population SQL performance | Verified | Timings above on both databases |
| Restart/concurrent startup safety | Verified | SQLite subprocess test, PostgreSQL bootstrap runs |
| Docker image builds and isolated container health | Verified | Both amd64 images and isolated stack |
| GitHub publication gating | Implemented-not-verified | Release workflow awaits publication run |
| ZimaBoard release migration and portal login | Implemented-not-verified | Network unavailable at this checkpoint |
| Existing PostgreSQL volume definition untouched | Verified | No Compose diff; real mount and block hash |
| Automatic recurrence, notifications, backup automation | Not done | Explicitly outside scope |
