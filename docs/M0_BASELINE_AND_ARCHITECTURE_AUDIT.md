# M0 — Baseline and Architecture Audit

**Date:** 2026-10-11  
**Scope:** VRAP repository baseline only. No production service, credentials, Tenable tenant, or persisted production data was accessed.

## Baseline verification

| Check | Result | Notes |
|---|---:|---|
| Backend suite | PASS | 78 passed, 2 skipped. |
| Frontend production build | PASS | TypeScript and Vite build complete. The bundle-size warning remains an optimization item. |
| Fresh SQLite migration chain | PASS | `DATABASE_URL=sqlite:////tmp/vrap-m0-migration.db ... alembic upgrade head`. |
| Docker runtime | NOT RUN | Docker Desktop daemon is unavailable on this workstation. |
| Direct PostgreSQL migration | NOT RUN | Local host cannot resolve the Compose-only `db` hostname. This is expected outside Compose. |

## Architecture map

| Area | Primary paths | Current state |
|---|---|---|
| API and session auth | `backend/app/main.py`, `auth.py`, `api/*.py` | FastAPI, server-side sessions, CSRF, three roles and workspace selection. |
| Persistence | `models.py`, `migrations/versions` | SQLAlchemy/PostgreSQL-compatible schema; assets and findings carry workspace. |
| Risk assessment | `risk/engine.py`, `risk/policy.py`, `services.py` | Versioned normalized 0–100 calculation plus GRC 5×5 crosswalk. |
| Ingestion | `imports/*`, `integrations/tenable.py`, `api/tenable.py` | CSV/XLSX validation and Tenable background task implementation. |
| Governance | `api/governance.py`, `campaigns.py` | Assessment, review campaigns, exceptions, controls, audit log. |
| Frontend | `frontend/src/pages`, `components/UI.tsx` | React/TypeScript; several large pages remain monolithic. |
| Delivery | `.github/workflows/publish.yml`, Dockerfiles, Compose | Test/build pipeline and container image publishing. |

## Traceability matrix

| Requirement / finding | Status | Evidence | Severity | M1 disposition |
|---|---|---|---|---|
| Workspace isolation on finding APIs | Existing | `api/core.py` guards finding workspace | High | Continue endpoint-by-endpoint audit. |
| Exception decision IDOR | Broken | `PUT /exceptions/{id}` fetched by ID without workspace | Critical | Fixed in M1 slice. |
| Import object IDOR and duplicate scope | Broken | `imports.py` did not apply workspace to every mutation or duplicate lookup | Critical | Fixed in M1 slice. |
| Plugin bulk assessment preserves per-asset context | Broken | `bulk_assess_plugin` reused submitted `Context` for all findings | Critical | Fixed in M1 slice. |
| Risk acceptance governance | Partial | Individual/bulk admin path existed; no segregation-of-duties model | High | Bulk acceptance is now blocked; formal approval redesign remains M1/M2. |
| Asset provenance and immutable regulatory memberships | Missing | Free-form JSON `Asset.context`, no provenance/version tables | Critical | Design/migration planned before classification UI. |
| Current assessment denominator | Partial | Dashboard checks assessment revision/methodology; campaign and report definitions need one shared service | High | M1 follow-up. |
| Material-change fingerprint | Missing | `services.ingest()` increments revision on any Tenable update | High | M1 follow-up. |
| Atomic Tenable snapshot publication | Missing | Records are committed in batches during export | High | M1 follow-up. |
| TLS/trusted proxy/cookie deployment safety | Partial | Headers/cookies exist; Docker used unrestricted forwarded headers and main push redeployed | High | Automatic deployment removed; proxy boundary narrowed. |
| Control evidence lifecycle | Partial | Assessment controls have evidence and validation fields, no expiry/recertification | Medium | M5. |
| Mission Center / classification quest | Missing | No authoritative proposal/wizard models | Medium | M2/M3. |

## Threat model summary

1. **Cross-workspace forced browsing:** guessed IDs could modify an exception or import in another workspace. Mitigated in this slice with workspace-scoped retrieval and tests.
2. **Classification downgrade through bulk workflows:** a plugin-level operator could submit one context that changed per-asset regulatory/criticality inputs. Mitigated in this slice by treating asset-held classification fields as authoritative for each calculation.
3. **Improper risk acceptance:** bulk flow was able to create an acceptance status. Bulk acceptance is now rejected; formal delegated approval is still pending.
4. **Unsafe deployment propagation:** a `main` push published images and called Portainer. CI now verifies every push but publishes images only through an explicit dispatch, without deployment.
5. **Sync partial visibility:** current Tenable batches are visible before the export succeeds. A staging snapshot/atomic promotion model remains required.

## M1 implementation plan

1. **P0 completed in this slice:** endpoint workspace enforcement, self-approval guard, per-asset bulk context, and explicit promotion boundary.
2. **P0 next:** asset-context provenance/locking and regulatory-membership table; material evidence fingerprint; cross-workspace audit of every mutation route.
3. **P1:** current/stale/draft denominator service shared by dashboard, campaigns, reports; Tenable staging snapshot and retry worker boundary.
4. **M2:** classification-change request, review/approval workflow and accessibility-first quest.

## Rollback notes

This slice contains no schema migration. Reverting its commit restores prior endpoint behavior, but doing so would reintroduce cross-workspace mutation and bulk-classification vulnerabilities. Deployment behavior is intentionally changed: image publication/deployment must be manually approved.
