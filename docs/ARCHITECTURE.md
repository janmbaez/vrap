# VRAP architecture and implementation contract

## Assumptions and scope
Single organization; Tenable Vulnerability Management cloud API; no Security Center adapter. Phase 1 is the MVP. All demo records are synthetic, not intelligence about real CVEs. PostgreSQL is the deployment database; SQLite is an explicitly optional local demo/test profile. React/TypeScript, FastAPI/Pydantic, SQLAlchemy, Recharts and Docker preserve the requested architecture. No cloud deployment or live account access is assumed.

## 1. Architecture
Browser → same-origin reverse proxy → FastAPI services → relational database. The risk engine is a pure Python module with no network/database/UI dependencies. The API is the sole scoring authority, including debounced previews. Ingestion normalizes upstream records before persistence; assessment records never mutate source evidence. Configuration is append-only by version. AI is a future proposal provider; it must submit proposed values through an explicit analyst approval operation and never write scores.

## 2. Relational schema
- users(id, username unique, password_hash, role, active)
- sessions(id hash, user_id FK, workspace, csrf_hash, expires_at)
- assets(id, workspace, external_id nullable, hostname, ip, os, tags JSON, context JSON); unique workspace/hostname and workspace/external_id
- vulnerabilities(id, identity unique, plugin_id, name, cves JSON, technical JSON)
- vulnerability_instances(id, asset_id FK, vulnerability_id FK, port, protocol, source, source_record JSON, observed JSON, revision); unique asset/vulnerability/port/protocol
- risk_methodologies(id, version unique, configuration JSON, created_by FK, created_at)
- assessments(id, instance_id FK, revision, methodology_id FK, analyst_id FK, context JSON, notes, justification, decision, status, created_at); unique instance/revision
- assessment_controls(id, assessment_id FK, name, component, effectiveness, validated, evidence, notes, design_maturity, operating_effectiveness)
- risk_scores(id, assessment_id unique FK, result JSON): result contains inputs, as-of date, appetite and full factor/control trace
- audit_log(id, actor_id FK nullable, action, entity, entity_id, details JSON, created_at)
- imports(id, owner_id FK, filename, source, headers JSON, mapping JSON, status, counts JSON, created_at)
- import_rows(id, import_id FK, row_number, original JSON, errors JSON, instance_id FK nullable)
- tenable_sync_history(id, kind, status, counts JSON, error, started_at, finished_at)
- integration_settings(id, enabled, base_url, access_key_encrypted, secret_key_encrypted)
- asset_rules(id, name, priority, active, match_type, match_value, context JSON, controls JSON, created_by FK, created_at)

Risk factors, thresholds, appetite, requirements, severity maps and control policy are immutable typed configuration inside each methodology (rather than mutable global factor rows). Normalized assessment control evidence is separate. Snapshot JSON is used only for versioned configuration/evidence and is not a replacement for relational entities.

## 3. API contract
All protected paths are under /api; session cookie required. Writes require X-CSRF-Token. Viewer reads; Analyst creates findings/imports/assessments; Administrator additionally creates users/methodologies and manages integration.
POST /auth/login (Demo or Production); GET /auth/me; POST /auth/logout
GET /findings; POST /findings; GET /findings/{id}
POST /findings/{id}/preview; POST /findings/{id}/assessments; GET /findings/{id}/history
GET /assessment-groups; GET /assessment-groups/{vulnerability_id}; PUT /assessment-groups/{vulnerability_id}/assets
GET /assets; PUT /assets/{id}; GET/POST /asset-rules; POST /asset-rules/{id}/apply; GET /dashboard; GET /audit
GET /methodologies; POST /methodologies
GET /users; POST /users
POST /imports/preview (multipart); POST /imports/{id}/validate; POST /imports/{id}/commit; GET /imports
GET /tenable; PUT /tenable; POST /tenable/test; POST /tenable/sync/{kind}
GET /health
Assessment saves require the expected finding revision and methodology id. The server rejects stale saves (409). Revisions, score and audit event commit atomically.

## 4. UI
The login panel explicitly selects Demo or Production, and each session is restricted to that workspace. Persistent sidebar and compact header. Dashboard: KPI cards, residual distribution, prioritized findings. Findings: searchable asset-level table and filters. Assessments: plugin-grouped queue with affected-asset drill-down, assessment progress, per-finding workbench links and bulk authoritative asset-context updates. Workbench: source evidence / organizational context and validated controls / live risk explanation, GRC matrix and decision. Assets carry authoritative context across every linked finding; changing an asset through a plugin group flags all of that asset's findings for reassessment. Ordered CIDR, hostname-suffix, tag and catch-all rules apply context and provisional controls during ingestion and can be applied to existing assets. Plugin templates retain shared rationale, controls, ownership and workflow state while calculating each finding with its own asset context. Governed exceptions require justification, evidence, administrator approval, review frequency and expiration. Other pages cover durable background imports with progress and retryable state, data-quality checks, operational dashboards, a reusable mapped control library, printable executive reporting, Tenable administration, versioned methodology, audit trail and user administration. SLA and ticket-reference fields are intentionally excluded pending a future Jira integration.

## 5. Tenable adapter
Administrators may save TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY and TENABLE_BASE_URL in the UI; keys are encrypted at rest with the server-only Fernet key and are never returned by the API. Deployment-managed environment credentials remain supported. The default base URL is `https://cloud.tenable.com`. The base URL must be HTTPS with a deployment-configured host allowlist, so the browser cannot select arbitrary destinations. Async asset/vulnerability export jobs use bounded polling, retries for transient failures, chunk parsing, timeouts, idempotent upserts and safe errors. Failed synchronization does not commit partial finding updates. MVP jobs run in the API process; a durable queue/scheduler is a later deployment task.
References: https://developer.tenable.com/reference/exports-vulns-request-export ; https://developer.tenable.com/reference/exports-vulns-export-status ; https://developer.tenable.com/reference/export-assets-v1 . Full export uses an explicit time filter because Tenable defaults to recent data.

## 6. Imports
CSV UTF-8 and XLSX only, 100 MiB input, 100,000 rows, 100 columns, and a 300 MiB expanded-XLSX ceiling. Reject macro files, formulas, malformed archives, duplicate headers and unsupported MIME types. Require hostname or IP plus plugin name; other columns optional. Preview persisted original rows → map → validate → commit. Validation applies the same typed ingestion model as manual entry. Duplicates are counted and skipped, including duplicates within the upload. Transactional commit; a batch can only be committed once. Imported control presence is unvalidated and earns no reduction.

## 7–8. Risk engine and provisional methodology
Technical risk = configured weighted mean of available CVSS×10 and VPR×10; fall back to severity mapping if unavailable and flag missing information. Context factors map to normalized 0–100 values through versioned tables. Missing values use the explicit configurable unknown score (70 initially), remain in the trace, and block completion when required.
Likelihood = weighted mean of technical, exploitation, known exploitation, exposure, age and threat intelligence. Impact = weighted mean of technical, asset/business criticality, classification, regulatory scope, production, privilege and critical-process impact. Inherent risk = sqrt(likelihood × impact), before controls; baseline inherent risk uses default unknown organizational context. Contextual inherent risk uses analyst context and still excludes controls.
For each validated control with evidence and applicable scenario: component_after = component_before × (1 − effectiveness). Controls stack multiplicatively, with a configured maximum aggregate reduction of 85% per component. WAF requires web applicability, MFA requires authentication applicability; EDR/segmentation/firewall/IPS/backups require explicit applicability. Backups modify impact only. Residual = sqrt(adjusted likelihood × adjusted impact). Trace shows every weighted contribution, each applied/ignored control, caps and exact score deltas. No claim of calibrated probability or expected financial loss.
Classification uses unrounded scores and configurable lower bounds (Low 0, Medium 25, High 50, Critical 75). Display two decimals. Appetite comparison is ordinal; initial Medium. Within appetite never means accepted. Administrator approval is required for Risk Accepted; justification is always required to save. Requirements and configuration are validated before a new version can be published.

The parallel GRC crosswalk follows `Jan TVM Risk Analysis.xlsx`: likelihood and impact are each 1–5, inherent risk is their product, control design maturity plus operating-effectiveness maturity produces gross control strength 2–10, and the workbook lookup converts that strength into remaining risk. Residual bands are Informational 1–3, Low 4–6, Medium 7–9, High 10–16 and Critical 17–25. The authorized tolerance is the top of Medium; results above it recommend remediation. The original normalized engine remains the assessment authority while the crosswalk makes the GRC model explicit and reviewable.

## 9. Security
Argon2id hashes, random opaque tokens stored hashed, HttpOnly/SameSite cookies, secure cookies in deployment, 8-hour expiry, CSRF header checks plus origin checks on login, login throttling, server-side roles and database parameterization. Pydantic forbids unexpected fields. Uploaded input and logs are bounded. Source notes are plain text. Safe upstream errors never include API credentials. Saved integration keys use authenticated encryption with a deployment-managed Fernet key. No production default credentials or public signup. Database privileged administrators remain able to alter audit records; external immutable log retention, SSO/MFA, malware scanning and organizational retention policy are deployment extensions.

## 10–11. Deployment and folders
Docker Compose: PostgreSQL volume/healthcheck; Python API; nginx serving compiled React and proxying /api. Bind frontend to localhost by default. Place behind an organizational TLS reverse proxy and set APP_ORIGIN/COOKIE_SECURE for deployment. Run versioned Alembic migrations before the API. Explicit demo seed command, never automatic production seeding.
backend/app/{api,risk,integrations,imports}, backend/tests, backend/migrations, frontend/src/{components,pages}, docs. Dependency lock files and environment example included. Local demo SQLite makes testing possible when Docker is unavailable and does not replace PostgreSQL deployment validation.

## 12. Phases
1. Implement and verify schema/authentication, demo data, dashboard, manual finding entry, workbench, engine/explanations, decisions and audit.
2. Implement Tenable adapter, settings and sync history; mock tests now, tenant integration acceptance later.
3. Implement bounded CSV/XLSX preview/mapping/validation/import.
4. Basic version administration included early because methodology must be configurable; advanced reporting, bulk assessment, AI extraction, durable scheduling, ticketing, approval expiry and SSO remain extensions.
