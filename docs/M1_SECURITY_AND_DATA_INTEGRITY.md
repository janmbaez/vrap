# M1 — Security and Data Integrity

**Status:** In progress — first two P0 slices verified locally on 2026-10-11.

## Delivered safeguards

- Workspace-scoped import and exception mutations, with cross-workspace tests.
- Exception separation of duties: requesters cannot approve or reject their own exception.
- Per-asset context authority during plugin bulk assessment; bulk risk acceptance is rejected.
- Explicit delivery boundary: routine branch/main verification no longer deploys to Portainer.
- Liveness/readiness endpoints and narrower trusted-proxy default.
- Asset context version/provenance migration (`0007`).
- Imports and asset rules classify only missing context; they do not overwrite existing values.
- Shared plugin asset updates cannot alter protected classification fields.
- Rule disable/delete reconciles only explicitly rule-derived values, preserving manual and ambiguous legacy context.
- Shared assessment-currency rules now drive live dashboard counts, campaign score snapshots, and executive reporting. A current assessment is latest, completed, methodology-matching, revision-valid, and scored.
- Finding evidence fingerprints now keep an unchanged Tenable rescan from advancing assessment revision; scan freshness and lifecycle transitions are stored separately.

## Migration and rollback

`0007_asset_context_provenance` and `0008_finding_sync_state` are additive. It assigns safe defaults for existing assets. Its downgrade intentionally retains provenance data because audit evidence must not be silently deleted. Application rollback is possible, but it restores weaker enforcement and should be a security-reviewed change.

## Remaining M1 work

- Replace transitional JSON provenance with independent classification/membership and approval/effective-date records.
- Extend the shared current/stale/draft assessment denominator to every queue and export route, and define the operational policy for which non-scanner asset/control changes are material.
- Complete the mutation-route workspace audit and add snapshot-based Tenable ingestion.
- Add delegated risk-owner/GRC approval workflow for formal acceptance.
