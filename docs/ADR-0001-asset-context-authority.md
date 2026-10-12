# ADR-0001: Asset context authority and bulk-assessment boundary

**Status:** Accepted for M1 transitional enforcement  
**Date:** 2026-10-11

## Decision

Plugin assessment submissions represent shared technical scenario information. They are not a source of truth for `asset_criticality`, `business_criticality`, `data_classification`, `regulatory`, `environment`, `exposure`, or derived `production` / `publicly_accessible` values.

For every finding in a bulk plugin assessment, VRAP merges shared scenario fields with the current asset-held values. Non-empty asset-held authority fields win. The resulting context is persisted with that individual assessment and evaluated per finding.

Bulk risk acceptance is prohibited. A requester cannot approve or reject their own exception. The delivered M1 schema extension now records governed classification-change requests and independent regulatory memberships. Delegated authority, questionnaire state and richer evidence lifecycle remain M2 work.

## Authority matrix

| Field family | Current authority | Allowed current mutation | Planned authority metadata |
|---|---|---|---|
| PCI DSS / SOC 2 memberships | Asset context, protected during bulk assessment | Controlled asset action only | Independent membership records with source, approval and effective dates |
| Criticality, classification, environment, exposure | Asset context, protected during bulk assessment | Controlled asset action only | Provenance, lock, verifier, confidence and context version |
| Shared exploit scenario and analyst notes | Bulk assessment input | Analyst assessment | Scenario template/version and evidence |
| Control applicability/evidence | Assessment control | Analyst; validation must remain explicit | Control-library evidence lifecycle |
| Formal risk acceptance | Exception workflow | Not bulk; self-approval blocked | Delegated risk-owner/GRC approval |

## Consequences

Migration `0007` now records an incrementing context version and per-field provenance. Imports and rules fill only unknown asset values, and rule reconciliation deletes only values explicitly marked rule-derived. Existing assets without provenance remain transitional: VRAP preserves ambiguous legacy values rather than risk clearing an authoritative classification. A future schema must add independent regulatory memberships, approval/effective-date records, and formal classification-change requests.
