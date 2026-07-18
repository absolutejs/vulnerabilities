# Changelog

## 0.9.0 - 2026-07-18

- Add deterministic alerts for emergency findings and remediation SLAs.
- Detect approaching deadlines, overdue verification, and expiring VEX decisions.
- Detect failed or stale vulnerability feeds and workers.

## 0.8.1 - 2026-07-18

- Require the still-active deployment release to match every approved target.
- Reject deployment evidence outside the remediation execution window.

## 0.8.0 - 2026-07-18

- Add approval-gated remediation planning and execution lifecycle helpers.
- Require deployment evidence plus later inventory absence before closing findings.
- Add remediation plan, execution, and verification persistence contracts.
- Hold remediating findings open until verification completes.

## 0.5.0 - 2026-07-18

- Add provider-neutral feed sync-history contracts and recorded synchronization.
- Add managed-finding persistence contracts with tenant-scoped filters.
- Keep database adapters replaceable without changing orchestration code.

## 0.4.0 - 2026-07-18

- Add provider-neutral feed adapters, cursors, snapshots, and stores.
- Add incremental record merging, deletion handling, and deterministic ordering.
- Preserve cached intelligence during provider failures and distinguish stale
  snapshots from transient failures.
- Extend advisory contracts with OSV-compatible affected packages and ranges.

## 0.3.0 - 2026-07-18

- Add normalized Package URL component identities.
- Add explainable Debian, SemVer, Go, PEP 440, and NuGet comparisons.
- Add version-constraint evaluation for advisory affected ranges.
- Add comparator adapters for ecosystems that require native or verified
  implementations, returning `unknown` instead of guessing.

## 0.2.0 - 2026-07-18

- Add versioned contracts for assets, components, advisories, observations,
  managed findings, VEX decisions, risk assessments, remediation plans, and
  execution evidence.
- Add deterministic finding identities independent of scanner record IDs.
- Preserve the 0.1 Grype summary and policy APIs for PAAS compatibility.

## 0.1.0 - 2026-07-18

- Add scanner-neutral severity counts and policy evaluation.
- Add Grype report normalization with finding metadata.
- Add Debian/Ubuntu package and vendor security-status inventory.
- Add structured vulnerability evidence generation.
