# Changelog

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
