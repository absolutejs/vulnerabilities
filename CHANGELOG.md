# Changelog

## 0.12.1 - 2026-07-19

- Keep all JavaScript entrypoints and the verification CLI at their declared
  package export paths when building the expanded witness release.

## 0.12.0 - 2026-07-19

- Add independently signed transparency checkpoints with pinned witness-key
  verification and exact log-head and log-size binding.

## 0.11.0 - 2026-07-19

- Add a signed, hash-chained evidence-key transparency log covering key
  creation, cross-signed rotation, and explicit revocation.
- Verify bundles against pinned genesis fingerprints and transparency heads,
  detecting rewritten, reordered, truncated, and revoked signing history.
- Ship `absolute-vulnerability-evidence verify` for offline client validation.

## 0.10.6 - 2026-07-19

- Sign portable vulnerability evidence bundles with Ed25519 keys that clients
  can verify without access to control-plane secrets.
- Cross-sign key rotations and verify a bundle back to a pinned public trust
  anchor while retaining SBOM, intelligence, admission, and VEX evidence.

## 0.10.5 - 2026-07-19

- Sign admission-intelligence snapshots that bind exact package/version query
  coverage to retained OSV advisories, CISA KEV records, and a freshness SLA.
- Verify snapshot integrity and distinguish invalid evidence from expired data.

## 0.10.4 - 2026-07-18

- Validate CycloneDX 1.6 structure, npm Package URLs, timestamps, component
  identity, and uniqueness before correlation or attestation signing.

## 0.10.3 - 2026-07-18

- Use the immutable release ID as the application component version so runtime
  SBOM generation supports applications without a declared package version.

## 0.10.2 - 2026-07-18

- Generate CycloneDX 1.6 inventories from the dependency tree actually present
  in `node_modules` and convert them to vulnerability inventory targets.
- Sign and verify immutable SBOM attestations with a keyed SHA-256 envelope.
- Add fail-closed deployment admission for critical and CISA KEV findings with
  reviewed, evidence-backed VEX exceptions.

## 0.10.1 - 2026-07-18

- Allow inventory correlation observations to retain an immutable provider URI
  and SHA-256 evidence digest.

## 0.10.0 - 2026-07-18

- Add a validated alert configuration contract for evaluation SLAs, escalation
  timing, and notification routing.
- Resolve owner and administrator audiences deterministically with an
  administrator fallback for alerts without an owning asset.

## 0.9.1 - 2026-07-18

- Keep finding alert identities stable when remediation plans are attached.

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
