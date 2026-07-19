# @absolutejs/vulnerabilities

Reusable vulnerability-management primitives for AbsoluteJS applications.
The package normalizes scanner output, applies explicit severity thresholds,
collects Debian/Ubuntu host inventory through a deploy-compatible target, and
produces evidence objects suitable for storage or compliance reporting.

Version `0.2.0` also defines the canonical contracts shared by feed adapters,
scanner adapters, persistence layers, remediation workers, and PAAS. Assets,
components, advisories, scanner observations, managed findings, VEX decisions,
risk assessments, remediation plans, and execution evidence all carry an
explicit contract version.

It deliberately preserves distribution package versions and vendor security
status. A version such as `1.24.0-2ubuntu7.5` must not be reduced to upstream
`1.24.0`: Ubuntu and other distributions backport security fixes without
changing the upstream version, and discarding the distro revision creates false
positives.

```ts
import {
  assertVulnerabilityPolicy,
  createVulnerabilityEvidence,
  summarizeGrypeReport,
} from "@absolutejs/vulnerabilities";

const counts = summarizeGrypeReport(await Bun.file("grype.json").json());
assertVulnerabilityPolicy(counts, {
  maximums: { critical: 0, high: 0 },
});

const evidence = createVulnerabilityEvidence({
  asset: { id: imageDigest, kind: "container" },
  scan: {
    ...counts,
    databaseBuiltAt: grypeDatabaseBuiltAt,
    scannedAt: new Date().toISOString(),
    scanner: "grype",
  },
});
```

Host collection is structurally compatible with `@absolutejs/deploy` targets:

```ts
import { collectDebianHostInventory } from "@absolutejs/vulnerabilities/host";

const inventory = await collectDebianHostInventory(deployTarget);
```

Scanner execution, scheduling, persistence, remediation approvals, and user
interfaces remain application concerns. This package owns the contracts and
decisions those applications should not hand-roll.

The remediation lifecycle keeps deployment success separate from security
verification. A successful execution requires deployment evidence, and a
finding becomes `fixed` only after a later inventory observation proves it is
absent. Remediating findings remain open while that verification is pending.

Inventory correlation is ecosystem-aware and fails closed when a version
scheme cannot be compared. `osv.ecosystem` on a component preserves vendor
release context such as `Ubuntu:24.04` while the component purl remains a
standard `pkg:deb` identifier.

```ts
import { correlateVulnerabilityInventory } from "@absolutejs/vulnerabilities";

const result = correlateVulnerabilityInventory({
  advisories,
  asset,
  components,
  existingFindings,
  observedAt: new Date().toISOString(),
});

await findingStore.saveMany(result.upserts);
```

Managed finding identities are deterministic and scanner-independent:

```ts
import { createStableFindingId } from "@absolutejs/vulnerabilities";

const findingId = createStableFindingId({
  tenantId: "tenant-1",
  assetId: "production-web-1",
  componentIdentity: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5",
  vulnerabilityIds: ["CVE-2026-0001", "USN-9999-1"],
});
```

Alias order, duplicate aliases, and identifier case do not change the result.
Changing the tenant, asset, component identity, or vulnerability identity does.

## Version intelligence

Version comparison is ecosystem-aware and explainable. Debian/Ubuntu revisions,
epochs, and backport suffixes are preserved rather than reduced to upstream
versions. SemVer, Go module, Python PEP 440, and NuGet versions use their native
ordering rules.

```ts
import {
  comparePackageVersions,
  evaluateVersionConstraints,
} from "@absolutejs/vulnerabilities";

comparePackageVersions({
  ecosystem: "ubuntu",
  left: "1.24.0-2ubuntu7.4",
  right: "1.24.0-2ubuntu7.5",
});

evaluateVersionConstraints({
  ecosystem: "ubuntu",
  installedVersion: "1.24.0-2ubuntu7.4",
  constraints: [
    { operator: "gte", version: "1.24.0" },
    { operator: "lt", version: "1.24.0-2ubuntu7.5" },
  ],
});
```

RPM, APK, and Maven comparisons require a verified adapter. Without one, the
package returns `unknown`; it never substitutes lexicographic or generic SemVer
ordering for an ecosystem it cannot compare defensibly.

## Advisory feeds

Feed adapters share cursor, snapshot, cache, and failure-isolation contracts.
Applications can persist snapshots in their own storage while keeping provider
fetching separate from policy and remediation logic.

Alert operations can use `VulnerabilityAlertConfiguration` to keep evaluation
SLAs, severity-specific escalation timing, and opened/escalated/resolved
notification routing in one validated contract. Use
`validateVulnerabilityAlertConfiguration` at persistence boundaries and
`resolveVulnerabilityAlertAudiences` when queuing deliveries. Owner routes fall
back to administrators when an alert has no owning asset.

```ts
import { createMemoryFeedStore, syncFeed } from "@absolutejs/vulnerabilities";

const result = await syncFeed({
  adapter,
  maxStaleMs: 24 * 60 * 60 * 1_000,
  store: createMemoryFeedStore(),
});

if (result.status === "stale") {
  // Cached intelligence remains available, with the provider error attached.
}
```

An adapter can replace a complete provider snapshot or incrementally merge
records and deletions. `not_modified` responses require an existing cached
snapshot, and provider failures never erase the last successful snapshot.

Production stores remain replaceable through the `FeedSnapshotStore`,
`FeedSyncRunStore`, and `ManagedFindingStore` contracts. Recorded refreshes
persist status, errors, revisions, timestamps, and record counts without
coupling feed orchestration to a database driver.

Deployment admission can retain a signed OSV and CISA KEV snapshot instead of
calling upstream providers on the activation path. Exact package/version
coverage is part of the signed payload, including queries that returned no
advisories, so missing intelligence cannot be interpreted as a clean result.

```ts
import {
  admissionIntelligenceCoverageKey,
  signAdmissionIntelligenceSnapshot,
} from "@absolutejs/vulnerabilities/intelligence-snapshot";

const attestation = signAdmissionIntelligenceSnapshot({
  coverage: components.map(({ identity }) =>
    admissionIntelligenceCoverageKey(identity),
  ),
  issuedAt: new Date().toISOString(),
  kev: kevSnapshot,
  keyId: "vulnerability-intelligence-v1",
  maxAgeMs: 24 * 60 * 60 * 1_000,
  osv: osvSnapshot,
  secret: signingSecret,
});
```

Client evidence can be wrapped in an Ed25519 bundle that binds the runtime
SBOM, signed intelligence snapshot, admission decision, and the exact VEX
exceptions used. Verification requires only the public key. Cross-signed key
transitions preserve trust when an operator rotates the signing identity.

```ts
import {
  createEvidenceSigningIdentity,
  evidenceVerificationKeyFrom,
  signVulnerabilityEvidenceBundle,
  verifyVulnerabilityEvidenceBundle,
} from "@absolutejs/vulnerabilities/evidence-bundle";

const identity = createEvidenceSigningIdentity();
const bundle = signVulnerabilityEvidenceBundle({ identity, payload });
const verification = verifyVulnerabilityEvidenceBundle({
  bundle,
  trustedKeys: [evidenceVerificationKeyFrom(identity)],
});
```

Private keys remain an application secret. Published trust anchors contain
only the key ID, fingerprint, creation time, algorithm, and DER public key.

Key creation, rotation, and revocation can also be recorded in a signed,
hash-chained transparency log. A client pins the genesis key fingerprint, the
latest log head, or both through a trusted out-of-band channel. This detects
rewritten or truncated history and rejects bundles signed by revoked keys.

```bash
absolute-vulnerability-evidence verify \
  --bundle vulnerability-evidence.json \
  --registry vulnerability-evidence-registry.json \
  --trusted-fingerprint <genesis-sha256-fingerprint> \
  --trusted-head <sha256-log-head> \
  --trusted-witness-fingerprint <witness-sha256-fingerprint>
```

The command exits `0` only for trusted evidence, `1` for cryptographically
valid but untrusted or revoked evidence, and `2` for invalid input or usage.
When a registry includes a receipt from an independent witness, the optional
witness fingerprint requires that receipt to match the exact log head and size.
