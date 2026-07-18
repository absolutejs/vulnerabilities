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
