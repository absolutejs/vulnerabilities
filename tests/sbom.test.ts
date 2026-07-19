import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  evaluateDeploymentAdmission,
  VULNERABILITY_CONTRACT_VERSION,
  type ManagedVulnerabilityFinding,
  type VexDecision,
} from "../src";
import {
  cycloneDxSbomToInventory,
  generateCycloneDxSbom,
  parseCycloneDxSbom,
  signSbomAttestation,
  verifySbomAttestation,
} from "../src/sbom";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe("runtime CycloneDX SBOM", () => {
  test("records the actual installed npm tree and signs immutable evidence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "absolutejs-sbom-"));
    roots.push(root);
    await mkdir(path.join(root, "node_modules", "fixture"), {
      recursive: true,
    });
    await writeFile(
      path.join(root, "package.json"),
      JSON.stringify({ name: "client-web" }),
    );
    await writeFile(
      path.join(root, "node_modules", "fixture", "package.json"),
      JSON.stringify({ name: "fixture", version: "2.3.4" }),
    );
    const sbom = await generateCycloneDxSbom({
      generatedAt: "2026-07-18T20:00:00Z",
      releaseId: "release-1",
      root,
    });
    expect(sbom).toMatchObject({
      bomFormat: "CycloneDX",
      metadata: { component: { version: "release-1" } },
      specVersion: "1.6",
    });
    expect(sbom.components.map(({ purl }) => purl)).toEqual([
      "pkg:npm/fixture@2.3.4",
    ]);
    const inventory = cycloneDxSbomToInventory({
      asset: {
        criticality: "high",
        environment: "production",
        id: "project-1",
        kind: "deployment",
        labels: {},
        name: "client-web",
        tenantId: "project-1",
        version: "release-1",
      },
      sbom,
    });
    expect(inventory.components[0]?.identity.version).toBe("2.3.4");
    const signed = signSbomAttestation({
      issuedAt: "2026-07-18T20:01:00Z",
      keyId: "control-plane-audit",
      projectId: "project-1",
      releaseId: "release-1",
      sbom,
      secret: "a-secure-sbom-signing-secret-with-32-bytes",
    });
    expect(
      verifySbomAttestation(
        signed,
        "a-secure-sbom-signing-secret-with-32-bytes",
      ),
    ).toBe(true);
    expect(
      verifySbomAttestation(
        { ...signed, releaseId: "release-2" },
        "a-secure-sbom-signing-secret-with-32-bytes",
      ),
    ).toBe(false);
    expect(() =>
      parseCycloneDxSbom({ ...sbom, components: [{ name: "forged" }] }),
    ).toThrow("type is invalid");
  });
});

describe("deployment admission", () => {
  const finding: ManagedVulnerabilityFinding = {
    assetId: "project-1",
    componentId: "fixture",
    contract: VULNERABILITY_CONTRACT_VERSION,
    firstSeenAt: "2026-07-18T20:00:00Z",
    id: `vuln_${"a".repeat(64)}`,
    lastSeenAt: "2026-07-18T20:00:00Z",
    observationIds: ["observation-1"],
    severity: "critical",
    status: "confirmed",
    tenantId: "project-1",
    vulnerabilityIds: ["CVE-2026-0001"],
  };
  const decision: VexDecision = {
    author: "security@example.com",
    contract: VULNERABILITY_CONTRACT_VERSION,
    createdAt: "2026-07-18T19:00:00Z",
    evidence: [
      {
        collectedAt: "2026-07-18T19:00:00Z",
        digest: null,
        kind: "vendor-status",
        source: "vendor-review",
        uri: null,
      },
    ],
    expiresAt: "2026-08-18T20:00:00Z",
    id: "vex-1",
    justification: "vendor_backport_applied",
    productId: "project-1",
    reviewedAt: "2026-07-18T19:30:00Z",
    statement: "The deployed build is not affected.",
    status: "not_affected",
    vulnerabilityId: "CVE-2026-0001",
  };

  test("blocks critical and known-exploited findings", () => {
    expect(
      evaluateDeploymentAdmission({
        evaluatedAt: "2026-07-18T20:00:00Z",
        findings: [finding],
        knownExploitedCves: new Set(["CVE-2026-0001"]),
        productId: "project-1",
      }),
    ).toMatchObject({
      status: "failed",
      violations: [{ reasons: ["critical", "known_exploited"] }],
    });
  });

  test("records a reviewed VEX decision as a signed-admission exception", () => {
    expect(
      evaluateDeploymentAdmission({
        decisions: [decision],
        evaluatedAt: "2026-07-18T20:00:00Z",
        findings: [finding],
        knownExploitedCves: new Set(["CVE-2026-0001"]),
        productId: "project-1",
      }),
    ).toMatchObject({
      exceptions: [{ decisionId: "vex-1", findingId: finding.id }],
      status: "passed",
      violations: [],
    });
  });
});
