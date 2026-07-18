import { describe, expect, test } from "bun:test";
import { Value } from "@sinclair/typebox/value";
import {
  ManagedVulnerabilityFindingSchema,
  RemediationExecutionSchema,
  RemediationPlanSchema,
  RemediationVerificationSchema,
  VULNERABILITY_CONTRACT_VERSION,
  VexDecisionSchema,
  VulnerabilityAdvisorySchema,
  VulnerabilityAssetSchema,
  VulnerabilityComponentSchema,
  VulnerabilityObservationSchema,
  VulnerabilityRiskAssessmentSchema,
  canonicalVulnerabilityIds,
  createStableFindingId,
} from "../src";

const timestamp = "2026-07-18T18:30:00Z";
const findingId = createStableFindingId({
  assetId: "production-web-1",
  componentIdentity: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5",
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001", "USN-9999-1"],
});

const fixtures = [
  {
    schema: VulnerabilityAssetSchema,
    value: {
      contract: VULNERABILITY_CONTRACT_VERSION,
      criticality: "critical",
      environment: "production",
      id: "production-web-1",
      kind: "host",
      labels: { region: "nyc3" },
      name: "Production web host",
      tenantId: "tenant-1",
      version: "Ubuntu 24.04.3 LTS",
    },
  },
  {
    schema: VulnerabilityComponentSchema,
    value: {
      contract: VULNERABILITY_CONTRACT_VERSION,
      id: "component-nginx",
      identity: {
        ecosystem: "deb",
        name: "nginx",
        namespace: "ubuntu",
        purl: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5",
        version: "1.24.0-2ubuntu7.5",
      },
      licenses: ["BSD-2-Clause"],
      locations: ["/usr/sbin/nginx"],
      properties: { architecture: "amd64" },
    },
  },
  {
    schema: VulnerabilityAdvisorySchema,
    value: {
      aliases: ["CVE-2026-0001", "USN-9999-1"],
      contract: VULNERABILITY_CONTRACT_VERSION,
      details: "A fixture advisory",
      id: "USN-9999-1",
      modifiedAt: timestamp,
      publishedAt: timestamp,
      severity: [
        { score: 8.1, system: "cvss-v3", value: "high", vector: null },
      ],
      source: {
        fetchedAt: timestamp,
        name: "ubuntu",
        revision: "9999-1",
        url: "https://ubuntu.com/security/notices/USN-9999-1",
      },
      summary: "Fixture advisory",
      withdrawnAt: null,
    },
  },
  {
    schema: VulnerabilityObservationSchema,
    value: {
      advisoryIds: ["CVE-2026-0001"],
      assetId: "production-web-1",
      componentId: "component-nginx",
      contract: VULNERABILITY_CONTRACT_VERSION,
      evidence: [
        {
          collectedAt: timestamp,
          digest: null,
          kind: "scan",
          source: "grype",
          uri: "scan://release-1/nginx",
        },
      ],
      id: "observation-1",
      observedAt: timestamp,
      scanner: "grype",
      scannerRecordId: "match-42",
      severity: "high",
    },
  },
  {
    schema: ManagedVulnerabilityFindingSchema,
    value: {
      assetId: "production-web-1",
      componentId: "component-nginx",
      contract: VULNERABILITY_CONTRACT_VERSION,
      firstSeenAt: timestamp,
      id: findingId,
      lastSeenAt: timestamp,
      observationIds: ["observation-1"],
      severity: "high",
      status: "under_investigation",
      tenantId: "tenant-1",
      vulnerabilityIds: ["CVE-2026-0001", "USN-9999-1"],
    },
  },
  {
    schema: VexDecisionSchema,
    value: {
      author: "security@example.com",
      contract: VULNERABILITY_CONTRACT_VERSION,
      createdAt: timestamp,
      evidence: [
        {
          collectedAt: timestamp,
          digest: null,
          kind: "vendor-status",
          source: "ubuntu-usn",
          uri: "https://ubuntu.com/security/notices/USN-9999-1",
        },
      ],
      expiresAt: "2026-10-18T18:30:00Z",
      id: "vex-1",
      justification: "vendor_backport_applied",
      productId: "production-web-1",
      reviewedAt: timestamp,
      statement: "Ubuntu's distro revision contains the vendor backport.",
      status: "not_affected",
      vulnerabilityId: "CVE-2026-0001",
    },
  },
  {
    schema: VulnerabilityRiskAssessmentSchema,
    value: {
      assessedAt: timestamp,
      contract: VULNERABILITY_CONTRACT_VERSION,
      epssPercentile: 0.97,
      epssProbability: 0.31,
      findingId,
      fixAvailable: true,
      internetExposed: true,
      kev: false,
      policyVersion: "policy-1",
      priority: "high",
      reachability: "reachable",
      reasons: ["Internet exposed", "Fix available"],
      remediateBy: "2026-07-21T18:30:00Z",
    },
  },
  {
    schema: RemediationPlanSchema,
    value: {
      actions: [
        {
          assetId: "production-web-1",
          componentId: "component-nginx",
          fromVersion: "1.24.0-2ubuntu7.4",
          id: "action-1",
          kind: "package_upgrade",
          requiresRestart: true,
          toVersion: "1.24.0-2ubuntu7.5",
        },
      ],
      approvedAt: null,
      approvedBy: null,
      contract: VULNERABILITY_CONTRACT_VERSION,
      createdAt: timestamp,
      createdBy: "operator@example.com",
      findingIds: [findingId],
      id: "plan-1",
      rollbackSummary: "Restore the previous package from the apt cache.",
      status: "draft",
    },
  },
  {
    schema: RemediationExecutionSchema,
    value: {
      completedAt: null,
      contract: VULNERABILITY_CONTRACT_VERSION,
      evidence: [],
      id: "execution-1",
      message: null,
      planId: "plan-1",
      startedAt: timestamp,
      status: "running",
    },
  },
  {
    schema: RemediationVerificationSchema,
    value: {
      contract: VULNERABILITY_CONTRACT_VERSION,
      deployments: [
        {
          activatedAt: timestamp,
          assetId: "production-web-1",
          releaseId: "release-2",
        },
      ],
      evidence: [
        {
          collectedAt: timestamp,
          digest: null,
          kind: "verification",
          source: "absolutejs-inventory",
          uri: "inventory://production-web-1/release-2",
        },
      ],
      executionId: "execution-1",
      fixedFindingIds: [findingId],
      id: "verification-1",
      observedAt: timestamp,
      planId: "plan-1",
      remainingFindingIds: [],
      status: "passed",
    },
  },
] as const;

describe("versioned contracts", () => {
  test("validate after JSON serialization", () => {
    for (const fixture of fixtures) {
      const serialized = JSON.parse(JSON.stringify(fixture.value)) as unknown;
      expect(Value.Check(fixture.schema, serialized)).toBe(true);
    }
  });

  test("reject a future unsupported contract version", () => {
    const asset = { ...fixtures[0].value, contract: 2 };
    expect(Value.Check(VulnerabilityAssetSchema, asset)).toBe(false);
  });

  test("reject additional properties", () => {
    const asset = { ...fixtures[0].value, secret: "not part of the contract" };
    expect(Value.Check(VulnerabilityAssetSchema, asset)).toBe(false);
  });
});

describe("stable finding identity", () => {
  test("is independent of alias order, duplicates, and case", () => {
    const reordered = createStableFindingId({
      assetId: "production-web-1",
      componentIdentity: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5",
      tenantId: "tenant-1",
      vulnerabilityIds: ["usn-9999-1", "cve-2026-0001", "CVE-2026-0001"],
    });
    expect(reordered).toBe(findingId);
  });

  test("changes across tenants, assets, and component identities", () => {
    const base = {
      assetId: "production-web-1",
      componentIdentity: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5",
      tenantId: "tenant-1",
      vulnerabilityIds: ["CVE-2026-0001"],
    };
    const ids = new Set([
      createStableFindingId(base),
      createStableFindingId({ ...base, tenantId: "tenant-2" }),
      createStableFindingId({ ...base, assetId: "production-web-2" }),
      createStableFindingId({
        ...base,
        componentIdentity: "pkg:deb/ubuntu/nginx@1.26.0",
      }),
    ]);
    expect(ids.size).toBe(4);
  });

  test("canonicalizes vulnerability identifiers", () => {
    expect(canonicalVulnerabilityIds([" ghsa-2 ", "CVE-1", "cve-1"])).toEqual([
      "CVE-1",
      "GHSA-2",
    ]);
    expect(() => canonicalVulnerabilityIds([])).toThrow(
      "requires vulnerability ids",
    );
  });
});
