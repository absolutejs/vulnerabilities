import { describe, expect, test } from "bun:test";
import {
  correlateVulnerabilityInventory,
  evaluateAdvisoryComponent,
  VULNERABILITY_CONTRACT_VERSION,
  type ManagedVulnerabilityFinding,
  type VulnerabilityAdvisory,
  type VulnerabilityAsset,
  type VulnerabilityComponent,
} from "../src";

const timestamp = "2026-07-18T20:00:00Z";
const asset: VulnerabilityAsset = {
  contract: VULNERABILITY_CONTRACT_VERSION,
  criticality: "critical",
  environment: "production",
  id: "deployment-1",
  kind: "deployment",
  labels: {},
  name: "client-web",
  tenantId: "tenant-1",
  version: "sha256:release",
};
const component = (version: string): VulnerabilityComponent => ({
  contract: VULNERABILITY_CONTRACT_VERSION,
  id: `nginx-${version}`,
  identity: {
    ecosystem: "deb",
    name: "nginx",
    namespace: "ubuntu",
    purl: `pkg:deb/ubuntu/nginx@${version}`,
    version,
  },
  licenses: [],
  locations: ["/usr/sbin/nginx"],
  properties: { "osv.ecosystem": "Ubuntu:24.04" },
});
const advisory: VulnerabilityAdvisory = {
  affected: [
    {
      package: { ecosystem: "Ubuntu:24.04", name: "nginx", purl: null },
      ranges: [
        {
          events: [{ introduced: "0" }, { fixed: "1.24.0-2ubuntu7.5" }],
          repository: null,
          type: "ecosystem",
        },
      ],
      versions: [],
    },
  ],
  aliases: ["USN-9999-1", "CVE-2026-0001"],
  contract: VULNERABILITY_CONTRACT_VERSION,
  details: null,
  id: "USN-9999-1",
  modifiedAt: timestamp,
  publishedAt: timestamp,
  severity: [
    { score: 9.8, system: "cvss-v3", value: "critical", vector: null },
  ],
  source: {
    fetchedAt: timestamp,
    name: "ubuntu",
    revision: "1",
    url: "https://security.example/USN-9999-1",
  },
  summary: "nginx issue",
  withdrawnAt: null,
};

describe("vulnerability inventory correlation", () => {
  test("uses distribution versions and vendor ecosystem metadata", () => {
    expect(
      evaluateAdvisoryComponent({
        advisory,
        component: component("1.24.0-2ubuntu7.4"),
      }).status,
    ).toBe("matched");
    expect(
      evaluateAdvisoryComponent({
        advisory,
        component: component("1.24.0-2ubuntu7.5"),
      }).status,
    ).toBe("not_matched");
  });

  test("creates stable findings and deterministic observations", () => {
    const first = correlateVulnerabilityInventory({
      advisories: [advisory],
      asset,
      components: [component("1.24.0-2ubuntu7.4")],
      observedAt: timestamp,
    });
    const second = correlateVulnerabilityInventory({
      advisories: [advisory],
      asset,
      components: [component("1.24.0-2ubuntu7.4")],
      existingFindings: first.findings,
      observedAt: "2026-07-19T20:00:00Z",
    });
    expect(first.findings).toHaveLength(1);
    expect(second.findings[0]?.id).toBe(first.findings[0]?.id);
    expect(second.findings[0]?.firstSeenAt).toBe(timestamp);
    expect(second.findings[0]?.lastSeenAt).toBe("2026-07-19T20:00:00Z");
    expect(second.findings[0]?.observationIds).toHaveLength(1);
    expect(second.findings[0]?.vulnerabilityIds).toEqual([
      "CVE-2026-0001",
      "USN-9999-1",
    ]);
    const duplicated = correlateVulnerabilityInventory({
      advisories: [advisory, advisory],
      asset,
      components: [component("1.24.0-2ubuntu7.4")],
      observedAt: timestamp,
    });
    expect(duplicated.observations).toHaveLength(1);
  });

  test("does not turn unknown version comparisons into findings", () => {
    const unsupported = component("1.0-r1");
    unsupported.identity.ecosystem = "apk";
    unsupported.identity.purl = "pkg:apk/alpine/nginx@1.0-r1";
    unsupported.properties["osv.ecosystem"] = "Alpine:v3.20";
    const alpine: VulnerabilityAdvisory = {
      ...advisory,
      affected: [
        {
          package: {
            ecosystem: "Alpine:v3.20",
            name: "nginx",
            purl: null,
          },
          ranges: [
            {
              events: [{ introduced: "0" }, { fixed: "1.0-r2" }],
              repository: null,
              type: "ecosystem",
            },
          ],
          versions: [],
        },
      ],
    };
    const result = correlateVulnerabilityInventory({
      advisories: [alpine],
      asset,
      components: [unsupported],
      observedAt: timestamp,
    });
    expect(result.findings).toEqual([]);
    expect(result.evaluations[0]?.status).toBe("unknown");
    const unresolved: ManagedVulnerabilityFinding = {
      assetId: asset.id,
      componentId: unsupported.id,
      contract: VULNERABILITY_CONTRACT_VERSION,
      firstSeenAt: timestamp,
      id: `vuln_${"a".repeat(64)}`,
      lastSeenAt: timestamp,
      observationIds: ["prior-observation"],
      severity: "high",
      status: "confirmed",
      tenantId: asset.tenantId,
      vulnerabilityIds: advisory.aliases,
    };
    const retained = correlateVulnerabilityInventory({
      advisories: [alpine],
      asset,
      components: [unsupported],
      existingFindings: [unresolved],
      observedAt: timestamp,
    });
    expect(retained.resolved).toEqual([]);
  });

  test("resolves absent findings and reopens them when they return", () => {
    const active = correlateVulnerabilityInventory({
      advisories: [advisory],
      asset,
      components: [component("1.24.0-2ubuntu7.4")],
      observedAt: timestamp,
    }).findings[0]!;
    const resolved = correlateVulnerabilityInventory({
      advisories: [],
      asset,
      components: [],
      existingFindings: [active],
      observedAt: "2026-07-19T20:00:00Z",
    }).resolved[0]!;
    expect(resolved.status).toBe("fixed");
    const reopened = correlateVulnerabilityInventory({
      advisories: [advisory],
      asset,
      components: [component("1.24.0-2ubuntu7.4")],
      existingFindings: [resolved as ManagedVulnerabilityFinding],
      observedAt: "2026-07-20T20:00:00Z",
    }).findings[0]!;
    expect(reopened.status).toBe("reopened");
  });

  test("holds remediating findings open for deployment verification", () => {
    const active = correlateVulnerabilityInventory({
      advisories: [advisory],
      asset,
      components: [component("1.24.0-2ubuntu7.4")],
      observedAt: timestamp,
    }).findings[0]!;
    const result = correlateVulnerabilityInventory({
      advisories: [],
      asset,
      components: [],
      existingFindings: [{ ...active, status: "remediating" }],
      observedAt: "2026-07-19T20:00:00Z",
    });

    expect(result.resolved).toEqual([]);
    expect(result.verificationPending[0]?.status).toBe("remediating");
  });
});
