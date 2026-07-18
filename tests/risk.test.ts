import { describe, expect, test } from "bun:test";
import {
  assessVulnerabilityRisk,
  VULNERABILITY_CONTRACT_VERSION,
  type ManagedVulnerabilityFinding,
} from "../src";

const finding: ManagedVulnerabilityFinding = {
  assetId: "asset-1",
  componentId: "component-1",
  contract: VULNERABILITY_CONTRACT_VERSION,
  firstSeenAt: "2026-07-18T00:00:00Z",
  id: `vuln_${"a".repeat(64)}`,
  lastSeenAt: "2026-07-18T00:00:00Z",
  observationIds: ["observation-1"],
  severity: "high",
  status: "new",
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001"],
};

const input = {
  assetCriticality: "high" as const,
  assessedAt: "2026-07-18T12:00:00Z",
  finding,
  fixAvailable: true,
  internetExposed: false,
  reachability: "unknown" as const,
  signals: { epss: null, kev: null },
};

describe("vulnerability risk prioritization", () => {
  test("makes internet-exposed KEV findings emergencies with the earliest deadline", () => {
    const assessment = assessVulnerabilityRisk({
      ...input,
      internetExposed: true,
      signals: {
        epss: { percentile: 0.99, probability: 0.42 },
        kev: {
          dueDate: "2026-07-19",
          knownRansomwareCampaignUse: "Unknown",
        },
      },
    });
    expect(assessment.priority).toBe("emergency");
    expect(assessment.kev).toBe(true);
    expect(assessment.remediateBy).toBe("2026-07-19T12:00:00.000Z");
    expect(assessment.reasons).toContain("kev_internet_exposed");
  });

  test("uses EPSS thresholds without treating a missing score as zero", () => {
    const elevated = assessVulnerabilityRisk({
      ...input,
      finding: { ...finding, severity: "low" },
      signals: {
        epss: { percentile: 0.96, probability: 0.02 },
        kev: null,
      },
    });
    const absent = assessVulnerabilityRisk({
      ...input,
      finding: { ...finding, severity: "low" },
    });
    expect(elevated.priority).toBe("high");
    expect(absent.priority).toBe("informational");
    expect(absent.epssProbability).toBeNull();
  });

  test("promotes critical assets and preserves explicit reasons", () => {
    const assessment = assessVulnerabilityRisk({
      ...input,
      assetCriticality: "critical",
    });
    expect(assessment.priority).toBe("high");
    expect(assessment.reasons).toEqual([
      "high_severity",
      "critical_asset_promotion",
      "fix_available",
    ]);
  });

  test("rejects invalid provider probabilities and KEV dates", () => {
    expect(() =>
      assessVulnerabilityRisk({
        ...input,
        signals: {
          epss: { percentile: 2, probability: 0.1 },
          kev: null,
        },
      }),
    ).toThrow("between 0 and 1");
    expect(() =>
      assessVulnerabilityRisk({
        ...input,
        signals: {
          epss: null,
          kev: {
            dueDate: "tomorrow",
            knownRansomwareCampaignUse: "Unknown",
          },
        },
      }),
    ).toThrow("YYYY-MM-DD");
  });
});
