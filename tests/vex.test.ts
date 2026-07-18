import { describe, expect, test } from "bun:test";
import {
  applyVexDecision,
  endVexApplication,
  evaluateVexDecision,
  selectVexDecision,
  VULNERABILITY_CONTRACT_VERSION,
  type ManagedVulnerabilityFinding,
  type VexDecision,
} from "../src";

const now = "2026-07-18T20:00:00Z";
const finding: ManagedVulnerabilityFinding = {
  assetId: "asset-1",
  componentId: "component-1",
  contract: VULNERABILITY_CONTRACT_VERSION,
  firstSeenAt: now,
  id: `vuln_${"a".repeat(64)}`,
  lastSeenAt: now,
  observationIds: ["observation-1"],
  severity: "high",
  status: "confirmed",
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001", "USN-9999-1"],
};
const decision: VexDecision = {
  author: "security@example.com",
  contract: VULNERABILITY_CONTRACT_VERSION,
  createdAt: "2026-07-18T18:00:00Z",
  evidence: [
    {
      collectedAt: "2026-07-18T17:00:00Z",
      digest: null,
      kind: "vendor-status",
      source: "ubuntu-security-status",
      uri: "https://security.example/evidence/1",
    },
  ],
  expiresAt: "2026-08-18T18:00:00Z",
  id: "vex-decision-1",
  justification: "vendor_backport_applied",
  productId: "asset-1",
  reviewedAt: "2026-07-18T19:00:00Z",
  statement: "Ubuntu vendor fix is present in the installed revision.",
  status: "not_affected",
  vulnerabilityId: "CVE-2026-0001",
};

describe("VEX decision management", () => {
  test("requires review, justification, and evidence for conclusive decisions", () => {
    const result = evaluateVexDecision(
      { ...decision, evidence: [], justification: null, reviewedAt: null },
      now,
    );
    expect(result.status).toBe("invalid");
    expect(result.reasons).toEqual([
      "not_affected_requires_justification",
      "conclusive_decision_requires_review",
      "conclusive_decision_requires_evidence",
    ]);
  });

  test("selects the newest active matching decision", () => {
    const selected = selectVexDecision({
      decisions: [
        { ...decision, expiresAt: "2026-07-18T19:00:00Z", id: "expired" },
        decision,
      ],
      finding,
      now,
      productId: "asset-1",
    });
    expect(selected.decision?.id).toBe(decision.id);
    expect(selected.evaluations.map(({ status }) => status).sort()).toEqual([
      "active",
      "expired",
    ]);
  });

  test("applies not-affected without deleting evidence", () => {
    const result = applyVexDecision({ appliedAt: now, decision, finding });
    expect(result.finding.status).toBe("false_positive");
    expect(result.finding.observationIds).toEqual(finding.observationIds);
    expect(result.application).toMatchObject({
      decisionId: decision.id,
      previousStatus: "confirmed",
      resultingStatus: "false_positive",
    });
  });

  test("only reopens an ended application when the finding is still present", () => {
    const applied = applyVexDecision({ appliedAt: now, decision, finding });
    const present = endVexApplication({
      application: applied.application,
      endedAt: "2026-08-19T00:00:00Z",
      finding: applied.finding,
      findingPresent: true,
    });
    const absent = endVexApplication({
      application: applied.application,
      endedAt: "2026-08-19T00:00:00Z",
      finding: { ...applied.finding, status: "fixed" },
      findingPresent: false,
    });
    expect(present.finding.status).toBe("reopened");
    expect(absent.finding.status).toBe("fixed");
  });
});
