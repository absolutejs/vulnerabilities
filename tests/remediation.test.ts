import { describe, expect, test } from "bun:test";
import {
  approveRemediationPlan,
  cancelRemediationPlan,
  completeRemediationExecution,
  createRemediationPlan,
  startRemediationExecution,
  verifyRemediationExecution,
  VULNERABILITY_CONTRACT_VERSION,
  type ManagedVulnerabilityFinding,
  type RemediationAction,
} from "../src";

const finding: ManagedVulnerabilityFinding = {
  assetId: "deployment-1",
  componentId: "component-1",
  contract: VULNERABILITY_CONTRACT_VERSION,
  firstSeenAt: "2026-07-18T18:00:00Z",
  id: `vuln_${"a".repeat(64)}`,
  lastSeenAt: "2026-07-18T18:00:00Z",
  observationIds: ["observation-1"],
  severity: "high",
  status: "confirmed",
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001"],
};
const action: RemediationAction = {
  assetId: finding.assetId,
  componentId: finding.componentId,
  fromVersion: "release-1",
  id: "action-1",
  kind: "rebuild",
  requiresRestart: true,
  toVersion: "release-2",
};
const deploymentEvidence = {
  collectedAt: "2026-07-18T20:00:00Z",
  digest: "sha256:release-2",
  kind: "verification" as const,
  source: "absolutejs-deploy",
  uri: "deployment://deployment-1/releases/release-2",
};

describe("remediation lifecycle", () => {
  test("cancels draft and approved plans without leaving findings reserved", () => {
    const draft = createRemediationPlan({
      actions: [action],
      createdAt: "2026-07-18T18:30:00Z",
      createdBy: "security-team",
      findings: [finding],
      id: "plan-cancel",
      rollbackSummary: "Reactivate the retained release.",
    });
    const cancelledDraft = cancelRemediationPlan({
      findings: [finding],
      plan: draft,
    });
    expect(cancelledDraft.plan.status).toBe("cancelled");
    expect(cancelledDraft.findings[0]?.status).toBe("confirmed");

    const approved = approveRemediationPlan({
      approvedAt: "2026-07-18T19:00:00Z",
      approvedBy: "operator-2",
      findings: [finding],
      plan: draft,
    });
    const cancelledApproved = cancelRemediationPlan({
      findings: approved.findings,
      plan: approved.plan,
    });
    expect(cancelledApproved.plan.status).toBe("cancelled");
    expect(cancelledApproved.findings[0]?.status).toBe("confirmed");
  });

  test("requires approval, deployment evidence, and later inventory absence", () => {
    const draft = createRemediationPlan({
      actions: [action],
      createdAt: "2026-07-18T18:30:00Z",
      createdBy: "security-team",
      findings: [finding],
      id: "plan-1",
      rollbackSummary: "Restore release-1.",
    });
    const approved = approveRemediationPlan({
      approvedAt: "2026-07-18T19:00:00Z",
      approvedBy: "operator-1",
      findings: [finding],
      plan: draft,
    });
    const started = startRemediationExecution({
      executionId: "execution-1",
      findings: approved.findings,
      plan: approved.plan,
      startedAt: "2026-07-18T19:30:00Z",
    });
    const completed = completeRemediationExecution({
      completedAt: "2026-07-18T20:00:00Z",
      evidence: [deploymentEvidence],
      execution: started.execution,
      message: "Release activated.",
      plan: started.plan,
      status: "succeeded",
    });
    const verified = verifyRemediationExecution({
      deployments: [
        {
          activatedAt: "2026-07-18T20:00:00Z",
          assetId: finding.assetId,
          releaseId: "release-2",
        },
      ],
      evidence: [
        {
          ...deploymentEvidence,
          collectedAt: "2026-07-18T21:00:00Z",
          uri: "inventory://deployment-1/release-2",
        },
      ],
      execution: completed.execution,
      findings: started.findings,
      observedAt: "2026-07-18T21:00:00Z",
      plan: completed.plan,
      verificationId: "verification-1",
    });

    expect(approved.findings[0]?.status).toBe("remediation_planned");
    expect(started.findings[0]?.status).toBe("remediating");
    expect(completed.execution.evidence).toHaveLength(1);
    expect(verified.verification.status).toBe("passed");
    expect(verified.findings[0]?.status).toBe("fixed");
  });

  test("does not close a finding still present in post-deployment inventory", () => {
    const draft = createRemediationPlan({
      actions: [action],
      createdAt: "2026-07-18T18:30:00Z",
      createdBy: "security-team",
      findings: [finding],
      id: "plan-1",
      rollbackSummary: "Restore release-1.",
    });
    const approved = approveRemediationPlan({
      approvedAt: "2026-07-18T19:00:00Z",
      approvedBy: "operator-1",
      findings: [finding],
      plan: draft,
    });
    const started = startRemediationExecution({
      executionId: "execution-1",
      findings: approved.findings,
      plan: approved.plan,
      startedAt: "2026-07-18T19:30:00Z",
    });
    const completed = completeRemediationExecution({
      completedAt: "2026-07-18T20:00:00Z",
      evidence: [deploymentEvidence],
      execution: started.execution,
      message: null,
      plan: started.plan,
      status: "succeeded",
    });
    const present = {
      ...started.findings[0]!,
      lastSeenAt: "2026-07-18T21:00:00Z",
    };
    const verified = verifyRemediationExecution({
      deployments: [
        {
          activatedAt: "2026-07-18T20:00:00Z",
          assetId: finding.assetId,
          releaseId: "release-2",
        },
      ],
      evidence: [{ ...deploymentEvidence, collectedAt: present.lastSeenAt }],
      execution: completed.execution,
      findings: [present],
      observedAt: present.lastSeenAt,
      plan: completed.plan,
      verificationId: "verification-1",
    });

    expect(verified.verification.status).toBe("failed");
    expect(verified.findings[0]?.status).toBe("remediating");
  });

  test("rejects success without deployment evidence", () => {
    const draft = createRemediationPlan({
      actions: [action],
      createdAt: "2026-07-18T18:30:00Z",
      createdBy: "security-team",
      findings: [finding],
      id: "plan-1",
      rollbackSummary: "Restore release-1.",
    });
    const approved = approveRemediationPlan({
      approvedAt: "2026-07-18T19:00:00Z",
      approvedBy: "operator-1",
      findings: [finding],
      plan: draft,
    });
    const started = startRemediationExecution({
      executionId: "execution-1",
      findings: approved.findings,
      plan: approved.plan,
      startedAt: "2026-07-18T19:30:00Z",
    });

    expect(() =>
      completeRemediationExecution({
        completedAt: "2026-07-18T20:00:00Z",
        evidence: [],
        execution: started.execution,
        message: null,
        plan: started.plan,
        status: "succeeded",
      }),
    ).toThrow("requires deployment evidence");
  });

  test("rejects verification after the approved release was rolled back", () => {
    const draft = createRemediationPlan({
      actions: [action],
      createdAt: "2026-07-18T18:30:00Z",
      createdBy: "security-team",
      findings: [finding],
      id: "plan-1",
      rollbackSummary: "Restore release-1.",
    });
    const approved = approveRemediationPlan({
      approvedAt: "2026-07-18T19:00:00Z",
      approvedBy: "operator-1",
      findings: [finding],
      plan: draft,
    });
    const started = startRemediationExecution({
      executionId: "execution-1",
      findings: approved.findings,
      plan: approved.plan,
      startedAt: "2026-07-18T19:30:00Z",
    });
    const completed = completeRemediationExecution({
      completedAt: "2026-07-18T20:00:00Z",
      evidence: [deploymentEvidence],
      execution: started.execution,
      message: null,
      plan: started.plan,
      status: "succeeded",
    });

    expect(() =>
      verifyRemediationExecution({
        deployments: [
          {
            activatedAt: "2026-07-18T20:30:00Z",
            assetId: finding.assetId,
            releaseId: "release-1",
          },
        ],
        evidence: [
          { ...deploymentEvidence, collectedAt: "2026-07-18T21:00:00Z" },
        ],
        execution: completed.execution,
        findings: started.findings,
        observedAt: "2026-07-18T21:00:00Z",
        plan: completed.plan,
        verificationId: "verification-rollback",
      }),
    ).toThrow("does not match the approved target");
  });
});
