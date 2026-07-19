import { describe, expect, test } from "bun:test";
import {
  DEFAULT_VULNERABILITY_ALERT_CONFIGURATION,
  evaluateVulnerabilityAlerts,
  resolveVulnerabilityAlertAudiences,
  validateVulnerabilityAlertConfiguration,
  type ManagedVulnerabilityFinding,
  type RemediationExecution,
  type RemediationPlan,
  type RemediationVerification,
  type VulnerabilityRiskAssessment,
  type VexDecision,
  type VexFindingApplication,
} from "../src";

const now = "2026-07-18T12:00:00.000Z";
const finding: ManagedVulnerabilityFinding = {
  assetId: "project-1",
  componentId: "component-1",
  contract: 1,
  firstSeenAt: "2026-07-15T12:00:00.000Z",
  id: `vuln_${"a".repeat(64)}`,
  lastSeenAt: "2026-07-18T11:00:00.000Z",
  observationIds: ["observation-1"],
  severity: "critical",
  status: "confirmed",
  tenantId: "tenant-1",
  vulnerabilityIds: ["CVE-2026-0001"],
};
const risk: VulnerabilityRiskAssessment = {
  assessedAt: "2026-07-17T12:00:00.000Z",
  contract: 1,
  epssPercentile: 0.99,
  epssProbability: 0.8,
  findingId: finding.id,
  fixAvailable: true,
  internetExposed: true,
  kev: true,
  policyVersion: "test",
  priority: "emergency",
  reachability: "reachable",
  reasons: ["kev_internet_exposed"],
  remediateBy: "2026-07-18T10:00:00.000Z",
};

describe("vulnerability alerts", () => {
  test("validates escalation and resolves configurable notification routes", () => {
    const configured = validateVulnerabilityAlertConfiguration({
      ...structuredClone(DEFAULT_VULNERABILITY_ALERT_CONFIGURATION),
      routing: {
        ...structuredClone(DEFAULT_VULNERABILITY_ALERT_CONFIGURATION.routing),
        emergency: {
          escalated: ["admin"],
          opened: ["owner", "admin"],
          resolved: ["owner"],
        },
      },
    });
    expect(
      resolveVulnerabilityAlertAudiences({
        configuration: configured,
        hasOwner: true,
        kind: "opened",
        severity: "emergency",
      }),
    ).toEqual(["owner", "admin"]);
    expect(
      resolveVulnerabilityAlertAudiences({
        configuration: configured,
        hasOwner: false,
        kind: "resolved",
        severity: "emergency",
      }),
    ).toEqual(["admin"]);
    expect(() =>
      validateVulnerabilityAlertConfiguration({
        ...configured,
        routing: {
          ...configured.routing,
          warning: { ...configured.routing.warning, opened: [] },
        },
      }),
    ).toThrow("routing.warning.opened must not be empty");
  });

  test("emits deterministic emergency, deadline, and planning alerts", () => {
    const input = { findings: [finding], now, riskAssessments: [risk] };
    const first = evaluateVulnerabilityAlerts(input);
    const second = evaluateVulnerabilityAlerts(input);

    expect(first).toEqual(second);
    expect(first.map(({ kind }) => kind)).toEqual([
      "emergency_finding",
      "remediation_deadline",
      "remediation_plan_overdue",
    ]);
    expect(first.every(({ id }) => id.startsWith("vulnerability_alert_"))).toBe(
      true,
    );
  });

  test("keeps finding alert identities stable when a plan is attached", () => {
    const withoutPlan = evaluateVulnerabilityAlerts({
      findings: [finding],
      now,
      riskAssessments: [risk],
    });
    const draft: RemediationPlan = {
      actions: [
        {
          assetId: finding.assetId,
          componentId: finding.componentId,
          fromVersion: "1.0.0",
          id: "action-draft",
          kind: "package_upgrade",
          requiresRestart: false,
          toVersion: "1.0.1",
        },
      ],
      approvedAt: null,
      approvedBy: null,
      contract: 1,
      createdAt: now,
      createdBy: "owner-1",
      findingIds: [finding.id],
      id: "plan-draft",
      rollbackSummary: "Rollback release",
      status: "draft",
    };
    const withPlan = evaluateVulnerabilityAlerts({
      findings: [finding],
      now,
      plans: [draft],
      riskAssessments: [risk],
    });
    for (const kind of ["emergency_finding", "remediation_deadline"] as const)
      expect(withPlan.find((entry) => entry.kind === kind)?.id).toBe(
        withoutPlan.find((entry) => entry.kind === kind)?.id,
      );
  });

  test("alerts on approved execution and successful verification SLAs", () => {
    const approved: RemediationPlan = {
      actions: [
        {
          assetId: finding.assetId,
          componentId: finding.componentId,
          fromVersion: "1.0.0",
          id: "action-1",
          kind: "package_upgrade",
          requiresRestart: false,
          toVersion: "1.0.1",
        },
      ],
      approvedAt: "2026-07-16T12:00:00.000Z",
      approvedBy: "owner-1",
      contract: 1,
      createdAt: "2026-07-16T10:00:00.000Z",
      createdBy: "owner-1",
      findingIds: [finding.id],
      id: "plan-1",
      rollbackSummary: "Rollback release",
      status: "approved",
    };
    expect(
      evaluateVulnerabilityAlerts({
        findings: [finding],
        now,
        plans: [approved],
      }).map(({ kind }) => kind),
    ).toContain("remediation_execution_overdue");

    const succeeded: RemediationPlan = { ...approved, status: "succeeded" };
    const execution: RemediationExecution = {
      completedAt: "2026-07-16T14:00:00.000Z",
      contract: 1,
      evidence: [],
      id: "execution-1",
      message: null,
      planId: approved.id,
      startedAt: "2026-07-16T13:00:00.000Z",
      status: "succeeded",
    };
    expect(
      evaluateVulnerabilityAlerts({
        executions: [execution],
        findings: [finding],
        now,
        plans: [succeeded],
      }).map(({ kind }) => kind),
    ).toContain("verification_overdue");

    const verification: RemediationVerification = {
      contract: 1,
      deployments: [
        {
          activatedAt: "2026-07-16T14:00:00.000Z",
          assetId: finding.assetId,
          releaseId: "1.0.1",
        },
      ],
      evidence: [
        {
          collectedAt: now,
          digest: null,
          kind: "verification",
          source: "test",
          uri: null,
        },
      ],
      executionId: execution.id,
      fixedFindingIds: [finding.id],
      id: "verification-1",
      observedAt: now,
      planId: approved.id,
      remainingFindingIds: [],
      status: "passed",
    };
    expect(
      evaluateVulnerabilityAlerts({
        executions: [execution],
        findings: [{ ...finding, status: "fixed" }],
        now,
        plans: [succeeded],
        verifications: [verification],
      }),
    ).toEqual([]);
  });

  test("warns for active expiring VEX and ignores ended applications", () => {
    const investigatedFinding: ManagedVulnerabilityFinding = {
      ...finding,
      status: "under_investigation",
    };
    const decision: VexDecision = {
      author: "analyst-1",
      contract: 1,
      createdAt: "2026-07-01T12:00:00.000Z",
      evidence: [],
      expiresAt: "2026-07-20T12:00:00.000Z",
      id: "decision-1",
      justification: null,
      productId: finding.assetId,
      reviewedAt: null,
      statement: "Investigation remains active",
      status: "under_investigation",
      vulnerabilityId: "CVE-2026-0001",
    };
    const application: VexFindingApplication = {
      appliedAt: "2026-07-01T13:00:00.000Z",
      contract: 1,
      decisionId: decision.id,
      endedAt: null,
      findingId: finding.id,
      previousStatus: "confirmed",
      resultingStatus: "under_investigation",
      tenantId: finding.tenantId,
    };
    expect(
      evaluateVulnerabilityAlerts({
        decisions: [decision],
        findings: [investigatedFinding],
        now,
        vexApplications: [application],
      }).map(({ kind }) => kind),
    ).toEqual(["vex_expiring"]);
    expect(
      evaluateVulnerabilityAlerts({
        decisions: [decision],
        findings: [investigatedFinding],
        now,
        vexApplications: [{ ...application, endedAt: now }],
      }),
    ).toEqual([]);
  });

  test("distinguishes failed and stale feed and worker health", () => {
    const alerts = evaluateVulnerabilityAlerts({
      findings: [],
      health: [
        {
          error: "OSV unavailable",
          id: "osv",
          kind: "feed",
          lastObservedAt: "2026-07-16T00:00:00.000Z",
          lastSucceededAt: "2026-07-15T00:00:00.000Z",
          status: "failed",
          tenantId: "control-plane",
        },
        {
          error: null,
          id: "primary",
          kind: "worker",
          lastObservedAt: "2026-07-18T08:00:00.000Z",
          lastSucceededAt: "2026-07-18T08:00:00.000Z",
          status: "healthy",
          tenantId: "control-plane",
        },
      ],
      now,
    });
    expect(alerts.map(({ kind }) => kind)).toEqual([
      "intelligence_failed",
      "intelligence_stale",
      "worker_stale",
    ]);
  });

  test("turns active evidence posture failures into stable admin alerts", () => {
    const condition = {
      body: "Witness quorum has 1/2 trusted receipts.",
      dueAt: null,
      kind: "evidence_witness_quorum_failed" as const,
      observedAt: now,
      severity: "critical" as const,
      sourceId: "evidence-witness-quorum",
      tenantId: "control-plane",
    };
    const first = evaluateVulnerabilityAlerts({
      evidenceConditions: [condition],
      findings: [],
      now,
    });
    const next = evaluateVulnerabilityAlerts({
      evidenceConditions: [
        { ...condition, observedAt: "2026-07-18T12:01:00.000Z" },
      ],
      findings: [],
      now: "2026-07-18T12:01:00.000Z",
    });

    expect(first).toHaveLength(1);
    expect(first[0]?.id).toBe(next[0]?.id);
    expect(first[0]).toMatchObject({
      assetId: null,
      kind: "evidence_witness_quorum_failed",
      sourceId: "evidence-witness-quorum",
      title: "Evidence witness quorum is unavailable",
    });
  });

  test("rejects evidence posture conditions without durable identities", () => {
    expect(() =>
      evaluateVulnerabilityAlerts({
        evidenceConditions: [
          {
            body: "Missing backup proof",
            dueAt: null,
            kind: "evidence_witness_backup_stale",
            observedAt: now,
            severity: "critical",
            sourceId: "",
            tenantId: "control-plane",
          },
        ],
        findings: [],
        now,
      }),
    ).toThrow("Evidence condition sourceId is required");
  });

  test("rejects invalid timestamps and policy durations", () => {
    expect(() =>
      evaluateVulnerabilityAlerts({ findings: [], now: "not-a-time" }),
    ).toThrow("Alert evaluation time must be a timestamp");
    expect(() =>
      evaluateVulnerabilityAlerts({
        findings: [],
        now,
        policy: {
          deadlineWarningMs: -1,
          executionStartSlaMs: 1,
          intelligenceStaleAfterMs: 1,
          remediationPlanSlaMs: 1,
          verificationSlaMs: 1,
          vexExpirationWarningMs: 1,
          workerStaleAfterMs: 1,
        },
      }),
    ).toThrow("deadlineWarningMs must be a non-negative integer");
  });
});
