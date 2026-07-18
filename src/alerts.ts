import { createHash } from "node:crypto";
import type {
  ManagedVulnerabilityFinding,
  RemediationExecution,
  RemediationPlan,
  RemediationVerification,
  VulnerabilityRiskAssessment,
  VexDecision,
  VexFindingApplication,
} from "./contracts";
import { evaluateVexDecision } from "./vex";

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

export type VulnerabilityAlertKind =
  | "emergency_finding"
  | "intelligence_failed"
  | "intelligence_stale"
  | "remediation_deadline"
  | "remediation_execution_overdue"
  | "remediation_plan_overdue"
  | "verification_overdue"
  | "vex_expiring"
  | "worker_failed"
  | "worker_stale";

export type VulnerabilityAlertSeverity = "emergency" | "critical" | "warning";

export type VulnerabilityAlert = {
  assetId: string | null;
  body: string;
  dueAt: string | null;
  findingId: string | null;
  fingerprint: string;
  id: string;
  kind: VulnerabilityAlertKind;
  observedAt: string;
  planId: string | null;
  severity: VulnerabilityAlertSeverity;
  sourceId: string | null;
  tenantId: string;
  title: string;
};

export type VulnerabilityIntelligenceHealth = {
  error: string | null;
  id: string;
  kind: "feed" | "worker";
  lastObservedAt: string;
  lastSucceededAt: string | null;
  status: "failed" | "healthy" | "unknown";
  tenantId: string;
};

export type VulnerabilityAlertPolicy = {
  deadlineWarningMs: number;
  executionStartSlaMs: number;
  intelligenceStaleAfterMs: number;
  remediationPlanSlaMs: number;
  verificationSlaMs: number;
  vexExpirationWarningMs: number;
  workerStaleAfterMs: number;
};

export const DEFAULT_VULNERABILITY_ALERT_POLICY = {
  deadlineWarningMs: 3 * DAY_MS,
  executionStartSlaMs: DAY_MS,
  intelligenceStaleAfterMs: 26 * HOUR_MS,
  remediationPlanSlaMs: DAY_MS,
  verificationSlaMs: DAY_MS,
  vexExpirationWarningMs: 7 * DAY_MS,
  workerStaleAfterMs: 2 * HOUR_MS,
} as const satisfies VulnerabilityAlertPolicy;

export type VulnerabilityAlertEvaluationInput = {
  decisions?: readonly VexDecision[];
  executions?: readonly RemediationExecution[];
  findings: readonly ManagedVulnerabilityFinding[];
  health?: readonly VulnerabilityIntelligenceHealth[];
  now: string;
  plans?: readonly RemediationPlan[];
  policy?: VulnerabilityAlertPolicy;
  riskAssessments?: readonly VulnerabilityRiskAssessment[];
  vexApplications?: readonly VexFindingApplication[];
  verifications?: readonly RemediationVerification[];
};

const timestamp = (value: string, label: string) => {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be a timestamp`);
  return parsed;
};

const validateDuration = (value: number, label: string) => {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error(`${label} must be a non-negative integer`);
};

const identity = (parts: readonly (string | null)[]) => {
  const fingerprint = createHash("sha256")
    .update(parts.map((part) => part ?? "-").join("\n"))
    .digest("hex");
  return { fingerprint, id: `vulnerability_alert_${fingerprint}` };
};

const alert = (
  input: Omit<VulnerabilityAlert, "fingerprint" | "id">,
): VulnerabilityAlert => ({
  ...input,
  ...identity([
    input.tenantId,
    input.kind,
    input.findingId ?? input.planId ?? input.sourceId,
  ]),
});

const inactiveFindingStatuses = new Set<ManagedVulnerabilityFinding["status"]>([
  "accepted_risk",
  "false_positive",
  "fixed",
  "mitigated",
]);

const latestByFinding = (
  assessments: readonly VulnerabilityRiskAssessment[],
) => {
  const latest = new Map<string, VulnerabilityRiskAssessment>();
  for (const assessment of assessments) {
    const present = latest.get(assessment.findingId);
    if (
      !present ||
      timestamp(assessment.assessedAt, "Risk assessedAt") >
        timestamp(present.assessedAt, "Risk assessedAt")
    )
      latest.set(assessment.findingId, assessment);
  }
  return latest;
};

export const evaluateVulnerabilityAlerts = (
  input: VulnerabilityAlertEvaluationInput,
): VulnerabilityAlert[] => {
  const now = timestamp(input.now, "Alert evaluation time");
  const observedAt = new Date(now).toISOString();
  const policy = input.policy ?? DEFAULT_VULNERABILITY_ALERT_POLICY;
  for (const [label, value] of Object.entries(policy))
    validateDuration(value, label);

  const plans = input.plans ?? [];
  const executions = input.executions ?? [];
  const verifications = input.verifications ?? [];
  const risk = latestByFinding(input.riskAssessments ?? []);
  const planByFinding = new Map<string, RemediationPlan>();
  for (const plan of plans) {
    if (plan.status === "cancelled") continue;
    for (const findingId of plan.findingIds) {
      const present = planByFinding.get(findingId);
      if (
        !present ||
        timestamp(plan.createdAt, "Remediation plan createdAt") >
          timestamp(present.createdAt, "Remediation plan createdAt")
      )
        planByFinding.set(findingId, plan);
    }
  }
  const executionByPlan = new Map<string, RemediationExecution>();
  for (const execution of executions) {
    const present = executionByPlan.get(execution.planId);
    if (
      !present ||
      timestamp(execution.startedAt, "Remediation execution startedAt") >
        timestamp(present.startedAt, "Remediation execution startedAt")
    )
      executionByPlan.set(execution.planId, execution);
  }
  const passedPlans = new Set(
    verifications
      .filter(({ status }) => status === "passed")
      .map(({ planId }) => planId),
  );
  const alerts: VulnerabilityAlert[] = [];

  for (const finding of input.findings) {
    if (inactiveFindingStatuses.has(finding.status)) continue;
    const assessment = risk.get(finding.id);
    const plan = planByFinding.get(finding.id);
    if (assessment?.priority === "emergency")
      alerts.push(
        alert({
          assetId: finding.assetId,
          body: `Emergency vulnerability ${finding.vulnerabilityIds.join(", ")} requires immediate action.`,
          dueAt: assessment.remediateBy,
          findingId: finding.id,
          kind: "emergency_finding",
          observedAt,
          planId: plan?.id ?? null,
          severity: "emergency",
          sourceId: null,
          tenantId: finding.tenantId,
          title: "Emergency vulnerability detected",
        }),
      );
    if (assessment?.remediateBy) {
      const due = timestamp(assessment.remediateBy, "Remediation deadline");
      if (!plan || !passedPlans.has(plan.id)) {
        const remaining = due - now;
        if (remaining <= policy.deadlineWarningMs)
          alerts.push(
            alert({
              assetId: finding.assetId,
              body:
                remaining <= 0
                  ? `The remediation deadline for ${finding.vulnerabilityIds.join(", ")} has passed.`
                  : `The remediation deadline for ${finding.vulnerabilityIds.join(", ")} is approaching.`,
              dueAt: new Date(due).toISOString(),
              findingId: finding.id,
              kind: "remediation_deadline",
              observedAt,
              planId: plan?.id ?? null,
              severity:
                remaining <= 0 || assessment.priority === "emergency"
                  ? "critical"
                  : "warning",
              sourceId: null,
              tenantId: finding.tenantId,
              title:
                remaining <= 0
                  ? "Vulnerability remediation is overdue"
                  : "Vulnerability remediation deadline approaching",
            }),
          );
      }
    }
    if (
      (finding.status === "confirmed" || finding.status === "reopened") &&
      !plan &&
      now -
        timestamp(
          assessment?.assessedAt ?? finding.firstSeenAt,
          "Finding age",
        ) >=
        policy.remediationPlanSlaMs
    )
      alerts.push(
        alert({
          assetId: finding.assetId,
          body: "The finding has no remediation plan within the configured SLA.",
          dueAt: new Date(
            timestamp(
              assessment?.assessedAt ?? finding.firstSeenAt,
              "Finding age",
            ) + policy.remediationPlanSlaMs,
          ).toISOString(),
          findingId: finding.id,
          kind: "remediation_plan_overdue",
          observedAt,
          planId: null,
          severity: "critical",
          sourceId: null,
          tenantId: finding.tenantId,
          title: "Remediation plan SLA missed",
        }),
      );
  }

  for (const plan of plans) {
    const tenantId = input.findings.find(({ id }) =>
      plan.findingIds.includes(id),
    )?.tenantId;
    if (!tenantId) continue;
    if (
      plan.status === "approved" &&
      plan.approvedAt &&
      !executionByPlan.has(plan.id) &&
      now - timestamp(plan.approvedAt, "Remediation approvedAt") >=
        policy.executionStartSlaMs
    )
      alerts.push(
        alert({
          assetId: plan.actions[0]?.assetId ?? null,
          body: "The approved remediation plan has not started within the configured SLA.",
          dueAt: new Date(
            timestamp(plan.approvedAt, "Remediation approvedAt") +
              policy.executionStartSlaMs,
          ).toISOString(),
          findingId: null,
          kind: "remediation_execution_overdue",
          observedAt,
          planId: plan.id,
          severity: "critical",
          sourceId: null,
          tenantId,
          title: "Remediation execution SLA missed",
        }),
      );
    const execution = executionByPlan.get(plan.id);
    if (
      plan.status === "succeeded" &&
      execution?.status === "succeeded" &&
      execution.completedAt &&
      !passedPlans.has(plan.id) &&
      now - timestamp(execution.completedAt, "Remediation completedAt") >=
        policy.verificationSlaMs
    )
      alerts.push(
        alert({
          assetId: plan.actions[0]?.assetId ?? null,
          body: "Successful deployment evidence has not been followed by passing verification within the configured SLA.",
          dueAt: new Date(
            timestamp(execution.completedAt, "Remediation completedAt") +
              policy.verificationSlaMs,
          ).toISOString(),
          findingId: null,
          kind: "verification_overdue",
          observedAt,
          planId: plan.id,
          severity: "critical",
          sourceId: null,
          tenantId,
          title: "Remediation verification SLA missed",
        }),
      );
  }

  const decisions = new Map(
    (input.decisions ?? []).map((decision) => [decision.id, decision]),
  );
  const findings = new Map(
    input.findings.map((finding) => [finding.id, finding]),
  );
  for (const application of input.vexApplications ?? []) {
    if (application.endedAt !== null) continue;
    const decision = decisions.get(application.decisionId);
    const finding = findings.get(application.findingId);
    if (!decision?.expiresAt || !finding) continue;
    if (evaluateVexDecision(decision, observedAt).status !== "active") continue;
    const expiresAt = timestamp(decision.expiresAt, "VEX expiresAt");
    if (expiresAt - now <= policy.vexExpirationWarningMs)
      alerts.push(
        alert({
          assetId: finding.assetId,
          body: `VEX decision ${decision.id} expires soon and requires review.`,
          dueAt: new Date(expiresAt).toISOString(),
          findingId: finding.id,
          kind: "vex_expiring",
          observedAt,
          planId: null,
          severity: "warning",
          sourceId: decision.id,
          tenantId: application.tenantId,
          title: "VEX decision is expiring",
        }),
      );
  }

  for (const health of input.health ?? []) {
    const observed = timestamp(health.lastObservedAt, "Health observedAt");
    const staleAfter =
      health.kind === "worker"
        ? policy.workerStaleAfterMs
        : policy.intelligenceStaleAfterMs;
    const stale = now - observed >= staleAfter;
    if (health.status === "failed")
      alerts.push(
        alert({
          assetId: null,
          body:
            health.error ?? `${health.kind} ${health.id} reported a failure.`,
          dueAt: null,
          findingId: null,
          kind:
            health.kind === "worker" ? "worker_failed" : "intelligence_failed",
          observedAt,
          planId: null,
          severity: "critical",
          sourceId: health.id,
          tenantId: health.tenantId,
          title:
            health.kind === "worker"
              ? "Vulnerability worker failed"
              : "Vulnerability intelligence refresh failed",
        }),
      );
    if (stale)
      alerts.push(
        alert({
          assetId: null,
          body: `${health.kind} ${health.id} has not reported within the configured freshness SLA.`,
          dueAt: new Date(observed + staleAfter).toISOString(),
          findingId: null,
          kind:
            health.kind === "worker" ? "worker_stale" : "intelligence_stale",
          observedAt,
          planId: null,
          severity: "critical",
          sourceId: health.id,
          tenantId: health.tenantId,
          title:
            health.kind === "worker"
              ? "Vulnerability worker is stale"
              : "Vulnerability intelligence is stale",
        }),
      );
  }

  return alerts.sort(
    (left, right) =>
      left.tenantId.localeCompare(right.tenantId) ||
      left.kind.localeCompare(right.kind) ||
      left.id.localeCompare(right.id),
  );
};
