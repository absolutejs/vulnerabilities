import type {
  EvidenceReference,
  ManagedVulnerabilityFinding,
  RemediationAction,
  RemediationDeployment,
  RemediationExecution,
  RemediationPlan,
  RemediationVerification,
} from "./contracts";

const time = (value: string, label: string) => {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be a timestamp`);
  return parsed;
};

const assertPlanFindings = (
  plan: RemediationPlan,
  findings: readonly ManagedVulnerabilityFinding[],
) => {
  const expected = [...plan.findingIds].sort();
  const received = findings.map(({ id }) => id).sort();
  if (JSON.stringify(expected) !== JSON.stringify(received))
    throw new Error("Remediation findings must exactly match the plan");
};

export const createRemediationPlan = (input: {
  actions: readonly RemediationAction[];
  createdAt: string;
  createdBy: string;
  findings: readonly ManagedVulnerabilityFinding[];
  id: string;
  rollbackSummary: string;
}) => {
  time(input.createdAt, "Remediation plan createdAt");
  if (input.findings.length === 0)
    throw new Error("Remediation plan requires findings");
  if (input.actions.length === 0)
    throw new Error("Remediation plan requires actions");
  if (
    input.findings.some(
      ({ status }) => status !== "confirmed" && status !== "reopened",
    )
  )
    throw new Error("Only confirmed or reopened findings can be planned");
  const assets = new Set(input.findings.map(({ assetId }) => assetId));
  if (input.actions.some(({ assetId }) => !assets.has(assetId)))
    throw new Error("Remediation action does not match a finding asset");
  return {
    actions: [...input.actions],
    approvedAt: null,
    approvedBy: null,
    contract: input.findings[0]!.contract,
    createdAt: new Date(input.createdAt).toISOString(),
    createdBy: input.createdBy,
    findingIds: [...new Set(input.findings.map(({ id }) => id))].sort(),
    id: input.id,
    rollbackSummary: input.rollbackSummary,
    status: "draft" as const,
  } satisfies RemediationPlan;
};

export const approveRemediationPlan = (input: {
  approvedAt: string;
  approvedBy: string;
  findings: readonly ManagedVulnerabilityFinding[];
  plan: RemediationPlan;
}) => {
  if (input.plan.status !== "draft")
    throw new Error("Only draft remediation plans can be approved");
  assertPlanFindings(input.plan, input.findings);
  const approvedAt = new Date(
    time(input.approvedAt, "Remediation approvedAt"),
  ).toISOString();
  if (Date.parse(approvedAt) < Date.parse(input.plan.createdAt))
    throw new Error("Remediation approval precedes plan creation");
  return {
    findings: input.findings.map((finding) => ({
      ...finding,
      status: "remediation_planned" as const,
    })),
    plan: {
      ...input.plan,
      approvedAt,
      approvedBy: input.approvedBy,
      status: "approved" as const,
    },
  };
};

export const startRemediationExecution = (input: {
  executionId: string;
  findings: readonly ManagedVulnerabilityFinding[];
  plan: RemediationPlan;
  startedAt: string;
}) => {
  if (input.plan.status !== "approved")
    throw new Error("Only approved remediation plans can execute");
  assertPlanFindings(input.plan, input.findings);
  const startedAt = new Date(
    time(input.startedAt, "Remediation startedAt"),
  ).toISOString();
  if (
    input.plan.approvedAt === null ||
    Date.parse(startedAt) < Date.parse(input.plan.approvedAt)
  )
    throw new Error("Remediation execution precedes approval");
  const execution: RemediationExecution = {
    completedAt: null,
    contract: input.plan.contract,
    evidence: [],
    id: input.executionId,
    message: null,
    planId: input.plan.id,
    startedAt,
    status: "running",
  };
  return {
    execution,
    findings: input.findings.map((finding) => ({
      ...finding,
      status: "remediating" as const,
    })),
    plan: { ...input.plan, status: "executing" as const },
  };
};

export const completeRemediationExecution = (input: {
  completedAt: string;
  evidence: readonly EvidenceReference[];
  execution: RemediationExecution;
  message: string | null;
  plan: RemediationPlan;
  status: "cancelled" | "failed" | "succeeded";
}) => {
  if (input.execution.status !== "running" || input.plan.status !== "executing")
    throw new Error("Remediation execution is not running");
  const completedAt = new Date(
    time(input.completedAt, "Remediation completedAt"),
  ).toISOString();
  if (Date.parse(completedAt) < Date.parse(input.execution.startedAt))
    throw new Error("Remediation completion precedes execution start");
  if (input.status === "succeeded" && input.evidence.length === 0)
    throw new Error("Successful remediation requires deployment evidence");
  return {
    execution: {
      ...input.execution,
      completedAt,
      evidence: [...input.evidence],
      message: input.message,
      status: input.status,
    },
    plan: { ...input.plan, status: input.status },
  };
};

export const verifyRemediationExecution = (input: {
  deployments: readonly RemediationDeployment[];
  evidence: readonly EvidenceReference[];
  execution: RemediationExecution;
  findings: readonly ManagedVulnerabilityFinding[];
  observedAt: string;
  plan: RemediationPlan;
  verificationId: string;
}) => {
  if (
    input.execution.status !== "succeeded" ||
    input.execution.completedAt === null ||
    input.plan.status !== "succeeded"
  )
    throw new Error("Only successful remediation can be verified");
  assertPlanFindings(input.plan, input.findings);
  const observedAt = new Date(
    time(input.observedAt, "Remediation verification observedAt"),
  ).toISOString();
  if (Date.parse(observedAt) <= Date.parse(input.execution.completedAt))
    throw new Error("Verification inventory must follow deployment completion");
  if (input.evidence.length === 0)
    throw new Error("Remediation verification requires evidence");
  const deploymentAssets = new Set(
    input.deployments.map(({ assetId }) => assetId),
  );
  if (
    input.deployments.length === 0 ||
    input.plan.actions.some(({ assetId }) => !deploymentAssets.has(assetId))
  )
    throw new Error(
      "Deployment evidence does not cover every remediation asset",
    );
  if (
    input.deployments.some(
      ({ activatedAt }) =>
        time(activatedAt, "Deployment activatedAt") > Date.parse(observedAt),
    )
  )
    throw new Error("Deployment activation follows verification inventory");
  const fixed = input.findings.filter(
    ({ lastSeenAt }) => Date.parse(lastSeenAt) < Date.parse(observedAt),
  );
  const remaining = input.findings.filter(
    ({ lastSeenAt }) => Date.parse(lastSeenAt) >= Date.parse(observedAt),
  );
  const verification: RemediationVerification = {
    contract: input.plan.contract,
    deployments: [...input.deployments],
    evidence: [...input.evidence],
    executionId: input.execution.id,
    fixedFindingIds: fixed.map(({ id }) => id).sort(),
    id: input.verificationId,
    observedAt,
    planId: input.plan.id,
    remainingFindingIds: remaining.map(({ id }) => id).sort(),
    status: remaining.length === 0 ? "passed" : "failed",
  };
  return {
    findings: input.findings.map((finding) =>
      fixed.some(({ id }) => id === finding.id)
        ? { ...finding, status: "fixed" as const }
        : finding,
    ),
    verification,
  };
};
