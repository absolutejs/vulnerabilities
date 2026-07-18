import type {
  FindingStatus,
  ManagedVulnerabilityFinding,
  VexDecision,
  VexFindingApplication,
} from "./contracts";
import {
  canonicalVulnerabilityIds,
  normalizeVulnerabilityId,
} from "./identity";

export type VexDecisionEvaluation = {
  decision: VexDecision;
  reasons: string[];
  status: "active" | "expired" | "invalid";
};

const timestamp = (value: string, label: string) => {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be a timestamp`);
  return parsed;
};

export const evaluateVexDecision = (
  decision: VexDecision,
  now: string,
): VexDecisionEvaluation => {
  const nowTime = timestamp(now, "VEX evaluation time");
  const createdAt = timestamp(decision.createdAt, "VEX createdAt");
  const reasons: string[] = [];
  if (createdAt > nowTime) reasons.push("created_at_is_in_the_future");
  if (decision.reviewedAt !== null) {
    const reviewedAt = timestamp(decision.reviewedAt, "VEX reviewedAt");
    if (reviewedAt < createdAt) reasons.push("review_precedes_creation");
    if (reviewedAt > nowTime) reasons.push("review_is_in_the_future");
  }
  if (decision.expiresAt !== null) {
    const expiresAt = timestamp(decision.expiresAt, "VEX expiresAt");
    if (expiresAt <= createdAt) reasons.push("expiry_does_not_follow_creation");
    if (reasons.length === 0 && expiresAt <= nowTime)
      return { decision, reasons: ["decision_expired"], status: "expired" };
  }
  if (decision.status === "not_affected" && decision.justification === null)
    reasons.push("not_affected_requires_justification");
  if (
    (decision.status === "not_affected" || decision.status === "fixed") &&
    decision.reviewedAt === null
  )
    reasons.push("conclusive_decision_requires_review");
  if (
    (decision.status === "not_affected" || decision.status === "fixed") &&
    decision.evidence.length === 0
  )
    reasons.push("conclusive_decision_requires_evidence");
  return {
    decision,
    reasons,
    status: reasons.length === 0 ? "active" : "invalid",
  };
};

const resultingStatus = (
  decision: VexDecision,
  finding: ManagedVulnerabilityFinding,
): FindingStatus => {
  if (decision.status === "not_affected") return "false_positive";
  if (decision.status === "fixed") return "fixed";
  if (decision.status === "under_investigation") return "under_investigation";
  if (
    finding.status === "accepted_risk" ||
    finding.status === "remediation_planned" ||
    finding.status === "remediating"
  )
    return finding.status;
  return "confirmed";
};

export const selectVexDecision = (input: {
  decisions: readonly VexDecision[];
  finding: ManagedVulnerabilityFinding;
  now: string;
  productId: string;
}) => {
  const vulnerabilityIds = new Set(
    canonicalVulnerabilityIds(input.finding.vulnerabilityIds),
  );
  const evaluations = input.decisions
    .filter(
      (decision) =>
        decision.productId === input.productId &&
        vulnerabilityIds.has(
          normalizeVulnerabilityId(decision.vulnerabilityId),
        ),
    )
    .map((decision) => evaluateVexDecision(decision, input.now))
    .sort(
      (left, right) =>
        Date.parse(right.decision.createdAt) -
          Date.parse(left.decision.createdAt) ||
        right.decision.id.localeCompare(left.decision.id),
    );
  return {
    decision:
      evaluations.find(({ status }) => status === "active")?.decision ?? null,
    evaluations,
  };
};

export const applyVexDecision = (input: {
  appliedAt: string;
  decision: VexDecision;
  finding: ManagedVulnerabilityFinding;
}) => {
  const evaluation = evaluateVexDecision(input.decision, input.appliedAt);
  if (evaluation.status !== "active")
    throw new Error(
      `VEX decision ${input.decision.id} is ${evaluation.status}: ${evaluation.reasons.join(", ")}`,
    );
  if (
    !canonicalVulnerabilityIds(input.finding.vulnerabilityIds).includes(
      normalizeVulnerabilityId(input.decision.vulnerabilityId),
    )
  )
    throw new Error("VEX decision does not match finding vulnerability ids");
  const status = resultingStatus(input.decision, input.finding);
  const application: VexFindingApplication = {
    appliedAt: new Date(input.appliedAt).toISOString(),
    contract: input.finding.contract,
    decisionId: input.decision.id,
    endedAt: null,
    findingId: input.finding.id,
    previousStatus: input.finding.status,
    resultingStatus: status,
    tenantId: input.finding.tenantId,
  };
  return {
    application,
    finding: { ...input.finding, status },
  };
};

export const endVexApplication = (input: {
  application: VexFindingApplication;
  endedAt: string;
  finding: ManagedVulnerabilityFinding;
  findingPresent: boolean;
}) => {
  const endedAt = new Date(
    timestamp(input.endedAt, "VEX application endedAt"),
  ).toISOString();
  const application = { ...input.application, endedAt };
  if (
    !input.findingPresent ||
    input.finding.status !== input.application.resultingStatus
  )
    return { application, finding: input.finding };
  return {
    application,
    finding: { ...input.finding, status: "reopened" as const },
  };
};
