import type { ManagedVulnerabilityFinding, VexDecision } from "./contracts";
import { selectVexDecision } from "./vex";

export type DeploymentAdmissionPolicy = {
  blockCritical: boolean;
  blockKnownExploited: boolean;
  version: string;
};

export const DEFAULT_DEPLOYMENT_ADMISSION_POLICY: DeploymentAdmissionPolicy = {
  blockCritical: true,
  blockKnownExploited: true,
  version: "absolutejs-deployment-admission-v1",
};

export type DeploymentAdmissionEvaluation = {
  evaluatedAt: string;
  exceptions: Array<{ decisionId: string; findingId: string }>;
  policyVersion: string;
  status: "failed" | "passed";
  violations: Array<{
    findingId: string;
    reasons: Array<"critical" | "known_exploited">;
    vulnerabilityIds: string[];
  }>;
};

export const evaluateDeploymentAdmission = (input: {
  decisions?: readonly VexDecision[];
  evaluatedAt: string;
  findings: readonly ManagedVulnerabilityFinding[];
  knownExploitedCves?: ReadonlySet<string>;
  policy?: DeploymentAdmissionPolicy;
  productId: string;
}): DeploymentAdmissionEvaluation => {
  const policy = input.policy ?? DEFAULT_DEPLOYMENT_ADMISSION_POLICY;
  const exceptions: DeploymentAdmissionEvaluation["exceptions"] = [];
  const violations: DeploymentAdmissionEvaluation["violations"] = [];
  for (const finding of input.findings) {
    const reasons: DeploymentAdmissionEvaluation["violations"][number]["reasons"] =
      [];
    if (policy.blockCritical && finding.severity === "critical")
      reasons.push("critical");
    if (
      policy.blockKnownExploited &&
      finding.vulnerabilityIds.some((id) =>
        input.knownExploitedCves?.has(id.toUpperCase()),
      )
    )
      reasons.push("known_exploited");
    if (reasons.length === 0) continue;
    const selected = selectVexDecision({
      decisions: input.decisions ?? [],
      finding,
      now: input.evaluatedAt,
      productId: input.productId,
    });
    if (
      selected.decision &&
      (selected.decision.status === "not_affected" ||
        selected.decision.status === "fixed")
    ) {
      exceptions.push({
        decisionId: selected.decision.id,
        findingId: finding.id,
      });
      continue;
    }
    violations.push({
      findingId: finding.id,
      reasons,
      vulnerabilityIds: [...finding.vulnerabilityIds],
    });
  }

  return {
    evaluatedAt: input.evaluatedAt,
    exceptions,
    policyVersion: policy.version,
    status: violations.length === 0 ? "passed" : "failed",
    violations,
  };
};
