import type {
  AssetCriticality,
  ManagedVulnerabilityFinding,
  RiskPriority,
  VulnerabilityRiskAssessment,
} from "./contracts";

export const DEFAULT_VULNERABILITY_RISK_POLICY = {
  deadlinesDays: {
    critical: 7,
    emergency: 1,
    high: 30,
    informational: null,
    low: 90,
    medium: 60,
  },
  epssHighPercentile: 0.95,
  epssHighProbability: 0.1,
  epssMediumPercentile: 0.9,
  epssMediumProbability: 0.05,
  version: "absolutejs-risk-v1",
} as const;

export type VulnerabilityRiskPolicy = {
  deadlinesDays: Record<RiskPriority, number | null>;
  epssHighPercentile: number;
  epssHighProbability: number;
  epssMediumPercentile: number;
  epssMediumProbability: number;
  version: string;
};

export type VulnerabilityRiskSignals = {
  epss: {
    percentile: number;
    probability: number;
  } | null;
  kev: {
    dueDate: string;
    knownRansomwareCampaignUse: string;
  } | null;
};

const priorityOrder: RiskPriority[] = [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
  "emergency",
];

const validateProbability = (value: number, label: string) => {
  if (!Number.isFinite(value) || value < 0 || value > 1)
    throw new Error(`${label} must be between 0 and 1`);
  return value;
};

const promote = (priority: RiskPriority): RiskPriority =>
  priorityOrder[Math.min(priorityOrder.indexOf(priority) + 1, 5)]!;

const policyDeadline = (
  assessedAt: string,
  priority: RiskPriority,
  policy: VulnerabilityRiskPolicy,
) => {
  const days = policy.deadlinesDays[priority];
  if (days === null) return null;
  if (!Number.isSafeInteger(days) || days < 0)
    throw new Error(`Risk deadline for ${priority} must be non-negative days`);
  return new Date(Date.parse(assessedAt) + days * 86_400_000).toISOString();
};

const kevDeadline = (date: string) => {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(date) || !Number.isFinite(Date.parse(date)))
    throw new Error("KEV dueDate must use YYYY-MM-DD");
  return `${date}T23:59:59.999Z`;
};

const earliest = (left: string | null, right: string | null) => {
  if (left === null) return right;
  if (right === null) return left;
  return Date.parse(left) <= Date.parse(right) ? left : right;
};

export const assessVulnerabilityRisk = (input: {
  assetCriticality: AssetCriticality;
  assessedAt: string;
  finding: ManagedVulnerabilityFinding;
  fixAvailable: boolean;
  internetExposed: boolean;
  policy?: VulnerabilityRiskPolicy;
  reachability: VulnerabilityRiskAssessment["reachability"];
  signals: VulnerabilityRiskSignals;
}): VulnerabilityRiskAssessment => {
  if (!Number.isFinite(Date.parse(input.assessedAt)))
    throw new Error("Risk assessedAt must be a timestamp");
  const policy = input.policy ?? DEFAULT_VULNERABILITY_RISK_POLICY;
  const reasons: string[] = [];
  const epss = input.signals.epss;
  if (epss) {
    validateProbability(epss.percentile, "EPSS percentile");
    validateProbability(epss.probability, "EPSS probability");
  }
  const kev = input.signals.kev;
  const ransomware =
    kev?.knownRansomwareCampaignUse.trim().toLowerCase() === "known";
  let priority: RiskPriority;
  if (kev && (input.internetExposed || ransomware)) {
    priority = "emergency";
    reasons.push(
      input.internetExposed
        ? "kev_internet_exposed"
        : "kev_known_ransomware_campaign",
    );
  } else if (kev) {
    priority = "critical";
    reasons.push("cisa_known_exploited_vulnerability");
  } else if (
    input.finding.severity === "critical" &&
    (input.internetExposed || input.reachability === "reachable")
  ) {
    priority = "critical";
    reasons.push("critical_severity_reachable");
  } else if (
    epss &&
    (epss.probability >= policy.epssHighProbability ||
      epss.percentile >= policy.epssHighPercentile)
  ) {
    priority = "high";
    reasons.push("epss_high_exploitation_likelihood");
  } else if (input.finding.severity === "critical") {
    priority = "high";
    reasons.push("critical_severity");
  } else if (
    input.finding.severity === "high" ||
    (epss !== null &&
      (epss.probability >= policy.epssMediumProbability ||
        epss.percentile >= policy.epssMediumPercentile))
  ) {
    priority = "medium";
    reasons.push(
      input.finding.severity === "high"
        ? "high_severity"
        : "epss_elevated_exploitation_likelihood",
    );
  } else if (input.finding.severity === "medium") {
    priority = "low";
    reasons.push("medium_severity");
  } else {
    priority = "informational";
    reasons.push(`${input.finding.severity}_severity`);
  }
  if (
    input.assetCriticality === "critical" &&
    priority !== "emergency" &&
    priority !== "critical"
  ) {
    priority = promote(priority);
    reasons.push("critical_asset_promotion");
  }
  if (input.fixAvailable) reasons.push("fix_available");
  else reasons.push("no_fix_identified");
  const remediateBy = earliest(
    policyDeadline(input.assessedAt, priority, policy),
    kev ? kevDeadline(kev.dueDate) : null,
  );
  return {
    assessedAt: new Date(input.assessedAt).toISOString(),
    contract: input.finding.contract,
    epssPercentile: epss?.percentile ?? null,
    epssProbability: epss?.probability ?? null,
    findingId: input.finding.id,
    fixAvailable: input.fixAvailable,
    internetExposed: input.internetExposed,
    kev: kev !== null,
    policyVersion: policy.version,
    priority,
    reachability: input.reachability,
    reasons,
    remediateBy,
  };
};
