import { Type, type Static } from "@sinclair/typebox";
import { ISO_TIMESTAMP_PATTERN } from "./primitives";

export * from "./contracts";
export * from "./identity";
export {
  ISO_TIMESTAMP_PATTERN,
  IdentifierSchema,
  NullableTimestampSchema,
  TimestampSchema,
} from "./primitives";

export const VulnerabilitySeveritySchema = Type.Union([
  Type.Literal("critical"),
  Type.Literal("high"),
  Type.Literal("medium"),
  Type.Literal("low"),
  Type.Literal("negligible"),
  Type.Literal("unknown"),
]);

export type VulnerabilitySeverity = Static<typeof VulnerabilitySeveritySchema>;

export const VULNERABILITY_SEVERITIES: readonly VulnerabilitySeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "negligible",
  "unknown",
];

export const VulnerabilityCountsSchema = Type.Object(
  {
    critical: Type.Integer({ minimum: 0 }),
    high: Type.Integer({ minimum: 0 }),
    medium: Type.Integer({ minimum: 0 }),
    low: Type.Integer({ minimum: 0 }),
    negligible: Type.Integer({ minimum: 0 }),
    unknown: Type.Integer({ minimum: 0 }),
  },
  { additionalProperties: false },
);

export type VulnerabilityCounts = Static<typeof VulnerabilityCountsSchema>;

export const VulnerabilityScanSummarySchema = Type.Object(
  {
    ...VulnerabilityCountsSchema.properties,
    databaseBuiltAt: Type.Union([
      Type.Null(),
      Type.String({ pattern: ISO_TIMESTAMP_PATTERN }),
    ]),
    scannedAt: Type.String({ pattern: ISO_TIMESTAMP_PATTERN }),
    scanner: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);

export type VulnerabilityScanSummary = Static<
  typeof VulnerabilityScanSummarySchema
>;

export type VulnerabilityFinding = {
  id: string | null;
  package: {
    name: string | null;
    type: string | null;
    version: string | null;
  };
  severity: VulnerabilitySeverity;
  source: string | null;
};

export type GrypeReportSummary = {
  counts: VulnerabilityCounts;
  findings: VulnerabilityFinding[];
};

const record = (input: unknown): Record<string, unknown> | null =>
  input !== null && typeof input === "object" && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : null;

const stringOrNull = (input: unknown) =>
  typeof input === "string" && input.length > 0 ? input : null;

export const emptyVulnerabilityCounts = (): VulnerabilityCounts => ({
  critical: 0,
  high: 0,
  low: 0,
  medium: 0,
  negligible: 0,
  unknown: 0,
});

export const normalizeVulnerabilitySeverity = (
  input: unknown,
): VulnerabilitySeverity => {
  if (typeof input !== "string") return "unknown";
  const normalized = input.trim().toLowerCase();
  if (normalized === "moderate") return "medium";
  return VULNERABILITY_SEVERITIES.includes(normalized as VulnerabilitySeverity)
    ? (normalized as VulnerabilitySeverity)
    : "unknown";
};

export const parseGrypeReport = (input: unknown): GrypeReportSummary => {
  const root = record(input);
  if (root === null) throw new Error("Grype report must be an object");
  if (!Array.isArray(root.matches))
    throw new Error("Grype report must contain matches");

  const counts = emptyVulnerabilityCounts();
  const findings = root.matches.map((candidate): VulnerabilityFinding => {
    const match = record(candidate);
    const vulnerability = record(match?.vulnerability);
    const artifact = record(match?.artifact);
    const severity = normalizeVulnerabilitySeverity(vulnerability?.severity);
    counts[severity] += 1;

    return {
      id: stringOrNull(vulnerability?.id),
      package: {
        name: stringOrNull(artifact?.name),
        type: stringOrNull(artifact?.type),
        version: stringOrNull(artifact?.version),
      },
      severity,
      source: stringOrNull(vulnerability?.namespace),
    };
  });

  return { counts, findings };
};

export const summarizeGrypeReport = (input: unknown): VulnerabilityCounts =>
  parseGrypeReport(input).counts;

export type VulnerabilityPolicy = {
  maximums: Partial<Record<VulnerabilitySeverity, number>>;
};

export type VulnerabilityPolicyViolation = {
  actual: number;
  maximum: number;
  severity: VulnerabilitySeverity;
};

export type VulnerabilityPolicyEvaluation = {
  status: "failed" | "passed";
  violations: VulnerabilityPolicyViolation[];
};

export const DEFAULT_VULNERABILITY_POLICY: VulnerabilityPolicy = {
  maximums: { critical: 0, high: 0 },
};

export const evaluateVulnerabilityPolicy = (
  counts: VulnerabilityCounts,
  policy: VulnerabilityPolicy = DEFAULT_VULNERABILITY_POLICY,
): VulnerabilityPolicyEvaluation => {
  const violations: VulnerabilityPolicyViolation[] = [];
  for (const severity of VULNERABILITY_SEVERITIES) {
    const maximum = policy.maximums[severity];
    if (maximum === undefined) continue;
    if (!Number.isSafeInteger(maximum) || maximum < 0)
      throw new Error(`Invalid maximum for ${severity}: ${maximum}`);
    if (counts[severity] > maximum)
      violations.push({ actual: counts[severity], maximum, severity });
  }

  return {
    status: violations.length === 0 ? "passed" : "failed",
    violations,
  };
};

export class VulnerabilityPolicyError extends Error {
  readonly evaluation: VulnerabilityPolicyEvaluation;

  constructor(evaluation: VulnerabilityPolicyEvaluation) {
    const details = evaluation.violations
      .map(
        ({ actual, maximum, severity }) =>
          `${severity}=${actual} (max ${maximum})`,
      )
      .join(", ");
    super(`Vulnerability policy failed: ${details}`);
    this.name = "VulnerabilityPolicyError";
    this.evaluation = evaluation;
  }
}

export const assertVulnerabilityPolicy = (
  counts: VulnerabilityCounts,
  policy: VulnerabilityPolicy = DEFAULT_VULNERABILITY_POLICY,
) => {
  const evaluation = evaluateVulnerabilityPolicy(counts, policy);
  if (evaluation.status === "failed")
    throw new VulnerabilityPolicyError(evaluation);
  return evaluation;
};

export type VulnerabilityEvidence = {
  asset: {
    id: string;
    kind: "container" | "host" | "package" | "repository";
    version?: string;
  };
  policy: VulnerabilityPolicy;
  result: VulnerabilityPolicyEvaluation;
  scan: VulnerabilityScanSummary;
};

export const createVulnerabilityEvidence = (input: {
  asset: VulnerabilityEvidence["asset"];
  policy?: VulnerabilityPolicy;
  scan: VulnerabilityScanSummary;
}): VulnerabilityEvidence => {
  const policy = input.policy ?? DEFAULT_VULNERABILITY_POLICY;
  return {
    asset: input.asset,
    policy,
    result: evaluateVulnerabilityPolicy(input.scan, policy),
    scan: input.scan,
  };
};
