import { Type, type Static } from "@sinclair/typebox";
import {
  IdentifierSchema,
  NullableTimestampSchema,
  TimestampSchema,
} from "./primitives";

export const VULNERABILITY_CONTRACT_VERSION = 1 as const;

export const AssetKindSchema = Type.Union([
  Type.Literal("container"),
  Type.Literal("host"),
  Type.Literal("package"),
  Type.Literal("repository"),
  Type.Literal("deployment"),
]);
export type AssetKind = Static<typeof AssetKindSchema>;

export const AssetEnvironmentSchema = Type.Union([
  Type.Literal("production"),
  Type.Literal("staging"),
  Type.Literal("development"),
  Type.Literal("test"),
  Type.Literal("unknown"),
]);
export type AssetEnvironment = Static<typeof AssetEnvironmentSchema>;

export const AssetCriticalitySchema = Type.Union([
  Type.Literal("critical"),
  Type.Literal("high"),
  Type.Literal("medium"),
  Type.Literal("low"),
  Type.Literal("unknown"),
]);
export type AssetCriticality = Static<typeof AssetCriticalitySchema>;

export const VulnerabilityAssetSchema = Type.Object(
  {
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    criticality: AssetCriticalitySchema,
    environment: AssetEnvironmentSchema,
    id: IdentifierSchema,
    kind: AssetKindSchema,
    labels: Type.Record(Type.String(), Type.String()),
    name: IdentifierSchema,
    tenantId: IdentifierSchema,
    version: Type.Union([Type.Null(), IdentifierSchema]),
  },
  { additionalProperties: false },
);
export type VulnerabilityAsset = Static<typeof VulnerabilityAssetSchema>;

export const ComponentIdentitySchema = Type.Object(
  {
    ecosystem: IdentifierSchema,
    name: IdentifierSchema,
    namespace: Type.Union([Type.Null(), IdentifierSchema]),
    purl: Type.Union([
      Type.Null(),
      Type.String({ minLength: 5, pattern: "^pkg:" }),
    ]),
    version: IdentifierSchema,
  },
  { additionalProperties: false },
);
export type ComponentIdentity = Static<typeof ComponentIdentitySchema>;

export const VulnerabilityComponentSchema = Type.Object(
  {
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    id: IdentifierSchema,
    identity: ComponentIdentitySchema,
    licenses: Type.Array(IdentifierSchema, { uniqueItems: true }),
    locations: Type.Array(IdentifierSchema, { uniqueItems: true }),
    properties: Type.Record(Type.String(), Type.String()),
  },
  { additionalProperties: false },
);
export type VulnerabilityComponent = Static<
  typeof VulnerabilityComponentSchema
>;

export const AdvisorySourceSchema = Type.Object(
  {
    fetchedAt: TimestampSchema,
    name: IdentifierSchema,
    revision: Type.Union([Type.Null(), IdentifierSchema]),
    url: Type.Union([
      Type.Null(),
      Type.String({ minLength: 1, pattern: "^https://" }),
    ]),
  },
  { additionalProperties: false },
);
export type AdvisorySource = Static<typeof AdvisorySourceSchema>;

export const AdvisorySeveritySchema = Type.Object(
  {
    score: Type.Union([Type.Null(), Type.Number({ minimum: 0, maximum: 10 })]),
    system: Type.Union([
      Type.Literal("cvss-v2"),
      Type.Literal("cvss-v3"),
      Type.Literal("cvss-v4"),
      Type.Literal("vendor"),
      Type.Literal("unknown"),
    ]),
    value: Type.Union([
      Type.Literal("critical"),
      Type.Literal("high"),
      Type.Literal("medium"),
      Type.Literal("low"),
      Type.Literal("negligible"),
      Type.Literal("unknown"),
    ]),
    vector: Type.Union([Type.Null(), IdentifierSchema]),
  },
  { additionalProperties: false },
);
export type AdvisorySeverity = Static<typeof AdvisorySeveritySchema>;

export const VulnerabilityAdvisorySchema = Type.Object(
  {
    affected: Type.Optional(
      Type.Array(
        Type.Object(
          {
            package: Type.Object(
              {
                ecosystem: IdentifierSchema,
                name: IdentifierSchema,
                purl: Type.Union([Type.Null(), IdentifierSchema]),
              },
              { additionalProperties: false },
            ),
            ranges: Type.Array(
              Type.Object(
                {
                  events: Type.Array(
                    Type.Object(
                      {
                        fixed: Type.Optional(IdentifierSchema),
                        introduced: Type.Optional(IdentifierSchema),
                        lastAffected: Type.Optional(IdentifierSchema),
                        limit: Type.Optional(IdentifierSchema),
                      },
                      { additionalProperties: false },
                    ),
                  ),
                  repository: Type.Union([Type.Null(), IdentifierSchema]),
                  type: Type.Union([
                    Type.Literal("ecosystem"),
                    Type.Literal("git"),
                    Type.Literal("semver"),
                  ]),
                },
                { additionalProperties: false },
              ),
            ),
            versions: Type.Array(IdentifierSchema, { uniqueItems: true }),
          },
          { additionalProperties: false },
        ),
      ),
    ),
    aliases: Type.Array(IdentifierSchema, { minItems: 1, uniqueItems: true }),
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    details: Type.Union([Type.Null(), Type.String()]),
    id: IdentifierSchema,
    modifiedAt: TimestampSchema,
    publishedAt: NullableTimestampSchema,
    severity: Type.Array(AdvisorySeveritySchema),
    source: AdvisorySourceSchema,
    summary: IdentifierSchema,
    withdrawnAt: NullableTimestampSchema,
  },
  { additionalProperties: false },
);
export type VulnerabilityAdvisory = Static<typeof VulnerabilityAdvisorySchema>;

export const EvidenceReferenceSchema = Type.Object(
  {
    collectedAt: TimestampSchema,
    digest: Type.Union([
      Type.Null(),
      Type.String({ pattern: "^sha256:[a-f0-9]{64}$" }),
    ]),
    kind: Type.Union([
      Type.Literal("advisory"),
      Type.Literal("inventory"),
      Type.Literal("scan"),
      Type.Literal("vendor-status"),
      Type.Literal("vex"),
      Type.Literal("verification"),
    ]),
    source: IdentifierSchema,
    uri: Type.Union([Type.Null(), IdentifierSchema]),
  },
  { additionalProperties: false },
);
export type EvidenceReference = Static<typeof EvidenceReferenceSchema>;

export const VulnerabilityObservationSchema = Type.Object(
  {
    advisoryIds: Type.Array(IdentifierSchema, { uniqueItems: true }),
    assetId: IdentifierSchema,
    componentId: IdentifierSchema,
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    evidence: Type.Array(EvidenceReferenceSchema),
    id: IdentifierSchema,
    observedAt: TimestampSchema,
    scanner: IdentifierSchema,
    scannerRecordId: Type.Union([Type.Null(), IdentifierSchema]),
    severity: Type.Union([
      Type.Literal("critical"),
      Type.Literal("high"),
      Type.Literal("medium"),
      Type.Literal("low"),
      Type.Literal("negligible"),
      Type.Literal("unknown"),
    ]),
  },
  { additionalProperties: false },
);
export type VulnerabilityObservation = Static<
  typeof VulnerabilityObservationSchema
>;

export const FindingStatusSchema = Type.Union([
  Type.Literal("new"),
  Type.Literal("triaged"),
  Type.Literal("under_investigation"),
  Type.Literal("confirmed"),
  Type.Literal("remediation_planned"),
  Type.Literal("remediating"),
  Type.Literal("mitigated"),
  Type.Literal("fixed"),
  Type.Literal("accepted_risk"),
  Type.Literal("false_positive"),
  Type.Literal("reopened"),
]);
export type FindingStatus = Static<typeof FindingStatusSchema>;

export const ManagedVulnerabilityFindingSchema = Type.Object(
  {
    assetId: IdentifierSchema,
    componentId: IdentifierSchema,
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    firstSeenAt: TimestampSchema,
    id: Type.String({ pattern: "^vuln_[a-f0-9]{64}$" }),
    lastSeenAt: TimestampSchema,
    observationIds: Type.Array(IdentifierSchema, {
      minItems: 1,
      uniqueItems: true,
    }),
    severity: Type.Union([
      Type.Literal("critical"),
      Type.Literal("high"),
      Type.Literal("medium"),
      Type.Literal("low"),
      Type.Literal("negligible"),
      Type.Literal("unknown"),
    ]),
    status: FindingStatusSchema,
    tenantId: IdentifierSchema,
    vulnerabilityIds: Type.Array(IdentifierSchema, {
      minItems: 1,
      uniqueItems: true,
    }),
  },
  { additionalProperties: false },
);
export type ManagedVulnerabilityFinding = Static<
  typeof ManagedVulnerabilityFindingSchema
>;

export const VexStatusSchema = Type.Union([
  Type.Literal("affected"),
  Type.Literal("not_affected"),
  Type.Literal("fixed"),
  Type.Literal("under_investigation"),
]);
export type VexStatus = Static<typeof VexStatusSchema>;

export const VexJustificationSchema = Type.Union([
  Type.Literal("component_not_present"),
  Type.Literal("vulnerable_code_not_present"),
  Type.Literal("vulnerable_code_not_executed"),
  Type.Literal("vulnerable_configuration_disabled"),
  Type.Literal("vendor_backport_applied"),
  Type.Literal("compensating_control"),
  Type.Literal("scanner_identification_incorrect"),
  Type.Literal("other"),
]);
export type VexJustification = Static<typeof VexJustificationSchema>;

export const VexDecisionSchema = Type.Object(
  {
    author: IdentifierSchema,
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    createdAt: TimestampSchema,
    evidence: Type.Array(EvidenceReferenceSchema),
    expiresAt: NullableTimestampSchema,
    id: IdentifierSchema,
    justification: Type.Union([Type.Null(), VexJustificationSchema]),
    productId: IdentifierSchema,
    reviewedAt: NullableTimestampSchema,
    statement: IdentifierSchema,
    status: VexStatusSchema,
    vulnerabilityId: IdentifierSchema,
  },
  { additionalProperties: false },
);
export type VexDecision = Static<typeof VexDecisionSchema>;

export const VexFindingApplicationSchema = Type.Object(
  {
    appliedAt: TimestampSchema,
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    decisionId: IdentifierSchema,
    endedAt: NullableTimestampSchema,
    findingId: IdentifierSchema,
    previousStatus: FindingStatusSchema,
    resultingStatus: FindingStatusSchema,
    tenantId: IdentifierSchema,
  },
  { additionalProperties: false },
);
export type VexFindingApplication = Static<typeof VexFindingApplicationSchema>;

export const RiskPrioritySchema = Type.Union([
  Type.Literal("emergency"),
  Type.Literal("critical"),
  Type.Literal("high"),
  Type.Literal("medium"),
  Type.Literal("low"),
  Type.Literal("informational"),
]);
export type RiskPriority = Static<typeof RiskPrioritySchema>;

export const VulnerabilityRiskAssessmentSchema = Type.Object(
  {
    assessedAt: TimestampSchema,
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    epssPercentile: Type.Union([
      Type.Null(),
      Type.Number({ minimum: 0, maximum: 1 }),
    ]),
    epssProbability: Type.Union([
      Type.Null(),
      Type.Number({ minimum: 0, maximum: 1 }),
    ]),
    findingId: IdentifierSchema,
    fixAvailable: Type.Boolean(),
    internetExposed: Type.Boolean(),
    kev: Type.Boolean(),
    policyVersion: IdentifierSchema,
    priority: RiskPrioritySchema,
    reachability: Type.Union([
      Type.Literal("reachable"),
      Type.Literal("not_reachable"),
      Type.Literal("unknown"),
    ]),
    reasons: Type.Array(IdentifierSchema, { minItems: 1 }),
    remediateBy: NullableTimestampSchema,
  },
  { additionalProperties: false },
);
export type VulnerabilityRiskAssessment = Static<
  typeof VulnerabilityRiskAssessmentSchema
>;

export const RemediationActionSchema = Type.Object(
  {
    assetId: IdentifierSchema,
    componentId: Type.Union([Type.Null(), IdentifierSchema]),
    fromVersion: Type.Union([Type.Null(), IdentifierSchema]),
    id: IdentifierSchema,
    kind: Type.Union([
      Type.Literal("package_upgrade"),
      Type.Literal("configuration_change"),
      Type.Literal("workaround"),
      Type.Literal("remove_component"),
      Type.Literal("rebuild"),
      Type.Literal("reboot"),
    ]),
    requiresRestart: Type.Boolean(),
    toVersion: Type.Union([Type.Null(), IdentifierSchema]),
  },
  { additionalProperties: false },
);
export type RemediationAction = Static<typeof RemediationActionSchema>;

export const RemediationPlanSchema = Type.Object(
  {
    actions: Type.Array(RemediationActionSchema, { minItems: 1 }),
    approvedAt: NullableTimestampSchema,
    approvedBy: Type.Union([Type.Null(), IdentifierSchema]),
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    createdAt: TimestampSchema,
    createdBy: IdentifierSchema,
    findingIds: Type.Array(IdentifierSchema, {
      minItems: 1,
      uniqueItems: true,
    }),
    id: IdentifierSchema,
    rollbackSummary: IdentifierSchema,
    status: Type.Union([
      Type.Literal("draft"),
      Type.Literal("approved"),
      Type.Literal("executing"),
      Type.Literal("succeeded"),
      Type.Literal("failed"),
      Type.Literal("cancelled"),
    ]),
  },
  { additionalProperties: false },
);
export type RemediationPlan = Static<typeof RemediationPlanSchema>;

export const RemediationExecutionSchema = Type.Object(
  {
    completedAt: NullableTimestampSchema,
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    evidence: Type.Array(EvidenceReferenceSchema),
    id: IdentifierSchema,
    message: Type.Union([Type.Null(), Type.String()]),
    planId: IdentifierSchema,
    startedAt: TimestampSchema,
    status: Type.Union([
      Type.Literal("running"),
      Type.Literal("succeeded"),
      Type.Literal("failed"),
      Type.Literal("cancelled"),
    ]),
  },
  { additionalProperties: false },
);
export type RemediationExecution = Static<typeof RemediationExecutionSchema>;

export const RemediationDeploymentSchema = Type.Object(
  {
    activatedAt: TimestampSchema,
    assetId: IdentifierSchema,
    releaseId: IdentifierSchema,
  },
  { additionalProperties: false },
);
export type RemediationDeployment = Static<typeof RemediationDeploymentSchema>;

export const RemediationVerificationSchema = Type.Object(
  {
    contract: Type.Literal(VULNERABILITY_CONTRACT_VERSION),
    deployments: Type.Array(RemediationDeploymentSchema, { minItems: 1 }),
    evidence: Type.Array(EvidenceReferenceSchema, { minItems: 1 }),
    executionId: IdentifierSchema,
    fixedFindingIds: Type.Array(IdentifierSchema, { uniqueItems: true }),
    id: IdentifierSchema,
    observedAt: TimestampSchema,
    planId: IdentifierSchema,
    remainingFindingIds: Type.Array(IdentifierSchema, { uniqueItems: true }),
    status: Type.Union([Type.Literal("passed"), Type.Literal("failed")]),
  },
  { additionalProperties: false },
);
export type RemediationVerification = Static<
  typeof RemediationVerificationSchema
>;
