import type {
  ManagedVulnerabilityFinding,
  VulnerabilityObservation,
  VulnerabilityRiskAssessment,
  VexDecision,
  VexFindingApplication,
} from "./contracts";

export type ManagedFindingFilter = {
  assetId?: string;
  limit?: number;
  severity?: ManagedVulnerabilityFinding["severity"];
  status?: ManagedVulnerabilityFinding["status"];
  tenantId: string;
};

export type VexDecisionFilter = {
  limit?: number;
  productId?: string;
  tenantId: string;
  vulnerabilityId?: string;
};

export type VexDecisionStore = {
  get: (tenantId: string, decisionId: string) => Promise<VexDecision | null>;
  list: (filter: VexDecisionFilter) => Promise<VexDecision[]>;
  save: (tenantId: string, decision: VexDecision) => Promise<void>;
  saveMany: (
    tenantId: string,
    decisions: readonly VexDecision[],
  ) => Promise<void>;
};

export type VexFindingApplicationStore = {
  get: (
    tenantId: string,
    findingId: string,
  ) => Promise<VexFindingApplication | null>;
  save: (application: VexFindingApplication) => Promise<void>;
  saveMany: (applications: readonly VexFindingApplication[]) => Promise<void>;
};

export type VulnerabilityRiskAssessmentFilter = {
  limit?: number;
  priority?: VulnerabilityRiskAssessment["priority"];
  tenantId: string;
};

export type VulnerabilityRiskAssessmentStore = {
  get: (
    tenantId: string,
    findingId: string,
  ) => Promise<VulnerabilityRiskAssessment | null>;
  list: (
    filter: VulnerabilityRiskAssessmentFilter,
  ) => Promise<VulnerabilityRiskAssessment[]>;
  save: (
    tenantId: string,
    assessment: VulnerabilityRiskAssessment,
  ) => Promise<void>;
  saveMany: (
    tenantId: string,
    assessments: readonly VulnerabilityRiskAssessment[],
  ) => Promise<void>;
};

export type ManagedFindingStore = {
  get: (
    tenantId: string,
    findingId: string,
  ) => Promise<ManagedVulnerabilityFinding | null>;
  list: (
    filter: ManagedFindingFilter,
  ) => Promise<ManagedVulnerabilityFinding[]>;
  save: (finding: ManagedVulnerabilityFinding) => Promise<void>;
  saveMany: (findings: readonly ManagedVulnerabilityFinding[]) => Promise<void>;
};

export type VulnerabilityObservationFilter = {
  assetId?: string;
  componentId?: string;
  limit?: number;
  tenantId: string;
};

export type VulnerabilityObservationStore = {
  get: (
    tenantId: string,
    observationId: string,
  ) => Promise<VulnerabilityObservation | null>;
  list: (
    filter: VulnerabilityObservationFilter,
  ) => Promise<VulnerabilityObservation[]>;
  save: (
    tenantId: string,
    observation: VulnerabilityObservation,
  ) => Promise<void>;
  saveMany: (
    tenantId: string,
    observations: readonly VulnerabilityObservation[],
  ) => Promise<void>;
};
