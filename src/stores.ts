import type {
  ManagedVulnerabilityFinding,
  VulnerabilityObservation,
} from "./contracts";

export type ManagedFindingFilter = {
  assetId?: string;
  limit?: number;
  severity?: ManagedVulnerabilityFinding["severity"];
  status?: ManagedVulnerabilityFinding["status"];
  tenantId: string;
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
