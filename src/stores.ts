import type { ManagedVulnerabilityFinding } from "./contracts";

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
