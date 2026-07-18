import { createHash } from "node:crypto";

export type StableFindingIdentityInput = {
  assetId: string;
  componentIdentity: string;
  tenantId: string;
  vulnerabilityIds: readonly string[];
};

const requiredIdentityPart = (label: string, value: string) => {
  const normalized = value.trim();
  if (normalized.length === 0)
    throw new Error(`Stable finding identity requires ${label}`);
  return normalized;
};

export const normalizeVulnerabilityId = (value: string) =>
  requiredIdentityPart("a vulnerability id", value).toUpperCase();

export const canonicalVulnerabilityIds = (values: readonly string[]) => {
  const normalized = [...new Set(values.map(normalizeVulnerabilityId))].sort();
  if (normalized.length === 0)
    throw new Error("Stable finding identity requires vulnerability ids");
  return normalized;
};

export const createStableFindingId = (input: StableFindingIdentityInput) => {
  const canonical = JSON.stringify([
    requiredIdentityPart("tenantId", input.tenantId),
    requiredIdentityPart("assetId", input.assetId),
    requiredIdentityPart("componentIdentity", input.componentIdentity),
    canonicalVulnerabilityIds(input.vulnerabilityIds),
  ]);
  return `vuln_${createHash("sha256").update(canonical).digest("hex")}`;
};
