import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { VULNERABILITY_CONTRACT_VERSION } from "./contracts";
import type { VulnerabilityAsset, VulnerabilityComponent } from "./contracts";

export type CycloneDxComponent = {
  "bom-ref": string;
  group?: string;
  name: string;
  purl: string;
  type: "application" | "library";
  version: string;
};

export type CycloneDxSbom = {
  bomFormat: "CycloneDX";
  components: CycloneDxComponent[];
  metadata: {
    component: CycloneDxComponent;
    timestamp: string;
    tools: {
      components: Array<{ name: string; type: "application"; version: string }>;
    };
  };
  serialNumber: `urn:uuid:${string}`;
  specVersion: "1.6";
  version: 1;
};

const record = (value: unknown, label: string) => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object`);

  return value as Record<string, unknown>;
};

const parseComponent = (value: unknown, label: string): CycloneDxComponent => {
  const input = record(value, label);
  const type = input.type;
  if (type !== "application" && type !== "library")
    throw new Error(`${label} type is invalid`);
  for (const field of ["bom-ref", "name", "purl", "version"] as const)
    if (typeof input[field] !== "string" || !input[field].trim())
      throw new Error(`${label} ${field} is required`);
  if (!(input.purl as string).startsWith("pkg:npm/"))
    throw new Error(`${label} purl must identify an npm package`);
  if (input.group !== undefined && typeof input.group !== "string")
    throw new Error(`${label} group must be a string`);

  return {
    "bom-ref": input["bom-ref"] as string,
    ...(typeof input.group === "string" ? { group: input.group } : {}),
    name: input.name as string,
    purl: input.purl as string,
    type,
    version: input.version as string,
  };
};

export const parseCycloneDxSbom = (value: unknown): CycloneDxSbom => {
  const input = record(value, "CycloneDX SBOM");
  if (
    input.bomFormat !== "CycloneDX" ||
    input.specVersion !== "1.6" ||
    input.version !== 1
  )
    throw new Error("CycloneDX SBOM contract is unsupported");
  if (
    typeof input.serialNumber !== "string" ||
    !/^urn:uuid:[0-9a-f-]{36}$/iu.test(input.serialNumber)
  )
    throw new Error("CycloneDX SBOM serialNumber is invalid");
  if (!Array.isArray(input.components))
    throw new Error("CycloneDX SBOM components must be an array");
  const components = input.components.map((entry, index) =>
    parseComponent(entry, `CycloneDX component ${index}`),
  );
  if (new Set(components.map(({ purl }) => purl)).size !== components.length)
    throw new Error("CycloneDX SBOM component purls must be unique");
  const metadata = record(input.metadata, "CycloneDX metadata");
  if (
    typeof metadata.timestamp !== "string" ||
    Number.isNaN(Date.parse(metadata.timestamp))
  )
    throw new Error("CycloneDX metadata timestamp is invalid");
  const tools = record(metadata.tools, "CycloneDX metadata tools");
  if (!Array.isArray(tools.components))
    throw new Error("CycloneDX metadata tools components must be an array");

  return {
    bomFormat: "CycloneDX",
    components,
    metadata: {
      component: parseComponent(
        metadata.component,
        "CycloneDX metadata component",
      ),
      timestamp: metadata.timestamp,
      tools: {
        components: tools.components.map((entry, index) => {
          const tool = record(entry, `CycloneDX tool ${index}`);
          if (
            tool.type !== "application" ||
            typeof tool.name !== "string" ||
            !tool.name.trim() ||
            typeof tool.version !== "string" ||
            !tool.version.trim()
          )
            throw new Error(`CycloneDX tool ${index} is invalid`);

          return {
            name: tool.name,
            type: "application" as const,
            version: tool.version,
          };
        }),
      },
    },
    serialNumber: input.serialNumber as `urn:uuid:${string}`,
    specVersion: "1.6",
    version: 1,
  };
};

type PackageManifest = { name?: string; version?: string };

const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`)
      .join(",")}}`;

  return JSON.stringify(value);
};

const sha256 = (value: string) =>
  createHash("sha256").update(value).digest("hex");

const npmIdentity = (name: string, version: string) => {
  const slash = name.startsWith("@") ? name.indexOf("/") : -1;
  const group = slash > 1 ? name.slice(0, slash) : undefined;
  const packageName = slash > 1 ? name.slice(slash + 1) : name;
  const purlName = group
    ? `%40${encodeURIComponent(group.slice(1))}/${encodeURIComponent(packageName)}`
    : encodeURIComponent(packageName);
  const purl = `pkg:npm/${purlName}@${encodeURIComponent(version)}`;

  return { group, name: packageName, purl };
};

const component = (
  name: string,
  version: string,
  type: CycloneDxComponent["type"],
): CycloneDxComponent => {
  const identity = npmIdentity(name, version);

  return {
    "bom-ref": identity.purl,
    ...(identity.group ? { group: identity.group } : {}),
    name: identity.name,
    purl: identity.purl,
    type,
    version,
  };
};

const manifestAt = async (root: string) => {
  const value = JSON.parse(
    await readFile(path.join(root, "package.json"), "utf8"),
  ) as PackageManifest;
  if (!value.name?.trim() || !value.version?.trim()) return null;

  return { name: value.name.trim(), version: value.version.trim() };
};

const applicationManifestAt = async (root: string, releaseId: string) => {
  const value = JSON.parse(
    await readFile(path.join(root, "package.json"), "utf8"),
  ) as PackageManifest;
  if (!value.name?.trim())
    throw new Error("SBOM root package.json requires name");

  return { name: value.name.trim(), version: releaseId };
};

export const generateCycloneDxSbom = async (input: {
  generatedAt?: string;
  releaseId: string;
  root: string;
}): Promise<CycloneDxSbom> => {
  const rootManifest = await applicationManifestAt(input.root, input.releaseId);
  const installed = new Map<string, CycloneDxComponent>();
  const visited = new Set<string>();
  const visitNodeModules = async (nodeModules: string): Promise<void> => {
    const entries = await readdir(nodeModules, { withFileTypes: true }).catch(
      (error: unknown) => {
        if (
          error &&
          typeof error === "object" &&
          "code" in error &&
          error.code === "ENOENT"
        )
          return [];
        throw error;
      },
    );
    for (const entry of entries) {
      if (entry.name === ".bin" || entry.name === ".bun") continue;
      const candidate = path.join(nodeModules, entry.name);
      if (entry.name.startsWith("@")) {
        await visitNodeModules(candidate);
        continue;
      }
      const resolved = await realpath(candidate).catch(() => candidate);
      if (visited.has(resolved)) continue;
      visited.add(resolved);
      const manifest = await manifestAt(candidate).catch(() => null);
      if (!manifest) continue;
      const found = component(manifest.name, manifest.version, "library");
      installed.set(found["bom-ref"], found);
      await visitNodeModules(path.join(candidate, "node_modules"));
    }
  };
  await visitNodeModules(path.join(input.root, "node_modules"));
  const application = component(
    rootManifest.name,
    input.releaseId,
    "application",
  );
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const serialSeed = sha256(canonical([application, [...installed.values()]]));
  const uuid = `${serialSeed.slice(0, 8)}-${serialSeed.slice(8, 12)}-4${serialSeed.slice(13, 16)}-a${serialSeed.slice(17, 20)}-${serialSeed.slice(20, 32)}`;

  return {
    bomFormat: "CycloneDX",
    components: [...installed.values()].sort((left, right) =>
      left.purl.localeCompare(right.purl),
    ),
    metadata: {
      component: application,
      timestamp: generatedAt,
      tools: {
        components: [
          {
            name: "@absolutejs/vulnerabilities",
            type: "application",
            version: "0.10.3",
          },
        ],
      },
    },
    serialNumber: `urn:uuid:${uuid}`,
    specVersion: "1.6",
    version: 1,
  };
};

export const cycloneDxSbomToInventory = (input: {
  asset: Omit<VulnerabilityAsset, "contract">;
  sbom: CycloneDxSbom;
}): { asset: VulnerabilityAsset; components: VulnerabilityComponent[] } => {
  const sbom = parseCycloneDxSbom(input.sbom);

  return {
    asset: { ...input.asset, contract: VULNERABILITY_CONTRACT_VERSION },
    components: sbom.components.map((entry) => {
      const fullName = entry.group
        ? `${entry.group}/${entry.name}`
        : entry.name;
      return {
        contract: VULNERABILITY_CONTRACT_VERSION,
        id: `component_${sha256(entry.purl)}`,
        identity: {
          ecosystem: "npm",
          name: fullName,
          namespace: entry.group?.replace(/^@/, "") ?? null,
          purl: entry.purl,
          version: entry.version,
        },
        licenses: [],
        locations: ["node_modules"],
        properties: { "inventory.source": "cyclonedx-runtime" },
      };
    }),
  };
};

export type SignedSbomAttestation = {
  algorithm: "HS256";
  digest: `sha256:${string}`;
  issuedAt: string;
  keyId: string;
  projectId: string;
  releaseId: string;
  sbom: CycloneDxSbom;
  signature: string;
};

export const signSbomAttestation = (input: {
  issuedAt?: string;
  keyId: string;
  projectId: string;
  releaseId: string;
  sbom: CycloneDxSbom;
  secret: string;
}): SignedSbomAttestation => {
  if (Buffer.byteLength(input.secret) < 32)
    throw new Error("SBOM signing secret must be at least 32 bytes");
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  const sbom = parseCycloneDxSbom(input.sbom);
  const payload = {
    algorithm: "HS256" as const,
    issuedAt,
    keyId: input.keyId,
    projectId: input.projectId,
    releaseId: input.releaseId,
    sbom,
  };
  const bytes = canonical(payload);

  return {
    ...payload,
    digest: `sha256:${sha256(canonical(sbom))}`,
    signature: createHmac("sha256", input.secret)
      .update(bytes)
      .digest("base64url"),
  };
};

export const verifySbomAttestation = (
  attestation: SignedSbomAttestation,
  secret: string,
) => {
  const { digest, signature, ...payload } = attestation;
  const expectedDigest = `sha256:${sha256(canonical(attestation.sbom))}`;
  const expectedSignature = createHmac("sha256", secret)
    .update(canonical(payload))
    .digest();
  const actualSignature = Buffer.from(signature, "base64url");

  return (
    digest === expectedDigest &&
    actualSignature.length === expectedSignature.length &&
    timingSafeEqual(actualSignature, expectedSignature)
  );
};
