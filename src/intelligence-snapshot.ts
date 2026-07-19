import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { VulnerabilityAdvisory } from "./contracts";
import type { FeedCursor, FeedRecord, FeedSnapshot } from "./feeds";

export const ADMISSION_INTELLIGENCE_CONTRACT =
  "absolutejs.vulnerability-admission-intelligence/v1" as const;

export type AdmissionIntelligencePackage = {
  ecosystem: string;
  name: string;
  version: string;
};

export type AdmissionIntelligencePayload<TKev = unknown> = {
  contract: typeof ADMISSION_INTELLIGENCE_CONTRACT;
  coverage: string[];
  kev: FeedSnapshot<TKev>;
  osv: FeedSnapshot<VulnerabilityAdvisory>;
};

export type SignedAdmissionIntelligenceSnapshot<TKev = unknown> = {
  algorithm: "HS256";
  digest: `sha256:${string}`;
  expiresAt: string;
  issuedAt: string;
  keyId: string;
  payload: AdmissionIntelligencePayload<TKev>;
  signature: string;
};

export type AdmissionIntelligenceVerification<TKev = unknown> =
  | { status: "expired" | "invalid" }
  | {
      payload: AdmissionIntelligencePayload<TKev>;
      status: "verified";
    };

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

const requiredText = (value: unknown, label: string) => {
  if (typeof value !== "string" || !value.trim())
    throw new Error(`${label} is required`);

  return value.trim();
};

const timestamp = (value: unknown, label: string) => {
  const parsed = requiredText(value, label);
  if (!Number.isFinite(Date.parse(parsed)))
    throw new Error(`${label} must be a timestamp`);

  return parsed;
};

const cursor = (value: unknown): FeedCursor => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Admission intelligence cursor must be an object");
  const input = value as Record<string, unknown>;
  const optional = (field: keyof FeedCursor) => {
    const entry = input[field];
    if (entry !== null && typeof entry !== "string")
      throw new Error(`Admission intelligence cursor ${field} is invalid`);

    return entry as string | null;
  };

  return {
    etag: optional("etag"),
    lastModified: optional("lastModified"),
    token: optional("token"),
  };
};

const snapshot = <T>(value: FeedSnapshot<T>, expectedId: string) => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`Admission intelligence ${expectedId} snapshot is invalid`);
  if (value.feed?.id !== expectedId)
    throw new Error(`Admission intelligence ${expectedId} feed is required`);
  const records = value.records.map(
    (entry): FeedRecord<T> => ({
      id: requiredText(entry.id, `${expectedId} record id`),
      modifiedAt: timestamp(
        entry.modifiedAt,
        `${expectedId} record modifiedAt`,
      ),
      value: structuredClone(entry.value),
    }),
  );
  if (new Set(records.map(({ id }) => id)).size !== records.length)
    throw new Error(`Admission intelligence ${expectedId} records repeat ids`);

  return {
    cursor: cursor(value.cursor),
    feed: {
      id: expectedId,
      name: requiredText(value.feed.name, `${expectedId} feed name`),
      url: requiredText(value.feed.url, `${expectedId} feed URL`),
    },
    fetchedAt: timestamp(value.fetchedAt, `${expectedId} fetchedAt`),
    records: records.sort((left, right) => left.id.localeCompare(right.id)),
    revision:
      value.revision === null
        ? null
        : requiredText(value.revision, `${expectedId} revision`),
  } satisfies FeedSnapshot<T>;
};

export const admissionIntelligenceCoverageKey = (
  input: AdmissionIntelligencePackage,
) =>
  canonical([
    requiredText(input.ecosystem, "Package ecosystem"),
    requiredText(input.name, "Package name"),
    requiredText(input.version, "Package version"),
  ]);

export const normalizeAdmissionIntelligencePayload = <TKev>(input: {
  coverage: readonly string[];
  kev: FeedSnapshot<TKev>;
  osv: FeedSnapshot<VulnerabilityAdvisory>;
}): AdmissionIntelligencePayload<TKev> => ({
  contract: ADMISSION_INTELLIGENCE_CONTRACT,
  coverage: [
    ...new Set(
      input.coverage.map((entry) => requiredText(entry, "Coverage key")),
    ),
  ].sort(),
  kev: snapshot(input.kev, "cisa-kev"),
  osv: snapshot(input.osv, "osv"),
});

export const signAdmissionIntelligenceSnapshot = <TKev>(input: {
  coverage: readonly string[];
  issuedAt?: string;
  kev: FeedSnapshot<TKev>;
  keyId: string;
  maxAgeMs: number;
  osv: FeedSnapshot<VulnerabilityAdvisory>;
  secret: string;
}): SignedAdmissionIntelligenceSnapshot<TKev> => {
  if (Buffer.byteLength(input.secret) < 32)
    throw new Error(
      "Admission intelligence signing secret must be at least 32 bytes",
    );
  if (!Number.isSafeInteger(input.maxAgeMs) || input.maxAgeMs <= 0)
    throw new Error(
      "Admission intelligence maxAgeMs must be a positive integer",
    );
  const issuedAt = timestamp(
    input.issuedAt ?? new Date().toISOString(),
    "Admission intelligence issuedAt",
  );
  const payload = normalizeAdmissionIntelligencePayload(input);
  const oldestFetchedAt = Math.min(
    Date.parse(payload.kev.fetchedAt),
    Date.parse(payload.osv.fetchedAt),
  );
  const expiresAt = new Date(oldestFetchedAt + input.maxAgeMs).toISOString();
  if (Date.parse(issuedAt) > Date.parse(expiresAt))
    throw new Error("Admission intelligence feeds are stale");
  const signed = {
    algorithm: "HS256" as const,
    expiresAt,
    issuedAt,
    keyId: requiredText(input.keyId, "Admission intelligence keyId"),
    payload,
  };

  return {
    ...signed,
    digest: `sha256:${sha256(canonical(payload))}`,
    signature: createHmac("sha256", input.secret)
      .update(canonical(signed))
      .digest("base64url"),
  };
};

export const verifyAdmissionIntelligenceSnapshot = <TKev>(input: {
  attestation: SignedAdmissionIntelligenceSnapshot<TKev>;
  now?: string;
  secret: string;
}): AdmissionIntelligenceVerification<TKev> => {
  try {
    if (input.attestation.algorithm !== "HS256") return { status: "invalid" };
    const issuedAt = timestamp(
      input.attestation.issuedAt,
      "Admission intelligence issuedAt",
    );
    const expiresAt = timestamp(
      input.attestation.expiresAt,
      "Admission intelligence expiresAt",
    );
    const payload = normalizeAdmissionIntelligencePayload(
      input.attestation.payload,
    );
    if (payload.contract !== input.attestation.payload.contract)
      return { status: "invalid" };
    const signed = {
      algorithm: "HS256" as const,
      expiresAt,
      issuedAt,
      keyId: requiredText(
        input.attestation.keyId,
        "Admission intelligence keyId",
      ),
      payload,
    };
    const expectedDigest = `sha256:${sha256(canonical(payload))}`;
    const expectedSignature = createHmac("sha256", input.secret)
      .update(canonical(signed))
      .digest();
    const actualSignature = Buffer.from(
      input.attestation.signature,
      "base64url",
    );
    if (
      input.attestation.digest !== expectedDigest ||
      actualSignature.length !== expectedSignature.length ||
      !timingSafeEqual(actualSignature, expectedSignature)
    )
      return { status: "invalid" };
    if (
      Date.parse(input.now ?? new Date().toISOString()) > Date.parse(expiresAt)
    )
      return { status: "expired" };

    return { payload, status: "verified" };
  } catch {
    return { status: "invalid" };
  }
};
