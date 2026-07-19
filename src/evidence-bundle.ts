import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import type { DeploymentAdmissionEvaluation } from "./admission";
import type { VexDecision } from "./contracts";
import type { SignedAdmissionIntelligenceSnapshot } from "./intelligence-snapshot";
import type { SignedSbomAttestation } from "./sbom";

export const VULNERABILITY_EVIDENCE_BUNDLE_CONTRACT =
  "absolutejs.vulnerability-evidence-bundle/v1" as const;

export type EvidenceVerificationKey = {
  algorithm: "ed25519";
  createdAt: string;
  fingerprint: string;
  keyId: string;
  publicKey: string;
};

export type EvidenceSigningIdentity = EvidenceVerificationKey & {
  privateKey: string;
};

export type EvidenceSigningKeyTransition = {
  algorithm: "ed25519";
  nextKey: EvidenceVerificationKey;
  previousKey: EvidenceVerificationKey;
  rotatedAt: string;
  signature: string;
};

export type VulnerabilityEvidenceBundlePayload<TKev = unknown> = {
  admission: DeploymentAdmissionEvaluation;
  generatedAt: string;
  intelligence: SignedAdmissionIntelligenceSnapshot<TKev>;
  project: { id: string; name: string };
  releaseId: string;
  sbom: SignedSbomAttestation;
  vex: VexDecision[];
};

export type SignedVulnerabilityEvidenceBundle<TKev = unknown> = {
  contract: typeof VULNERABILITY_EVIDENCE_BUNDLE_CONTRACT;
  key: EvidenceVerificationKey;
  payload: VulnerabilityEvidenceBundlePayload<TKev>;
  signature: {
    algorithm: "ed25519";
    keyId: string;
    signedAt: string;
    value: string;
  };
  transitions: EvidenceSigningKeyTransition[];
};

export type VulnerabilityEvidenceBundleVerification = {
  chainValid: boolean;
  signatureValid: boolean;
  trust: "trusted" | "untrusted";
  trustedKeyId: string | null;
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

const requiredText = (value: string, label: string) => {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);

  return normalized;
};

const timestamp = (value: string, label: string) => {
  const normalized = requiredText(value, label);
  if (!Number.isFinite(Date.parse(normalized)))
    throw new Error(`${label} must be a timestamp`);

  return normalized;
};

const publicKeyFrom = (value: string) => {
  const key = createPublicKey({
    format: "der",
    key: Buffer.from(value, "base64url"),
    type: "spki",
  });
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Evidence public key must be Ed25519");

  return key;
};

const privateKeyFrom = (value: string) => {
  const key = createPrivateKey({
    format: "der",
    key: Buffer.from(value, "base64url"),
    type: "pkcs8",
  });
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Evidence private key must be Ed25519");

  return key;
};

const fingerprint = (publicKey: string) =>
  createHash("sha256")
    .update(Buffer.from(publicKey, "base64url"))
    .digest("hex");

export const evidenceVerificationKeyFrom = (
  identity: EvidenceSigningIdentity,
): EvidenceVerificationKey => ({
  algorithm: identity.algorithm,
  createdAt: identity.createdAt,
  fingerprint: identity.fingerprint,
  keyId: identity.keyId,
  publicKey: identity.publicKey,
});

export const parseEvidenceVerificationKey = (
  value: EvidenceVerificationKey,
) => {
  if (value.algorithm !== "ed25519")
    throw new Error("Evidence key algorithm is unsupported");
  timestamp(value.createdAt, "Evidence key createdAt");
  requiredText(value.keyId, "Evidence key keyId");
  publicKeyFrom(value.publicKey);
  if (fingerprint(value.publicKey) !== value.fingerprint)
    throw new Error("Evidence key fingerprint is invalid");

  return structuredClone(value);
};

export const parseEvidenceSigningIdentity = (
  value: EvidenceSigningIdentity,
) => {
  const publicKey = parseEvidenceVerificationKey(value);
  const privateKey = privateKeyFrom(value.privateKey);
  const challenge = Buffer.from(
    "absolutejs.vulnerability-evidence-key-pair-check",
  );
  if (
    !verify(
      null,
      challenge,
      publicKeyFrom(publicKey.publicKey),
      sign(null, challenge, privateKey),
    )
  )
    throw new Error("Evidence signing key pair does not match");

  return structuredClone(value);
};

export const createEvidenceSigningIdentity = (
  input: {
    createdAt?: string;
    keyId?: string;
  } = {},
): EvidenceSigningIdentity => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });

  return {
    algorithm: "ed25519",
    createdAt: timestamp(
      input.createdAt ?? new Date().toISOString(),
      "Evidence key createdAt",
    ),
    fingerprint: createHash("sha256").update(publicKeyBytes).digest("hex"),
    keyId: input.keyId ?? crypto.randomUUID(),
    privateKey: privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64url"),
    publicKey: publicKeyBytes.toString("base64url"),
  };
};

const transitionPayload = (
  transition: Omit<EvidenceSigningKeyTransition, "signature">,
) => ({
  algorithm: transition.algorithm,
  nextKey: transition.nextKey,
  previousKey: transition.previousKey,
  purpose: "absolutejs.vulnerability-evidence-key-rotation",
  rotatedAt: transition.rotatedAt,
});

export const createEvidenceSigningKeyTransition = (input: {
  nextKey: EvidenceVerificationKey;
  previousIdentity: EvidenceSigningIdentity;
  rotatedAt?: string;
}): EvidenceSigningKeyTransition => {
  const previousIdentity = parseEvidenceSigningIdentity(input.previousIdentity);
  const unsigned = {
    algorithm: "ed25519" as const,
    nextKey: parseEvidenceVerificationKey(input.nextKey),
    previousKey: evidenceVerificationKeyFrom(previousIdentity),
    rotatedAt: timestamp(
      input.rotatedAt ?? new Date().toISOString(),
      "Evidence key rotatedAt",
    ),
  };

  return {
    ...unsigned,
    signature: sign(
      null,
      Buffer.from(canonical(transitionPayload(unsigned))),
      privateKeyFrom(previousIdentity.privateKey),
    ).toString("base64url"),
  };
};

export const verifyEvidenceSigningKeyTransition = (
  value: EvidenceSigningKeyTransition,
) => {
  try {
    const unsigned = {
      algorithm: value.algorithm,
      nextKey: parseEvidenceVerificationKey(value.nextKey),
      previousKey: parseEvidenceVerificationKey(value.previousKey),
      rotatedAt: timestamp(value.rotatedAt, "Evidence key rotatedAt"),
    };
    return verify(
      null,
      Buffer.from(canonical(transitionPayload(unsigned))),
      publicKeyFrom(unsigned.previousKey.publicKey),
      Buffer.from(value.signature, "base64url"),
    );
  } catch {
    return false;
  }
};

const bundleUnsigned = <TKev>(input: {
  key: EvidenceVerificationKey;
  payload: VulnerabilityEvidenceBundlePayload<TKev>;
  signedAt: string;
  transitions: EvidenceSigningKeyTransition[];
}) => ({
  contract: VULNERABILITY_EVIDENCE_BUNDLE_CONTRACT,
  key: input.key,
  payload: input.payload,
  signature: {
    algorithm: "ed25519" as const,
    keyId: input.key.keyId,
    signedAt: input.signedAt,
  },
  transitions: input.transitions,
});

export const signVulnerabilityEvidenceBundle = <TKev>(input: {
  identity: EvidenceSigningIdentity;
  payload: VulnerabilityEvidenceBundlePayload<TKev>;
  signedAt?: string;
  transitions?: readonly EvidenceSigningKeyTransition[];
}): SignedVulnerabilityEvidenceBundle<TKev> => {
  const identity = parseEvidenceSigningIdentity(input.identity);
  const unsigned = bundleUnsigned({
    key: evidenceVerificationKeyFrom(identity),
    payload: structuredClone(input.payload),
    signedAt: timestamp(
      input.signedAt ?? new Date().toISOString(),
      "Evidence bundle signedAt",
    ),
    transitions: structuredClone([...(input.transitions ?? [])]),
  });

  return {
    ...unsigned,
    signature: {
      ...unsigned.signature,
      value: sign(
        null,
        Buffer.from(canonical(unsigned)),
        privateKeyFrom(identity.privateKey),
      ).toString("base64url"),
    },
  };
};

const keyMatches = (
  left: EvidenceVerificationKey,
  right: EvidenceVerificationKey,
) =>
  left.keyId === right.keyId &&
  left.fingerprint === right.fingerprint &&
  left.publicKey === right.publicKey;

export const verifyVulnerabilityEvidenceBundle = <TKev>(input: {
  bundle: SignedVulnerabilityEvidenceBundle<TKev>;
  trustedKeys?: readonly EvidenceVerificationKey[];
}): VulnerabilityEvidenceBundleVerification => {
  let signatureValid = false;
  let chainValid = input.bundle.transitions.every(
    verifyEvidenceSigningKeyTransition,
  );
  try {
    const key = parseEvidenceVerificationKey(input.bundle.key);
    const unsigned = bundleUnsigned({
      key,
      payload: structuredClone(input.bundle.payload),
      signedAt: input.bundle.signature.signedAt,
      transitions: structuredClone(input.bundle.transitions),
    });
    signatureValid =
      input.bundle.contract === VULNERABILITY_EVIDENCE_BUNDLE_CONTRACT &&
      input.bundle.signature.algorithm === "ed25519" &&
      input.bundle.signature.keyId === key.keyId &&
      verify(
        null,
        Buffer.from(canonical(unsigned)),
        publicKeyFrom(key.publicKey),
        Buffer.from(input.bundle.signature.value, "base64url"),
      );
  } catch {
    signatureValid = false;
  }
  const trusted = (input.trustedKeys ?? []).map(parseEvidenceVerificationKey);
  let cursor = input.bundle.key;
  const visited = new Set<string>();
  while (!trusted.some((key) => keyMatches(key, cursor))) {
    if (visited.has(cursor.keyId)) {
      chainValid = false;
      break;
    }
    visited.add(cursor.keyId);
    const transition = input.bundle.transitions.find((entry) =>
      keyMatches(entry.nextKey, cursor),
    );
    if (!transition || !verifyEvidenceSigningKeyTransition(transition)) break;
    cursor = transition.previousKey;
  }
  const trustedKey = trusted.find((key) => keyMatches(key, cursor)) ?? null;

  return {
    chainValid,
    signatureValid,
    trust: signatureValid && chainValid && trustedKey ? "trusted" : "untrusted",
    trustedKeyId: trustedKey?.keyId ?? null,
  };
};
