import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import {
  evidenceVerificationKeyFrom,
  parseEvidenceSigningIdentity,
  parseEvidenceVerificationKey,
  type EvidenceSigningIdentity,
  type EvidenceVerificationKey,
} from "./evidence-bundle";
import type { EvidenceKeyTransparencyLog } from "./evidence-transparency";

export const EVIDENCE_WITNESS_CHECKPOINT_CONTRACT =
  "absolutejs.vulnerability-evidence-witness-checkpoint/v1" as const;

export type EvidenceWitnessCheckpoint = {
  contract: typeof EVIDENCE_WITNESS_CHECKPOINT_CONTRACT;
  logHead: `sha256:${string}`;
  logSize: number;
  observedAt: string;
  origin: string;
};

export type SignedEvidenceWitnessCheckpoint = EvidenceWitnessCheckpoint & {
  signature: { algorithm: "ed25519"; keyId: string; value: string };
  witness: EvidenceVerificationKey;
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

const checkpoint = (input: EvidenceWitnessCheckpoint) => {
  if (input.contract !== EVIDENCE_WITNESS_CHECKPOINT_CONTRACT)
    throw new Error("Evidence witness contract is unsupported");
  if (!input.origin.trim())
    throw new Error("Evidence witness origin is required");
  if (!Number.isSafeInteger(input.logSize) || input.logSize < 1)
    throw new Error("Evidence witness log size is invalid");
  if (!/^sha256:[a-f0-9]{64}$/u.test(input.logHead))
    throw new Error("Evidence witness log head is invalid");
  if (!Number.isFinite(Date.parse(input.observedAt)))
    throw new Error("Evidence witness observedAt is invalid");
  return {
    contract: input.contract,
    logHead: input.logHead,
    logSize: input.logSize,
    observedAt: input.observedAt,
    origin: input.origin,
  };
};

export const createEvidenceWitnessCheckpoint = (input: {
  identity: EvidenceSigningIdentity;
  log: EvidenceKeyTransparencyLog;
  observedAt?: string;
  origin: string;
}): SignedEvidenceWitnessCheckpoint => {
  const identity = parseEvidenceSigningIdentity(input.identity);
  const payload = checkpoint({
    contract: EVIDENCE_WITNESS_CHECKPOINT_CONTRACT,
    logHead: input.log.head,
    logSize: input.log.entries.length,
    observedAt: input.observedAt ?? new Date().toISOString(),
    origin: input.origin,
  });
  return {
    ...payload,
    signature: {
      algorithm: "ed25519",
      keyId: identity.keyId,
      value: sign(
        null,
        Buffer.from(canonical(payload)),
        createPrivateKey({
          format: "der",
          key: Buffer.from(identity.privateKey, "base64url"),
          type: "pkcs8",
        }),
      ).toString("base64url"),
    },
    witness: evidenceVerificationKeyFrom(identity),
  };
};

export const verifyEvidenceWitnessCheckpoint = (input: {
  checkpoint: SignedEvidenceWitnessCheckpoint;
  log?: EvidenceKeyTransparencyLog;
  trustedWitnesses?: readonly EvidenceVerificationKey[];
}) => {
  try {
    const payload = checkpoint(input.checkpoint);
    const witness = parseEvidenceVerificationKey(input.checkpoint.witness);
    const signatureValid =
      input.checkpoint.signature.algorithm === "ed25519" &&
      input.checkpoint.signature.keyId === witness.keyId &&
      verify(
        null,
        Buffer.from(canonical(payload)),
        createPublicKey({
          format: "der",
          key: Buffer.from(witness.publicKey, "base64url"),
          type: "spki",
        }),
        Buffer.from(input.checkpoint.signature.value, "base64url"),
      );
    const logMatches = input.log
      ? input.log.head === payload.logHead &&
        input.log.entries.length === payload.logSize
      : true;
    const trustedWitness = (input.trustedWitnesses ?? []).find(
      (key) =>
        key.keyId === witness.keyId &&
        key.fingerprint === witness.fingerprint &&
        key.publicKey === witness.publicKey,
    );
    return {
      logMatches,
      signatureValid,
      trust:
        signatureValid && logMatches && trustedWitness
          ? ("trusted" as const)
          : ("untrusted" as const),
      witnessKeyId: trustedWitness?.keyId ?? null,
    };
  } catch {
    return {
      logMatches: false,
      signatureValid: false,
      trust: "untrusted" as const,
      witnessKeyId: null,
    };
  }
};
