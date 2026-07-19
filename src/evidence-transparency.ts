import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import {
  evidenceVerificationKeyFrom,
  parseEvidenceSigningIdentity,
  parseEvidenceVerificationKey,
  verifyEvidenceSigningKeyTransition,
  verifyVulnerabilityEvidenceBundle,
  type EvidenceSigningIdentity,
  type EvidenceSigningKeyTransition,
  type EvidenceVerificationKey,
  type SignedVulnerabilityEvidenceBundle,
  type VulnerabilityEvidenceBundleVerification,
} from "./evidence-bundle";

export const EVIDENCE_KEY_TRANSPARENCY_CONTRACT =
  "absolutejs.vulnerability-evidence-key-transparency/v1" as const;

export type EvidenceKeyRevocation = {
  key: EvidenceVerificationKey;
  reason: string;
  revokedAt: string;
};

export type EvidenceKeyTransparencyEvent =
  | { key: EvidenceVerificationKey; kind: "key_created" }
  | { kind: "key_rotated"; transition: EvidenceSigningKeyTransition }
  | ({ kind: "key_revoked" } & EvidenceKeyRevocation);

export type EvidenceKeyTransparencyEntry = {
  contract: typeof EVIDENCE_KEY_TRANSPARENCY_CONTRACT;
  digest: `sha256:${string}`;
  event: EvidenceKeyTransparencyEvent;
  previousDigest: `sha256:${string}` | null;
  sequence: number;
  signature: {
    algorithm: "ed25519";
    keyId: string;
    signedAt: string;
    value: string;
  };
  signedBy: EvidenceVerificationKey;
};

export type EvidenceKeyTransparencyLog = {
  contract: typeof EVIDENCE_KEY_TRANSPARENCY_CONTRACT;
  entries: EvidenceKeyTransparencyEntry[];
  head: `sha256:${string}`;
  version: 1;
};

export type EvidenceKeyTransparencyVerification = {
  activeKeyId: string | null;
  chainValid: boolean;
  head: `sha256:${string}` | null;
  headMatches: boolean;
  keys: EvidenceVerificationKey[];
  revocations: EvidenceKeyRevocation[];
  signaturesValid: boolean;
  trust: "trusted" | "untrusted";
  trustedKeyId: string | null;
};

export type VulnerabilityEvidenceTransparencyVerification =
  VulnerabilityEvidenceBundleVerification & {
    keyInTransparencyLog: boolean;
    revoked: boolean;
    transparency: EvidenceKeyTransparencyVerification;
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

const timestamp = (value: string, label: string) => {
  if (!value.trim() || !Number.isFinite(Date.parse(value)))
    throw new Error(`${label} must be a timestamp`);

  return value;
};

const requiredText = (value: string, label: string) => {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);

  return normalized;
};

const keysMatch = (
  left: EvidenceVerificationKey,
  right: EvidenceVerificationKey,
) =>
  left.keyId === right.keyId &&
  left.fingerprint === right.fingerprint &&
  left.publicKey === right.publicKey;

const privateKeyFrom = (identity: EvidenceSigningIdentity) =>
  createPrivateKey({
    format: "der",
    key: Buffer.from(identity.privateKey, "base64url"),
    type: "pkcs8",
  });

const publicKeyFrom = (key: EvidenceVerificationKey) =>
  createPublicKey({
    format: "der",
    key: Buffer.from(key.publicKey, "base64url"),
    type: "spki",
  });

const entryUnsigned = (input: {
  event: EvidenceKeyTransparencyEvent;
  previousDigest: `sha256:${string}` | null;
  sequence: number;
  signedAt: string;
  signedBy: EvidenceVerificationKey;
}) => ({
  contract: EVIDENCE_KEY_TRANSPARENCY_CONTRACT,
  event: input.event,
  previousDigest: input.previousDigest,
  sequence: input.sequence,
  signature: {
    algorithm: "ed25519" as const,
    keyId: input.signedBy.keyId,
    signedAt: input.signedAt,
  },
  signedBy: input.signedBy,
});

const digestEntry = (
  entry: Omit<EvidenceKeyTransparencyEntry, "digest">,
): `sha256:${string}` =>
  `sha256:${createHash("sha256").update(canonical(entry)).digest("hex")}`;

const signEntry = (input: {
  event: EvidenceKeyTransparencyEvent;
  identity: EvidenceSigningIdentity;
  previousDigest: `sha256:${string}` | null;
  sequence: number;
  signedAt: string;
}): EvidenceKeyTransparencyEntry => {
  const identity = parseEvidenceSigningIdentity(input.identity);
  const signedBy = evidenceVerificationKeyFrom(identity);
  const unsigned = entryUnsigned({ ...input, signedBy });
  const entry = {
    ...unsigned,
    signature: {
      ...unsigned.signature,
      value: sign(
        null,
        Buffer.from(canonical(unsigned)),
        privateKeyFrom(identity),
      ).toString("base64url"),
    },
  };

  return { ...entry, digest: digestEntry(entry) };
};

const verifyEntrySignature = (entry: EvidenceKeyTransparencyEntry) => {
  try {
    const signedBy = parseEvidenceVerificationKey(entry.signedBy);
    const unsigned = entryUnsigned({
      event: structuredClone(entry.event),
      previousDigest: entry.previousDigest,
      sequence: entry.sequence,
      signedAt: timestamp(
        entry.signature.signedAt,
        "Evidence transparency signedAt",
      ),
      signedBy,
    });
    return (
      entry.contract === EVIDENCE_KEY_TRANSPARENCY_CONTRACT &&
      entry.signature.algorithm === "ed25519" &&
      entry.signature.keyId === signedBy.keyId &&
      verify(
        null,
        Buffer.from(canonical(unsigned)),
        publicKeyFrom(signedBy),
        Buffer.from(entry.signature.value, "base64url"),
      ) &&
      entry.digest ===
        digestEntry({
          ...unsigned,
          signature: { ...unsigned.signature, value: entry.signature.value },
        })
    );
  } catch {
    return false;
  }
};

export const verifyEvidenceKeyTransparencyLog = (input: {
  log: EvidenceKeyTransparencyLog;
  pinnedHead?: string;
  trustedKeys?: readonly EvidenceVerificationKey[];
}): EvidenceKeyTransparencyVerification => {
  const keys: EvidenceVerificationKey[] = [];
  const revocations: EvidenceKeyRevocation[] = [];
  let activeKey: EvidenceVerificationKey | null = null;
  let chainValid =
    input.log.contract === EVIDENCE_KEY_TRANSPARENCY_CONTRACT &&
    input.log.version === 1 &&
    input.log.entries.length > 0;
  let signaturesValid = true;
  let previousDigest: `sha256:${string}` | null = null;
  for (const [index, entry] of input.log.entries.entries()) {
    const signatureValid = verifyEntrySignature(entry);
    signaturesValid &&= signatureValid;
    chainValid &&=
      entry.sequence === index && entry.previousDigest === previousDigest;
    if (index === 0) {
      chainValid &&=
        entry.event.kind === "key_created" &&
        keysMatch(entry.event.key, entry.signedBy);
      if (entry.event.kind === "key_created") {
        const key = parseEvidenceVerificationKey(entry.event.key);
        keys.push(key);
        activeKey = key;
      }
    } else if (entry.event.kind === "key_rotated") {
      const transition = entry.event.transition;
      chainValid &&=
        activeKey !== null &&
        keysMatch(entry.signedBy, activeKey) &&
        keysMatch(transition.previousKey, activeKey) &&
        verifyEvidenceSigningKeyTransition(transition);
      const nextKey = parseEvidenceVerificationKey(transition.nextKey);
      if (keys.some((key) => key.keyId === nextKey.keyId)) chainValid = false;
      keys.push(nextKey);
      activeKey = nextKey;
    } else if (entry.event.kind === "key_revoked") {
      const key = parseEvidenceVerificationKey(entry.event.key);
      chainValid &&=
        activeKey !== null &&
        keysMatch(entry.signedBy, activeKey) &&
        !keysMatch(key, activeKey) &&
        keys.some((known) => keysMatch(known, key)) &&
        !revocations.some((revocation) => keysMatch(revocation.key, key));
      revocations.push({
        key,
        reason: requiredText(entry.event.reason, "Evidence revocation reason"),
        revokedAt: timestamp(
          entry.event.revokedAt,
          "Evidence revocation revokedAt",
        ),
      });
    } else {
      chainValid = false;
    }
    previousDigest = entry.digest;
  }
  const head = previousDigest;
  chainValid &&= head !== null && input.log.head === head;
  const headMatches = input.pinnedHead
    ? input.pinnedHead === input.log.head
    : true;
  const genesisKey = keys[0] ?? null;
  const trustedKey = genesisKey
    ? ((input.trustedKeys ?? [])
        .map(parseEvidenceVerificationKey)
        .find((key) => keysMatch(key, genesisKey)) ?? null)
    : null;
  const trusted =
    chainValid && signaturesValid && headMatches && trustedKey !== null;

  return {
    activeKeyId: activeKey?.keyId ?? null,
    chainValid,
    head,
    headMatches,
    keys,
    revocations,
    signaturesValid,
    trust: trusted ? "trusted" : "untrusted",
    trustedKeyId: trustedKey?.keyId ?? null,
  };
};

const verifiedLogForAppend = (
  log: EvidenceKeyTransparencyLog,
  identity: EvidenceSigningIdentity,
) => {
  const parsedIdentity = parseEvidenceSigningIdentity(identity);
  const genesis = log.entries[0];
  if (!genesis || genesis.event.kind !== "key_created")
    throw new Error("Evidence transparency genesis is missing");
  const verification = verifyEvidenceKeyTransparencyLog({
    log,
    trustedKeys: [genesis.event.key],
  });
  if (verification.trust !== "trusted")
    throw new Error("Evidence transparency log is invalid");
  if (verification.activeKeyId !== parsedIdentity.keyId)
    throw new Error("Evidence transparency signer is not the active key");

  return parsedIdentity;
};

export const createEvidenceKeyTransparencyLog = (input: {
  identity: EvidenceSigningIdentity;
  signedAt?: string;
}): EvidenceKeyTransparencyLog => {
  const identity = parseEvidenceSigningIdentity(input.identity);
  const entry = signEntry({
    event: { key: evidenceVerificationKeyFrom(identity), kind: "key_created" },
    identity,
    previousDigest: null,
    sequence: 0,
    signedAt: timestamp(
      input.signedAt ?? identity.createdAt,
      "Evidence transparency signedAt",
    ),
  });

  return {
    contract: EVIDENCE_KEY_TRANSPARENCY_CONTRACT,
    entries: [entry],
    head: entry.digest,
    version: 1,
  };
};

export const appendEvidenceKeyRotation = (input: {
  identity: EvidenceSigningIdentity;
  log: EvidenceKeyTransparencyLog;
  transition: EvidenceSigningKeyTransition;
}): EvidenceKeyTransparencyLog => {
  const identity = verifiedLogForAppend(input.log, input.identity);
  if (
    !keysMatch(
      evidenceVerificationKeyFrom(identity),
      input.transition.previousKey,
    )
  )
    throw new Error("Evidence rotation does not start at the active key");
  if (!verifyEvidenceSigningKeyTransition(input.transition))
    throw new Error("Evidence rotation transition is invalid");
  const entry = signEntry({
    event: { kind: "key_rotated", transition: input.transition },
    identity,
    previousDigest: input.log.head,
    sequence: input.log.entries.length,
    signedAt: input.transition.rotatedAt,
  });

  return {
    ...structuredClone(input.log),
    entries: [...structuredClone(input.log.entries), entry],
    head: entry.digest,
  };
};

export const appendEvidenceKeyRevocation = (input: {
  identity: EvidenceSigningIdentity;
  key: EvidenceVerificationKey;
  log: EvidenceKeyTransparencyLog;
  reason: string;
  revokedAt?: string;
}): EvidenceKeyTransparencyLog => {
  const identity = verifiedLogForAppend(input.log, input.identity);
  const key = parseEvidenceVerificationKey(input.key);
  const verification = verifyEvidenceKeyTransparencyLog({
    log: input.log,
    trustedKeys: [input.log.entries[0]!.signedBy],
  });
  if (!verification.keys.some((known) => keysMatch(known, key)))
    throw new Error("Evidence revocation key is not in the transparency log");
  if (key.keyId === verification.activeKeyId)
    throw new Error("Rotate the active evidence key before revoking it");
  if (verification.revocations.some((entry) => keysMatch(entry.key, key)))
    throw new Error("Evidence key is already revoked");
  const revokedAt = timestamp(
    input.revokedAt ?? new Date().toISOString(),
    "Evidence revocation revokedAt",
  );
  const entry = signEntry({
    event: {
      key,
      kind: "key_revoked",
      reason: requiredText(input.reason, "Evidence revocation reason"),
      revokedAt,
    },
    identity,
    previousDigest: input.log.head,
    sequence: input.log.entries.length,
    signedAt: revokedAt,
  });

  return {
    ...structuredClone(input.log),
    entries: [...structuredClone(input.log.entries), entry],
    head: entry.digest,
  };
};

export const verifyVulnerabilityEvidenceWithTransparency = <TKev>(input: {
  bundle: SignedVulnerabilityEvidenceBundle<TKev>;
  log: EvidenceKeyTransparencyLog;
  pinnedHead?: string;
  trustedKeys?: readonly EvidenceVerificationKey[];
}): VulnerabilityEvidenceTransparencyVerification => {
  const transparency = verifyEvidenceKeyTransparencyLog(input);
  const bundle = verifyVulnerabilityEvidenceBundle({
    bundle: input.bundle,
    trustedKeys: input.trustedKeys,
  });
  const keyInTransparencyLog = transparency.keys.some((key) =>
    keysMatch(key, input.bundle.key),
  );
  const revoked = transparency.revocations.some((entry) =>
    keysMatch(entry.key, input.bundle.key),
  );
  const trusted =
    bundle.trust === "trusted" &&
    transparency.trust === "trusted" &&
    keyInTransparencyLog &&
    !revoked;

  return {
    ...bundle,
    keyInTransparencyLog,
    revoked,
    transparency,
    trust: trusted ? "trusted" : "untrusted",
  };
};
