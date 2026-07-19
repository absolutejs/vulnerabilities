import { describe, expect, test } from "bun:test";
import {
  createEvidenceSigningIdentity,
  evidenceVerificationKeyFrom,
} from "../src/evidence-bundle";
import { createEvidenceKeyTransparencyLog } from "../src/evidence-transparency";
import {
  createEvidenceWitnessCheckpoint,
  createEvidenceWitnessCheckpointForHead,
  verifyEvidenceWitnessCheckpoint,
  verifyEvidenceWitnessQuorum,
} from "../src/evidence-witness";

describe("evidence transparency witnesses", () => {
  test("binds an independently signed receipt to the exact log checkpoint", () => {
    const evidence = createEvidenceSigningIdentity({ keyId: "evidence" });
    const witness = createEvidenceSigningIdentity({ keyId: "witness" });
    const log = createEvidenceKeyTransparencyLog({ identity: evidence });
    const receipt = createEvidenceWitnessCheckpoint({
      identity: witness,
      log,
      observedAt: "2026-07-19T23:00:00Z",
      origin: "https://witness.example",
    });

    expect(
      verifyEvidenceWitnessCheckpoint({
        checkpoint: receipt,
        log,
        trustedWitnesses: [evidenceVerificationKeyFrom(witness)],
      }),
    ).toMatchObject({
      logMatches: true,
      signatureValid: true,
      trust: "trusted",
      witnessKeyId: "witness",
    });
    expect(
      verifyEvidenceWitnessCheckpoint({
        checkpoint: { ...receipt, logSize: receipt.logSize + 1 },
        log,
        trustedWitnesses: [evidenceVerificationKeyFrom(witness)],
      }).signatureValid,
    ).toBe(false);
  });

  test("requires distinct trusted witnesses to satisfy a quorum", () => {
    const evidence = createEvidenceSigningIdentity({ keyId: "evidence" });
    const first = createEvidenceSigningIdentity({ keyId: "witness-1" });
    const second = createEvidenceSigningIdentity({ keyId: "witness-2" });
    const log = createEvidenceKeyTransparencyLog({ identity: evidence });
    const firstReceipt = createEvidenceWitnessCheckpoint({
      identity: first,
      log,
      origin: "https://witness-1.example",
    });
    const secondReceipt = createEvidenceWitnessCheckpointForHead({
      identity: second,
      logHead: log.head,
      logSize: log.entries.length,
      origin: "https://witness-2.example",
    });
    const verification = verifyEvidenceWitnessQuorum({
      checkpoints: [firstReceipt, firstReceipt, secondReceipt],
      log,
      minimum: 2,
      trustedWitnesses: [
        evidenceVerificationKeyFrom(first),
        evidenceVerificationKeyFrom(second),
      ],
    });

    expect(verification.quorumMet).toBe(true);
    expect(verification.trustedCheckpoints).toHaveLength(2);
    expect(verification.invalidCheckpoints).toHaveLength(1);
  });

  test("fails closed when the distinct witness minimum is not met", () => {
    const evidence = createEvidenceSigningIdentity({ keyId: "evidence" });
    const witness = createEvidenceSigningIdentity({ keyId: "witness" });
    const log = createEvidenceKeyTransparencyLog({ identity: evidence });
    const receipt = createEvidenceWitnessCheckpoint({
      identity: witness,
      log,
      origin: "https://witness.example",
    });

    expect(
      verifyEvidenceWitnessQuorum({
        checkpoints: [receipt],
        log,
        minimum: 2,
        trustedWitnesses: [evidenceVerificationKeyFrom(witness)],
      }).quorumMet,
    ).toBe(false);
  });
});
