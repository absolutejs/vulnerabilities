import { describe, expect, test } from "bun:test";
import {
  createEvidenceSigningIdentity,
  evidenceVerificationKeyFrom,
} from "../src/evidence-bundle";
import { createEvidenceKeyTransparencyLog } from "../src/evidence-transparency";
import {
  createEvidenceWitnessCheckpoint,
  verifyEvidenceWitnessCheckpoint,
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
});
