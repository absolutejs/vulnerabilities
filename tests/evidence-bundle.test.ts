import { describe, expect, test } from "bun:test";
import {
  createEvidenceSigningIdentity,
  createEvidenceSigningKeyTransition,
  evidenceVerificationKeyFrom,
  signVulnerabilityEvidenceBundle,
  verifyVulnerabilityEvidenceBundle,
} from "../src/evidence-bundle";

const payload = {
  admission: {
    evaluatedAt: "2026-07-19T20:00:00Z",
    exceptions: [],
    policyVersion: "deployment-admission/v1" as const,
    status: "passed" as const,
    violations: [],
  },
  generatedAt: "2026-07-19T20:01:00Z",
  intelligence: { digest: "sha256:intelligence" },
  project: { id: "project-1", name: "Client website" },
  releaseId: "release-1",
  sbom: { digest: "sha256:sbom" },
  vex: [],
};

describe("public vulnerability evidence bundles", () => {
  test("verifies payload integrity against a pinned public key", () => {
    const identity = createEvidenceSigningIdentity({
      createdAt: "2026-07-19T20:00:00Z",
      keyId: "evidence-key-1",
    });
    const bundle = signVulnerabilityEvidenceBundle({
      identity,
      payload: payload as never,
      signedAt: "2026-07-19T20:02:00Z",
    });

    expect(
      verifyVulnerabilityEvidenceBundle({
        bundle,
        trustedKeys: [evidenceVerificationKeyFrom(identity)],
      }),
    ).toEqual({
      chainValid: true,
      signatureValid: true,
      trust: "trusted",
      trustedKeyId: "evidence-key-1",
    });
    expect(
      verifyVulnerabilityEvidenceBundle({
        bundle: {
          ...bundle,
          payload: { ...bundle.payload, releaseId: "forged" },
        },
        trustedKeys: [evidenceVerificationKeyFrom(identity)],
      }).signatureValid,
    ).toBe(false);
  });

  test("preserves trust across a cross-signed key rotation", () => {
    const previous = createEvidenceSigningIdentity({ keyId: "previous" });
    const next = createEvidenceSigningIdentity({ keyId: "next" });
    const transition = createEvidenceSigningKeyTransition({
      nextKey: evidenceVerificationKeyFrom(next),
      previousIdentity: previous,
      rotatedAt: "2026-07-19T21:00:00Z",
    });
    const bundle = signVulnerabilityEvidenceBundle({
      identity: next,
      payload: payload as never,
      transitions: [transition],
    });

    expect(
      verifyVulnerabilityEvidenceBundle({
        bundle,
        trustedKeys: [evidenceVerificationKeyFrom(previous)],
      }),
    ).toMatchObject({
      chainValid: true,
      signatureValid: true,
      trust: "trusted",
      trustedKeyId: "previous",
    });
  });
});
