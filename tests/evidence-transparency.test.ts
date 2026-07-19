import { describe, expect, test } from "bun:test";
import {
  createEvidenceSigningIdentity,
  createEvidenceSigningKeyTransition,
  evidenceVerificationKeyFrom,
  signVulnerabilityEvidenceBundle,
} from "../src/evidence-bundle";
import {
  appendEvidenceKeyRevocation,
  appendEvidenceKeyRotation,
  createEvidenceKeyTransparencyLog,
  verifyEvidenceKeyTransparencyLog,
  verifyVulnerabilityEvidenceWithTransparency,
} from "../src/evidence-transparency";

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

describe("evidence key transparency", () => {
  test("detects removed, reordered, and rewritten key history", () => {
    const first = createEvidenceSigningIdentity({ keyId: "first" });
    const second = createEvidenceSigningIdentity({ keyId: "second" });
    const transition = createEvidenceSigningKeyTransition({
      nextKey: evidenceVerificationKeyFrom(second),
      previousIdentity: first,
      rotatedAt: "2026-07-19T21:00:00Z",
    });
    const genesis = createEvidenceKeyTransparencyLog({
      identity: first,
      signedAt: "2026-07-19T20:00:00Z",
    });
    const log = appendEvidenceKeyRotation({
      identity: first,
      log: genesis,
      transition,
    });
    const trustedKeys = [evidenceVerificationKeyFrom(first)];

    expect(
      verifyEvidenceKeyTransparencyLog({
        log,
        pinnedHead: log.head,
        trustedKeys,
      }),
    ).toMatchObject({
      activeKeyId: "second",
      chainValid: true,
      headMatches: true,
      signaturesValid: true,
      trust: "trusted",
    });
    expect(
      verifyEvidenceKeyTransparencyLog({
        log: genesis,
        pinnedHead: log.head,
        trustedKeys,
      }).headMatches,
    ).toBe(false);
    expect(
      verifyEvidenceKeyTransparencyLog({
        log: {
          ...log,
          entries: [
            log.entries[0]!,
            {
              ...log.entries[1]!,
              event: {
                ...log.entries[1]!.event,
                kind: "key_rotated",
                transition: {
                  ...transition,
                  rotatedAt: "2026-07-20T00:00:00Z",
                },
              },
            },
          ],
        },
        trustedKeys,
      }).signaturesValid,
    ).toBe(false);
  });

  test("marks every bundle signed by an explicitly revoked key untrusted", () => {
    const first = createEvidenceSigningIdentity({ keyId: "first" });
    const second = createEvidenceSigningIdentity({ keyId: "second" });
    const transition = createEvidenceSigningKeyTransition({
      nextKey: evidenceVerificationKeyFrom(second),
      previousIdentity: first,
      rotatedAt: "2026-07-19T21:00:00Z",
    });
    const rotated = appendEvidenceKeyRotation({
      identity: first,
      log: createEvidenceKeyTransparencyLog({ identity: first }),
      transition,
    });
    const log = appendEvidenceKeyRevocation({
      identity: second,
      key: evidenceVerificationKeyFrom(first),
      log: rotated,
      reason: "Key material may have been exposed",
      revokedAt: "2026-07-19T22:00:00Z",
    });
    const bundle = signVulnerabilityEvidenceBundle({
      identity: first,
      payload: payload as never,
    });

    expect(
      verifyVulnerabilityEvidenceWithTransparency({
        bundle,
        log,
        trustedKeys: [evidenceVerificationKeyFrom(first)],
      }),
    ).toMatchObject({
      keyInTransparencyLog: true,
      revoked: true,
      signatureValid: true,
      trust: "untrusted",
    });
  });
});
