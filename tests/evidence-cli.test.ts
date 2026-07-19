import { describe, expect, test } from "bun:test";
import {
  createEvidenceSigningIdentity,
  evidenceVerificationKeyFrom,
  signVulnerabilityEvidenceBundle,
} from "../src/evidence-bundle";
import { runEvidenceCli } from "../src/evidence-cli";
import { createEvidenceKeyTransparencyLog } from "../src/evidence-transparency";

const bundlePayload = {
  admission: {
    evaluatedAt: "2026-07-19T20:00:00Z",
    exceptions: [],
    policyVersion: "deployment-admission/v1",
    status: "passed",
    violations: [],
  },
  generatedAt: "2026-07-19T20:01:00Z",
  intelligence: { digest: "sha256:intelligence" },
  project: { id: "project-1", name: "Client website" },
  releaseId: "release-1",
  sbom: { digest: "sha256:sbom" },
  vex: [],
};

describe("evidence verification CLI", () => {
  test("verifies an offline bundle against pinned registry evidence", async () => {
    const identity = createEvidenceSigningIdentity({ keyId: "trusted" });
    const log = createEvidenceKeyTransparencyLog({ identity });
    const files = new Map([
      [
        "bundle.json",
        JSON.stringify(
          signVulnerabilityEvidenceBundle({
            identity,
            payload: bundlePayload as never,
          }),
        ),
      ],
      ["registry.json", JSON.stringify({ transparency: log })],
    ]);
    const output: string[] = [];
    const errors: string[] = [];
    const exitCode = await runEvidenceCli(
      [
        "verify",
        "--bundle",
        "bundle.json",
        "--registry",
        "registry.json",
        "--trusted-fingerprint",
        evidenceVerificationKeyFrom(identity).fingerprint,
        "--trusted-head",
        log.head,
      ],
      {
        readText: async (path) => files.get(path) ?? "",
        stderr: (value) => errors.push(value),
        stdout: (value) => output.push(value),
      },
    );

    expect(exitCode).toBe(0);
    expect(errors).toEqual([]);
    expect(JSON.parse(output[0]!)).toMatchObject({
      fingerprintMatches: true,
      revoked: false,
      trusted: true,
    });
  });

  test("fails closed without an out-of-band trust anchor", async () => {
    const errors: string[] = [];
    const exitCode = await runEvidenceCli(
      ["verify", "--bundle", "bundle.json", "--registry", "registry.json"],
      {
        readText: async () => "{}",
        stderr: (value) => errors.push(value),
        stdout: () => undefined,
      },
    );

    expect(exitCode).toBe(2);
    expect(errors[0]).toContain("trusted fingerprint or transparency head");
  });
});
