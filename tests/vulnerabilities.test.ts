import { describe, expect, test } from "bun:test";
import {
  assertVulnerabilityPolicy,
  createVulnerabilityEvidence,
  evaluateVulnerabilityPolicy,
  parseGrypeReport,
  summarizeGrypeReport,
  VulnerabilityPolicyError,
} from "../src";
import {
  collectDebianHostInventory,
  parseDpkgQuery,
  parseOsRelease,
} from "../src/host";

describe("Grype normalization", () => {
  test("normalizes known, moderate, and unrecognized severities", () => {
    const report = parseGrypeReport({
      matches: [
        {
          artifact: { name: "openssl", type: "deb", version: "3.0.1" },
          vulnerability: {
            id: "CVE-2026-0001",
            namespace: "ubuntu:distro:ubuntu:24.04",
            severity: "Critical",
          },
        },
        { vulnerability: { severity: "Moderate" } },
        { vulnerability: { severity: "Important" } },
        null,
      ],
    });

    expect(report.counts).toEqual({
      critical: 1,
      high: 0,
      low: 0,
      medium: 1,
      negligible: 0,
      unknown: 2,
    });
    expect(report.findings[0]?.source).toBe("ubuntu:distro:ubuntu:24.04");
  });

  test("rejects input without a matches array", () => {
    expect(() => summarizeGrypeReport({})).toThrow(
      "Grype report must contain matches",
    );
  });
});

describe("policy", () => {
  const counts = {
    critical: 0,
    high: 1,
    low: 3,
    medium: 2,
    negligible: 0,
    unknown: 0,
  };

  test("returns structured violations", () => {
    expect(evaluateVulnerabilityPolicy(counts)).toEqual({
      status: "failed",
      violations: [{ actual: 1, maximum: 0, severity: "high" }],
    });
  });

  test("throws a typed gate error", () => {
    expect(() => assertVulnerabilityPolicy(counts)).toThrow(
      VulnerabilityPolicyError,
    );
  });

  test("creates evidence with its policy result", () => {
    const evidence = createVulnerabilityEvidence({
      asset: { id: "image@sha256:abc", kind: "container" },
      policy: { maximums: { critical: 0, high: 1 } },
      scan: {
        ...counts,
        databaseBuiltAt: null,
        scannedAt: "2026-07-18T12:00:00Z",
        scanner: "grype",
      },
    });
    expect(evidence.result.status).toBe("passed");
  });
});

describe("Debian host inventory", () => {
  test("preserves distro package versions and architecture", () => {
    expect(parseDpkgQuery("nginx:amd64\t1.24.0-2ubuntu7.5\n")).toEqual([
      {
        architecture: "amd64",
        name: "nginx",
        version: "1.24.0-2ubuntu7.5",
      },
    ]);
    expect(
      parseOsRelease('ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n'),
    ).toEqual({ ID: "ubuntu", PRETTY_NAME: "Ubuntu 24.04.3 LTS" });
  });

  test("collects through a deploy-compatible target", async () => {
    const outputs = new Map([
      [
        "cat /etc/os-release",
        { exitCode: 0, stderr: "", stdout: "ID=ubuntu\n" },
      ],
      ["uname -r", { exitCode: 0, stderr: "", stdout: "6.8.0-64-generic\n" }],
      [
        "dpkg-query -W -f='${binary:Package}\\t${Version}\\n'",
        {
          exitCode: 0,
          stderr: "",
          stdout: "openssh-server:amd64\t1:9.6p1-3ubuntu13.13\n",
        },
      ],
      [
        "test -f /var/run/reboot-required",
        { exitCode: 0, stderr: "", stdout: "" },
      ],
      [
        "pro security-status --format json",
        { exitCode: 0, stderr: "", stdout: '{"summary":{"attention":13}}' },
      ],
    ]);
    const inventory = await collectDebianHostInventory(
      {
        description: "ssh production",
        exec: async (command) => {
          const result = outputs.get(command);
          if (!result) throw new Error(`Unexpected command: ${command}`);
          return result;
        },
      },
      { collectedAt: "2026-07-18T12:00:00Z" },
    );

    expect(inventory.packages[0]?.version).toBe("1:9.6p1-3ubuntu13.13");
    expect(inventory.rebootRequired).toBe(true);
    expect(inventory.vendorSecurityStatus).toEqual({
      summary: { attention: 13 },
    });
  });
});
