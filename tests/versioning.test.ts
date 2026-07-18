import { describe, expect, test } from "bun:test";
import {
  compareDebianVersions,
  compareNugetVersions,
  comparePackageVersions,
  componentIdentityKey,
  createComponentIdentity,
  evaluateVersionConstraints,
  normalizePackageUrl,
  versionSchemeForEcosystem,
} from "../src";

describe("ecosystem mapping", () => {
  test("normalizes distribution and language ecosystem aliases", () => {
    expect(versionSchemeForEcosystem("Ubuntu")).toBe("debian");
    expect(versionSchemeForEcosystem("npm")).toBe("semver");
    expect(versionSchemeForEcosystem("cargo")).toBe("semver");
    expect(versionSchemeForEcosystem("golang")).toBe("go");
    expect(versionSchemeForEcosystem("PyPI")).toBe("pep440");
    expect(versionSchemeForEcosystem("Alpine")).toBe("apk");
    expect(versionSchemeForEcosystem("unregistered")).toBe("unknown");
  });

  test("recognizes OSV distribution release ecosystems", () => {
    expect(versionSchemeForEcosystem("Ubuntu:24.04:LTS")).toBe("debian");
    expect(versionSchemeForEcosystem("Alpine:v3.20")).toBe("apk");
  });
});

describe("Debian version ordering", () => {
  const cases: Array<[string, string, -1 | 0 | 1]> = [
    ["1.24.0-2ubuntu7.4", "1.24.0-2ubuntu7.5", -1],
    ["1.24.0-2ubuntu7.5", "1.24.0-2ubuntu7.5", 0],
    ["1:9.6p1-3ubuntu13.13", "9.9p1-1", 1],
    ["1.0~beta1", "1.0", -1],
    ["1.0~~snapshot", "1.0~beta1", -1],
    ["1.0", "1.0-1", -1],
    ["1.0-1", "1.0-01", 0],
    ["2.6.0pre3-1", "2.6.0-1", 1],
    ["0:1.0-1", "1.0-1", 0],
  ];

  test.each(cases)("compares %s against %s", (left, right, expected) => {
    expect(compareDebianVersions(left, right)).toBe(expected);
  });

  test("rejects invalid epochs and empty versions", () => {
    expect(compareDebianVersions("epoch:1.0", "1.0")).toBeNull();
    expect(compareDebianVersions("", "1.0")).toBeNull();
  });
});

describe("language ecosystem ordering", () => {
  test("uses SemVer precedence for npm and Cargo", () => {
    expect(
      comparePackageVersions({
        ecosystem: "npm",
        left: "1.10.0",
        right: "1.9.0",
      }),
    ).toMatchObject({ order: 1, scheme: "semver", status: "comparable" });
    expect(
      comparePackageVersions({
        ecosystem: "cargo",
        left: "1.0.0-rc.1",
        right: "1.0.0",
      }),
    ).toMatchObject({ order: -1, status: "comparable" });
    expect(
      comparePackageVersions({
        ecosystem: "npm",
        left: "1.0.0+build.1",
        right: "1.0.0+build.2",
      }),
    ).toMatchObject({ order: 0, status: "comparable" });
  });

  test("orders canonical Go module and pseudo versions", () => {
    expect(
      comparePackageVersions({
        ecosystem: "go",
        left: "v1.2.3",
        right: "v1.2.4",
      }),
    ).toMatchObject({ order: -1, scheme: "go", status: "comparable" });
    expect(
      comparePackageVersions({
        ecosystem: "go",
        left: "v0.0.0-20260718120000-aaaaaaaaaaaa",
        right: "v0.0.0-20260719120000-bbbbbbbbbbbb",
      }),
    ).toMatchObject({ order: -1, status: "comparable" });
    expect(
      comparePackageVersions({
        ecosystem: "go",
        left: "1.2.3",
        right: "v1.2.4",
      }),
    ).toMatchObject({ order: null, status: "unknown" });
  });

  test("uses PEP 440 ordering for Python", () => {
    expect(
      comparePackageVersions({
        ecosystem: "pypi",
        left: "1.0.dev1",
        right: "1.0a1",
      }),
    ).toMatchObject({ order: -1, scheme: "pep440" });
    expect(
      comparePackageVersions({
        ecosystem: "python",
        left: "1.0.post1",
        right: "1.0",
      }),
    ).toMatchObject({ order: 1, status: "comparable" });
  });
});

describe("NuGet version ordering", () => {
  const cases: Array<[string, string, -1 | 0 | 1]> = [
    ["1", "1.0.0.0", 0],
    ["1.0.0-Alpha", "1.0.0-alpha", 0],
    ["1.0.0-rc.10", "1.0.0-rc.2", 1],
    ["1.0.0-alpha", "1.0.0-alpha.1", -1],
    ["1.0.0", "1.0.0-zzz", 1],
    ["1.0.0+build.1", "1.0.0+build.2", 0],
    ["1.0.0.1", "1.0.0", 1],
  ];

  test.each(cases)("compares %s against %s", (left, right, expected) => {
    expect(compareNugetVersions(left, right)).toBe(expected);
  });
});

describe("safe comparison fallbacks", () => {
  test("returns unknown for schemes without a verified comparator", () => {
    expect(
      comparePackageVersions({
        ecosystem: "rpm",
        left: "1.0-1",
        right: "1.0-2",
      }),
    ).toEqual({
      comparator: null,
      left: "1.0-1",
      order: null,
      reason: "rpm comparison requires a verified adapter",
      right: "1.0-2",
      scheme: "rpm",
      status: "unknown",
    });
  });

  test("uses an injected verified adapter", () => {
    expect(
      comparePackageVersions({
        adapters: { rpm: (left, right) => (left === right ? 0 : -1) },
        ecosystem: "rpm",
        left: "1.0-1",
        right: "1.0-2",
      }),
    ).toMatchObject({ comparator: "adapter", order: -1, status: "comparable" });
  });
});

describe("advisory constraints", () => {
  test("matches an affected Ubuntu range while preserving distro revisions", () => {
    expect(
      evaluateVersionConstraints({
        constraints: [
          { operator: "gte", version: "1.24.0" },
          { operator: "lt", version: "1.24.0-2ubuntu7.5" },
        ],
        ecosystem: "ubuntu",
        installedVersion: "1.24.0-2ubuntu7.4",
      }),
    ).toMatchObject({ status: "matched" });
    expect(
      evaluateVersionConstraints({
        constraints: [{ operator: "lt", version: "1.24.0-2ubuntu7.5" }],
        ecosystem: "ubuntu",
        installedVersion: "1.24.0-2ubuntu7.5",
      }),
    ).toMatchObject({ status: "not_matched" });
  });

  test("propagates unknown instead of treating invalid input as affected", () => {
    expect(
      evaluateVersionConstraints({
        constraints: [{ operator: "lt", version: "2.0.0" }],
        ecosystem: "npm",
        installedVersion: "not-semver",
      }),
    ).toMatchObject({ status: "unknown" });
  });
});

describe("Package URL identity", () => {
  test("creates canonical distro component identities", () => {
    const identity = createComponentIdentity({
      ecosystem: "ubuntu",
      name: "nginx",
      namespace: "ubuntu",
      qualifiers: { arch: "amd64" },
      version: "1.24.0-2ubuntu7.5",
    });
    expect(identity).toEqual({
      ecosystem: "deb",
      name: "nginx",
      namespace: "ubuntu",
      purl: "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5?arch=amd64",
      version: "1.24.0-2ubuntu7.5",
    });
    expect(componentIdentityKey(identity)).toBe(
      "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.5?arch=amd64",
    );
  });

  test("normalizes and validates supplied Package URLs", () => {
    expect(
      normalizePackageUrl("pkg:npm/%40absolutejs/vulnerabilities@0.3.0"),
    ).toBe("pkg:npm/%40absolutejs/vulnerabilities@0.3.0");
    expect(() =>
      createComponentIdentity({
        ecosystem: "npm",
        name: "different-name",
        purl: "pkg:npm/actual-name@1.0.0",
        version: "1.0.0",
      }),
    ).toThrow("Package URL name does not match");
  });
});
