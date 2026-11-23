import { afterEach, expect, test } from "bun:test";
import { mkdtemp, writeFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { advisoryFindings, scanExitCode, scanProject } from "../src/scan";
import { lockedPackages } from "../src/project/inventory";
const roots: string[] = [];
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "scan-fixture-"));
  roots.push(root);
  return root;
}
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
test("Bun inventory follows resolved identities across aliases, peer variants and local workspaces", async () => {
  const root = await fixture();
  await writeFile(
    join(root, "bun.lock"),
    JSON.stringify({
      lockfileVersion: 1,
      workspaces: { "": {}, "packages/widget": {} },
      packages: {
        aliased: ["real@1.0.0"],
        "nested/real": ["real@1.0.0"],
        scoped: ["@scope/dep@2.0.0"],
        local: ["widget@workspace:packages/widget"],
        other: ["other@git:unresolved"],
      },
    }),
  );
  expect(await lockedPackages(root)).toEqual({
    file: "bun.lock",
    purls: ["pkg:npm/%40scope/dep@2.0.0", "pkg:npm/real@1.0.0"],
    unresolved: 1,
  });
});
test("npm inventory includes nested versions and reports malformed or missing coverage", async () => {
  const root = await fixture(),
    lock = join(root, "package-lock.json");
  await writeFile(
    lock,
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/a": { version: "1.0.0" },
        "node_modules/b/node_modules/a": { version: "2.0.0" },
      },
    }),
  );
  expect((await lockedPackages(root)).purls).toHaveLength(2);
  await writeFile(lock, "{}");
  const incomplete = await scanProject({ root });
  expect(scanExitCode(incomplete)).toBe(2);
});
test("never reads a linked lockfile or calls an unavailable scanner clean", async () => {
  const root = await fixture();
  await symlink(join(root, "elsewhere"), join(root, "bun.lock"));
  expect((await scanProject({ root })).complete).toBe(false);
  await rm(join(root, "bun.lock"));
  await writeFile(
    join(root, "bun.lock"),
    '{"lockfileVersion":1,"workspaces":{"":{}},"packages":{"a":["a@1.0.0"]}}',
  );
  expect(
    scanExitCode(await scanProject({ root, grype: join(root, "missing") })),
  ).toBe(2);
});
test("blocking needs both high or critical severity and an available fix", () => {
  const match = (id: string, severity: string, versions: string[]) => ({
    artifact: { name: "dependency", version: "1.0.0" },
    vulnerability: {
      id,
      severity,
      fix: { state: versions.length ? "fixed" : "not-fixed", versions },
    },
  });
  const report = {
    matches: [
      match("one", "High", ["1.1.0"]),
      match("two", "Critical", []),
      match("three", "Medium", ["1.5.0"]),
      match("one", "High", ["1.1.0"]),
    ],
  };
  const findings = advisoryFindings(report, "bun.lock", "dependencies");
  expect(findings).toHaveLength(3);
  expect(
    findings.filter((i) => i.severity === "severe").map((i) => i.advisory?.id),
  ).toEqual(["one"]);
  expect(() => advisoryFindings({ matches: [{}] }, "image", "image")).toThrow();
});

test("declared dependencies require locked versions, including when a lockfile is empty", async () => {
  const root = await fixture();
  expect((await scanProject({ root })).complete).toBe(true);
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({ dependencies: { example: "^1" } }),
  );
  expect((await scanProject({ root })).complete).toBe(false);
  await writeFile(
    join(root, "bun.lock"),
    JSON.stringify({
      lockfileVersion: 1,
      workspaces: { "": {} },
      packages: {},
    }),
  );
  expect((await scanProject({ root })).complete).toBe(false);
});
