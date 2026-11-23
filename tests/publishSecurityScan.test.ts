import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { scanProjectDirectory } from "../src/project/publishSecurityScan";

const STRIPE_LIVE = ["sk_", "live_", "q8Zr2LmX4vT9pK1sW7nB3cYd"].join("");

let root = "";
let outside = "";

const put = async (file: string, content: string) => {
  await mkdir(path.dirname(path.join(root, file)), { recursive: true });
  await writeFile(path.join(root, file), content);
};

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), "publish-security-"));
  outside = await mkdtemp(path.join(tmpdir(), "publish-security-outside-"));
});

afterEach(async () => {
  await rm(root, { force: true, recursive: true });
  await rm(outside, { force: true, recursive: true });
});

describe("scanProjectDirectory", () => {
  test("a clean project has nothing to show", async () => {
    await put("package.json", '{"name":"shop"}');
    await put(
      "src/backend/server.ts",
      "const key = process.env.STRIPE_SECRET_KEY;",
    );
    await put("src/frontend/pages/Home.tsx", "export const Home = () => null;");

    const scan = await scanProjectDirectory(root);

    expect(scan.findings).toEqual([]);
    expect(scan.complete).toBe(true);
    expect(scan.checkedFiles).toBe(3);
  });

  test("finds what matters and puts serious findings first", async () => {
    await put(
      "src/frontend/pages/Checkout.tsx",
      "process.env.STRIPE_SECRET_KEY",
    );
    await put("src/backend/payments.ts", `new Stripe('${STRIPE_LIVE}')`);
    await put("public/dump.sql", "select 1;");

    const scan = await scanProjectDirectory(root);

    expect(scan.findings.map((finding) => finding.file)).toEqual([
      "public/dump.sql",
      "src/backend/payments.ts",
      "src/frontend/pages/Checkout.tsx",
    ]);
    expect(scan.counts).toEqual({ info: 0, severe: 2, warning: 1 });
  });

  test("never opens .env files or generated folders", async () => {
    await put(".env", `STRIPE=${STRIPE_LIVE}`);
    await put(".env.local", `STRIPE=${STRIPE_LIVE}`);
    await put("node_modules/pkg/index.js", `'${STRIPE_LIVE}'`);
    await put("build/server.js", `'${STRIPE_LIVE}'`);
    await put(".git/config", `'${STRIPE_LIVE}'`);

    const scan = await scanProjectDirectory(root);

    expect(scan.findings).toEqual([]);
  });

  test("a .env in a repository checkout is reported, still unread", async () => {
    await put(".env.local", `STRIPE=${STRIPE_LIVE}`);
    await put(".env.example", "STRIPE=");

    const scan = await scanProjectDirectory(root, { committed: true });

    expect(scan.findings).toHaveLength(1);
    expect(scan.findings[0]?.rule).toBe("committed-env-file");
    expect(scan.findings[0]?.excerpt).toBeNull();
  });

  test("a Studio copy keeps its .env on the platform: not a finding", async () => {
    await put(".env", "PORT=3000");

    const scan = await scanProjectDirectory(root);

    expect(scan.findings).toEqual([]);
  });

  test("never follows a link out of the project", async () => {
    await writeFile(path.join(outside, "secret.ts"), `'${STRIPE_LIVE}'`);
    await mkdir(path.join(root, "src"), { recursive: true });
    await symlink(
      path.join(outside, "secret.ts"),
      path.join(root, "src/linked.ts"),
    );
    await symlink(outside, path.join(root, "linked-dir"));

    const scan = await scanProjectDirectory(root);

    expect(scan.findings).toEqual([]);
  });

  test("one key repeated through a file is one finding", async () => {
    await put(
      "logs/console.log",
      [1, 2, 3].map((line) => `${line} ${STRIPE_LIVE}`).join("\n"),
    );

    const scan = await scanProjectDirectory(root);

    expect(scan.findings).toHaveLength(1);
    expect(scan.findings[0]?.line).toBe(1);
    expect(scan.findings[0]?.summary).toContain("appears 3 times");
  });

  test("skips binary files", async () => {
    await put("src/data.bin", `\0\0${STRIPE_LIVE}`);
    await put("public/logo.png", STRIPE_LIVE);

    const scan = await scanProjectDirectory(root);

    expect(scan.findings).toEqual([]);
  });

  test("a scan out of time says it was partial, with what it found", async () => {
    await put("src/a.ts", "const a = 1;");

    const scan = await scanProjectDirectory(root, { timeBudgetMs: -1 });

    expect(scan.complete).toBe(false);
    expect(scan.findings.map((finding) => finding.rule)).toEqual([
      "scan-incomplete",
    ]);
  });

  test("uses the folders absolute.config names", async () => {
    await put(
      "absolute.config.ts",
      'export default defineConfig({ reactDirectory: "web", publicDirectory: "static" });',
    );
    await put("static/backup.sqlite", "x");
    await put("web/pages/Home.tsx", "process.env.DATABASE_URL");
    await put("public/old.sql", "x");

    const scan = await scanProjectDirectory(root);

    expect(scan.findings.map((finding) => finding.file).sort()).toEqual([
      "static/backup.sqlite",
      "web/pages/Home.tsx",
    ]);
  });
});
