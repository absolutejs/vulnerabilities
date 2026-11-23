import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { normalizeVulnerabilitySeverity } from "./index";
import { lockedPackages } from "./project/inventory";
import { fingerprintOf } from "./project/publishSecurityChecks";
import {
  scanProjectDirectory,
  countFindings,
} from "./project/publishSecurityScan";
import type { PublishSecurityFinding } from "./project/types";

export * from "./project/types";
export * from "./project/publishSecurityChecks";
export * from "./project/publishSecurityScan";

const execute = promisify(execFile);
export type ScanCheck = {
  name: "source" | "dependencies" | "image";
  complete: boolean;
  checked: number;
  detail: string;
  databaseBuilt?: string;
  scannerVersion?: string;
};
export type ProjectSecurityReport = {
  schemaVersion: 1;
  complete: boolean;
  checks: ScanCheck[];
  findings: PublishSecurityFinding[];
  counts: ReturnType<typeof countFindings>;
  checkedFiles: number;
};
export type ScanOptions = {
  root: string;
  committed?: boolean;
  trackedFiles?: ReadonlySet<string>;
  sourceTimeBudgetMs?: number;
  only?: "source" | "dependencies" | "image";
  image?: string;
  offline?: boolean;
  grype?: string;
};
const object = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== "object" || Array.isArray(v))
    throw new Error("Malformed scanner output");
  return Object.fromEntries(Object.entries(v));
};
const required = (v: unknown) => {
  if (typeof v !== "string" || !v.trim())
    throw new Error("Malformed scanner output");
  return v;
};

export function advisoryFindings(
  report: unknown,
  file: string,
  scope: "dependencies" | "image",
) {
  const data = object(report);
  if (!Array.isArray(data.matches)) throw new Error("Malformed scanner output");
  const unique = new Map<string, PublishSecurityFinding>();
  for (const row of data.matches) {
    const match = object(row),
      vuln = object(match.vulnerability),
      pkg = object(match.artifact);
    const id = required(vuln.id),
      name = required(pkg.name),
      version = required(pkg.version);
    const severity = normalizeVulnerabilitySeverity(required(vuln.severity));
    const fix = object(vuln.fix);
    if (
      !Array.isArray(fix.versions) ||
      !fix.versions.every((v) => typeof v === "string")
    )
      throw new Error("Malformed advisory fix versions");
    const fixedVersions = fix.versions.filter((v) => v.trim().length > 0);
    const fixable = fix.state === "fixed" && fixedVersions.length > 0;
    const blocks = fixable && (severity === "critical" || severity === "high");
    const rule = scope === "image" ? "image-advisory" : "dependency-advisory";
    const fingerprint = fingerprintOf(
      rule,
      file,
      [id, pkg.purl ?? name, version].join("|"),
    );
    unique.set(fingerprint, {
      file,
      line: null,
      rule,
      fingerprint,
      excerpt: null,
      severity: blocks ? "severe" : "info",
      title: `${name} ${version} · ${id}`,
      summary: `${severity} severity advisory in ${scope === "image" ? "the image" : "the dependency lockfile"}.`,
      fix: fixable
        ? `Upgrade to a compatible patched release. Reported fixes: ${fixedVersions.join(", ")}.`
        : "Monitor this advisory and review mitigations; the scanner reports no available fixed version.",
      advisory: {
        id,
        package: name,
        installedVersion: version,
        fixedVersions,
        severity,
        fixable,
      },
    });
  }
  return [...unique.values()].sort((a, b) =>
    a.fingerprint.localeCompare(b.fingerprint),
  );
}

async function scanAdvisories(
  options: ScanOptions,
  scope: "dependencies" | "image",
  checks: ScanCheck[],
  findings: PublishSecurityFinding[],
) {
  let directory: string | undefined;
  let file = scope === "image" ? "image" : "lockfile";
  let checked = 0;
  let detail = "Install Grype and run grype db update, then retry.";
  try {
    directory = await mkdtemp(join(tmpdir(), "absolute-scan-"));
    let target: string;
    let unresolved = 0;
    if (scope === "dependencies") {
      detail =
        "Cannot read a supported dependency lockfile. Use a Bun text lockfile or npm v2/v3 lockfile.";
      const inventory = await lockedPackages(options.root);
      file = inventory.file;
      unresolved = inventory.unresolved;
      checked = inventory.purls.length;
      if (!checked && !unresolved) {
        checks.push({
          name: scope,
          checked: 0,
          complete: true,
          detail: "No registry packages in " + file,
        });
        return;
      }
      target = "purl:" + join(directory, "packages");
      await writeFile(
        join(directory, "packages"),
        inventory.purls.join("\n") + "\n",
        { mode: 0o600 },
      );
    } else {
      detail = "Supply a registry image reference with a tag or digest.";
      if (
        !options.image ||
        !/^[a-z0-9][a-zA-Z0-9._:/@-]+$/.test(options.image) ||
        options.image.includes("://")
      )
        throw new Error();
      if (options.offline) throw new Error();
      file = options.image;
      target = "registry:" + file;
    }
    detail =
      "Grype could not complete the scan. Check its installation, database freshness and access to the selected target.";
    const config = join(directory, "scanner.yaml");
    await writeFile(config, "{}\n", { mode: 0o600 });
    const result = await execute(
      options.grype ?? "grype",
      ["--config", config, "-q", "-o", "json", target],
      {
        cwd: directory,
        timeout: 180000,
        maxBuffer: 96 * 1024 * 1024,
        env: {
          ...process.env,
          GRYPE_DB_VALIDATE_AGE: "true",
          GRYPE_CHECK_FOR_APP_UPDATE: "false",
          ...(options.offline ? { GRYPE_DB_AUTO_UPDATE: "false" } : {}),
        },
      },
    );
    detail = "Grype returned an invalid or incomplete report.";
    const report = object(JSON.parse(result.stdout));
    const descriptor = object(report.descriptor);
    const scannerVersion = required(descriptor.version);
    const found = advisoryFindings(report, file, scope);
    const db = object(descriptor.db);
    const status =
      db.status && typeof db.status === "object" ? object(db.status) : db;
    const databaseBuilt =
      typeof status.built === "string" ? status.built : undefined;
    if (status.valid !== true || !databaseBuilt)
      throw new Error("Unverified database");
    findings.push(...found);
    checks.push({
      name: scope,
      checked: scope === "image" ? 1 : checked,
      complete: unresolved === 0,
      scannerVersion,
      databaseBuilt,
      detail: unresolved
        ? `${unresolved} lockfile entries could not be identified by package and version.`
        : file,
    });
  } catch {
    checks.push({ name: scope, checked, complete: false, detail });
  } finally {
    if (directory) await rm(directory, { recursive: true, force: true });
  }
}

export async function scanProject(
  options: ScanOptions,
): Promise<ProjectSecurityReport> {
  const root = resolve(options.root),
    checks: ScanCheck[] = [],
    findings: PublishSecurityFinding[] = [];
  let checkedFiles = 0;
  if (!options.only || options.only === "source") {
    try {
      const source = await scanProjectDirectory(root, {
        committed: options.committed,
        trackedFiles: options.trackedFiles,
        timeBudgetMs: options.sourceTimeBudgetMs,
      });
      checkedFiles = source.checkedFiles;
      findings.push(...source.findings);
      checks.push({
        name: "source",
        checked: checkedFiles,
        complete: source.complete,
        detail: source.complete
          ? "Project source"
          : "Source coverage was partial.",
      });
    } catch {
      checks.push({
        name: "source",
        complete: false,
        checked: 0,
        detail: "Project source could not be read.",
      });
    }
  }
  if (!options.only || options.only === "dependencies")
    await scanAdvisories(
      { ...options, root },
      "dependencies",
      checks,
      findings,
    );
  if (options.only === "image" || (!options.only && options.image))
    await scanAdvisories(options, "image", checks, findings);
  for (const check of checks) {
    if (
      check.complete ||
      (check.name === "source" &&
        findings.some((item) => item.rule === "scan-incomplete"))
    )
      continue;
    findings.push({
      rule: "scan-incomplete",
      severity: "info",
      title: "Incomplete " + check.name + " scan",
      file: check.name,
      summary: check.detail,
      fix: "Resolve the reported issue and run the scan again.",
      fingerprint: fingerprintOf("scan-incomplete", check.name, "coverage"),
      line: null,
      excerpt: null,
    });
  }
  return {
    schemaVersion: 1,
    complete: checks.every((c) => c.complete),
    checkedFiles,
    checks,
    findings,
    counts: countFindings(findings),
  };
}

export const scanExitCode = (report: ProjectSecurityReport) =>
  !report.complete ? 2 : report.counts.severe ? 1 : 0;
