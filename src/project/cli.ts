import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { parseArgs } from "node:util";
import { scanProject, scanExitCode } from "../scan";

const help = `absolute scan [--path DIR] [--only source|dependencies|image] [--image REGISTRY/IMAGE:TAG] [--committed] [--offline] [--json]

Checks source exposure and locked dependencies. --image adds a registry image scan.
--committed treats all files as committed; use it on an exported commit.
--offline uses the local Grype database for dependency checks. Image scans need registry access.
Exit 0: complete and publishable; 1: blocking findings; 2: incomplete or invalid request.`;

export async function runScanCli(args: string[]) {
  if (args.includes("--help") || args.includes("-h")) {
    console.log(help);
    return 0;
  }
  let values;
  try {
    values = parseArgs({
      args,
      options: {
        path: { type: "string" },
        only: { type: "string" },
        image: { type: "string" },
        offline: { type: "boolean" },
        json: { type: "boolean" },
        committed: { type: "boolean" },
      },
    }).values;
  } catch {
    console.error(help);
    return 2;
  }
  const only = values.only;
  if (
    (only !== undefined &&
      only !== "dependencies" &&
      only !== "source" &&
      only !== "image") ||
    (only === "image" && !values.image) ||
    (values.image && only && only !== "image") ||
    (values.image && values.offline)
  ) {
    console.error(help);
    return 2;
  }
  const root = values.path ?? process.cwd();
  let trackedFiles: Set<string> | undefined;
  if (!values.committed && (!only || only === "source")) {
    try {
      const result = await promisify(execFile)(
        "git",
        [
          "-c",
          "core.fsmonitor=false",
          "ls-files",
          "--cached",
          "-z",
          "--",
          ".env*",
          "**/.env*",
        ],
        { cwd: root, timeout: 5000, maxBuffer: 1024 * 1024 },
      );
      trackedFiles = new Set(result.stdout.split("\0").filter(Boolean));
    } catch {
      /* An exported source tree can be checked with --committed. */
    }
  }
  const report = await scanProject({
    root,
    trackedFiles,
    only,
    image: values.image,
    offline: values.offline,
    committed: values.committed,
  });
  if (values.json) console.log(JSON.stringify(report));
  else {
    for (const check of report.checks)
      console.log(
        `${check.name}: ${check.complete ? "complete" : "INCOMPLETE"} · ${check.checked} checked · ${check.detail}`,
      );
    for (const finding of report.findings)
      console.log(
        `\n[${finding.severity}] ${finding.file}${finding.line ? `:${finding.line}` : ""} · ${finding.title}\n${finding.summary}\n${finding.fix}`,
      );
    console.log(
      `\n${report.findings.length} findings · ${report.counts.severe} blocking · ${report.complete ? "scan complete" : "scan incomplete"}`,
    );
  }
  return scanExitCode(report);
}
