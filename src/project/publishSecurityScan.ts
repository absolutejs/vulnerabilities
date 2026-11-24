import { constants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import path from "node:path";
import type {
  PublishSecurityCounts,
  PublishSecurityFinding,
  PublishSecurityScanResult,
  PublishSecuritySeverity,
  SourceScanCoverage,
  SourceScanStop,
} from "./types";
import {
  checkCommittedEnvFile,
  checkPublicFile,
  fingerprintOf,
  isCredentialFile,
  layoutFromConfig,
  type ProjectLayout,
  scanFileText,
} from "./publishSecurityChecks";

/**
 * The security check a publish runs over a project's files. It reads the
 * same tree the release is built from, never follows a symbolic link (the
 * tree is the tenant's, and an excerpt must never come from outside it), and
 * never opens a credential file. It is bounded so it stays a second or two
 * on any project: past a limit it stops and says the check was partial.
 */

const MAXIMUM_FILES = 8_000;
/* A generated search index, a data file, an SVG with an embedded image:
 * real projects commit text files of several MB, and an unread file makes
 * the whole scan incomplete (production refuses that). 32 MiB reads them
 * all (11 MB scans in well under a second) while the total and the time
 * budget still bound the scan. */
const MAXIMUM_FILE_BYTES = 33_554_432;
const MAXIMUM_TOTAL_BYTES = 67_108_864;
const BINARY_SNIFF_BYTES = 4_096;
const DEFAULT_TIME_BUDGET_MS = 15_000;
const SEVERITY_ORDER: Record<PublishSecuritySeverity, number> = {
  info: 2,
  severe: 0,
  warning: 1,
};
/* Generated, installed or private-to-the-platform directories, as a release
 * leaves them out (releaseExclusions) plus other frameworks' build output. */
const SKIPPED_DIRECTORIES = new Set([
  ".absolute",
  ".absolutejs",
  ".cache",
  ".data",
  ".git",
  ".next",
  ".nuxt",
  ".output",
  ".svelte-kit",
  ".turbo",
  ".vercel",
  "build",
  "coverage",
  "dist",
  "node_modules",
]);
/* Lockfiles are integrity hashes and package URLs; binaries are not text. */
const SKIPPED_FILES = new Set([
  "bun.lock",
  "bun.lockb",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);
const BINARY_EXTENSIONS = new Set([
  ".avif",
  ".bmp",
  ".eot",
  ".gif",
  ".glb",
  ".gz",
  ".ico",
  ".jpeg",
  ".jpg",
  ".mov",
  ".mp3",
  ".mp4",
  ".otf",
  ".pdf",
  ".png",
  ".tar",
  ".tgz",
  ".ttf",
  ".wasm",
  ".webm",
  ".webp",
  ".woff",
  ".woff2",
  ".zip",
]);
const CONFIG_FILES = ["absolute.config.ts", "absolute.config.js"];

/** Bumped whenever the rules change, so a Studio host still running an older
 *  scanner is not asked (the control plane scans an export instead). */
export const PUBLISH_SECURITY_SCANNER_VERSION = 2;

export type PublishSecurityScanOptions = {
  /** The tree is a checkout of a repository commit, so every file in it is
   *  committed. A Studio copy is not: its .env stays on the platform. */
  committed?: boolean;
  trackedFiles?: ReadonlySet<string>;
  timeBudgetMs?: number;
};

type ScanState = {
  budgetMs: number;
  bytes: number;
  checked: number;
  complete: boolean;
  deadline: number;
  files: string[];
  listed: number;
  readable: number;
  /** The first limit the scan reached; it stops there. */
  stop: SourceScanStop | null;
  /** A folder inside the source could not be read. The rest is scanned. */
  unreadable: boolean;
  /** What could not be read, and why: the first few. */
  unreadablePaths: { path: string; error: string }[];
};

const UNREADABLE_PATHS_KEPT = 5;

const errorText = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

const noteUnreadable = (state: ScanState, file: string, error: unknown) => {
  state.unreadable = true;
  if (state.unreadablePaths.length < UNREADABLE_PATHS_KEPT)
    state.unreadablePaths.push({ error: errorText(error), path: file || "." });
};

const stopAt = (state: ScanState, stop: SourceScanStop) => {
  state.complete = false;
  state.stop ??= stop;
};

const listFiles = async (root: string, state: ScanState) => {
  const visit: (relative: string) => Promise<void> = async (relative) => {
    if (!state.complete) return;
    const listing = readdir(path.join(root, relative), {
      withFileTypes: true,
    });
    /* The source itself must be readable: a scan of nothing would pass
     * as clean. A folder inside it that cannot be read is reported as
     * an incomplete scan rather than skipped as if it were empty. */
    const entries =
      relative === ""
        ? await listing
        : await listing.catch((error: unknown) => {
            noteUnreadable(state, relative, error);

            return [];
          });
    const directories: string[] = [];
    for (const entry of entries) {
      // Neither branch follows a link: Dirent reports the link itself.
      const child = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory() && !SKIPPED_DIRECTORIES.has(entry.name))
        directories.push(child);
      else if (entry.isFile()) state.files.push(child);
    }
    if (state.files.length > MAXIMUM_FILES)
      stopAt(state, { limit: MAXIMUM_FILES, reason: "file-limit" });
    await directories.reduce<Promise<void>>(
      (pending, directory) => pending.then(() => visit(directory)),
      Promise.resolve(),
    );
  };
  await visit("");
  state.files.splice(MAXIMUM_FILES);
  state.files.sort();
  state.listed = state.files.length;
};

const readTextFile = async (absolute: string) => {
  // O_NOFOLLOW: a file swapped for a link after listing is not read.
  const handle = await open(
    absolute,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const info = await handle.stat();
    if (!info.isFile()) return null;
    if (info.size > MAXIMUM_FILE_BYTES)
      throw new Error("File exceeds scanner size limit");
    const data = Buffer.alloc(info.size + 1);
    let length = 0;
    while (length < data.length) {
      const read = await handle.read(
        data,
        length,
        data.length - length,
        length,
      );
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    if (length > info.size) throw new Error("File changed during scan");
    const buffer = data.subarray(0, length);
    const sniff = buffer.subarray(0, BINARY_SNIFF_BYTES);

    return sniff.includes(0) ? null : buffer.toString("utf8");
  } finally {
    await handle.close();
  }
};

const shouldRead = (file: string) => {
  const name = path.basename(file);

  return (
    !isCredentialFile(file) &&
    !name.startsWith(".absolutejs-hmr-") &&
    !SKIPPED_FILES.has(name) &&
    !BINARY_EXTENSIONS.has(path.extname(name).toLowerCase())
  );
};

const readLayout = async (root: string) => {
  const configs = await Promise.all(
    CONFIG_FILES.map((name) =>
      readTextFile(path.join(root, name)).catch(() => null),
    ),
  );

  return layoutFromConfig(configs.find((config) => config !== null) ?? null);
};

const placementFindings = (
  files: string[],
  layout: ProjectLayout,
  committed: boolean,
  trackedFiles?: ReadonlySet<string>,
) =>
  files.flatMap((file) => {
    const found = [
      checkPublicFile(file, layout),
      committed || trackedFiles?.has(file) ? checkCommittedEnvFile(file) : null,
    ];

    return found.filter(
      (finding): finding is PublishSecurityFinding => finding !== null,
    );
  });

const contentFindings = async (
  root: string,
  files: string[],
  layout: ProjectLayout,
  state: ScanState,
) => {
  const findings: PublishSecurityFinding[] = [];
  const scanOne = async (file: string) => {
    if (state.stop) return;
    if (Date.now() > state.deadline)
      stopAt(state, { budgetMs: state.budgetMs, reason: "time-budget" });
    else if (state.bytes > MAXIMUM_TOTAL_BYTES)
      stopAt(state, { limitBytes: MAXIMUM_TOTAL_BYTES, reason: "byte-limit" });
    if (state.stop) return;
    const text = await readTextFile(path.join(root, file)).catch(
      (error: unknown) => {
        noteUnreadable(state, file, error);

        return null;
      },
    );
    if (text === null) return;
    state.bytes += Buffer.byteLength(text);
    state.checked += 1;
    findings.push(...scanFileText(file, text, layout));
  };
  // One file at a time: the scan shares the host with builds.
  const readable = files.filter(shouldRead);
  state.readable = readable.length;
  await readable.reduce<Promise<void>>(
    (pending, file) => pending.then(() => scanOne(file)),
    Promise.resolve(),
  );

  return findings;
};

const MEBIBYTE = 1_048_576;
const megabytes = (bytes: number) => `${(bytes / MEBIBYTE).toFixed(1)} MB`;

/** What stopped a source scan, and how much it read, in a sentence. */
export const describeSourceStop = (
  stop: SourceScanStop,
  coverage: SourceScanCoverage,
) => {
  const read = `${coverage.checkedFiles} of ${coverage.readableFiles} files (${megabytes(coverage.checkedBytes)})`;
  if (stop.reason === "time-budget")
    return `Stopped at its ${stop.budgetMs / 1000} s time budget after ${read}.`;
  if (stop.reason === "file-limit")
    return `Stopped at its limit of ${stop.limit} files; read ${read}.`;
  if (stop.reason === "byte-limit")
    return `Stopped at its limit of ${megabytes(stop.limitBytes)} read; read ${read}.`;
  const paths = stop.paths
    .map((entry) => `${entry.path} (${entry.error})`)
    .join(", ");

  return `Could not read ${paths}; read ${read}.`;
};

const incompleteFinding = (
  stop: SourceScanStop,
  coverage: SourceScanCoverage,
): PublishSecurityFinding => ({
  excerpt: null,
  file: ".",
  fingerprint: fingerprintOf("scan-incomplete", ".", ""),
  fix: "Nothing to do now. Removing large generated or copied folders from the project lets the whole check run.",
  line: null,
  rule: "scan-incomplete",
  severity: "info",
  summary: `${describeSourceStop(stop, coverage)} What it found is real; some files were not checked.`,
  title: "Only part of the project was checked",
});

/** One finding per problem: the same key repeated through a file (a log,
 * say) is one thing to fix, shown at its first line with how often it
 * appears. */
const uniqueFindings = (findings: PublishSecurityFinding[]) => {
  const groups = new Map<string, PublishSecurityFinding[]>();
  findings.forEach((finding) => {
    const group = groups.get(finding.fingerprint) ?? [];
    group.push(finding);
    groups.set(finding.fingerprint, group);
  });

  return [...groups.values()].flatMap(([first, ...rest]) =>
    first
      ? [
          rest.length === 0
            ? first
            : {
                ...first,
                summary: `${first.summary} It appears ${rest.length + 1} times in this file.`,
              },
        ]
      : [],
  );
};

export const countFindings = (findings: PublishSecurityFinding[]) =>
  findings.reduce<PublishSecurityCounts>(
    (counts, finding) => ({
      ...counts,
      [finding.severity]: counts[finding.severity] + 1,
    }),
    { info: 0, severe: 0, warning: 0 },
  );

const bySeverity = (
  left: PublishSecurityFinding,
  right: PublishSecurityFinding,
) =>
  SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity] ||
  left.file.localeCompare(right.file) ||
  (left.line ?? 0) - (right.line ?? 0);

export const scanProjectDirectory = async (
  root: string,
  {
    committed = false,
    trackedFiles,
    timeBudgetMs = DEFAULT_TIME_BUDGET_MS,
  }: PublishSecurityScanOptions = {},
): Promise<PublishSecurityScanResult> => {
  const state: ScanState = {
    budgetMs: timeBudgetMs,
    bytes: 0,
    checked: 0,
    complete: true,
    deadline: Date.now() + timeBudgetMs,
    files: [],
    listed: 0,
    readable: 0,
    stop: null,
    unreadable: false,
    unreadablePaths: [],
  };
  await listFiles(root, state);
  const layout = await readLayout(root);
  const found = [
    ...placementFindings(state.files, layout, committed, trackedFiles),
    ...(await contentFindings(root, state.files, layout, state)),
  ];
  const findings = uniqueFindings(found).sort(bySeverity);
  const complete = state.complete && !state.unreadable;
  const coverage: SourceScanCoverage = {
    checkedBytes: state.bytes,
    checkedFiles: state.checked,
    listedFiles: state.listed,
    readableFiles: state.readable,
  };
  const stop: SourceScanStop | null = complete
    ? null
    : (state.stop ?? { paths: state.unreadablePaths, reason: "unreadable" });
  if (stop) findings.push(incompleteFinding(stop, coverage));

  return {
    checkedFiles: state.checked,
    complete,
    counts: countFindings(findings),
    coverage,
    findings,
    stop,
  };
};
