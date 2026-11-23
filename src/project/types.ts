/* What the security check at publish found. Shared by the scanner, the record
 * kept per publish, and the publish dialog that shows it to the owner. */

/** `severe` refuses the publish until it is fixed; the server enforces it.
 *  `warning` asks the owner for "Publish anyway" at the Publish button (a push
 *  or a preview has no one to ask, so it is recorded and goes ahead). `info`
 *  is a note. */
export type PublishSecuritySeverity = "info" | "severe" | "warning";

export type PublishSecurityRule =
  | "dependency-advisory"
  | "image-advisory"
  | "browser-env-secret"
  | "committed-env-file"
  | "public-env-secret"
  | "public-sensitive-file"
  | "scan-incomplete"
  | "secret-in-source";

export type PublishSecurityFinding = {
  advisory?: {
    id: string;
    package: string;
    installedVersion: string;
    fixedVersions: string[];
    severity: string;
    fixable: boolean;
  };
  /** A short, redacted look at what matched. Never the secret itself. */
  excerpt: string | null;
  /** Relative to the project root. */
  file: string;
  /** Stable across publishes for the same problem in the same file, so a
   *  later scan can tell what is new. A truncated hash, never the value. */
  fingerprint: string;
  /** How to fix it, in plain words. */
  fix: string;
  line: number | null;
  rule: PublishSecurityRule;
  severity: PublishSecuritySeverity;
  /** What it is and why it matters, in plain words. */
  summary: string;
  title: string;
};

export type PublishSecurityCounts = Record<PublishSecuritySeverity, number>;

/** Why a source scan stopped before reading every file: the first limit it
 *  reached, or the files it could not read. */
export type SourceScanStop =
  | { reason: "time-budget"; budgetMs: number }
  | { reason: "file-limit"; limit: number }
  | { reason: "byte-limit"; limitBytes: number }
  | { reason: "unreadable"; paths: { path: string; error: string }[] };

/** How much of the source a scan covered. */
export type SourceScanCoverage = {
  /** Files found under the root (capped at the file limit). */
  listedFiles: number;
  /** Text files the scan meant to read. */
  readableFiles: number;
  checkedFiles: number;
  checkedBytes: number;
};

export type PublishSecurityScanResult = {
  checkedFiles: number;
  /** False when the scan stopped at a limit; the findings are still real. */
  complete: boolean;
  counts: PublishSecurityCounts;
  /** What the scan covered. Absent from results made before 0.17. */
  coverage?: SourceScanCoverage;
  findings: PublishSecurityFinding[];
  /** Why it stopped; null when complete. Absent from results made before
   *  0.17. */
  stop?: SourceScanStop | null;
};
