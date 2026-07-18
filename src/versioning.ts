import {
  compare as comparePep440,
  valid as validPep440,
} from "@renovatebot/pep440";
import { Type, type Static } from "@sinclair/typebox";
import { PackageURL, type PurlQualifiers } from "packageurl-js";
import { compare as compareSemver, valid as validSemver } from "semver";
import type { ComponentIdentity } from "./contracts";
import { IdentifierSchema } from "./primitives";

export const VersionSchemeSchema = Type.Union([
  Type.Literal("debian"),
  Type.Literal("semver"),
  Type.Literal("go"),
  Type.Literal("pep440"),
  Type.Literal("nuget"),
  Type.Literal("maven"),
  Type.Literal("rpm"),
  Type.Literal("apk"),
  Type.Literal("unknown"),
]);
export type VersionScheme = Static<typeof VersionSchemeSchema>;

export type VersionOrder = -1 | 0 | 1;

export type VersionComparison = {
  comparator: "builtin" | "adapter" | null;
  left: string;
  order: VersionOrder | null;
  reason: string;
  right: string;
  scheme: VersionScheme;
  status: "comparable" | "unknown";
};

export type VersionComparator = (
  left: string,
  right: string,
) => VersionOrder | null;

export type VersionComparatorAdapters = Partial<
  Record<VersionScheme, VersionComparator>
>;

const order = (value: number): VersionOrder =>
  value === 0 ? 0 : value < 0 ? -1 : 1;

const ecosystemAliases: Record<string, VersionScheme> = {
  alpine: "apk",
  apk: "apk",
  cargo: "semver",
  crates: "semver",
  deb: "debian",
  debian: "debian",
  fedora: "rpm",
  go: "go",
  golang: "go",
  maven: "maven",
  npm: "semver",
  nuget: "nuget",
  pypi: "pep440",
  python: "pep440",
  redhat: "rpm",
  rpm: "rpm",
  ubuntu: "debian",
};

export const versionSchemeForEcosystem = (ecosystem: string): VersionScheme => {
  const normalized = ecosystem.trim().toLowerCase();
  const family = normalized.split(":", 1)[0] ?? normalized;
  return ecosystemAliases[normalized] ?? ecosystemAliases[family] ?? "unknown";
};

type DebianVersion = {
  epoch: bigint;
  revision: string;
  upstream: string;
};

const parseDebianVersion = (value: string): DebianVersion | null => {
  if (value.length === 0) return null;
  const colon = value.indexOf(":");
  const epochText = colon < 0 ? "0" : value.slice(0, colon);
  if (!/^\d+$/.test(epochText)) return null;
  const remainder = colon < 0 ? value : value.slice(colon + 1);
  const hyphen = remainder.lastIndexOf("-");
  const upstream = hyphen < 0 ? remainder : remainder.slice(0, hyphen);
  const revision = hyphen < 0 ? "0" : remainder.slice(hyphen + 1);
  if (
    upstream.length === 0 ||
    !/^[A-Za-z0-9.+:~-]+$/.test(upstream) ||
    !/^[A-Za-z0-9.+~]+$/.test(revision)
  )
    return null;
  return { epoch: BigInt(epochText), revision, upstream };
};

const debianCharacterOrder = (character: string | undefined) => {
  if (character === "~") return -1;
  if (character === undefined) return 0;
  if (/^[A-Za-z]$/.test(character)) return character.charCodeAt(0);
  return character.charCodeAt(0) + 256;
};

const compareDebianPart = (left: string, right: string): VersionOrder => {
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length || rightIndex < right.length) {
    while (
      (leftIndex < left.length && !/\d/.test(left[leftIndex]!)) ||
      (rightIndex < right.length && !/\d/.test(right[rightIndex]!))
    ) {
      const difference =
        debianCharacterOrder(left[leftIndex]) -
        debianCharacterOrder(right[rightIndex]);
      if (difference !== 0) return order(difference);
      if (leftIndex < left.length) leftIndex += 1;
      if (rightIndex < right.length) rightIndex += 1;
    }

    while (left[leftIndex] === "0") leftIndex += 1;
    while (right[rightIndex] === "0") rightIndex += 1;
    const leftStart = leftIndex;
    const rightStart = rightIndex;
    while (leftIndex < left.length && /\d/.test(left[leftIndex]!))
      leftIndex += 1;
    while (rightIndex < right.length && /\d/.test(right[rightIndex]!))
      rightIndex += 1;
    const leftDigits = left.slice(leftStart, leftIndex);
    const rightDigits = right.slice(rightStart, rightIndex);
    if (leftDigits.length !== rightDigits.length)
      return order(leftDigits.length - rightDigits.length);
    if (leftDigits !== rightDigits) return leftDigits < rightDigits ? -1 : 1;
  }
  return 0;
};

export const compareDebianVersions: VersionComparator = (left, right) => {
  const leftVersion = parseDebianVersion(left);
  const rightVersion = parseDebianVersion(right);
  if (leftVersion === null || rightVersion === null) return null;
  if (leftVersion.epoch !== rightVersion.epoch)
    return leftVersion.epoch < rightVersion.epoch ? -1 : 1;
  const upstream = compareDebianPart(
    leftVersion.upstream,
    rightVersion.upstream,
  );
  if (upstream !== 0) return upstream;
  return compareDebianPart(leftVersion.revision, rightVersion.revision);
};

const compareSemanticVersions: VersionComparator = (left, right) => {
  const validLeft = validSemver(left);
  const validRight = validSemver(right);
  if (validLeft === null || validRight === null) return null;
  return order(compareSemver(validLeft, validRight));
};

const compareGoVersions: VersionComparator = (left, right) => {
  if (!left.startsWith("v") || !right.startsWith("v")) return null;
  return compareSemanticVersions(left.slice(1), right.slice(1));
};

const comparePythonVersions: VersionComparator = (left, right) => {
  if (validPep440(left) === null || validPep440(right) === null) return null;
  return order(comparePep440(left, right));
};

type NugetVersion = {
  core: bigint[];
  prerelease: string[] | null;
};

const parseNugetVersion = (value: string): NugetVersion | null => {
  const match =
    /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
      value,
    );
  if (!match) return null;
  const core = [
    match[1],
    match[2] ?? "0",
    match[3] ?? "0",
    match[4] ?? "0",
  ].map((part) => BigInt(part!));
  const prerelease = match[5]?.split(".") ?? null;
  if (prerelease?.some((part) => part.length === 0)) return null;
  return { core, prerelease };
};

const compareNugetPrerelease = (
  left: string[] | null,
  right: string[] | null,
): VersionOrder => {
  if (left === null && right === null) return 0;
  if (left === null) return 1;
  if (right === null) return -1;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = left[index];
    const rightPart = right[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    const leftNumeric = /^\d+$/.test(leftPart);
    const rightNumeric = /^\d+$/.test(rightPart);
    if (leftNumeric && rightNumeric) {
      const difference = BigInt(leftPart) - BigInt(rightPart);
      if (difference !== 0n) return difference < 0n ? -1 : 1;
      continue;
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    const normalizedLeft = leftPart.toLowerCase();
    const normalizedRight = rightPart.toLowerCase();
    if (normalizedLeft !== normalizedRight)
      return normalizedLeft < normalizedRight ? -1 : 1;
  }
  return 0;
};

export const compareNugetVersions: VersionComparator = (left, right) => {
  const leftVersion = parseNugetVersion(left);
  const rightVersion = parseNugetVersion(right);
  if (leftVersion === null || rightVersion === null) return null;
  for (let index = 0; index < leftVersion.core.length; index += 1) {
    const leftPart = leftVersion.core[index]!;
    const rightPart = rightVersion.core[index]!;
    if (leftPart !== rightPart) return leftPart < rightPart ? -1 : 1;
  }
  return compareNugetPrerelease(
    leftVersion.prerelease,
    rightVersion.prerelease,
  );
};

const builtinComparators: Partial<Record<VersionScheme, VersionComparator>> = {
  debian: compareDebianVersions,
  go: compareGoVersions,
  nuget: compareNugetVersions,
  pep440: comparePythonVersions,
  semver: compareSemanticVersions,
};

export const comparePackageVersions = (input: {
  adapters?: VersionComparatorAdapters;
  ecosystem: string;
  left: string;
  right: string;
}): VersionComparison => {
  const scheme = versionSchemeForEcosystem(input.ecosystem);
  const adapter = input.adapters?.[scheme];
  const comparator = adapter ?? builtinComparators[scheme];
  if (!comparator)
    return {
      comparator: null,
      left: input.left,
      order: null,
      reason:
        scheme === "unknown"
          ? `No version scheme is registered for ${input.ecosystem}`
          : `${scheme} comparison requires a verified adapter`,
      right: input.right,
      scheme,
      status: "unknown",
    };
  try {
    const comparison = comparator(input.left, input.right);
    if (comparison === null)
      return {
        comparator: adapter ? "adapter" : "builtin",
        left: input.left,
        order: null,
        reason: `Invalid ${scheme} version input`,
        right: input.right,
        scheme,
        status: "unknown",
      };
    return {
      comparator: adapter ? "adapter" : "builtin",
      left: input.left,
      order: comparison,
      reason:
        comparison === 0
          ? "Versions are equal"
          : comparison < 0
            ? "Left version is older"
            : "Left version is newer",
      right: input.right,
      scheme,
      status: "comparable",
    };
  } catch (error) {
    return {
      comparator: adapter ? "adapter" : "builtin",
      left: input.left,
      order: null,
      reason: `Version comparator failed: ${error instanceof Error ? error.message : "unknown error"}`,
      right: input.right,
      scheme,
      status: "unknown",
    };
  }
};

export const VersionConstraintSchema = Type.Object(
  {
    operator: Type.Union([
      Type.Literal("lt"),
      Type.Literal("lte"),
      Type.Literal("eq"),
      Type.Literal("gte"),
      Type.Literal("gt"),
    ]),
    version: IdentifierSchema,
  },
  { additionalProperties: false },
);
export type VersionConstraint = Static<typeof VersionConstraintSchema>;

export type VersionConstraintEvaluation = {
  comparisons: VersionComparison[];
  reason: string;
  status: "matched" | "not_matched" | "unknown";
};

const constraintMatches = (
  orderValue: VersionOrder,
  operator: VersionConstraint["operator"],
) => {
  if (operator === "lt") return orderValue < 0;
  if (operator === "lte") return orderValue <= 0;
  if (operator === "eq") return orderValue === 0;
  if (operator === "gte") return orderValue >= 0;
  return orderValue > 0;
};

export const evaluateVersionConstraints = (input: {
  adapters?: VersionComparatorAdapters;
  constraints: readonly VersionConstraint[];
  ecosystem: string;
  installedVersion: string;
}): VersionConstraintEvaluation => {
  if (input.constraints.length === 0)
    return {
      comparisons: [],
      reason: "No constraints were provided",
      status: "unknown",
    };
  const comparisons: VersionComparison[] = [];
  for (const constraint of input.constraints) {
    const comparison = comparePackageVersions({
      ...(input.adapters ? { adapters: input.adapters } : {}),
      ecosystem: input.ecosystem,
      left: input.installedVersion,
      right: constraint.version,
    });
    comparisons.push(comparison);
    if (comparison.status === "unknown" || comparison.order === null)
      return {
        comparisons,
        reason: comparison.reason,
        status: "unknown",
      };
    if (!constraintMatches(comparison.order, constraint.operator))
      return {
        comparisons,
        reason: `Installed version does not satisfy ${constraint.operator} ${constraint.version}`,
        status: "not_matched",
      };
  }
  return {
    comparisons,
    reason: "Installed version satisfies every constraint",
    status: "matched",
  };
};

const purlTypeForEcosystem = (ecosystem: string) => {
  const normalized = ecosystem.trim().toLowerCase();
  const aliases: Record<string, string> = {
    alpine: "apk",
    debian: "deb",
    go: "golang",
    python: "pypi",
    ubuntu: "deb",
  };
  return aliases[normalized] ?? normalized;
};

export const normalizePackageUrl = (value: string) =>
  PackageURL.fromString(value).toString();

export const createComponentIdentity = (input: {
  ecosystem: string;
  name: string;
  namespace?: string | null;
  purl?: string | null;
  qualifiers?: PurlQualifiers;
  version: string;
}): ComponentIdentity => {
  if (input.purl) {
    const parsed = PackageURL.fromString(input.purl);
    if (parsed.version !== undefined && parsed.version !== input.version)
      throw new Error("Package URL version does not match component version");
    if (parsed.name !== input.name)
      throw new Error("Package URL name does not match component name");
    return {
      ecosystem: parsed.type,
      name: parsed.name,
      namespace: parsed.namespace ?? null,
      purl: parsed.toString(),
      version: input.version,
    };
  }
  const purl = new PackageURL(
    purlTypeForEcosystem(input.ecosystem),
    input.namespace,
    input.name,
    input.version,
    input.qualifiers,
  ).toString();
  const parsed = PackageURL.fromString(purl);
  return {
    ecosystem: parsed.type,
    name: parsed.name,
    namespace: parsed.namespace ?? null,
    purl,
    version: input.version,
  };
};

export const componentIdentityKey = (identity: ComponentIdentity) =>
  identity.purl ??
  JSON.stringify([
    identity.ecosystem,
    identity.namespace,
    identity.name,
    identity.version,
  ]);
