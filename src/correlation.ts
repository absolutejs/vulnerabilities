import { createHash } from "node:crypto";
import type {
  ManagedVulnerabilityFinding,
  VulnerabilityAdvisory,
  VulnerabilityAsset,
  VulnerabilityComponent,
  VulnerabilityObservation,
} from "./contracts";
import { canonicalVulnerabilityIds, createStableFindingId } from "./identity";
import { comparePackageVersions, componentIdentityKey } from "./versioning";

type MatchStatus = "matched" | "not_matched" | "unknown";

export type AdvisoryComponentEvaluation = {
  advisoryId: string;
  componentId: string;
  reason: string;
  status: MatchStatus;
};

export type VulnerabilityCorrelationResult = {
  evaluations: AdvisoryComponentEvaluation[];
  findings: ManagedVulnerabilityFinding[];
  observations: VulnerabilityObservation[];
  resolved: ManagedVulnerabilityFinding[];
  upserts: ManagedVulnerabilityFinding[];
};

const severityOrder = {
  unknown: 0,
  negligible: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
} as const;

const highestSeverity = (advisory: VulnerabilityAdvisory) =>
  advisory.severity.reduce<ManagedVulnerabilityFinding["severity"]>(
    (highest, severity) =>
      severityOrder[severity.value] > severityOrder[highest]
        ? severity.value
        : highest,
    "unknown",
  );

const osvEcosystem = (component: VulnerabilityComponent) =>
  component.properties["osv.ecosystem"] ?? component.identity.ecosystem;

const packageMatches = (
  component: VulnerabilityComponent,
  affected: NonNullable<VulnerabilityAdvisory["affected"]>[number],
) =>
  component.identity.name === affected.package.name &&
  osvEcosystem(component).toLowerCase() ===
    affected.package.ecosystem.toLowerCase();

const rangeComparison = (input: {
  component: VulnerabilityComponent;
  rangeType: "ecosystem" | "git" | "semver";
  version: string;
}) => {
  if (input.rangeType === "git") return null;
  return comparePackageVersions({
    ecosystem:
      input.rangeType === "semver" ? "npm" : osvEcosystem(input.component),
    left: input.component.identity.version,
    right: input.version,
  });
};

const evaluateRange = (
  component: VulnerabilityComponent,
  range: NonNullable<
    VulnerabilityAdvisory["affected"]
  >[number]["ranges"][number],
): { reason: string; status: MatchStatus } => {
  if (range.events.length === 0)
    return { reason: "Advisory range has no events", status: "unknown" };
  let affected = false;
  for (const event of range.events) {
    if (event.introduced !== undefined) {
      if (event.introduced === "0") affected = true;
      else {
        const comparison = rangeComparison({
          component,
          rangeType: range.type,
          version: event.introduced,
        });
        if (comparison?.status !== "comparable" || comparison.order === null)
          return {
            reason:
              comparison?.reason ?? "Git ranges require commit-aware inventory",
            status: "unknown",
          };
        if (comparison.order < 0)
          return {
            reason: `Installed version predates introduced version ${event.introduced}`,
            status: affected ? "matched" : "not_matched",
          };
        affected = true;
      }
    }
    if (event.fixed !== undefined) {
      const comparison = rangeComparison({
        component,
        rangeType: range.type,
        version: event.fixed,
      });
      if (comparison?.status !== "comparable" || comparison.order === null)
        return {
          reason:
            comparison?.reason ?? "Git ranges require commit-aware inventory",
          status: "unknown",
        };
      if (comparison.order < 0)
        return {
          reason: `Installed version is before fixed version ${event.fixed}`,
          status: affected ? "matched" : "not_matched",
        };
      affected = false;
    }
    const upperBound = event.lastAffected ?? event.limit;
    if (upperBound !== undefined) {
      const comparison = rangeComparison({
        component,
        rangeType: range.type,
        version: upperBound,
      });
      if (comparison?.status !== "comparable" || comparison.order === null)
        return {
          reason:
            comparison?.reason ?? "Git ranges require commit-aware inventory",
          status: "unknown",
        };
      const inclusive = event.lastAffected !== undefined;
      if (comparison.order < 0 || (inclusive && comparison.order === 0))
        return {
          reason: `Installed version is within advisory upper bound ${upperBound}`,
          status: affected ? "matched" : "not_matched",
        };
      affected = false;
    }
  }
  return {
    reason: affected
      ? "Installed version remains in an affected range"
      : "Installed version is outside every affected interval",
    status: affected ? "matched" : "not_matched",
  };
};

export const evaluateAdvisoryComponent = (input: {
  advisory: VulnerabilityAdvisory;
  component: VulnerabilityComponent;
}): AdvisoryComponentEvaluation => {
  if (input.advisory.withdrawnAt !== null)
    return {
      advisoryId: input.advisory.id,
      componentId: input.component.id,
      reason: "Advisory is withdrawn",
      status: "not_matched",
    };
  const affected = (input.advisory.affected ?? []).filter((entry) =>
    packageMatches(input.component, entry),
  );
  if (affected.length === 0)
    return {
      advisoryId: input.advisory.id,
      componentId: input.component.id,
      reason: "Advisory does not name this package and ecosystem",
      status: "not_matched",
    };
  let unknownReason: string | null = null;
  for (const entry of affected) {
    if (entry.versions.includes(input.component.identity.version))
      return {
        advisoryId: input.advisory.id,
        componentId: input.component.id,
        reason: "Installed version is explicitly affected",
        status: "matched",
      };
    for (const range of entry.ranges) {
      const evaluation = evaluateRange(input.component, range);
      if (evaluation.status === "matched")
        return {
          advisoryId: input.advisory.id,
          componentId: input.component.id,
          ...evaluation,
        };
      if (evaluation.status === "unknown") unknownReason ??= evaluation.reason;
    }
  }
  return {
    advisoryId: input.advisory.id,
    componentId: input.component.id,
    reason: unknownReason ?? "Installed version is not affected",
    status: unknownReason === null ? "not_matched" : "unknown",
  };
};

const observationId = (
  advisory: VulnerabilityAdvisory,
  asset: VulnerabilityAsset,
  component: VulnerabilityComponent,
) =>
  `observation_${createHash("sha256")
    .update(
      JSON.stringify([
        asset.tenantId,
        asset.id,
        componentIdentityKey(component.identity),
        advisory.id,
        advisory.modifiedAt,
      ]),
    )
    .digest("hex")}`;

const identityVulnerabilityIds = (advisory: VulnerabilityAdvisory) => {
  const cves = advisory.aliases.filter((value) =>
    /^CVE-\d{4}-\d+$/i.test(value),
  );
  return canonicalVulnerabilityIds(cves.length > 0 ? cves : [advisory.id]);
};

const activeStatus = (
  existing: ManagedVulnerabilityFinding | undefined,
): ManagedVulnerabilityFinding["status"] => {
  if (!existing) return "new";
  if (existing.status === "fixed" || existing.status === "mitigated")
    return "reopened";
  return existing.status;
};

export const correlateVulnerabilityInventory = (input: {
  advisories: readonly VulnerabilityAdvisory[];
  asset: VulnerabilityAsset;
  components: readonly VulnerabilityComponent[];
  existingFindings?: readonly ManagedVulnerabilityFinding[];
  observedAt: string;
}): VulnerabilityCorrelationResult => {
  if (!Number.isFinite(Date.parse(input.observedAt)))
    throw new Error("Vulnerability correlation observedAt must be a timestamp");
  const existing = new Map(
    (input.existingFindings ?? []).map((finding) => [finding.id, finding]),
  );
  const evaluations: AdvisoryComponentEvaluation[] = [];
  const observations: VulnerabilityObservation[] = [];
  const findings = new Map<string, ManagedVulnerabilityFinding>();
  const inconclusiveFindingIds = new Set<string>();
  for (const component of input.components) {
    for (const advisory of input.advisories) {
      const evaluation = evaluateAdvisoryComponent({ advisory, component });
      evaluations.push(evaluation);
      if (evaluation.status === "unknown") {
        const advisoryIds = new Set(
          canonicalVulnerabilityIds(advisory.aliases),
        );
        for (const finding of existing.values())
          if (
            finding.componentId === component.id &&
            finding.vulnerabilityIds.some((id) => advisoryIds.has(id))
          )
            inconclusiveFindingIds.add(finding.id);
      }
      if (evaluation.status !== "matched") continue;
      const identityIds = identityVulnerabilityIds(advisory);
      const id = createStableFindingId({
        assetId: input.asset.id,
        componentIdentity: componentIdentityKey(component.identity),
        tenantId: input.asset.tenantId,
        vulnerabilityIds: identityIds,
      });
      const observation: VulnerabilityObservation = {
        advisoryIds: canonicalVulnerabilityIds(advisory.aliases),
        assetId: input.asset.id,
        componentId: component.id,
        contract: input.asset.contract,
        evidence: [
          {
            collectedAt: input.observedAt,
            digest: null,
            kind: "advisory",
            source: advisory.source.name,
            uri: advisory.source.url,
          },
          {
            collectedAt: input.observedAt,
            digest: null,
            kind: "inventory",
            source: input.asset.name,
            uri: component.identity.purl,
          },
        ],
        id: observationId(advisory, input.asset, component),
        observedAt: input.observedAt,
        scanner: "absolutejs-correlation",
        scannerRecordId: advisory.id,
        severity: highestSeverity(advisory),
      };
      observations.push(observation);
      const current = findings.get(id);
      const prior = existing.get(id);
      const vulnerabilityIds = canonicalVulnerabilityIds([
        ...(current?.vulnerabilityIds ?? prior?.vulnerabilityIds ?? []),
        ...advisory.aliases,
      ]);
      const observationIds = [
        ...new Set([
          ...(current?.observationIds ?? prior?.observationIds ?? []),
          observation.id,
        ]),
      ].sort();
      const severity = current?.severity ?? prior?.severity ?? "unknown";
      const advisorySeverity = highestSeverity(advisory);
      findings.set(id, {
        assetId: input.asset.id,
        componentId: component.id,
        contract: input.asset.contract,
        firstSeenAt: prior?.firstSeenAt ?? input.observedAt,
        id,
        lastSeenAt: input.observedAt,
        observationIds,
        severity:
          severityOrder[advisorySeverity] > severityOrder[severity]
            ? advisorySeverity
            : severity,
        status: activeStatus(prior),
        tenantId: input.asset.tenantId,
        vulnerabilityIds,
      });
    }
  }
  const activeIds = new Set(findings.keys());
  const resolved = [...existing.values()]
    .filter(
      (finding) =>
        finding.tenantId === input.asset.tenantId &&
        finding.assetId === input.asset.id &&
        !activeIds.has(finding.id) &&
        !inconclusiveFindingIds.has(finding.id) &&
        finding.status !== "fixed",
    )
    .map((finding) => ({ ...finding, status: "fixed" as const }));
  const active = [...findings.values()].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
  return {
    evaluations,
    findings: active,
    observations,
    resolved,
    upserts: [...active, ...resolved],
  };
};
