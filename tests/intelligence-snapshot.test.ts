import { describe, expect, test } from "bun:test";
import type { FeedSnapshot, VulnerabilityAdvisory } from "../src";
import {
  admissionIntelligenceCoverageKey,
  signAdmissionIntelligenceSnapshot,
  verifyAdmissionIntelligenceSnapshot,
} from "../src/intelligence-snapshot";

const feed = <T>(id: string, records: FeedSnapshot<T>["records"]) => ({
  cursor: { etag: null, lastModified: null, token: null },
  feed: { id, name: id, url: `https://security.example/${id}` },
  fetchedAt: "2026-07-19T12:00:00Z",
  records,
  revision: "revision-1",
});

describe("signed admission intelligence", () => {
  test("binds exact query coverage, OSV advisories, KEV, and freshness", () => {
    const coverage = admissionIntelligenceCoverageKey({
      ecosystem: "npm",
      name: "fixture",
      version: "1.0.0",
    });
    const signed = signAdmissionIntelligenceSnapshot({
      coverage: [coverage],
      issuedAt: "2026-07-19T12:01:00Z",
      kev: feed("cisa-kev", [
        {
          id: "CVE-2026-0001",
          modifiedAt: "2026-07-19T12:00:00Z",
          value: { cveId: "CVE-2026-0001" },
        },
      ]),
      keyId: "control-plane-audit-v1",
      maxAgeMs: 3_600_000,
      osv: feed<VulnerabilityAdvisory>("osv", []),
      secret: "admission-intelligence-secret-at-least-32-bytes",
    });

    expect(
      verifyAdmissionIntelligenceSnapshot({
        attestation: signed,
        now: "2026-07-19T12:30:00Z",
        secret: "admission-intelligence-secret-at-least-32-bytes",
      }),
    ).toMatchObject({ payload: { coverage: [coverage] }, status: "verified" });
    expect(
      verifyAdmissionIntelligenceSnapshot({
        attestation: signed,
        now: "2026-07-19T13:00:01Z",
        secret: "admission-intelligence-secret-at-least-32-bytes",
      }),
    ).toEqual({ status: "expired" });
    expect(
      verifyAdmissionIntelligenceSnapshot({
        attestation: {
          ...signed,
          payload: { ...signed.payload, coverage: ["forged"] },
        },
        secret: "admission-intelligence-secret-at-least-32-bytes",
      }),
    ).toEqual({ status: "invalid" });
  });
});
