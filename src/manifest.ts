import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["platform-operators", "security-teams"],
    intents: [
      "normalize vulnerability scanner output",
      "enforce vulnerability policy",
      "collect Debian host security inventory",
      "produce audit-ready vulnerability evidence",
      "verify offline vulnerability evidence and signing-key history",
      "verify independently witnessed transparency checkpoints",
      "verify vulnerability remediation after deployment",
    ],
    keywords: [
      "vulnerabilities",
      "CVE",
      "Grype",
      "SBOM",
      "host-inventory",
      "key-transparency",
      "security-policy",
      "remediation",
    ],
    protocols: ["Grype JSON", "Debian package inventory"],
  },
  identity: {
    accent: "#dc2626",
    category: "operations",
    description:
      "Scanner-neutral vulnerability normalization, remediation verification, Debian host inventory, and audit-ready evidence without discarding distribution package versions.",
    docsUrl: "https://github.com/absolutejs/vulnerabilities",
    name: "@absolutejs/vulnerabilities",
    tagline:
      "Turn scanner output and host state into defensible security decisions.",
  },
  settings: Type.Object({}),
  wiring: [],
});
