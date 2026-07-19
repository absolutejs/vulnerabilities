#!/usr/bin/env bun

import { readFile } from "node:fs/promises";
import type {
  EvidenceVerificationKey,
  SignedVulnerabilityEvidenceBundle,
} from "./evidence-bundle";
import {
  verifyEvidenceKeyTransparencyLog,
  verifyVulnerabilityEvidenceWithTransparency,
  type EvidenceKeyTransparencyLog,
} from "./evidence-transparency";

type EvidenceCliIo = {
  readText: (path: string) => Promise<string>;
  stderr: (value: string) => void;
  stdout: (value: string) => void;
};

type EvidenceRegistryFile = {
  transparency?: EvidenceKeyTransparencyLog;
};

const usage = () =>
  [
    "Usage:",
    "  absolute-vulnerability-evidence verify --bundle <file> --registry <file> \\",
    "    [--trusted-fingerprint <sha256>] [--trusted-head <sha256:digest>]",
    "",
    "At least one out-of-band trust anchor is required.",
  ].join("\n");

const option = (args: readonly string[], name: string) => {
  const index = args.indexOf(name);
  if (index < 0) return null;
  const value = args[index + 1]?.trim();
  if (!value || value.startsWith("--"))
    throw new Error(`${name} requires a value`);

  return value;
};

const parseJson = <T>(value: string, label: string): T => {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
};

const transparencyFrom = (
  value: EvidenceRegistryFile | EvidenceKeyTransparencyLog,
) =>
  "transparency" in value && value.transparency
    ? value.transparency
    : (value as EvidenceKeyTransparencyLog);

export const runEvidenceCli = async (
  args: readonly string[],
  io: EvidenceCliIo = {
    readText: (path) => readFile(path, "utf8"),
    stderr: (value) => process.stderr.write(`${value}\n`),
    stdout: (value) => process.stdout.write(`${value}\n`),
  },
) => {
  try {
    if (args[0] !== "verify") throw new Error(usage());
    const bundlePath = option(args, "--bundle");
    const registryPath = option(args, "--registry");
    const trustedFingerprint = option(args, "--trusted-fingerprint");
    const trustedHead = option(args, "--trusted-head");
    if (!bundlePath || !registryPath) throw new Error(usage());
    if (!trustedFingerprint && !trustedHead)
      throw new Error("A trusted fingerprint or transparency head is required");
    const [bundleText, registryText] = await Promise.all([
      io.readText(bundlePath),
      io.readText(registryPath),
    ]);
    const bundle = parseJson<SignedVulnerabilityEvidenceBundle>(
      bundleText,
      "Evidence bundle",
    );
    const log = transparencyFrom(
      parseJson<EvidenceRegistryFile | EvidenceKeyTransparencyLog>(
        registryText,
        "Evidence registry",
      ),
    );
    const untrustedLog = verifyEvidenceKeyTransparencyLog({ log });
    const genesis = untrustedLog.keys[0] ?? null;
    const fingerprintMatches = trustedFingerprint
      ? genesis?.fingerprint === trustedFingerprint
      : true;
    const trustedKeys: EvidenceVerificationKey[] =
      genesis && fingerprintMatches ? [genesis] : [];
    const verification = verifyVulnerabilityEvidenceWithTransparency({
      bundle,
      log,
      ...(trustedHead ? { pinnedHead: trustedHead } : {}),
      trustedKeys,
    });
    const trusted =
      verification.trust === "trusted" &&
      fingerprintMatches &&
      (!trustedHead || verification.transparency.headMatches);
    const result = {
      ...verification,
      fingerprintMatches,
      trusted,
    };
    io.stdout(JSON.stringify(result, null, 2));

    return trusted ? 0 : 1;
  } catch (error) {
    io.stderr(error instanceof Error ? error.message : "Verification failed");

    return 2;
  }
};

if (import.meta.main) process.exit(await runEvidenceCli(process.argv.slice(2)));
