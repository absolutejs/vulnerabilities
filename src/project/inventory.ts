import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { join } from "node:path";
import { valid } from "semver";
import { PackageURL } from "packageurl-js";

function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("Invalid lockfile structure");
  return Object.fromEntries(Object.entries(input));
}

async function readInput(root: string, name: string) {
  const handle = await open(
    join(root, name),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  ).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return null;
    throw new Error("Cannot open " + name);
  });
  if (!handle) return null;
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 32 * 1024 * 1024)
      throw new Error("Unsupported size or file type for " + name);
    const buffer = Buffer.alloc(stat.size + 1);
    let position = 0;
    while (position < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        position,
        buffer.length - position,
        position,
      );
      if (!bytesRead) break;
      position += bytesRead;
    }
    if (position !== stat.size) throw new Error("Lockfile changed during scan");
    return buffer.toString("utf8", 0, position);
  } finally {
    await handle.close();
  }
}

export async function lockedPackages(root: string) {
  const purls = new Set<string>();
  let unresolved = 0;
  function add(name: unknown, version: unknown) {
    if (
      typeof name !== "string" ||
      !/^(?:@[a-z0-9_.~-]+\/)?[a-z0-9_.~-]+$/i.test(name) ||
      typeof version !== "string" ||
      !valid(version)
    ) {
      unresolved++;
      return;
    }
    const parts = name.split("/");
    purls.add(
      new PackageURL(
        "npm",
        parts.length === 2 ? parts[0] : undefined,
        parts.at(-1)!,
        version,
        undefined,
        undefined,
      ).toString(),
    );
  }
  const manifestText = await readInput(root, "package.json");
  const manifest =
    manifestText === null ? {} : object(JSON.parse(manifestText));
  const requiresPackages = (entry: unknown) => {
    const pkg = object(entry);
    return [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ].some(
      (key) =>
        pkg[key] !== undefined && Object.keys(object(pkg[key])).length > 0,
    );
  };
  function verifyCoverage(entries: unknown[], inventorySize: number) {
    if (!inventorySize && [manifest, ...entries].some(requiresPackages))
      throw new Error("Declared dependencies have no locked packages");
  }
  const bun = await readInput(root, "bun.lock");
  if (bun !== null) {
    const lock = object(Bun.JSONC.parse(bun));
    /* Version 2 (Bun 1.3) adds `configVersion` and keeps every package as
     * `["name@version", …]`, the shape read below. */
    if (![0, 1, 2].includes(Number(lock.lockfileVersion)))
      throw new Error(
        `Unsupported bun.lock version ${String(lock.lockfileVersion)}`,
      );
    const workspaces = object(lock.workspaces);
    const packages = Object.values(object(lock.packages));
    verifyCoverage(Object.values(workspaces), packages.length);
    for (const entry of packages) {
      const value = Array.isArray(entry) ? entry[0] : undefined;
      const match =
        typeof value === "string" ? /^(@?[^@]+)@(.+)$/.exec(value) : null;
      if (!match) {
        unresolved++;
        continue;
      }
      const [, name, version] = match;
      if (
        version?.startsWith("workspace:") &&
        Object.hasOwn(workspaces, version.slice(10))
      )
        continue;
      add(name, version);
    }
    return { file: "bun.lock", purls: [...purls].sort(), unresolved };
  }
  for (const file of ["npm-shrinkwrap.json", "package-lock.json"]) {
    const text = await readInput(root, file);
    if (text === null) continue;
    const lock = object(JSON.parse(text));
    if (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3)
      throw new Error("Unsupported npm lockfile version");
    const packages = object(lock.packages);
    for (const [path, value] of Object.entries(packages)) {
      const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(path);
      if (!match) continue;
      const pkg = object(value);
      if (
        pkg.link === true &&
        typeof pkg.resolved === "string" &&
        Object.hasOwn(packages, pkg.resolved)
      )
        continue;
      if (
        typeof pkg.resolved === "string" &&
        /^(git|file:|link:)/.test(pkg.resolved)
      ) {
        unresolved++;
        continue;
      }
      add(pkg.name ?? match[1], pkg.version);
    }
    verifyCoverage(Object.values(packages), purls.size + unresolved);
    return { file, purls: [...purls].sort(), unresolved };
  }
  for (const unsupported of ["bun.lockb", "yarn.lock", "pnpm-lock.yaml"]) {
    if ((await readInput(root, unsupported)) !== null)
      throw new Error("Unsupported lockfile");
  }
  if (!requiresPackages(manifest) && !manifest.workspaces)
    return {
      file: manifestText === null ? "project" : "package.json",
      purls: [],
      unresolved: 0,
    };
  throw new Error(
    "A Bun text lockfile or npm v2/v3 lockfile is required for dependency coverage",
  );
}
