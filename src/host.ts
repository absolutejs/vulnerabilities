export type HostCommandResult = {
  exitCode: number;
  stderr: string;
  stdout: string;
};

export type HostCommandTarget = {
  readonly description?: string;
  exec: (command: string) => Promise<HostCommandResult>;
};

export type HostPackage = {
  architecture: string | null;
  name: string;
  version: string;
};

export type DebianHostInventory = {
  collectedAt: string;
  kernel: string;
  operatingSystem: Record<string, string>;
  packages: HostPackage[];
  rebootRequired: boolean;
  target: string | null;
  vendorSecurityStatus: unknown | null;
};

const required = async (target: HostCommandTarget, command: string) => {
  const result = await target.exec(command);
  if (result.exitCode !== 0)
    throw new Error(
      `Host inventory command failed (${result.exitCode}): ${result.stderr.trim() || command}`,
    );
  return result.stdout;
};

const unquote = (value: string) => {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")))
  )
    return trimmed.slice(1, -1).replaceAll('\\"', '"');
  return trimmed;
};

export const parseOsRelease = (input: string): Record<string, string> =>
  Object.fromEntries(
    input
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"))
      .map((line) => {
        const separator = line.indexOf("=");
        if (separator < 1) throw new Error("Invalid os-release entry");
        return [line.slice(0, separator), unquote(line.slice(separator + 1))];
      }),
  );

export const parseDpkgQuery = (input: string): HostPackage[] =>
  input
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => {
      const [qualifiedName, version] = line.split("\t");
      if (!qualifiedName || !version)
        throw new Error("Invalid dpkg-query entry");
      const separator = qualifiedName.lastIndexOf(":");
      return {
        architecture: separator < 0 ? null : qualifiedName.slice(separator + 1),
        name: separator < 0 ? qualifiedName : qualifiedName.slice(0, separator),
        version,
      };
    });

const optionalJson = async (target: HostCommandTarget, command: string) => {
  const result = await target.exec(command);
  if (result.exitCode !== 0 || result.stdout.trim().length === 0) return null;
  try {
    return JSON.parse(result.stdout) as unknown;
  } catch {
    throw new Error("Vendor security status was not valid JSON");
  }
};

export const collectDebianHostInventory = async (
  target: HostCommandTarget,
  options: { collectedAt?: string } = {},
): Promise<DebianHostInventory> => {
  const [osRelease, kernel, packages, reboot, vendorSecurityStatus] =
    await Promise.all([
      required(target, "cat /etc/os-release"),
      required(target, "uname -r"),
      required(target, "dpkg-query -W -f='${binary:Package}\\t${Version}\\n'"),
      target.exec("test -f /var/run/reboot-required"),
      optionalJson(target, "pro security-status --format json"),
    ]);

  return {
    collectedAt: options.collectedAt ?? new Date().toISOString(),
    kernel: kernel.trim(),
    operatingSystem: parseOsRelease(osRelease),
    packages: parseDpkgQuery(packages),
    rebootRequired: reboot.exitCode === 0,
    target: target.description ?? null,
    vendorSecurityStatus,
  };
};
