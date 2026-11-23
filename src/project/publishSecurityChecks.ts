import { createHash } from "node:crypto";
import path from "node:path";
import type {
  PublishSecurityFinding,
  PublishSecurityRule,
  PublishSecuritySeverity,
} from "./types";
import { isInRanges, literalRanges } from "./sourceLiterals";

/**
 * The checks the publish security scan runs, one file at a time. Every check
 * is deterministic (no AI, no network) and tuned to stay quiet unless it is
 * sure: a scan that cries wolf gets ignored, so each pattern is a credential
 * format a provider actually issues, and anything that reads like a
 * placeholder is left alone.
 */

const FINGERPRINT_LENGTH = 16;
const EXCERPT_HEAD = 8;
const EXCERPT_TAIL = 4;
const SHORT_SECRET = 16;
const MINIMUM_DISTINCT_CHARACTERS = 8;
const MINIMUM_DATABASE_PASSWORD = 8;
const PRIVATE_KEY_LOOKAHEAD = 600;
const PRIVATE_KEY_BODY = /^[A-Za-z0-9+/=]{64}/;
const PRIVATE_KEY_SPACING = /\\[nr]|\s|['"`+,]/g;

export type ProjectLayout = {
  /** Directories whose code is bundled for visitors' browsers. */
  frontendDirectories: string[];
  /** Directories served to anyone as they are. */
  publicDirectories: string[];
};

export const DEFAULT_PROJECT_LAYOUT: ProjectLayout = {
  frontendDirectories: ["src/frontend"],
  publicDirectories: ["public", "src/backend/assets"],
};

type SecretPattern = {
  label: string;
  pattern: RegExp;
  severity: PublishSecuritySeverity;
};

/* Formats each provider documents for its secret credentials. Publishable
 * and public keys (Stripe pk_, Supabase anon) are deliberately absent. */
const SECRET_PATTERNS: SecretPattern[] = [
  {
    label: "AWS access key",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    severity: "severe",
  },
  {
    label: "Stripe live secret key",
    pattern: /\b[rs]k_live_[0-9A-Za-z]{20,}\b/g,
    severity: "severe",
  },
  {
    label: "Stripe test secret key",
    pattern: /\b[rs]k_test_[0-9A-Za-z]{20,}\b/g,
    severity: "warning",
  },
  {
    label: "GitHub token",
    pattern: /\b(?:gh[oprsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/g,
    severity: "severe",
  },
  {
    label: "Slack token",
    pattern: /\bxox[abeprs]-[A-Za-z0-9-]{20,}/g,
    severity: "severe",
  },
  {
    label: "Anthropic API key",
    pattern: /\bsk-ant-[a-z]{3,5}\d{2}-[A-Za-z0-9_-]{60,}/g,
    severity: "severe",
  },
  {
    label: "OpenAI API key",
    pattern:
      /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{48}\b/g,
    severity: "severe",
  },
  {
    label: "Google API key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
    severity: "warning",
  },
  {
    label: "SendGrid API key",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g,
    severity: "severe",
  },
  {
    label: "Resend API key",
    pattern: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b/g,
    severity: "severe",
  },
  {
    label: "npm token",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: "severe",
  },
];

const PLACEHOLDER =
  /x{4,}|\*{3,}|\.{3}|•|<|>|\$\{|\{\{|your|example|placeholder|dummy|fake|sample|redacted|changeme|replace|insert/i;
const PRIVATE_KEY_HEADER =
  /-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----/g;
const DATABASE_URL =
  /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/([^\s:/@'"`]+):([^\s@'"`]+)@([^\s/:?'"`,]+)/g;
const PASSWORD_WORDS = new Set([
  "admin",
  "changeme",
  "pass",
  "password",
  "postgres",
  "root",
  "secret",
  "test",
]);
/* Hosts that never leave the machine or its compose network, and names
 * reserved for documentation. A service name with no dot is compose-local. */
const LOCAL_HOST =
  /^(?:[^.]+|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|.*\.(?:local|localhost|internal|test|invalid|example|example\.(?:com|net|org)))$/i;

const ENV_ACCESS =
  /(?:process\.env|import\.meta\.env|Bun\.env)(?:\.([A-Z][A-Z0-9_]*)|\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\])/g;
/* Prefixes the common frameworks inline into client bundles at build time
 * (Vite, Next.js, Create React App, Expo, Gatsby, Nuxt, SvelteKit/Astro). */
const PUBLIC_ENV_PREFIX =
  /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_|PUBLIC_)/;
/* A name that says it holds a secret. Matched on the end of the name, so
 * PASSWORD_MIN_LENGTH or SECRET_SANTA_ENABLED are not secrets. */
const SECRET_NAME =
  /(?:^|_)(?:SECRET|SECRET_KEY|SECRET_TOKEN|PRIVATE_KEY|PASSWORD|PASSWD|SERVICE_ROLE|SERVICE_ROLE_KEY|DATABASE_URL|DB_URL|CONNECTION_STRING|AUTH_TOKEN|API_SECRET|CLIENT_SECRET|WEBHOOK_SECRET|SIGNING_SECRET)$/;
/* A key that spends money when someone else uses it: AI and email APIs. */
const BILLABLE_KEY_NAME =
  /(?:^|_)(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|DEEPSEEK|PERPLEXITY|ELEVENLABS|REPLICATE|COHERE|OPENROUTER|RESEND|SENDGRID|POSTMARK|MAILGUN)(?:_[A-Z0-9]+)*_(?:API_KEY|KEY|TOKEN|API_TOKEN)$/;
/* Browser code reading these on AbsoluteJS: the build never inlines them, so
 * they either fail in the browser or leak through server rendering. */
const BROWSER_SECRET_NAME =
  /(?:^|_)(?:SECRET|SECRET_KEY|PRIVATE_KEY|PASSWORD|SERVICE_ROLE_KEY|DATABASE_URL|API_SECRET|CLIENT_SECRET|WEBHOOK_SECRET|API_KEY|AUTH_TOKEN)$/;
const CODE_EXTENSIONS = new Set([
  ".astro",
  ".cjs",
  ".js",
  ".jsx",
  ".mjs",
  ".svelte",
  ".ts",
  ".tsx",
  ".vue",
]);
const ENV_FILE = /^\.env(?:\..+)?$/;
const ENV_TEMPLATE =
  /^\.env\.(?:example|sample|template|dist|defaults|schema)$/;
const ENV_LOCAL = /^\.env(?:\..+)?\.local$|^\.env\.local$/;
const DATA_FILE = /\.(?:sql|sqlite|sqlite3|db|dump)$/i;
const KEYSTORE_FILE = /\.(?:p12|pfx|jks|keystore)$/i;
const TEST_FILE =
  /(?:^|\/)(?:__tests__|tests?|e2e|fixtures?)\/|\.(?:test|spec)\.[cm]?[jt]sx?$/;
const TOO_BROAD = new Set(["", ".", "src"]);
const CHARACTER_CLASSES = [/[a-z]/, /[A-Z]/, /\d/];
const MINIMUM_CHARACTER_CLASSES = 2;

export const fingerprintOf = (
  rule: PublishSecurityRule,
  file: string,
  value: string,
) =>
  createHash("sha256")
    .update(`${rule}\0${file}\0${value}`)
    .digest("hex")
    .slice(0, FINGERPRINT_LENGTH);

/** Enough to recognise the value, never enough to use it. */
export const redact = (value: string) =>
  value.length <= SHORT_SECRET
    ? "••••"
    : `${value.slice(0, EXCERPT_HEAD)}…${value.slice(-EXCERPT_TAIL)}`;

const lineAt = (text: string, index: number) =>
  text.slice(0, index).split("\n").length;

export const looksLikePlaceholder = (value: string) =>
  PLACEHOLDER.test(value) || new Set(value).size < MINIMUM_DISTINCT_CHARACTERS;

const isUnder = (file: string, directories: string[]) =>
  directories.some(
    (directory) =>
      directory.length > 0 &&
      (file === directory || file.startsWith(`${directory}/`)),
  );

/** Where a file ends up, which decides how its finding is worded. */
const exposureOf = (file: string, layout: ProjectLayout) => {
  if (isUnder(file, layout.publicDirectories)) return "public";
  if (TEST_FILE.test(file)) return "test";
  if (isUnder(file, layout.frontendDirectories)) return "browser";

  return "source";
};

/* Anyone can already fetch a file the site serves. A test file mostly holds
 * made-up keys, so it is never more than worth a look. */
const severityFor = (exposure: string, severity: PublishSecuritySeverity) => {
  if (exposure === "public") return "severe";
  if (exposure === "test") return "warning";

  return severity;
};

const secretSummary = (label: string, exposure: string) => {
  if (exposure === "public")
    return `A ${label} is in a file your site serves to anyone. Every visitor can download it.`;
  if (exposure === "browser")
    return `A ${label} is written in code that is sent to visitors' browsers, where anyone can read it.`;
  if (exposure === "test")
    return `A ${label} is written in a test file. If it is a real one, anyone who can see the code can use it; if it is made up for the test, there is nothing to fix.`;

  return `A ${label} is written in your project's code. Anyone who can see the code (teammates, a shared repository, a leaked copy) can use it as you.`;
};

const SECRET_FIX =
  "Treat this key as already exposed: create a new one with the provider and delete this one. Store the replacement in your server environment and read it only in backend code.";

type FileContext = { file: string; layout: ProjectLayout; text: string };

const secretFinding = (
  context: FileContext,
  label: string,
  severity: PublishSecuritySeverity,
  value: string,
  index: number,
  excerpt = redact(value),
): PublishSecurityFinding => {
  const exposure = exposureOf(context.file, context.layout);

  return {
    excerpt,
    file: context.file,
    fingerprint: fingerprintOf("secret-in-source", context.file, value),
    fix: SECRET_FIX,
    line: lineAt(context.text, index),
    rule: "secret-in-source",
    severity: severityFor(exposure, severity),
    summary: secretSummary(label, exposure),
    title: `${label[0]?.toUpperCase() ?? ""}${label.slice(1)} in your code`,
  };
};

const providerSecrets = (context: FileContext) =>
  SECRET_PATTERNS.flatMap(({ label, pattern, severity }) =>
    [...context.text.matchAll(pattern)]
      .filter((match) => !looksLikePlaceholder(match[0]))
      .map((match) =>
        secretFinding(context, label, severity, match[0], match.index),
      ),
  );

/* A header alone is what PEM-handling code looks like; a key has a body. */
const hasPrivateKeyBody = (text: string, headerEnd: number) =>
  PRIVATE_KEY_BODY.test(
    text
      .slice(headerEnd, headerEnd + PRIVATE_KEY_LOOKAHEAD)
      .replace(PRIVATE_KEY_SPACING, ""),
  );

const privateKeys = (context: FileContext) =>
  [...context.text.matchAll(PRIVATE_KEY_HEADER)]
    .filter((match) =>
      hasPrivateKeyBody(context.text, match.index + match[0].length),
    )
    .map((match) =>
      secretFinding(
        context,
        "private key",
        "severe",
        context.text.slice(match.index, match.index + PRIVATE_KEY_LOOKAHEAD),
        match.index,
        match[0],
      ),
    );

/* Generated database passwords mix letters and digits; "synthetic-secret"
 * or "hunter" is a fixture or an example, not one a provider issued. */
const looksGenerated = (password: string) =>
  CHARACTER_CLASSES.filter((characters) => characters.test(password)).length >=
  MINIMUM_CHARACTER_CLASSES;

const isRealDatabasePassword = (password: string, host: string) =>
  password.length >= MINIMUM_DATABASE_PASSWORD &&
  looksGenerated(password) &&
  !PASSWORD_WORDS.has(password.toLowerCase()) &&
  !password.startsWith("$") &&
  !looksLikePlaceholder(password) &&
  !LOCAL_HOST.test(host);

const databaseUrls = (context: FileContext) =>
  [...context.text.matchAll(DATABASE_URL)]
    .filter(([, , , password = "", host = ""]) =>
      isRealDatabasePassword(password, host),
    )
    .map((match) => {
      const [whole, scheme, user, password = "", host] = match;

      return secretFinding(
        context,
        "database password",
        "severe",
        whole,
        match.index,
        `${scheme}://${user}:${redact(password)}@${host}`,
      );
    });

const envNamesIn = (text: string) =>
  [...text.matchAll(ENV_ACCESS)].map(({ 1: dotted, 2: bracketed, index }) => ({
    index,
    name: dotted ?? bracketed ?? "",
  }));

const publicEnvSecretFinding = (
  context: FileContext,
  name: string,
  index: number,
): PublishSecurityFinding => ({
  excerpt: name,
  file: context.file,
  fingerprint: fingerprintOf("public-env-secret", context.file, name),
  fix: `Rename it without the public prefix (for example ${name.replace(PUBLIC_ENV_PREFIX, "")}), read it only in backend code, and have the page ask your backend for what it needs. If this value was ever published, create a new one with the provider.`,
  line: lineAt(context.text, index),
  rule: "public-env-secret",
  severity: "severe",
  summary: `${name} starts with a prefix that tells the build to copy its value into the code sent to visitors' browsers, but its name says it is a secret. Anyone can read it there.`,
  title: "A secret is set up to be sent to browsers",
});

const isPublicSecretName = (name: string) => {
  if (!PUBLIC_ENV_PREFIX.test(name)) return false;
  const bare = name.replace(PUBLIC_ENV_PREFIX, "");

  return SECRET_NAME.test(bare) || BILLABLE_KEY_NAME.test(bare);
};

const browserEnvSecretFinding = (
  context: FileContext,
  name: string,
  index: number,
): PublishSecurityFinding => ({
  excerpt: name,
  file: context.file,
  fingerprint: fingerprintOf("browser-env-secret", context.file, name),
  fix: `Read ${name} in your backend (for example a route in src/backend) and have this page call that route. Pages should never see the secret itself.`,
  line: lineAt(context.text, index),
  rule: "browser-env-secret",
  severity: "warning",
  summary: `This file is page code, which also runs in visitors' browsers. Reading ${name} here either breaks in the browser or, if the value ends up on the page, gives the secret away.`,
  title: "Page code reads a server secret",
});

const envChecks = (context: FileContext) => {
  if (
    !CODE_EXTENSIONS.has(path.extname(context.file)) ||
    TEST_FILE.test(context.file)
  )
    return [];
  const names = envNamesIn(context.text);
  if (names.length === 0) return [];
  const browser = exposureOf(context.file, context.layout) === "browser";
  // A code sample in a string or a comment is not code that runs.
  const literals = literalRanges(context.text);
  const seen = new Set<string>();

  return names.flatMap(({ index, name }) => {
    if (seen.has(name) || isInRanges(literals, index)) return [];
    seen.add(name);
    if (isPublicSecretName(name))
      return [publicEnvSecretFinding(context, name, index)];
    if (browser && BROWSER_SECRET_NAME.test(name))
      return [browserEnvSecretFinding(context, name, index)];

    return [];
  });
};

/** Files whose contents are never read (credentials the control plane is
 *  kept out of; see RELEASE_EXCLUDED_NAMES) but whose place still matters. */
export const isCredentialFile = (file: string) => {
  const name = path.basename(file);

  return (
    ENV_FILE.test(name) ||
    name === ".netrc" ||
    name === ".npmrc" ||
    name === ".pypirc"
  );
};
/** Every content check for one text file. */
export const scanFileText = (
  file: string,
  text: string,
  layout: ProjectLayout = DEFAULT_PROJECT_LAYOUT,
) => {
  const context: FileContext = { file, layout, text };

  return [
    ...providerSecrets(context),
    ...privateKeys(context),
    ...databaseUrls(context),
    ...envChecks(context),
  ];
};

const publicFileFinding = (
  file: string,
  title: string,
  summary: string,
  fix: string,
): PublishSecurityFinding => ({
  excerpt: null,
  file,
  fingerprint: fingerprintOf("public-sensitive-file", file, file),
  fix,
  line: null,
  rule: "public-sensitive-file",
  severity: "severe",
  summary,
  title,
});

/** A credential file found in a repository checkout: it is in the
 *  repository's history, where everyone with access can read it. */
export const checkCommittedEnvFile = (
  file: string,
): PublishSecurityFinding | null => {
  const name = path.basename(file);
  if (!ENV_FILE.test(name) || ENV_TEMPLATE.test(name)) return null;
  // Any committed .env refuses the publish, defaults included: it is the
  // file people put keys in, and whatever it held stays in the history.
  const local = ENV_LOCAL.test(name);

  return {
    excerpt: null,
    file,
    fingerprint: fingerprintOf("committed-env-file", file, file),
    fix: `Remove ${file} from the repository, add it to .gitignore, and create new keys for anything it held: they stay in the repository's history. Keep secrets in Settings → Environment variables, and commit a .env.example with placeholder values if others need to know which variables to set.`,
    line: null,
    rule: "committed-env-file",
    severity: "severe",
    summary: local
      ? `${name} is the file meant for real keys on your own machine, and it is committed to your repository. Anyone with access to the repository can read it.`
      : `${name} is committed to your repository. Anyone with access to the repository can read it, and .env files are where keys usually end up.`,
    title: local
      ? "Your local keys file is in the repository"
      : "A .env file is in the repository",
  };
};

/** A file in a served directory that should never be downloadable. */
export const checkPublicFile = (file: string, layout: ProjectLayout) => {
  if (!isUnder(file, layout.publicDirectories)) return null;
  const name = path.basename(file);
  if (ENV_FILE.test(name) && !ENV_TEMPLATE.test(name))
    return publicFileFinding(
      file,
      "Your settings file can be downloaded",
      `${name} holds your project's settings and keys, and it is in a folder your site serves to anyone.`,
      `Delete ${file}. Put its values in Settings → Environment variables, and create new keys for anything it held.`,
    );
  if (DATA_FILE.test(name))
    return publicFileFinding(
      file,
      "A database file can be downloaded",
      `${name} looks like a database or a database export, and it is in a folder your site serves to anyone. Visitors could download all of its data.`,
      `Move ${file} out of the public folder (or delete it). Keep data in your project's database instead.`,
    );
  if (KEYSTORE_FILE.test(name))
    return publicFileFinding(
      file,
      "A key file can be downloaded",
      `${name} is a certificate store, which usually holds a private key, and it is in a folder your site serves to anyone.`,
      `Delete ${file} from the public folder and replace the certificate it holds.`,
    );

  return null;
};

const DIRECTORY_SETTING =
  /\b(react|svelte|vue|angular|html|htmx|public|assets)Directory\s*:\s*['"`]([^'"`]+)['"`]/g;

const normalizeDirectory = (directory: string) =>
  path.posix.normalize(directory).replace(/^\.\/?|\/$/g, "");

/** Reads where an AbsoluteJS project keeps page code and served files from
 *  its absolute.config, falling back to the template layout. */
export const layoutFromConfig = (config: string | null): ProjectLayout => {
  if (!config) return DEFAULT_PROJECT_LAYOUT;
  const settings = [...config.matchAll(DIRECTORY_SETTING)].map(
    ([, kind = "", directory = ""]) => ({
      directory: normalizeDirectory(directory),
      kind,
    }),
  );
  const pageSettings = settings.filter(
    ({ kind }) => kind !== "public" && kind !== "assets",
  );
  // A page folder of "src" holds the server too: no telling them apart.
  const frontend = pageSettings
    .map(({ directory }) => directory)
    .filter((directory) => !TOO_BROAD.has(directory));
  const served = settings
    .filter(({ kind }) => kind === "public" || kind === "assets")
    .map(({ directory }) => directory);

  return {
    frontendDirectories:
      pageSettings.length > 0
        ? frontend
        : DEFAULT_PROJECT_LAYOUT.frontendDirectories,
    publicDirectories:
      served.length > 0 ? served : DEFAULT_PROJECT_LAYOUT.publicDirectories,
  };
};
