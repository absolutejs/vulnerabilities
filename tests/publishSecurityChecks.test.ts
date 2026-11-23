import { describe, expect, test } from "bun:test";
import {
  checkCommittedEnvFile,
  checkPublicFile,
  DEFAULT_PROJECT_LAYOUT,
  isCredentialFile,
  layoutFromConfig,
  redact,
  scanFileText,
} from "../src/project/publishSecurityChecks";

/* Every credential here is assembled at run time from made-up characters, so
 * the repository never holds a string a secret scanner (ours or GitHub's)
 * would take for a real key. */
const join = (...parts: string[]) => parts.join("");
const RANDOM_24 = "q8Zr2LmX4vT9pK1sW7nB3cYd";
const RANDOM_36 = `${RANDOM_24}h6Gf0JuE5aRk`;
const STRIPE_LIVE = join("sk_", "live_", RANDOM_24);
const STRIPE_TEST = join("sk_", "test_", RANDOM_24);
const AWS_KEY = join("AKIA", "Q7ZL2MXP4RT9KW1S");
const GITHUB_TOKEN = join("gh", "p_", RANDOM_36);
const OPENAI_KEY = join("sk-", "proj-", RANDOM_36, RANDOM_24);
const RESEND_KEY = join("re_", "Ab3dE6gH", "_", RANDOM_24);
const GOOGLE_KEY = join("AI", "za", "Sy", RANDOM_24, "h6Gf0JuE5");
const PEM_BODY =
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ";
const PRIVATE_KEY_HEADER = join("-----BEGIN ", "PRIVATE KEY-----");
const PRIVATE_KEY = `${PRIVATE_KEY_HEADER}\n${PEM_BODY}\n-----END PRIVATE KEY-----`;

const rules = (file: string, text: string) =>
  scanFileText(file, text).map((finding) => [finding.rule, finding.severity]);

describe("secrets written in code", () => {
  test("finds a Stripe live secret key, and never repeats it back", () => {
    const [finding] = scanFileText(
      "src/backend/payments.ts",
      `const stripe = new Stripe('${STRIPE_LIVE}');`,
    );

    expect(finding?.rule).toBe("secret-in-source");
    expect(finding?.severity).toBe("severe");
    expect(finding?.line).toBe(1);
    expect(finding?.excerpt).not.toContain(STRIPE_LIVE);
    expect(JSON.stringify(finding)).not.toContain(STRIPE_LIVE);
  });

  test("a Stripe test key is worth fixing, not serious", () => {
    expect(rules("src/backend/payments.ts", `key = "${STRIPE_TEST}"`)).toEqual([
      ["secret-in-source", "warning"],
    ]);
  });

  test("finds AWS, GitHub, OpenAI and Resend keys on the right lines", () => {
    const text = [
      `const aws = "${AWS_KEY}";`,
      `const gh = "${GITHUB_TOKEN}";`,
      `const ai = "${OPENAI_KEY}";`,
      `const mail = "${RESEND_KEY}";`,
    ].join("\n");
    const found = scanFileText("src/backend/clients.ts", text);

    expect(found.map((finding) => finding.line).sort()).toEqual([1, 2, 3, 4]);
    expect(found.every((finding) => finding.severity === "severe")).toBe(true);
  });

  test("a Google API key is a warning: many are meant to be public", () => {
    expect(rules("src/backend/maps.ts", `k = '${GOOGLE_KEY}'`)).toEqual([
      ["secret-in-source", "warning"],
    ]);
  });

  test("a key in a served folder is serious whatever its kind", () => {
    expect(rules("public/config.js", `k = '${GOOGLE_KEY}'`)).toEqual([
      ["secret-in-source", "severe"],
    ]);
  });

  test("a key in a test file is only worth a look: most are made up", () => {
    expect(
      rules("src/backend/payments.test.ts", `k = '${STRIPE_LIVE}'`),
    ).toEqual([["secret-in-source", "warning"]]);
    expect(rules("tests/fixtures/keys.ts", `k = '${STRIPE_LIVE}'`)).toEqual([
      ["secret-in-source", "warning"],
    ]);
  });

  test("says when the key is in code sent to browsers", () => {
    const [finding] = scanFileText(
      "src/frontend/pages/Home.tsx",
      `const key = "${STRIPE_LIVE}";`,
    );

    expect(finding?.summary).toContain("browsers");
  });

  test("leaves placeholders and documentation examples alone", () => {
    const text = [
      `const stripe = '${join("sk_", "live_", "x".repeat(24))}';`,
      `const stripeAgain = '${join("sk_", "live_", "YOUR_KEY_GOES_HERE_PLEASE")}';`,
      `const aws = '${join("AKIA", "IOSFODNN7", "EXAMPLE")}';`,
      `if (key.startsWith('sk_live_')) warn();`,
      `const pk = '${join("pk_", "live_", RANDOM_24)}';`,
    ].join("\n");

    expect(scanFileText("src/backend/payments.ts", text)).toEqual([]);
  });

  test("finds a private key with its body", () => {
    const [finding] = scanFileText("deploy/key.pem", PRIVATE_KEY);

    expect(finding?.title).toBe("Private key in your code");
    expect(finding?.excerpt).toBe(PRIVATE_KEY_HEADER);
  });

  test("finds a private key escaped inside JSON (a service account file)", () => {
    const json = JSON.stringify({
      private_key: `${PRIVATE_KEY}\n`,
      type: "service_account",
    });

    expect(rules("google.json", json)).toEqual([
      ["secret-in-source", "severe"],
    ]);
  });

  test("code that handles PEM text is not a key", () => {
    const text = [
      `const header = '${PRIVATE_KEY_HEADER}';`,
      "const isKey = (pem: string) => pem.startsWith(header);",
      `const publicKey = '${join("-----BEGIN ", "PUBLIC KEY-----")}\\n${PEM_BODY}';`,
    ].join("\n");

    expect(scanFileText("src/backend/keys.ts", text)).toEqual([]);
  });
});

describe("database addresses with passwords", () => {
  test("finds a password for a hosted database and hides it", () => {
    const password = "Vq7xZ2mLp9Rk";
    const [finding] = scanFileText(
      "src/backend/db.ts",
      `const url = 'postgresql://app:${password}@ep-cool-fog-123.us-east-2.aws.neon.tech/neondb';`,
    );

    expect(finding?.severity).toBe("severe");
    expect(finding?.excerpt).toBe(
      "postgresql://app:••••@ep-cool-fog-123.us-east-2.aws.neon.tech",
    );
  });

  test("local, compose and placeholder addresses are fine", () => {
    const text = [
      "const local = 'postgres://postgres:postgres@localhost:5432/app';",
      "const compose = 'postgres://app:Vq7xZ2mLp9Rk@db:5432/app';",
      "const loopback = 'mysql://root:Vq7xZ2mLp9Rk@127.0.0.1/app';",
      "const docs = 'postgres://user:password@db.example.com/app';",
      "const env = `postgres://${user}:${pass}@${host}/app`;",
      "const shell = 'postgres://app:$PGPASSWORD@db.prod.acme.io/app';",
      "const fixture = 'postgresql://owner:synthetic-secret@ep-cool-darkness-123456.us-east-2.aws.neon.tech/neondb';",
      "const fromEnv = process.env.DATABASE_URL;",
    ].join("\n");

    expect(scanFileText("src/backend/db.ts", text)).toEqual([]);
  });
});

describe("secrets set up to reach browsers", () => {
  test("a public-prefixed secret is serious wherever it is read", () => {
    const text = [
      "const admin = createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);",
      "const stripe = process.env['NEXT_PUBLIC_STRIPE_SECRET_KEY'];",
      "const ai = import.meta.env.VITE_OPENAI_API_KEY;",
    ].join("\n");
    const found = scanFileText("src/lib/clients.ts", text);

    expect(found.map((finding) => finding.excerpt)).toEqual([
      "VITE_SUPABASE_SERVICE_ROLE_KEY",
      "NEXT_PUBLIC_STRIPE_SECRET_KEY",
      "VITE_OPENAI_API_KEY",
    ]);
    expect(
      found.every(
        (finding) =>
          finding.rule === "public-env-secret" && finding.severity === "severe",
      ),
    ).toBe(true);
  });

  test("public values that are meant to be public are fine", () => {
    const text = [
      "const pk = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY;",
      "const anon = import.meta.env.VITE_SUPABASE_ANON_KEY;",
      "const firebase = process.env.NEXT_PUBLIC_FIREBASE_API_KEY;",
      "const mapbox = process.env.NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN;",
      "const rule = import.meta.env.VITE_PASSWORD_MIN_LENGTH;",
      "type Env = { VITE_SUPABASE_SERVICE_ROLE_KEY: string };",
    ].join("\n");

    expect(scanFileText("src/lib/clients.ts", text)).toEqual([]);
  });

  test("AbsoluteJS page code reading a server secret is worth fixing", () => {
    const text = "const key = process.env.STRIPE_SECRET_KEY;";

    expect(rules("src/frontend/pages/Checkout.tsx", text)).toEqual([
      ["browser-env-secret", "warning"],
    ]);
    // The same line in backend code is how it should be done.
    expect(rules("src/backend/payments.ts", text)).toEqual([]);
  });

  test("tests may name any variable they like", () => {
    const text = [
      'process.env.STRIPE_SECRET_KEY = "x";',
      "const admin = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;",
    ].join("\n");

    expect(scanFileText("src/frontend/pages/Checkout.test.tsx", text)).toEqual(
      [],
    );
  });

  test("a code sample shown on a docs page is not code that runs", () => {
    const text = [
      "const sample = 'const ai = process.env.OPENAI_API_KEY;';",
      "const block = `aiChat({ apiKey: import.meta.env.VITE_OPENAI_API_KEY })`;",
      "// import.meta.env.VITE_JWT_SECRET is never read here",
      "/* process.env.STRIPE_SECRET_KEY */",
    ].join("\n");

    expect(scanFileText("src/frontend/pages/Docs.tsx", text)).toEqual([]);
  });

  test("an expression inside a template is code that runs", () => {
    const text =
      "const url = `${base}?key=${import.meta.env.VITE_OPENAI_API_KEY}`;";

    expect(rules("src/frontend/pages/Chat.tsx", text)).toEqual([
      ["public-env-secret", "severe"],
    ]);
  });

  test("page code reading ordinary settings is fine", () => {
    const text = [
      "const mode = process.env.NODE_ENV;",
      "const origin = process.env.PUBLIC_SITE_URL;",
    ].join("\n");

    expect(scanFileText("src/frontend/pages/Home.tsx", text)).toEqual([]);
  });

  test("reports each secret name once per file", () => {
    const text = [
      "a(import.meta.env.VITE_JWT_SECRET);",
      "b(import.meta.env.VITE_JWT_SECRET);",
    ].join("\n");

    expect(scanFileText("src/lib/auth.ts", text)).toHaveLength(1);
  });
});

describe("files in the wrong place", () => {
  test("a database file or settings file in a served folder is serious", () => {
    expect(
      checkPublicFile("public/backup.sql", DEFAULT_PROJECT_LAYOUT)?.severity,
    ).toBe("severe");
    expect(checkPublicFile("public/.env", DEFAULT_PROJECT_LAYOUT)?.title).toBe(
      "Your settings file can be downloaded",
    );
    expect(
      checkPublicFile("src/backend/assets/data.sqlite", DEFAULT_PROJECT_LAYOUT)
        ?.severity,
    ).toBe("severe");
  });

  test("ordinary served files and data kept elsewhere are fine", () => {
    expect(
      checkPublicFile("public/logo.png", DEFAULT_PROJECT_LAYOUT),
    ).toBeNull();
    expect(
      checkPublicFile("public/.env.example", DEFAULT_PROJECT_LAYOUT),
    ).toBeNull();
    expect(checkPublicFile("db/seed.sql", DEFAULT_PROJECT_LAYOUT)).toBeNull();
    expect(
      checkPublicFile("publications/a.db", DEFAULT_PROJECT_LAYOUT),
    ).toBeNull();
  });

  test("any committed .env file is severe, defaults included", () => {
    expect(checkCommittedEnvFile(".env.local")?.severity).toBe("severe");
    expect(
      checkCommittedEnvFile("apps/web/.env.production.local")?.severity,
    ).toBe("severe");
    expect(checkCommittedEnvFile(".env")?.severity).toBe("severe");
    expect(checkCommittedEnvFile(".env.production")?.severity).toBe("severe");
  });

  test("committed templates and other dotfiles are fine", () => {
    expect(checkCommittedEnvFile(".env.example")).toBeNull();
    expect(checkCommittedEnvFile(".env.sample")).toBeNull();
    expect(checkCommittedEnvFile(".envrc")).toBeNull();
    expect(checkCommittedEnvFile("src/env.ts")).toBeNull();
  });

  test("credential files are never opened", () => {
    expect(isCredentialFile(".env")).toBe(true);
    expect(isCredentialFile("apps/web/.env.local")).toBe(true);
    expect(isCredentialFile(".npmrc")).toBe(true);
    expect(isCredentialFile("src/env.ts")).toBe(false);
  });
});

describe("project layout", () => {
  test("reads page and served folders from absolute.config", () => {
    const layout = layoutFromConfig(`export default defineConfig({
			reactDirectory: "./src/web/",
			publicDirectory: 'static',
			assetsDirectory: "src/backend/assets",
		});`);

    expect(layout).toEqual({
      frontendDirectories: ["src/web"],
      publicDirectories: ["static", "src/backend/assets"],
    });
  });

  test("a page folder of src cannot tell pages from the server", () => {
    const layout = layoutFromConfig('reactDirectory: "src"');

    expect(layout.frontendDirectories).toEqual([]);
    expect(
      scanFileText(
        "src/server.ts",
        "const key = process.env.STRIPE_SECRET_KEY;",
        layout,
      ),
    ).toEqual([]);
  });

  test("falls back to the template layout", () => {
    expect(layoutFromConfig(null)).toEqual(DEFAULT_PROJECT_LAYOUT);
    expect(layoutFromConfig("export default {}")).toEqual(
      DEFAULT_PROJECT_LAYOUT,
    );
  });
});

test("redact keeps only the ends of long values", () => {
  expect(redact(STRIPE_LIVE)).toBe(`sk_live_…${STRIPE_LIVE.slice(-4)}`);
  expect(redact("short")).toBe("••••");
});
