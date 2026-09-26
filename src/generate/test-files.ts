/**
 * Generates the project's tests from answers: one block per answered policy,
 * each asserting the behaviour that answer chose. Blocks are real TS files in
 * templates/tests with {{NAME}} placeholders.
 */
import { readFileSync } from "node:fs";
import type { Answers } from "../wizard/answers.js";
import { enabledModulesFor } from "./modules.js";

const TPL = new URL("../../templates/tests/", import.meta.url);

function tpl(name: string, vars: Record<string, string | number | boolean> = {}): string {
  let s = readFileSync(new URL(`${name}.ts.tmpl`, TPL), "utf8");
  for (const [k, v] of Object.entries(vars)) s = s.split(`{{${k}}}`).join(String(v));
  const left = /\{\{[A-Z_]+\}\}/.exec(s);
  if (left) throw new Error(`template ${name}: unfilled ${left[0]}`);
  return s;
}

const OAUTH_HOSTS: Record<string, string> = {
  google: "accounts.google.com",
  github: "github.com",
  apple: "appleid.apple.com",
  kakao: "kauth.kakao.com",
  naver: "nid.naver.com",
};

export const FIXTURES: Record<string, string> = {
  supabase: "supabase-users.json",
  firebase: "firebase-users.json",
  auth0: "auth0-users.ndjson",
  generic: "generic-users.csv",
};

function signInKind(a: Answers): "password" | "magic" | "otp" | "google" {
  if (a.signIn.emailPassword) return "password";
  if (a.signIn.magicLink) return "magic";
  if (a.signIn.emailOtp) return "otp";
  return "google";
}

export function helpersFile(a: Answers): string {
  const pg = a.runtime.database === "postgres";
  const username = a.signIn.emailPassword && a.signIn.username;
  const dbImport =
    (pg ? 'import pg from "pg";' : 'import { DatabaseSync } from "node:sqlite";') +
    (username ? '\nimport { loadUsernameRules } from "boilauth/username";' : "");
  const dbFactory = pg
    ? `export const SKIP: string | false = process.env.TEST_DATABASE_URL ? false : "TEST_DATABASE_URL not set";

/** A fresh Postgres schema per auth instance, dropped after the run. */
async function testDatabase(): Promise<AuthDeps["database"]> {
  const url = process.env.TEST_DATABASE_URL!;
  const schema = "boilauth_test_" + randomBytes(5).toString("hex");
  const admin = new pg.Pool({ connectionString: url, max: 1 });
  await admin.query(\`create schema \${schema}\`);
  const pool = new pg.Pool({ connectionString: url, max: 4, options: \`-c search_path=\${schema}\` });
  cleanups.push(async () => {
    await pool.end();
    await admin.query(\`drop schema \${schema} cascade\`);
    await admin.end();
  });
  return pool;
}`
    : `export const SKIP: string | false = false;

async function testDatabase(): Promise<AuthDeps["database"]> {
  return new DatabaseSync(":memory:");
}`;
  const extra: string[] = [];
  if (a.migration.sources.includes("firebase")) extra.push("    firebaseKeys: [FIREBASE_SAMPLE_KEY],");
  if (username) extra.push("    usernameRules: USERNAME_RULES,");
  if (a.signIn.phone) extra.push("    sms: async (m) => {\n      smsOutbox.push(m);\n    },");
  if (a.signIn.oauth.length || signInKind(a) === "google") {
    extra.push(
      `    oauth: { ${a.signIn.oauth.map((p) => `${p}: { clientId: "test-${p}-id", clientSecret: "test-${p}-secret" }`).join(", ")} } as AuthDeps["oauth"],`,
    );
  }
  let signInHelpers = tpl(`signin-${signInKind(a)}`, a.signIn.emailPassword ? { VERIFICATION_REQUIRED: a.email.verification === "required" } : {});
  if (a.signIn.oauth.length) signInHelpers = tpl("oauth-helpers") + "\n" + signInHelpers;
  if (a.signIn.emailOtp) signInHelpers = tpl("code-helpers") + "\n" + signInHelpers;
  if (a.signIn.phone) signInHelpers = tpl("sms-helpers") + "\n" + signInHelpers;
  const firebaseKey = a.migration.sources.includes("firebase")
    ? `/** Public sample params from the firebase/scrypt README, not a real project key. */
export const FIREBASE_SAMPLE_KEY = {
  keyId: "sample-project",
  signerKey: "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
  saltSeparator: "Bw==",
  rounds: 8,
  memCost: 14,
};\n\n`
    : "";
  // Google drives the callback tests; when it is not a chosen provider it is added for tests only.
  const googleForTests =
    a.signIn.oauth.length && !a.signIn.oauth.includes("google")
      ? '    betterAuth: { socialProviders: { google: { clientId: "test-google-id", clientSecret: "test-google-secret" } } },\n'
      : "";
  const hibpStub =
    a.signIn.emailPassword && a.password.breachedCheck === "hibp"
      ? `
// Have I Been Pwned is on: tests never reach the real API. Default answer is "not breached";
// the breached-password test overrides it with withFetch.
const networkFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (url.startsWith("https://api.pwnedpasswords.com/range/")) return new Response("0000000000000000000000000000000000A:1");
  return networkFetch(input, init);
}) as typeof fetch;
`
      : "";
  return (
    tpl("helpers", {
      DB_IMPORT: dbImport,
      DB_FACTORY:
        firebaseKey +
        (username
          ? '/** The project\'s own rules file: the username tests follow whatever it says. */\nexport const USERNAME_RULES = loadUsernameRules(new URL("../boilauth.username.yaml", import.meta.url));\n\n'
          : "") +
        dbFactory,
      DEPS_EXTRA: extra.map((l) => l + "\n").join(""),
      SIGN_IN_HELPERS: signInHelpers,
    }).replace("    ...over,\n    betterAuth: { logger: { disabled: true }, ...over.betterAuth },", fixBetterAuth(googleForTests)) +
    hibpStub +
    "\nexport type { Auth };\n"
  );
}

function fixBetterAuth(googleForTests: string): string {
  const base = "logger: { disabled: true }";
  const extra = googleForTests
    ? `${base}, socialProviders: { google: { clientId: "test-google-id", clientSecret: "test-google-secret" } }`
    : base;
  return `    ...over,\n    betterAuth: { ${extra}, ...over.betterAuth },`;
}

export function testFile(a: Answers): string {
  const pw = a.signIn.emailPassword;
  const blocks: string[] = [];
  if (pw) {
    blocks.push(
      tpl("core", {
        VERIFICATION: a.email.verification,
        EARLY_STATUS: a.email.verification === "required" ? 403 : 200,
        MIN_LEN: a.password.minLength,
        RATE: a.rateLimit.signInPerMinute,
      }),
    );
    if (a.lockout.maxFailures > 0) blocks.push(tpl("lockout", { MAX_FAILURES: a.lockout.maxFailures, LOCK_MIN: a.lockout.minutes }));
    if (a.password.breachedCheck === "hibp") blocks.push(tpl("hibp"));
    for (const s of a.migration.sources) blocks.push(tpl(`migration-${s}`));
    if (a.signIn.username) {
      blocks.push(tpl("username"));
      if (a.lockout.maxFailures > 0) blocks.push(tpl("username-lockout", { MAX_FAILURES: a.lockout.maxFailures }));
    }
  }
  if (a.signIn.magicLink) blocks.push(tpl("magic"));
  if (a.signIn.emailOtp) blocks.push(tpl("email-otp"));
  if (a.signIn.phone) {
    blocks.push(tpl("phone"));
    if (pw) {
      const lock = a.lockout.maxFailures > 0 ? tpl("phone-lockout", { MAX_FAILURES: a.lockout.maxFailures }) : "";
      blocks.push(tpl("phone-password", { PHONE_LOCKOUT: lock }));
    }
  }
  if (a.signIn.oauth.length) {
    const hosts = Object.fromEntries(a.signIn.oauth.map((p) => [p, OAUTH_HOSTS[p]]));
    blocks.push(tpl("oauth", { OAUTH_HOSTS: JSON.stringify(hosts) }));
    blocks.push(tpl("linking", { LINKING: a.linking.mode, LINK_VERIFIED: a.linking.mode === "verified_only" }));
  }
  blocks.push(tpl("sessions", { DAYS: a.session.days, DEVICES: a.session.devices, FIRST_ALIVE: a.session.devices === "multi" }));
  if (pw && a.session.devices === "multi") {
    blocks.push(
      tpl("password-change", {
        REVOKE_LABEL: a.session.revokeOnPasswordChange ? "ends" : "keeps",
        OTHER_ALIVE: !a.session.revokeOnPasswordChange,
      }),
    );
  }
  if (a.mfa.mode !== "off") {
    blocks.push(tpl("mfa-optional"));
    blocks.push(tpl("mfa-backup", { AMOUNT: a.mfa.backupCodes }));
    if (a.mfa.emailOtp) blocks.push(tpl("mfa-email", { ADMIN_CHECK: a.mfa.mode === "totp_required_admin" && a.roles.mode !== "none" }));
  }
  if (a.mfa.mode === "totp_required_admin") {
    const otp = a.signIn.emailOtp
      ? `  const otpJar: h.Jar = new Map();
  assert.equal((await h.call(auth, "/email-otp/send-verification-otp", { body: { email, type: "sign-in" } })).status, 200);
  await h.call(auth, "/sign-in/email-otp", { body: { email, otp: h.lastCode(email) }, jar: otpJar });
  assert.equal((await h.call(auth, "/admin/list-users", { jar: otpJar })).status, 403, "email code session skipped TOTP");
`
      : "";
    const phone = a.signIn.phone
      ? `  const phone = h.newPhone();
  await h.call(auth, "/phone-number/send-otp", { body: { phoneNumber: phone }, jar: plain });
  assert.equal((await h.call(auth, "/phone-number/verify", { body: { phoneNumber: phone, code: h.lastSms(phone), updatePhoneNumber: true }, jar: plain })).status, 200);
  await h.call(auth, "/phone-number/send-otp", { body: { phoneNumber: phone } });
  const smsJar: h.Jar = new Map();
  assert.equal((await h.call(auth, "/phone-number/verify", { body: { phoneNumber: phone, code: h.lastSms(phone) }, jar: smsJar })).status, 200);
  assert.equal((await h.call(auth, "/admin/list-users", { jar: smsJar })).status, 403, "SMS code session skipped TOTP");
`
      : "";
    const magic = a.signIn.magicLink
      ? `  const viaLink = await h.call(auth, "/sign-in/magic-link", { body: { email, callbackURL: "/" } });
  assert.equal(viaLink.status, 200);
  const linkJar: h.Jar = new Map();
  await h.call(auth, h.lastMail(email, "/magic-link/verify"), { jar: linkJar });
  assert.equal((await h.call(auth, "/admin/list-users", { jar: linkJar })).status, 403, "magic link session skipped TOTP");
`
      : "";
    blocks.push(tpl("mfa-admin", { MFA_ADMIN_MAGIC: magic + otp + phone }));
  }
  blocks.push(rolesBlock(a));
  const deleteBody = pw ? "{ password: h.PW }" : "{}";
  blocks.push(tpl(`deletion-${a.deletion.mode}`, { DELETE_BODY: deleteBody }));
  if (a.deletion.export) blocks.push(tpl("export"));
  const modules = Object.fromEntries(enabledModulesFor(a).map((m) => [m, 1]));
  blocks.push(tpl("schema", { MODULES: JSON.stringify(modules), MODULES_LABEL: Object.keys(modules).join(", ") }));

  const imports = [
    "// Generated by `boilauth init` from boilauth.answers.json: one block per answered policy.",
    "// Regenerated on every init; add your own tests in other files.",
    'import { test } from "node:test";',
    'import assert from "node:assert/strict";',
    'import * as boil from "boilauth";',
    ...(a.deletion.mode === "soft" ? ['import { purgeDeleted } from "boilauth/deletion";'] : []),
    'import * as h from "./helpers.js";',
  ];
  return `${imports.join("\n")}\n\n${blocks.join("\n")}`;
}

function rolesBlock(a: Answers): string {
  const mfaAdmin = a.mfa.mode === "totp_required_admin";
  const allowed = mfaAdmin
    ? '  // With TOTP required for admins, the allowed path is covered by the MFA test.\n'
    : `  const again = await h.signIn(auth, email);
  assert.equal((await h.call(auth, "/admin/list-users", { jar: again })).status, 200);
`;
  switch (a.roles.mode) {
    case "none":
      return tpl("roles-none");
    case "admin":
      return tpl("roles-admin", { ADMIN_ALLOWED: allowed });
    case "custom": {
      const extra = a.roles.custom.filter((r) => r !== "admin" && r !== "user");
      const checks = extra
        .map(
          (r) => `  const { email: ${ident(r)} } = await h.newUser(auth, "rc");
  await boil.grantRole(auth, ${ident(r)}, ${JSON.stringify(r)});
  assert.equal(await can(${ident(r)}, "update"), true, ${JSON.stringify(r)});
  assert.equal(await can(${ident(r)}, "delete"), false, ${JSON.stringify(r)});
`,
        )
        .join("");
      return tpl("roles-admin", { ADMIN_ALLOWED: allowed }) + "\n" + tpl("roles-custom", { ROLES: a.roles.custom.join(", "), CUSTOM_ROLE_CHECKS: checks });
    }
    case "organizations": {
      const adminOnly = a.roles.orgCreation === "admin_only";
      const setup = adminOnly
        ? `  await boil.grantRole(auth, owner.email, "admin");
  owner.jar = await h.signIn(auth, owner.email);
`
        : "";
      const adminOnlyTest = adminOnly
        ? `
test("organizations: only admins create them", { skip: h.SKIP }, async () => {
  const auth = await h.makeAuth();
  const { jar } = await h.newUser(auth, "noorg");
  const r = await h.call(auth, "/organization/create", { body: { name: "Nope", slug: \`nope-\${Date.now()}\` }, jar });
  assert.equal(r.status, 403);
});
`
        : "";
      return tpl("roles-admin", { ADMIN_ALLOWED: allowed }) + "\n" + tpl("roles-org", { ORG_OWNER_SETUP: setup, ORG_ADMIN_ONLY: adminOnlyTest });
    }
  }
}

function ident(role: string): string {
  return "role_" + role.replace(/[^a-z0-9_]/g, "_");
}
