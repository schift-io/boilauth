/**
 * Generates the project's tests from answers: one block per answered policy,
 * each asserting the behaviour that answer chose. Blocks are real TS files in
 * templates/tests with {{NAME}} placeholders.
 */
import { readFileSync } from "node:fs";
import type { Answers } from "../wizard/answers.js";
import { enabledModulesFor } from "./modules.js";
import { needsSendLimits, sendEndpoint } from "./auth-file.js";
import { MODULE_VERSIONS } from "../schema.js";

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
    (username ? '\nimport { loadUsernameRules } from "boilauth/username";' : "") +
    (a.deletion.guard ? '\nimport { canDelete } from "../src/deletion-guard.js";' : "");
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
  if (a.deletion.guard) extra.push("    canDelete,");
  if (a.signIn.phone) extra.push("    sms: async (m) => {\n      smsOutbox.push(m);\n    },");
  if (a.signIn.oauth.length || signInKind(a) === "google") {
    extra.push(
      `    oauth: { ${a.signIn.oauth.map((p) => `${p}: { clientId: "test-${p}-id", clientSecret: "test-${p}-secret" }`).join(", ")} } as AuthDeps["oauth"],`,
    );
  }
  let signInHelpers = tpl(`signin-${signInKind(a)}`, a.signIn.emailPassword ? { VERIFICATION_REQUIRED: a.email.verification === "required" } : {});
  if (a.signIn.oauth.length) signInHelpers = tpl("oauth-helpers") + "\n" + signInHelpers;
  if (a.signIn.emailOtp) signInHelpers = tpl("code-helpers") + "\n" + signInHelpers;
  if (a.signIn.phone) signInHelpers = tpl("sms-helpers", { PHONE_CC: a.phone.allowedCountries[0] ?? "82" }) + "\n" + signInHelpers;
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
      IP_MODE: JSON.stringify(
        a.network.clientIp === "header"
          ? { mode: "header", header: a.network.clientIpHeader }
          : a.network.clientIp === "proxy"
            ? { mode: "proxy", proxy: a.network.trustedProxies[0].split("/")[0] }
            : { mode: "socket" },
      ),
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
    blocks.push(clientIpBlock(a));
    if (a.lockout.maxFailures > 0) {
      blocks.push(tpl("lockout", { MAX_FAILURES: a.lockout.maxFailures, LOCK_MIN: a.lockout.minutes, ACCOUNT_MAX: a.lockout.accountMaxFailures }));
    }
    if (a.password.breachedCheck === "hibp") blocks.push(tpl("hibp"));
    for (const s of a.migration.sources) blocks.push(tpl(`migration-${s}`));
    if (a.signIn.username) {
      blocks.push(tpl("username"));
      blocks.push(tpl(a.rateLimit.usernameCheckPerIpPerHour > 0 ? "username-check-limited" : "username-check-off", { PER_HOUR: a.rateLimit.usernameCheckPerIpPerHour }));
      if (a.lockout.maxFailures > 0) blocks.push(tpl("username-lockout", { MAX_FAILURES: a.lockout.maxFailures }));
    }
  }
  if (a.signIn.magicLink) blocks.push(tpl("magic"));
  if (a.signIn.emailOtp) blocks.push(tpl("email-otp"));
  if (a.signIn.phone) {
    blocks.push(tpl("phone"));
    blocks.push(smsLimitsBlock(a));
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
  if (needsSendLimits(a)) {
    const ep = sendEndpoint(a)!;
    const vars = { SEND_PATH: ep.path, NEW_DEST: ep.newDest, BODY: ep.body("d"), BODY_OTHER: ep.body("other") };
    blocks.push(tpl("rate-limit-helpers"));
    if (a.rateLimit.sendPerIpPerHour > 0) blocks.push(tpl("rate-limit-ip", { ...vars, PER_IP: a.rateLimit.sendPerIpPerHour }));
    if (a.rateLimit.sendPerAccountPerHour > 0) blocks.push(tpl("rate-limit-account", { ...vars, PER_ACCOUNT: a.rateLimit.sendPerAccountPerHour }));
  }
  blocks.push(tpl("sessions", { DAYS: a.session.days, DEVICES: a.session.devices, FIRST_ALIVE: a.session.devices === "multi" }));
  blocks.push(tpl("session-absolute", { ABS_DAYS: a.session.absoluteDays }));
  if (a.session.bearer) {
    const signIn = pw
      ? `  const signInHeaders: Record<string, string> = { origin: h.BASE, "content-type": "application/json" };
  const info = h.ipOf(signInHeaders, h.nextIp());
  const res = await auth.handler(
    new Request(\`\${h.BASE}/api/auth/sign-in/email\`, { method: "POST", headers: signInHeaders, body: JSON.stringify({ email, password: h.PW }) }),
    info,
  );
  assert.equal(res.status, 200);
  const token = res.headers.get("set-auth-token");
  assert.ok(token, "sign-in answers with set-auth-token");
  assert.equal((await get({ authorization: \`Bearer \${token}\` }))?.user?.email, email);
`
      : "";
    blocks.push(tpl("bearer", { BEARER_SIGNIN: signIn }));
  }
  if (pw && a.notify.securityChanges) blocks.push(tpl("notify"));
  if (pw && a.notify.newDevice) blocks.push(tpl("notify-new-device"));
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
${a.mfa.allSignIns
    ? `  const otpSignIn = await h.call(auth, "/sign-in/email-otp", { body: { email, otp: h.lastCode(email) }, jar: otpJar });
  assert.equal(otpSignIn.json?.twoFactorRedirect, true, "an email code asks for the second factor");
  assert.equal(await h.currentSession(auth, otpJar), null);
`
    : `  await h.call(auth, "/sign-in/email-otp", { body: { email, otp: h.lastCode(email) }, jar: otpJar });
  assert.equal((await h.call(auth, "/admin/list-users", { jar: otpJar })).status, 403, "email code session skipped TOTP");
`}`
      : "";
    const phone = a.signIn.phone
      ? `  const phone = h.newPhone();
  await h.call(auth, "/phone-number/send-otp", { body: { phoneNumber: phone }, jar: plain });
  assert.equal((await h.call(auth, "/phone-number/verify", { body: { phoneNumber: phone, code: h.lastSms(phone), updatePhoneNumber: true }, jar: plain })).status, 200);
  await h.call(auth, "/phone-number/send-otp", { body: { phoneNumber: phone } });
  const smsJar: h.Jar = new Map();
${a.mfa.allSignIns
    ? `  const smsSignIn = await h.call(auth, "/phone-number/verify", { body: { phoneNumber: phone, code: h.lastSms(phone) }, jar: smsJar });
  assert.equal(smsSignIn.json?.twoFactorRedirect, true, "an SMS code asks for the second factor");
  assert.equal(await h.currentSession(auth, smsJar), null);
`
    : `  assert.equal((await h.call(auth, "/phone-number/verify", { body: { phoneNumber: phone, code: h.lastSms(phone) }, jar: smsJar })).status, 200);
  assert.equal((await h.call(auth, "/admin/list-users", { jar: smsJar })).status, 403, "SMS code session skipped TOTP");
`}`
      : "";
    const magic = a.signIn.magicLink
      ? `  const viaLink = await h.call(auth, "/sign-in/magic-link", { body: { email, callbackURL: "/" } });
  assert.equal(viaLink.status, 200);
  const linkJar: h.Jar = new Map();
${a.mfa.allSignIns
    ? `  const viaLinkVerify = await h.call(auth, h.lastMail(email, "/magic-link/verify"), { jar: linkJar });
  assert.match(viaLinkVerify.location ?? "", /twoFactorRedirect=true/, "a magic link asks for the second factor");
  assert.equal(await h.currentSession(auth, linkJar), null);
`
    : `  await h.call(auth, h.lastMail(email, "/magic-link/verify"), { jar: linkJar });
  assert.equal((await h.call(auth, "/admin/list-users", { jar: linkJar })).status, 403, "magic link session skipped TOTP");
`}`
      : "";
    blocks.push(tpl("mfa-admin", { MFA_ADMIN_MAGIC: magic + otp + phone }));
  }
  blocks.push(rolesBlock(a));
  blocks.push(...deletionBlocks(a));
  if (a.deletion.export) blocks.push(tpl("export"));
  const modules = Object.fromEntries(enabledModulesFor(a).map((m) => [m, MODULE_VERSIONS[m]]));
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

function deletionBlocks(a: Answers): string[] {
  const body = a.signIn.emailPassword ? "{ password: h.PW }" : "{}";
  const anon = a.deletion.records === "anonymize";
  const path = a.deletion.mode === "soft" || anon ? "/boilauth/delete-account" : "/delete-user";
  const out: string[] = [];
  if (a.deletion.mode === "soft") {
    const softAnon = anon
      ? `
  const kept = (await ctx.adapter.findMany<{ email: string }>({ model: "user" })).filter((u) => u.email.endsWith("@deleted.invalid"));
  assert.equal(kept.length, 1, "records = anonymize: purge keeps the row, anonymized");`
      : "";
    out.push(tpl("deletion-soft", { DELETE_BODY: body, SOFT_ANON: softAnon }));
  } else {
    out.push(tpl(anon ? "deletion-anonymize" : "deletion-hard", { DELETE_BODY: body }));
  }
  if (a.deletion.guard) out.push(tpl("deletion-guard", { DELETE_PATH: path, DELETE_BODY: body }));
  if (a.roles.mode === "organizations") {
    const branch =
      a.deletion.lastOrgOwner === "block"
        ? `  assert.equal((await del()).status, 409, "an admin exists, but ownership is not handed over by itself");
  const adminMember = (await members()).find((m) => m.user.email === admin.email);
  const promoted = await h.call(auth, "/organization/update-member-role", { body: { memberId: adminMember.id, role: "owner", organizationId }, jar: owner.jar });
  assert.equal(promoted.status, 200, JSON.stringify(promoted.json));
  const done = await del();
  assert.equal(done.status, 200, JSON.stringify(done.json));
  assert.equal(await roleOf(admin.email), "owner");
`
        : `  const done = await del();
  assert.equal(done.status, 200, JSON.stringify(done.json));
  assert.equal(await roleOf(admin.email), "owner", "the oldest admin took over");
`;
    out.push(tpl("deletion-org", { LAST_OWNER: a.deletion.lastOrgOwner, ORG_OWNER_SETUP: orgOwnerSetup(a), DELETE_PATH: path, DELETE_BODY: body, LAST_OWNER_BRANCH: branch }));
  }
  return out;
}

function orgOwnerSetup(a: Answers): string {
  return a.roles.orgCreation === "admin_only"
    ? `  await boil.grantRole(auth, owner.email, "admin");
  owner.jar = await h.signIn(auth, owner.email);
`
    : "";
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
      return tpl("roles-admin", { ADMIN_ALLOWED: allowed, ...adminDenied(a) });
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
      return tpl("roles-admin", { ADMIN_ALLOWED: allowed, ...adminDenied(a) }) + "\n" + tpl("roles-custom", { ROLES: a.roles.custom.join(", "), CUSTOM_ROLE_CHECKS: checks });
    }
    case "organizations": {
      const adminOnly = a.roles.orgCreation === "admin_only";
      const setup = orgOwnerSetup(a);
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
      return tpl("roles-admin", { ADMIN_ALLOWED: allowed, ...adminDenied(a) }) + "\n" + tpl("roles-org", { ORG_OWNER_SETUP: setup, ORG_ADMIN_ONLY: adminOnlyTest });
    }
  }
}

function adminDenied(a: Answers): { ADMIN_DENIED: number; ADMIN_ANON: string } {
  return a.roles.hideAdmin
    ? {
        ADMIN_DENIED: 404,
        ADMIN_ANON: '\n  assert.equal((await h.call(auth, "/admin/list-users")).status, 404, "no session: the route looks absent too");',
      }
    : { ADMIN_DENIED: 403, ADMIN_ANON: "" };
}

function ident(role: string): string {
  return "role_" + role.replace(/[^a-z0-9_]/g, "_");
}

/** Rotating X-Forwarded-For must not buy fresh sign-in attempts, whatever network.clientIp says. */
function clientIpBlock(a: Answers): string {
  const n = a.network;
  const request =
    n.clientIp === "socket"
      ? { HEADERS: '{ "x-forwarded-for": `198.51.100.${i + 1}` }', INFO: '{ clientIp: "203.0.113.9" }', MODE: "the socket address" }
      : n.clientIp === "proxy"
        ? {
            HEADERS: '{ "x-forwarded-for": `1.2.3.${i + 1}, 203.0.113.9` }',
            INFO: `{ clientIp: ${JSON.stringify(n.trustedProxies[0].split("/")[0])} }`,
            MODE: "the right-most hop that is not a trusted proxy",
          }
        : { HEADERS: `{ ${JSON.stringify(n.clientIpHeader)}: "203.0.113.9", "x-forwarded-for": \`198.51.100.\${i + 1}\` }`, INFO: "undefined", MODE: `the ${n.clientIpHeader} header` };
  return tpl("client-ip", { ...request, RATE: a.rateLimit.signInPerMinute });
}

/** SMS pumping guards (audit F2): the country allowlist and the site-wide SMS budget. */
function smsLimitsBlock(a: Answers): string {
  const out: string[] = [];
  if (a.phone.allowedCountries.length) {
    const other = ["234", "7", "62", "44"].find((c) => !a.phone.allowedCountries.includes(c))!;
    out.push(`test("phone: numbers outside the allowed countries (${a.phone.allowedCountries.join(", ")}) get 400 and no SMS", { skip: h.SKIP }, async () => {
  const auth = await h.makeAuth();
  const before = h.smsOutbox.length;
  const r = await h.call(auth, "/phone-number/send-otp", { body: { phoneNumber: "+${other}9012345678" } });
  assert.equal(r.status, 400);
  assert.equal(h.smsOutbox.length, before);
});
`);
  }
  if (a.rateLimit.smsPerHour > 0 && a.rateLimit.smsPerHour <= 300) out.push(tpl("sms-budget", { PER_HOUR: a.rateLimit.smsPerHour }));
  return out.join("\n");
}
