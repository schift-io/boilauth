import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DEFAULT_ANSWERS, getPath, normalizeAnswers, validateAnswers } from "../src/wizard/answers.js";
import { QUESTIONS, type Question } from "../src/wizard/questions.js";
import { offeredOptions, parseOverride, runWizard } from "../src/wizard/run.js";
import { mergePackageJson, packageJson, planProject } from "../src/generate/project.js";

test("one question per policy key in docs/EDGE_CASES.md, and every question key is a real answer field", () => {
  const doc = readFileSync(new URL("../docs/EDGE_CASES.md", import.meta.url), "utf8");
  const docKeys = [...doc.matchAll(/^\| [^|]+ \| `([a-zA-Z.]+)` \|/gm)].map((m) => m[1]);
  const qKeys = QUESTIONS.map((q) => q.key);
  assert.ok(docKeys.length >= 20, `found only ${docKeys.length} policy keys in the doc`);
  assert.deepEqual([...qKeys].sort(), [...new Set(docKeys)].sort());
  assert.equal(new Set(qKeys).size, qKeys.length, "duplicate question");
  for (const k of qKeys) assert.notEqual(getPath(DEFAULT_ANSWERS, k), undefined, k);
});

test("the bold default in docs/EDGE_CASES.md is the default the wizard uses", () => {
  const doc = readFileSync(new URL("../docs/EDGE_CASES.md", import.meta.url), "utf8");
  const rows = [...doc.matchAll(/^\| [^|]+ \| `([a-zA-Z.]+)` \| ([^|]+) \|/gm)];
  assert.ok(rows.length >= 20);
  for (const [, key, choices] of rows) {
    const bold = /\*\*`?([^*`]+)`?\*\*/.exec(choices)?.[1];
    assert.ok(bold, `${key}: no bold default in the doc`);
    const def = getPath(DEFAULT_ANSWERS, key);
    const expected = Array.isArray(def)
      ? def.length ? def.join(",") : "none"
      : typeof def === "boolean" ? (def ? "yes" : "no") : String(def);
    assert.equal(bold, expected, key);
  }
});

test("interactive run: `when` hides questions that do not apply, hidden options are not offered", async () => {
  const asked: string[] = [];
  const offered: Record<string, string[]> = {};
  const script: Record<string, unknown> = {
    "situation.existingUsers": true,
    "signIn.emailPassword": true,
    "signIn.oauth": [],
    "migration.sources": ["firebase"],
    "roles.mode": "none",
    "mfa.mode": "totp_optional",
  };
  const ask = async (q: Question, current: unknown, a: typeof DEFAULT_ANSWERS) => {
    asked.push(q.key);
    offered[q.key] = (q.options ?? []).filter((o) => !q.hideOption?.(a, o.value)).map((o) => o.value);
    return q.key in script ? script[q.key] : current;
  };
  const a = await runWizard({ yes: false, existing: null, ask });
  assert.ok(asked.includes("migration.firebase.rounds"), "firebase params asked when firebase chosen");
  assert.ok(!asked.includes("linking.mode"), "linking not asked without OAuth");
  assert.ok(!asked.includes("roles.custom") && !asked.includes("roles.orgCreation"));
  assert.ok(!offered["mfa.mode"].includes("totp_required_admin"), "admin-only MFA hidden when roles = none");
  assert.equal(a.mfa.mode, "totp_optional");
});

test("re-run: keys already in the answers file are not asked again; --set overrides", async () => {
  const asked: string[] = [];
  const ask = async (q: Question, current: unknown) => {
    asked.push(q.key);
    return current;
  };
  const existing = { runtime: { database: "postgres" }, roles: { mode: "custom", custom: ["admin", "user", "ops"] } };
  const a = await runWizard({ yes: false, existing, ask, overrides: Object.fromEntries([parseOverride("session.days=14")]) });
  assert.ok(!asked.includes("runtime.database") && !asked.includes("roles.mode") && !asked.includes("session.days"));
  assert.equal(a.runtime.database, "postgres");
  assert.equal(a.session.days, 14);
  assert.deepEqual(a.roles.custom, ["admin", "user", "ops"]);
  assert.deepEqual(await runWizard({ yes: true, existing: a as never }), a, "same answers in, same answers out");
});

/** Runs the wizard answering only `script`; everything else keeps the offered default. */
async function answer(script: Record<string, unknown>) {
  const asked: string[] = [];
  const offered: Record<string, string[]> = {};
  const a = await runWizard({
    yes: false, existing: null,
    ask: async (q, current, ans) => {
      asked.push(q.key);
      offered[q.key] = offeredOptions(q, ans).map((o) => o.value);
      return q.key in script ? script[q.key] : current;
    },
  });
  return { a, asked, offered };
}

test("situation comes first; with no existing users the migration questions are skipped", async () => {
  const { a, asked } = await answer({});
  assert.deepEqual(asked.slice(0, 2), ["situation.existingUsers", "situation.audience"]);
  for (const k of ["situation.currentSignIn", "migration.sources", "situation.sourceVerifiedEmail"]) assert.ok(!asked.includes(k), k);
  assert.deepEqual(a, DEFAULT_ANSWERS, "accepting every default = --yes");
});

test("existing users: today's sign-in methods become the defaults, sources asked right after", async () => {
  const { a, asked } = await answer({
    "situation.existingUsers": true,
    "situation.currentSignIn": ["email_password", "kakao", "google"],
    "migration.sources": ["supabase"],
    "situation.sourceVerifiedEmail": "no",
  });
  assert.deepEqual(asked.slice(0, 5), ["situation.existingUsers", "situation.currentSignIn", "migration.sources", "situation.sourceVerifiedEmail", "situation.audience"]);
  assert.equal(a.signIn.emailPassword, true);
  assert.deepEqual(a.signIn.oauth, ["kakao", "google"]);
  assert.deepEqual(a.migration.sources, ["supabase"]);
  assert.equal(a.email.verification, "optional", "unverified source: imported users can still sign in");
  assert.ok(asked.includes("email.verification") && asked.includes("signIn.oauth"), "derived defaults are still asked");
});

test("existing users without passwords are not asked where their hashes are", async () => {
  const { a, asked } = await answer({ "situation.existingUsers": true, "situation.currentSignIn": ["magic_link"] });
  assert.ok(!asked.includes("migration.sources"));
  assert.deepEqual([a.signIn.emailPassword, a.signIn.magicLink], [false, true]);
  assert.deepEqual(validateAnswers(a), []);
});

test("audience sets roles and MFA defaults; an explicit answer wins", async () => {
  assert.equal((await answer({ "situation.audience": "b2b" })).a.roles.mode, "organizations");
  const internal = (await answer({ "situation.audience": "internal" })).a;
  assert.deepEqual([internal.roles.mode, internal.mfa.mode], ["admin", "totp_required_admin"]);
  const overridden = (await answer({ "situation.audience": "internal", "mfa.mode": "off" })).a;
  assert.equal(overridden.mfa.mode, "off");
  assert.equal(normalizeAnswers({ situation: { audience: "b2b" }, roles: { mode: "none" } }).roles.mode, "none");
});

test("Kakao and Naver are extras: last in the OAuth list, never on by default", async () => {
  for (const audience of ["b2c", "b2b", "internal"]) {
    const { a, offered } = await answer({ "situation.audience": audience });
    assert.deepEqual(offered["signIn.oauth"].slice(-2), ["kakao", "naver"], audience);
    assert.deepEqual(a.signIn.oauth, [], audience);
  }
});

test("--yes takes the defaults from the doc", async () => {
  assert.deepEqual(await runWizard({ yes: true, existing: null }), DEFAULT_ANSWERS);
});

test("invalid combinations are refused with the key named", () => {
  const none = normalizeAnswers({ signIn: { emailPassword: false, magicLink: false, oauth: [] } });
  assert.match(validateAnswers(none).join(), /at least one sign-in method/);
  assert.match(validateAnswers(normalizeAnswers({ password: { minLength: 4 } })).join(), /password.minLength/);
  assert.match(validateAnswers(normalizeAnswers({ roles: { mode: "custom", custom: ["editor"] } })).join(), /must include "admin"/);
  assert.throws(() => parseOverride("nope.key=1"), /unknown policy key/);
});

test("generated code imports only the chosen modules", () => {
  const auth = (answers: object) => planProject(normalizeAnswers(answers)).find((f) => f.path === "src/auth.ts")!.content;
  const def = auth({});
  for (const absent of ["twoFactor", "organization", "magicLink", "haveIBeenPwned", "requireAdminMfa", "firebaseKeys", "socialProviders"]) {
    assert.ok(!def.includes(absent), `default project mentions ${absent}`);
  }
  const full = auth({
    signIn: { magicLink: true, oauth: ["kakao"] },
    password: { breachedCheck: "hibp" },
    mfa: { mode: "totp_required_admin" },
    roles: { mode: "organizations" },
    migration: { sources: ["firebase"] },
  });
  for (const present of ["twoFactor(", "organization(", "magicLink(", "haveIBeenPwned()", "requireAdminMfa(", "firebaseKeys", "socialProviders"]) {
    assert.ok(full.includes(present), `missing ${present}`);
  }
  const files = planProject(normalizeAnswers({ roles: { mode: "custom" } })).map((f) => f.path);
  assert.ok(files.includes("src/permissions.ts"));
  assert.ok(!planProject(DEFAULT_ANSWERS).some((f) => f.path === "src/permissions.ts"));
});

test("init adds what it needs to an existing package.json and keeps the developer's values", () => {
  const mine = JSON.stringify({ name: "shop", scripts: { test: 'echo "Error: no test specified" && exit 1', start: "node ." }, dependencies: { boilauth: "file:../boilauth.tgz" } });
  const { text, added } = mergePackageJson(mine, packageJson(DEFAULT_ANSWERS));
  const out = JSON.parse(text);
  assert.equal(out.name, "shop");
  assert.equal(out.type, "module");
  assert.equal(out.dependencies.boilauth, "file:../boilauth.tgz", "existing dependency kept");
  assert.ok(out.dependencies["better-auth"] && out.devDependencies.tsx);
  assert.match(out.scripts.test, /--test test/, "npm placeholder test script replaced");
  assert.equal(out.scripts.start, "node .");
  assert.ok(added.includes("scripts.migrate"));
  const again = mergePackageJson(text, packageJson(DEFAULT_ANSWERS));
  assert.deepEqual(again.added, [], "second init adds nothing");
});
