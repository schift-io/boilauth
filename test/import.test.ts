import { test } from "node:test";
import assert from "node:assert/strict";
import {
  importUsers,
  parseAuth0Export,
  parseFirebaseExport,
  parseGenericExport,
  parseSupabaseExport,
  hashKind,
  type ImportRecord,
  type ImportSource,
} from "../src/index.js";
import { FIREBASE_SAMPLE_KEY, fixture, makeAuth, signIn, storedHash } from "./helpers.js";

/** Import, log in with the ORIGINAL password, check the hash was upgraded, log in again. */
async function importThenLogin(source: ImportSource, records: ImportRecord[], email: string, password: string, before: string) {
  const auth = await makeAuth();
  const report = await importUsers(auth, source, records);
  assert.ok(report.created >= 1, JSON.stringify(report));
  assert.equal(hashKind((await storedHash(auth, email))!), before);

  assert.equal((await signIn(auth, email, password + "!")).status, 401, "wrong password must fail");
  assert.equal(hashKind((await storedHash(auth, email))!), before, "failed login must not rehash");

  const first = await signIn(auth, email, password);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.ok(first.cookie?.includes("session_token"));
  assert.equal(hashKind((await storedHash(auth, email))!), "argon2id", "hash upgraded after login");

  const second = await signIn(auth, email, password);
  assert.equal(second.status, 200, "login still works on the argon2id hash");
  return { auth, report };
}

test("supabase JSON export: bcrypt $2a$ user logs in, hash upgraded", async () => {
  const records = parseSupabaseExport(fixture("supabase-users.json"));
  assert.equal(records[0].email, "Ada@Example.com");
  assert.equal(records[0].name, "Ada Lovelace");
  assert.equal(records[0].emailVerified, true);
  const { auth, report } = await importThenLogin("supabase", records, "ada@example.com", "U*U", "bcrypt");
  // OAuth-only row: created without password, cannot password-login.
  const o = report.outcomes.find((x) => x.email === "oauth-only@example.com");
  assert.deepEqual(o && o.result === "created" && o.password, false);
  assert.equal((await signIn(auth, "oauth-only@example.com", "anything-at-all")).status, 401);
});

test("supabase CSV export", async () => {
  const records = parseSupabaseExport(fixture("supabase-users.csv"));
  assert.equal(records[0].name, "Grace Hopper");
  await importThenLogin("supabase", records, "grace@example.com", "U*U*", "bcrypt");
});

test("firebase CSV export (firebase/scrypt README sample) logs in with user1password", async () => {
  const records = parseFirebaseExport(fixture("firebase-users.csv"), FIREBASE_SAMPLE_KEY);
  assert.equal(records[0].sourceId, "kYi4EvWQlQTKSfnJ3dRSP6IH3ed2");
  assert.equal(records[0].emailVerified, false);
  await importThenLogin("firebase", records, "user1@test.com", "user1password", "firebase-scrypt");
});

test("firebase JSON export", async () => {
  const records = parseFirebaseExport(fixture("firebase-users.json"), FIREBASE_SAMPLE_KEY);
  assert.equal(records[0].emailVerified, true);
  assert.equal(records[0].createdAt?.getTime(), 1508893925000);
  await importThenLogin("firebase", records, "user1@test.com", "user1password", "firebase-scrypt");
});

test("auth0 NDJSON export: $2b$ user logs in; md5 row reported as unsupported", async () => {
  const records = parseAuth0Export(fixture("auth0-users.ndjson"));
  assert.equal(records[0].sourceId, "60425dc43519d90068f82973");
  const { report } = await importThenLogin("auth0", records, "linus@example.com", "Kk4DQuMMfZL9o", "bcrypt");
  const md5 = report.outcomes.find((x) => x.email === "md5user@example.com");
  assert.deepEqual(md5, { sourceId: "60425dc43519d90068f82974", email: "md5user@example.com", result: "skipped", reason: "unsupported_hash" });
});

test("generic CSV export: bcrypt user logs in; a row without a hash is created without a password", async () => {
  const records = parseGenericExport(fixture("generic-users.csv"));
  assert.equal(records[0].sourceId, "u-1");
  assert.equal(records[0].emailVerified, true);
  assert.equal(records[1].emailVerified, false);
  assert.equal(records[1].passwordHash, null);
  const { auth, report } = await importThenLogin("generic", records, "margaret@example.com", "Kk4DQuMMfZL9o", "bcrypt");
  const o = report.outcomes.find((x) => x.email === "no-password@example.com");
  assert.deepEqual(o && o.result === "created" && o.password, false);
  assert.equal((await signIn(auth, "no-password@example.com", "anything-at-all")).status, 401);
});

test("generic JSON export reads the same columns", () => {
  const [r] = parseGenericExport(JSON.stringify([{ id: 7, email: "a@b.co", email_verified: "yes", password_hash: "" }]));
  assert.deepEqual([r.sourceId, r.emailVerified, r.passwordHash], ["7", true, null]);
});

test("MG-07: generic CSV rejects a truncated argon2id hash without storing the user", async () => {
  const records = parseGenericExport(
    "id,email,email_verified,password_hash,name,created_at\n" +
      "bad-argon,broken@example.com,true,$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$YWJj,Broken,",
  );
  assert.equal(records[0]?.passwordHash, "$argon2id$v=19$m=8192", "the unquoted CSV field is truncated at its first comma");

  const auth = await makeAuth();
  const report = await importUsers(auth, "generic", records);
  assert.deepEqual(report.outcomes, [
    {
      sourceId: "bad-argon",
      email: "broken@example.com",
      result: "skipped",
      reason: "unsupported_hash",
    },
  ]);
  assert.equal(await storedHash(auth, "broken@example.com"), null);
  const ctx = await auth.$context;
  assert.equal(await ctx.internalAdapter.findUserByEmail("broken@example.com"), null);
});

test("MG-07: every importer rejects incomplete supported hash encodings", async () => {
  const cases: [ImportSource, string, string][] = [
    ["supabase", "bad-supabase@example.com", "$2a$10$short"],
    ["firebase", "bad-firebase@example.com", "$firebase-scrypt$v=1$k=sample-project,r=8,m=14$AA==$Bw==$"],
    ["auth0", "bad-auth0@example.com", "$2b$12$short"],
    ["generic", "bad-generic@example.com", "$argon2id$v=19$m=8192"],
  ];
  const auth = await makeAuth();

  for (const [source, email, passwordHash] of cases) {
    const report = await importUsers(auth, source, [
      { sourceId: `bad-${source}`, email, emailVerified: true, passwordHash },
    ]);
    assert.deepEqual(report.outcomes, [
      { sourceId: `bad-${source}`, email, result: "skipped", reason: "unsupported_hash" },
    ]);
    assert.equal(await storedHash(auth, email), null);
  }
});

test("MG-07: malformed stored hashes sign in as a wrong password", async () => {
  const auth = await makeAuth();
  await auth.api.signUpEmail({
    body: { email: "corrupt@example.com", password: "a-long-password-1", name: "Corrupt" },
  });
  const ctx = await auth.$context;
  const found = await ctx.internalAdapter.findUserByEmail("corrupt@example.com");
  assert.ok(found);
  const account = await ctx.internalAdapter.findCredentialAccount(found.user.id);
  assert.ok(account);
  const malformed = [
    "$argon2id$v=19$m=8192",
    "$2b$10$short",
    "$firebase-scrypt$v=1$k=sample-project,r=8,m=14$AA==$Bw==$",
  ];

  for (const [index, passwordHash] of malformed.entries()) {
    await ctx.internalAdapter.updateAccount(account.id, { password: passwordHash });
    const result = await signIn(auth, "corrupt@example.com", "a-long-password-1", `198.51.100.${70 + index}`);
    assert.equal(result.status, 401, passwordHash);
    assert.equal(result.body?.code, "INVALID_EMAIL_OR_PASSWORD", passwordHash);
  }
});

test("re-running an import is idempotent", async () => {
  const auth = await makeAuth();
  const records = parseAuth0Export(fixture("auth0-users.ndjson"));
  await importUsers(auth, "auth0", records);
  const again = await importUsers(auth, "auth0", records);
  assert.equal(again.created, 0);
  assert.equal(again.merged, 0);
  assert.ok(again.outcomes.some((o) => o.result === "skipped" && o.reason === "already_imported"));
});
