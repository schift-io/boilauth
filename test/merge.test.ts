import { test } from "node:test";
import assert from "node:assert/strict";
import { importUsers, type ImportRecord } from "../src/index.js";
import { makeAuth, signIn, storedHash } from "./helpers.js";

const BCRYPT_UU = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"; // "U*U"

async function existingUser(auth: any, email: string, verified: boolean, withPassword: boolean) {
  const ctx = await auth.$context;
  const user = await ctx.internalAdapter.createUser({ email, name: "Existing", emailVerified: verified });
  if (withPassword) {
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "credential",
      accountId: user.id,
      password: await auth.boilauth.hasher.hash("existing-password-1"),
    });
  }
  return user.id as string;
}

const rec = (over: Partial<ImportRecord>): ImportRecord => ({
  sourceId: "src-1",
  email: "sam@example.com",
  emailVerified: true,
  passwordHash: BCRYPT_UU,
  ...over,
});

test("verified + verified → merged into the existing user; imported password attached when none existed", async () => {
  const auth = await makeAuth();
  const id = await existingUser(auth, "sam@example.com", true, false);
  const r = await importUsers(auth, "supabase", [rec({ email: "SAM@example.com" })]);
  assert.equal(r.merged, 1);
  assert.deepEqual(r.outcomes[0], { sourceId: "src-1", email: "sam@example.com", result: "merged", userId: id, password: "attached" });
  assert.equal((await signIn(auth, "sam@example.com", "U*U")).status, 200);
});

test("verified + verified with an existing password → merged, existing password kept", async () => {
  const auth = await makeAuth();
  await existingUser(auth, "sam@example.com", true, true);
  const r = await importUsers(auth, "auth0", [rec({})]);
  assert.equal(r.outcomes[0].result === "merged" && r.outcomes[0].password, "kept_existing");
  assert.equal((await signIn(auth, "sam@example.com", "U*U")).status, 401);
  assert.equal((await signIn(auth, "sam@example.com", "existing-password-1")).status, 200);
});

test("existing user NOT verified → no merge, nothing written", async () => {
  const auth = await makeAuth();
  await existingUser(auth, "sam@example.com", false, false);
  const r = await importUsers(auth, "supabase", [rec({})]);
  assert.deepEqual(r.outcomes[0], { sourceId: "src-1", email: "sam@example.com", result: "skipped", reason: "email_conflict_unverified" });
  assert.equal(await storedHash(auth, "sam@example.com"), null);
  const ctx = await auth.$context;
  assert.equal(await ctx.adapter.count({ model: "importedIdentity" }), 0);
});

test("imported record NOT verified → no merge into a verified user", async () => {
  const auth = await makeAuth();
  await existingUser(auth, "sam@example.com", true, false);
  const r = await importUsers(auth, "firebase", [rec({ emailVerified: false })]);
  assert.equal(r.skipped, 1);
  assert.equal(r.outcomes[0].result === "skipped" && r.outcomes[0].reason, "email_conflict_unverified");
  assert.equal(await storedHash(auth, "sam@example.com"), null);
});

test("same person in two sources (both verified) → one user, two imported identities", async () => {
  const auth = await makeAuth();
  const a = await importUsers(auth, "supabase", [rec({ sourceId: "sb-1" })]);
  const b = await importUsers(auth, "auth0", [rec({ sourceId: "a0-1" })]);
  assert.equal(a.created, 1);
  assert.equal(b.merged, 1);
  const ctx = await auth.$context;
  const ids = await ctx.adapter.findMany({ model: "importedIdentity" });
  assert.equal(ids.length, 2);
  assert.equal(new Set(ids.map((i: any) => i.userId)).size, 1);
});
