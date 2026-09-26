import { test } from "node:test";
import assert from "node:assert/strict";
import { grantRole } from "../src/index.js";
import { BASE, makeAuth, signIn } from "./helpers.js";

async function sessionFor(auth: any, cookie: string) {
  const token = /session_token=([^;]+)/.exec(cookie)![1];
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/get-session`, { headers: { cookie: `better-auth.session_token=${token}` } }),
  );
  return res.json();
}

test("grant admin: role written, old sessions revoked, new session carries the role", async () => {
  const auth = await makeAuth();
  await auth.api.signUpEmail({ body: { email: "ops@example.com", password: "ops-password-1", name: "Ops" } });
  const before = await signIn(auth, "ops@example.com", "ops-password-1");
  assert.equal((await sessionFor(auth, before.cookie!)).user.role, "user", "admin plugin default role");

  const r = await grantRole(auth, "OPS@example.com", "admin");
  assert.equal(r.before, "user");
  assert.equal(r.after, "admin");

  assert.equal(await sessionFor(auth, before.cookie!), null, "pre-grant session no longer valid");
  const after = await signIn(auth, "ops@example.com", "ops-password-1");
  assert.equal((await sessionFor(auth, after.cookie!)).user.role, "admin");
});

test("grantRole rejects junk role names and unknown users", async () => {
  const auth = await makeAuth();
  await assert.rejects(grantRole(auth, "x@example.com", "Admin; drop"), /invalid role/);
  await assert.rejects(grantRole(auth, "nobody@example.com", "admin"), /user not found/);
});
