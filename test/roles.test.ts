import { test } from "node:test";
import assert from "node:assert/strict";
import { admin } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { adminAc, defaultStatements, userAc } from "better-auth/plugins/admin/access";
import { grantRole } from "../src/index.js";
import { BASE, makeAuth, signIn } from "./helpers.js";

const customAccess = createAccessControl({ ...defaultStatements, project: ["read", "update"] });
const customRoles = {
  admin: customAccess.newRole({ ...adminAc.statements, project: ["read", "update"] }),
  user: customAccess.newRole({ ...userAc.statements, project: ["read"] }),
  editor: customAccess.newRole({ project: ["read", "update"] }),
};

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

test("RL-10: grantRole refuses an unconfigured custom role without changing role or sessions", async () => {
  const auth = await makeAuth({ admin: false, plugins: [admin({ ac: customAccess, roles: customRoles, adminRoles: ["admin"] })] });
  await auth.api.signUpEmail({ body: { email: "editor@example.com", password: "editor-password-1", name: "Editor" } });
  const before = await signIn(auth, "editor@example.com", "editor-password-1");
  const cookie = before.cookie;
  assert.ok(cookie);

  await assert.rejects(grantRole(auth, "editor@example.com", "root"), /not configured/);

  const ctx = await auth.$context;
  assert.equal((await ctx.internalAdapter.findUserByEmail("editor@example.com"))?.user.role, "user");
  assert.ok(await sessionFor(auth, cookie), "a refused role change deleted the user's session");
});
