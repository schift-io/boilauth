/** F14 (audit 2026-09-27): hidden admin routes recognise admins the way the admin plugin does. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { admin } from "better-auth/plugins";
import { adminAc, userAc } from "better-auth/plugins/admin/access";
import { BASE, makeAuth, signIn } from "./helpers.js";

async function listUsers(auth: Awaited<ReturnType<typeof makeAuth>>, cookie?: string) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/admin/list-users`, { headers: { origin: BASE, ...(cookie ? { cookie } : {}) } }),
    { clientIp: "203.0.113.5" },
  );
  return res.status;
}

async function userCookie(auth: Awaited<ReturnType<typeof makeAuth>>, email: string) {
  const u = await auth.api.signUpEmail({ body: { email, password: "a-long-password-1", name: "X" } });
  const s = await signIn(auth, email, "a-long-password-1");
  return { id: u.user.id, cookie: s.cookie!.split(";")[0] };
}

test("F14: an admin listed in adminUserIds is not hidden from /admin/*", async () => {
  const id = "fixed-admin-id";
  const auth = await makeAuth({ hideAdminRoutes: true, admin: false, plugins: [admin({ adminUserIds: [id] })] });
  const ctx = await auth.$context;
  const now = new Date();
  await ctx.adapter.create({ model: "user", data: { id, email: "probe@example.com", name: "P", emailVerified: true, createdAt: now, updatedAt: now }, forceAllowId: true });
  await ctx.internalAdapter.createAccount({ userId: id, providerId: "credential", accountId: id, password: await ctx.password.hash("a-long-password-1") });
  const s = await signIn(auth, "probe@example.com", "a-long-password-1");
  assert.equal(await listUsers(auth, s.cookie!.split(";")[0]), 200);
});

test("F14: a custom admin role name from admin({ adminRoles }) is recognised", async () => {
  const auth = await makeAuth({ hideAdminRoutes: true, admin: false, plugins: [admin({ adminRoles: ["superuser"], roles: { superuser: adminAc, user: userAc } })] });
  const u = await userCookie(auth, "su@example.com");
  const ctx = await auth.$context;
  await ctx.internalAdapter.updateUser(u.id, { role: "superuser" });
  const s = await signIn(auth, "su@example.com", "a-long-password-1");
  assert.equal(await listUsers(auth, s.cookie!.split(";")[0]), 200);
  const plain = await userCookie(auth, "plain@example.com");
  assert.equal(await listUsers(auth, plain.cookie), 404);
  assert.equal(await listUsers(auth), 404);
});
