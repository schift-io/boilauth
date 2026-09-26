/**
 * F12 (audit 2026-09-27): an admin removing a user goes through the same deletion rules as
 * self-service deletion — the app's veto, and the records policy.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { accountDeletion } from "../src/modules/deletion.js";
import { BASE, makeAuth, signIn } from "./helpers.js";
import type { DeletionCheck } from "../src/modules/deletion-steps.js";

async function setup(o: Parameters<typeof accountDeletion>[0]) {
  const auth = await makeAuth({ plugins: [accountDeletion(o)] });
  const victim = await auth.api.signUpEmail({ body: { email: "victim@example.com", password: "a-long-password-1", name: "V" } });
  await auth.api.signUpEmail({ body: { email: "boss@example.com", password: "a-long-password-1", name: "B" } });
  const ctx = await auth.$context;
  const boss = (await ctx.internalAdapter.findUserByEmail("boss@example.com"))!.user;
  await ctx.internalAdapter.updateUser(boss.id, { role: "admin" });
  const s = await signIn(auth, "boss@example.com", "a-long-password-1");
  return { auth, ctx, victimId: victim.user.id, cookie: s.cookie!.split(";")[0] };
}

async function removeUser(auth: Awaited<ReturnType<typeof makeAuth>>, cookie: string, userId: string) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/admin/remove-user`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE, cookie },
      body: JSON.stringify({ userId }),
    }),
    { clientIp: "203.0.113.4" },
  );
  return { status: res.status, json: await res.json().catch(() => null) };
}

test("F12: the app's veto applies to /admin/remove-user", async () => {
  const canDelete: DeletionCheck = async () => ({ ok: false, code: "active_subscription", message: "has a subscription" });
  const { auth, ctx, victimId, cookie } = await setup({ mode: "hard", exportData: false, canDelete });
  const r = await removeUser(auth, cookie, victimId);
  assert.equal(r.status, 409, JSON.stringify(r.json));
  assert.equal(r.json.code, "active_subscription");
  assert.ok(await ctx.internalAdapter.findUserById(victimId), "user still there");
});

test("F12: records = anonymize applies to /admin/remove-user", async () => {
  const { auth, ctx, victimId, cookie } = await setup({ mode: "hard", exportData: false, records: "anonymize" });
  const r = await removeUser(auth, cookie, victimId);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const row = await ctx.internalAdapter.findUserById(victimId);
  assert.ok(row, "row kept");
  assert.match(row!.email, /@deleted\.invalid$/);
});

test("F12: a non-admin still cannot remove users", async () => {
  const { auth, victimId } = await setup({ mode: "hard", exportData: false, records: "anonymize" });
  await auth.api.signUpEmail({ body: { email: "nobody@example.com", password: "a-long-password-1", name: "N" } });
  const s = await signIn(auth, "nobody@example.com", "a-long-password-1");
  const r = await removeUser(auth, s.cookie!.split(";")[0], victimId);
  assert.equal(r.status, 403);
});
