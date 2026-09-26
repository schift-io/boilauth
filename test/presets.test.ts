/** Preset strength (audit 2026-09-27 F8, F10). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PRESETS } from "../src/index.js";
import { BASE, makeAuth, signIn } from "./helpers.js";

test("F8: the default minimum password length is 12 (ASVS 2.1.1); 'password12' and '1234567890' are refused", async () => {
  const auth = await makeAuth();
  assert.equal(PRESETS.minPasswordLength, 12);
  for (const [i, pw] of ["password12", "1234567890"].entries()) {
    await assert.rejects(auth.api.signUpEmail({ body: { email: `w${i}@example.com`, password: pw, name: "W" } }), /too short/i);
  }
  const ok = await auth.api.signUpEmail({ body: { email: "s@example.com", password: "twelve-chars", name: "S" } });
  assert.ok(ok.user.id);
});

async function getSession(auth: Awaited<ReturnType<typeof makeAuth>>, cookie: string) {
  const res = await auth.handler(new Request(`${BASE}/api/auth/get-session`, { headers: { cookie } }), { clientIp: "203.0.113.1" });
  return res.json();
}

async function signedIn() {
  const auth = await makeAuth();
  await auth.api.signUpEmail({ body: { email: "abs@example.com", password: "a-long-password-1", name: "A" } });
  const r = await signIn(auth, "abs@example.com", "a-long-password-1");
  assert.equal(r.status, 200);
  const cookie = r.cookie!.split(";")[0];
  const ctx = await auth.$context;
  const [row] = await ctx.adapter.findMany({ model: "session", where: [] });
  return { auth, cookie, ctx, row: row as { id: string; token: string; createdAt: Date } };
}

test("F10: a session older than 30 days ends even while in use", async () => {
  const { auth, cookie, ctx, row } = await signedIn();
  const day = 86_400_000;
  await ctx.adapter.update({
    model: "session",
    where: [{ field: "id", value: row.id }],
    update: { createdAt: new Date(Date.now() - 31 * day), expiresAt: new Date(Date.now() + 6 * day) },
  });
  assert.equal(await getSession(auth, cookie), null, "31-day-old session with a slid expiry is refused");
});

test("F10: refreshing a session never moves its expiry past createdAt + 30 days", async () => {
  const { auth, cookie, ctx, row } = await signedIn();
  const day = 86_400_000;
  const created = Date.now() - 29 * day;
  await ctx.adapter.update({
    model: "session",
    where: [{ field: "id", value: row.id }],
    update: { createdAt: new Date(created), expiresAt: new Date(Date.now() + day / 2) },
  });
  const s = await getSession(auth, cookie);
  assert.ok(s?.session, "still valid at 29 days");
  const [after] = await ctx.adapter.findMany<{ expiresAt: Date }>({ model: "session", where: [{ field: "id", value: row.id }] });
  assert.ok(new Date(after.expiresAt).getTime() <= created + 30 * day + 1000, `expiry ${new Date(after.expiresAt).toISOString()}`);
});
