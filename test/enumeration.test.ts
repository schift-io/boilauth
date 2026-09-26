/**
 * Account enumeration (audit 2026-09-27): responses and timings must not tell whether an
 * email, phone number or username is registered.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BASE, freshIp, makeAuth } from "./helpers.js";

type Auth = Awaited<ReturnType<typeof makeAuth>>;

async function post(auth: Auth, path: string, body: unknown, ip = freshIp()) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify(body),
    }),
    { clientIp: ip },
  );
  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

async function medianMs(n: number, run: () => Promise<unknown>): Promise<number> {
  const xs: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    await run();
    xs.push(performance.now() - t);
  }
  xs.sort((a, b) => a - b);
  return xs[Math.floor(n / 2)];
}

test("F5: with email verification optional, a duplicate sign-up answers like a new one", async () => {
  const auth = await makeAuth({ requireEmailVerification: false, sendEmail: async () => {} });
  const first = await post(auth, "/sign-up/email", { email: "dup@example.com", password: "a-long-password-1", name: "D" });
  const again = await post(auth, "/sign-up/email", { email: "dup@example.com", password: "a-long-password-2", name: "D" });
  assert.equal(first.status, 200);
  assert.equal(again.status, 200, `duplicate sign-up answered ${again.status} ${JSON.stringify(again.json)}`);
  assert.equal(again.json.token, null);
});

test("F6: /sign-in/phone-number takes as long for an unknown number as for a known one", async () => {
  const auth = await makeAuth({ phone: { sendSms: async () => {} } });
  const ctx = await auth.$context;
  const user = await ctx.internalAdapter.createUser({ email: "p@example.com", name: "P", emailVerified: true });
  await ctx.internalAdapter.updateUser(user.id, { phoneNumber: "+821099990000", phoneNumberVerified: true });
  await ctx.internalAdapter.createAccount({ userId: user.id, providerId: "credential", accountId: user.id, password: await ctx.password.hash("a-long-password-1") });
  const known = await medianMs(9, () => post(auth, "/sign-in/phone-number", { phoneNumber: "+821099990000", password: "wrong-password-x" }));
  const unknown = await medianMs(9, () => post(auth, "/sign-in/phone-number", { phoneNumber: "+821099990001", password: "wrong-password-x" }));
  assert.ok(unknown > known * 0.5, `unknown ${unknown.toFixed(1)} ms vs known ${known.toFixed(1)} ms`);
});

test("F16: /sign-in/username takes as long for a user without a password as for one with", async () => {
  const auth = await makeAuth({ username: { minLength: 3, maxLength: 30, pattern: "^[a-z0-9_.]+$", reserved: [], caseInsensitive: true, immutable: false } });
  const ctx = await auth.$context;
  const withPw = await ctx.internalAdapter.createUser({ email: "u1@example.com", name: "U", emailVerified: true });
  await ctx.internalAdapter.updateUser(withPw.id, { username: "haspw" });
  await ctx.internalAdapter.createAccount({ userId: withPw.id, providerId: "credential", accountId: withPw.id, password: await ctx.password.hash("a-long-password-1") });
  const noPw = await ctx.internalAdapter.createUser({ email: "u2@example.com", name: "U", emailVerified: true });
  await ctx.internalAdapter.updateUser(noPw.id, { username: "nopw" });
  const a = await medianMs(9, () => post(auth, "/sign-in/username", { username: "haspw", password: "wrong-password-x" }));
  const b = await medianMs(9, () => post(auth, "/sign-in/username", { username: "nopw", password: "wrong-password-x" }));
  assert.ok(b > a * 0.5, `no password ${b.toFixed(1)} ms vs password ${a.toFixed(1)} ms`);
});

test("F7: /is-username-available is limited per IP per hour", async () => {
  const auth = await makeAuth({ username: { minLength: 3, maxLength: 30, pattern: "^[a-z0-9_.]+$", reserved: [], caseInsensitive: true, immutable: false } });
  const ip = "203.0.113.30";
  let limited = 0;
  for (let i = 0; i < 40; i++) if ((await post(auth, "/is-username-available", { username: `name${i}` }, ip)).status === 429) limited++;
  assert.ok(limited >= 5, `40 checks from one IP: ${limited}x429`);
});

test("F7: /is-username-available can be switched off", async () => {
  const auth = await makeAuth({
    username: { minLength: 3, maxLength: 30, pattern: "^[a-z0-9_.]+$", reserved: [], caseInsensitive: true, immutable: false },
    usernameCheckPerIpPerHour: 0,
  });
  assert.equal((await post(auth, "/is-username-available", { username: "someone" })).status, 404);
});
