import { test } from "node:test";
import assert from "node:assert/strict";
import { PRESETS } from "../src/index.js";
import { BASE, makeAuth, signIn } from "./helpers.js";

async function withUser(now: () => Date) {
  const auth = await makeAuth({ now });
  await auth.api.signUpEmail({ body: { email: "lock@example.com", password: "right-password-1", name: "L" } });
  return auth;
}

test("5 wrong passwords from one source lock that source; the right password is refused there, with the same 401", async () => {
  let t = new Date("2026-01-01T00:00:00Z").getTime();
  const auth = await withUser(() => new Date(t));
  const attacker = "198.51.100.66";
  for (let i = 0; i < PRESETS.lockout.maxFailures; i++) {
    const r = await signIn(auth, "lock@example.com", `wrong-${i}`, attacker);
    assert.equal(r.status, 401);
  }
  const locked = await signIn(auth, "lock@example.com", "right-password-1", attacker);
  assert.equal(locked.status, 401, "locked source refuses the correct password");
  assert.equal(locked.body.code, "INVALID_EMAIL_OR_PASSWORD", "lock is indistinguishable from a wrong password");

  t += (PRESETS.lockout.lockMinutes - 1) * 60_000;
  assert.equal((await signIn(auth, "lock@example.com", "right-password-1", attacker)).status, 401, "still locked at 14 min");

  t += 2 * 60_000;
  assert.equal((await signIn(auth, "lock@example.com", "right-password-1", attacker)).status, 200, "unlocked after 15 min");
});

test("F4: wrong passwords from other IPs do not lock the owner out", async () => {
  const t = new Date("2026-01-01T00:00:00Z");
  const auth = await withUser(() => t);
  for (let i = 0; i < PRESETS.lockout.maxFailures; i++) {
    assert.equal((await signIn(auth, "lock@example.com", `wrong-${i}`, `198.51.100.${10 + i}`)).status, 401);
  }
  assert.equal((await signIn(auth, "lock@example.com", "right-password-1", "203.0.113.5")).status, 200, "the owner is not locked out");
});

test("F4: a distributed guess attack locks the account for unknown sources; the owner's known source still gets in", async () => {
  const t = new Date("2026-01-01T00:00:00Z");
  const auth = await withUser(() => t);
  const home = "203.0.113.50";
  assert.equal((await signIn(auth, "lock@example.com", "right-password-1", home)).status, 200, "owner signs in once from home");
  for (let i = 0; i < PRESETS.lockout.accountMaxFailures; i++) {
    await signIn(auth, "lock@example.com", `wrong-${i}`, `198.51.${100 + (i >> 8)}.${i & 255}`);
  }
  const fresh = await signIn(auth, "lock@example.com", "right-password-1", "192.0.2.200");
  assert.equal(fresh.status, 401, "an unknown source is refused even with the right password");
  assert.equal(fresh.body.code, "INVALID_EMAIL_OR_PASSWORD");
  assert.equal((await signIn(auth, "lock@example.com", "right-password-1", home)).status, 200, "the owner's known source still works");
});

test("a success resets the failure counter", async () => {
  const t = new Date("2026-01-01T00:00:00Z");
  const auth = await withUser(() => t);
  const ip = "203.0.113.77";
  for (let i = 0; i < PRESETS.lockout.maxFailures - 1; i++) await signIn(auth, "lock@example.com", "nope", ip);
  const ok = await signIn(auth, "lock@example.com", "right-password-1", ip);
  assert.equal(ok.status, 200);
  for (const k of ["failedLoginCount", "lockedUntil", "knownSignInSources"]) assert.ok(!(k in ok.body.user), `${k} not exposed`);
  for (let i = 0; i < PRESETS.lockout.maxFailures - 1; i++) await signIn(auth, "lock@example.com", "nope", ip);
  assert.equal((await signIn(auth, "lock@example.com", "right-password-1", ip)).status, 200, "counter had been reset");
});

test("per-IP rate limit on /sign-in/email: 10 per minute, 11th gets 429; another IP is unaffected", async () => {
  const auth = await makeAuth();
  const ip = "10.9.9.9";
  const statuses: number[] = [];
  for (let i = 0; i < 11; i++) statuses.push((await signIn(auth, `nobody${i}@example.com`, "whatever-pw", ip)).status);
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401));
  assert.equal(statuses[10], 429);
  assert.equal((await signIn(auth, "nobody@example.com", "whatever-pw", "10.9.9.10")).status, 401);
});

test("rate limit state is in the database (shared across app instances on one DB)", async () => {
  const auth = await makeAuth();
  await signIn(auth, "x@example.com", "whatever-pw", "10.8.8.8");
  const ctx = await auth.$context;
  assert.ok((await ctx.adapter.count({ model: "rateLimit" })) >= 1);
});

test("sign-up is rate limited too (Better Auth built-in 3 per 10 s)", async () => {
  const auth = await makeAuth();
  const statuses: number[] = [];
  for (let i = 0; i < 4; i++) {
    const res = await auth.handler(
      new Request(`${BASE}/api/auth/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE },
        body: JSON.stringify({ email: `s${i}@example.com`, password: "long-enough-pw", name: "S" }),
      }),
      { clientIp: "10.7.7.7" },
    );
    statuses.push(res.status);
  }
  assert.deepEqual(statuses, [200, 200, 200, 429]);
});

test("passwords shorter than the preset minimum are refused at sign-up", async () => {
  const auth = await makeAuth();
  await assert.rejects(auth.api.signUpEmail({ body: { email: "short@example.com", password: "short", name: "S" } }));
});
