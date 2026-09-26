/**
 * Re-audit findings reproduced over real HTTP (C1-C4, L2, L3, unchecked session plugins).
 * Account-side findings (C5-C8) are in reaudit-http-account.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { bearer, deviceAuthorization, emailOTP, magicLink, twoFactor } from "better-auth/plugins";
import { DatabaseSync } from "node:sqlite";
import { createBoilAuth } from "../src/index.js";
import { enrollTotp, medianMs, PW, serve, totp, user, type Served } from "./http.js";

type Mail = { to: string; text: string };

function shape(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(shape);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).sort().map(([k, x]) => [k, shape(x)]));
  return v === null ? null : typeof v;
}

async function signUpPair(s: Served, n: number) {
  const c = s.client();
  const dupEmail = "taken@example.com";
  const first = await c.req("/sign-up/email", { body: { email: dupEmail, password: PW, name: "T" } });
  assert.equal(first.status, 200, first.text);
  let i = 0;
  const fresh = () => c.req("/sign-up/email", { body: { email: `new${++i}@example.com`, password: PW, name: "T" } });
  const dup = () => c.req("/sign-up/email", { body: { email: dupEmail, password: PW, name: "T" } });
  const a = await fresh();
  const b = await dup();
  const tNew = await medianMs(n, fresh);
  const tDup = await medianMs(n, dup);
  return { a, b, tNew, tDup };
}

for (const [label, opts] of [
  ["verification required", {}],
  ["verification optional", { requireEmailVerification: false }],
] as const) {
  test(`C1: a duplicate sign-up is indistinguishable from a new one (${label})`, async () => {
    const s = await serve(() => ({ sendEmail: async () => {}, ...opts, betterAuth: { rateLimit: { enabled: false } } }));
    try {
      const { a, b, tNew, tDup } = await signUpPair(s, 5);
      assert.equal(b.status, a.status);
      assert.deepEqual(shape(b.json), shape(a.json), `new ${a.text}\ndup ${b.text}`);
      for (const k of ["role", "emailVerified", "banned"]) assert.equal(b.json.user?.[k], a.json.user?.[k], k);
      assert.equal(b.json.token, a.json.token);
      const names = (h: Headers) => [...h.keys()].filter((k) => k !== "date").sort().join(",");
      assert.equal(names(b.headers), names(a.headers));
      assert.ok(tDup > tNew * 0.5 && tDup < tNew * 2, `new ${tNew.toFixed(1)} ms vs duplicate ${tDup.toFixed(1)} ms`);
    } finally {
      await s.close();
    }
  });
}

test("C2: betterAuth.advanced.ipAddress overrides of the client IP are refused at startup", () => {
  const base = { database: new DatabaseSync(":memory:"), secret: "x".repeat(40), baseURL: "http://localhost:3000" };
  assert.throws(
    () => createBoilAuth({ ...base, betterAuth: { advanced: { ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] } } } }),
    /ipAddressHeaders[\s\S]*clientIp/,
  );
  assert.throws(() => createBoilAuth({ ...base, betterAuth: { advanced: { ipAddress: { disableIpTracking: true } } } }), /disableIpTracking/);
  // ipv6Subnet stays tunable.
  assert.doesNotThrow(() => createBoilAuth({ ...base, betterAuth: { advanced: { ipAddress: { ipv6Subnet: 48 } } } }));
});

test("C3: after a magic link, the second factor cannot be an email code (TOTP or backup code only)", async () => {
  const mails: Mail[] = [];
  const s = await serve(() => ({
    sendEmail: async (m) => void mails.push(m),
    plugins: [
      magicLink({ sendMagicLink: async ({ email, url }) => void mails.push({ to: email, text: url }) }),
      twoFactor({ otpOptions: { sendOTP: async ({ user: u, otp }) => void mails.push({ to: u.email, text: otp }) } }),
    ],
  }));
  try {
    const u = await user(s, "m@example.com");
    const uri = await enrollTotp(s.client(), u.email);
    const c = s.client();
    await c.req("/sign-in/magic-link", { body: { email: u.email, callbackURL: "/" } });
    const link = mails.filter((m) => m.to === u.email).at(-1)!.text;
    const verified = await c.req(link);
    assert.match(verified.headers.get("location") ?? "", /twoFactorRedirect=true/);
    assert.equal(await c.session(), null);
    const sent = await c.req("/two-factor/send-otp", { body: {} });
    assert.equal(sent.status, 403, `send-otp after a magic link: ${sent.status} ${sent.text}`);
    assert.equal(sent.json?.code, "SECOND_FACTOR_NOT_ALLOWED");
    const verify = await c.req("/two-factor/verify-otp", { body: { code: "123456" } });
    assert.equal(verify.status, 403);
    assert.equal(await c.session(), null);
    const ok = await c.req("/two-factor/verify-totp", { body: { code: totp(uri, Date.now() + 30_000) } });
    assert.equal(ok.status, 200, ok.text);
    assert.equal((await c.session())?.user.email, u.email);

    // A password sign-in may still finish with an email code.
    const p = s.client();
    const first = await p.req("/sign-in/email", { body: { email: u.email, password: PW } });
    assert.equal(first.json?.twoFactorRedirect, true);
    assert.equal((await p.req("/two-factor/send-otp", { body: {} })).status, 200);
    const code = mails.filter((m) => m.to === u.email).at(-1)!.text;
    assert.equal((await p.req("/two-factor/verify-otp", { body: { code } })).status, 200);
    assert.equal((await p.session())?.user.email, u.email);
  } finally {
    await s.close();
  }
});

test("C4: unknown auth paths answer 404 without creating rate-limit rows", async () => {
  const s = await serve(() => ({}));
  try {
    const ctx = await s.auth.$context;
    const rows = async () => (await ctx.adapter.findMany({ model: "rateLimit" })).length;
    const before = await rows();
    const c = s.client();
    for (let i = 0; i < 25; i++) assert.equal((await c.req(`/x${i}-${Math.random()}`)).status, 404);
    assert.equal(await rows(), before, "each unknown path wrote a rateLimit row");
    assert.equal((await c.req("/get-session")).status, 200, "known paths still served");
  } finally {
    await s.close();
  }
});

test("L2 (HTTP): with autoSignInAfterVerification, email verification gives a TOTP user no session", async () => {
  const mails: Mail[] = [];
  const s = await serve(() => ({
    sendEmail: async (m) => void mails.push(m),
    plugins: [
      twoFactor(),
      emailOTP({ sendVerificationOTP: async ({ email, otp }) => void mails.push({ to: email, text: otp }) }),
    ],
    betterAuth: { emailVerification: { autoSignInAfterVerification: true } },
  }));
  try {
    const u = await user(s, "v@example.com");
    await enrollTotp(s.client(), u.email);
    const ctx = await s.auth.$context;
    await ctx.internalAdapter.updateUser(u.id, { emailVerified: false });

    const link = s.client();
    await link.req("/send-verification-email", { body: { email: u.email, callbackURL: "/" } });
    const url = mails.filter((m) => m.to === u.email).at(-1)!.text;
    const r = await link.req(url);
    assert.match(r.headers.get("location") ?? JSON.stringify(r.json), /twoFactorRedirect/);
    assert.equal(await link.session(), null, "/verify-email issued a session");

    await ctx.internalAdapter.updateUser(u.id, { emailVerified: false });
    const code = s.client();
    await code.req("/email-otp/send-verification-otp", { body: { email: u.email, type: "email-verification" } });
    const otp = mails.filter((m) => m.to === u.email).at(-1)!.text;
    const v = await code.req("/email-otp/verify-email", { body: { email: u.email, otp } });
    assert.equal(v.json?.twoFactorRedirect, true, v.text);
    assert.equal(await code.session(), null, "/email-otp/verify-email issued a session");
  } finally {
    await s.close();
  }
});

for (const [label, opts] of [
  ["bearer option", { bearer: true, plugins: [twoFactor()] }],
  ["bearer() in plugins", { plugins: [twoFactor(), bearer()] }],
  ["bearer() before twoFactor", { plugins: [bearer(), twoFactor()] }],
] as const) {
  test(`L3 (HTTP): a two-factor challenge carries no set-auth-token (${label})`, async () => {
    const s = await serve(() => opts);
    try {
      const u = await user(s, "b@example.com");
      const uri = await enrollTotp(s.client(), u.email);
      const c = s.client();
      const r = await c.req("/sign-in/email", { body: { email: u.email, password: PW } });
      assert.equal(r.json?.twoFactorRedirect, true);
      assert.equal(r.headers.get("set-auth-token"), null, "challenge handed out a token");
      const ok = await c.req("/two-factor/verify-totp", { body: { code: totp(uri, Date.now() + 30_000) } });
      assert.equal(ok.status, 200);
      assert.ok(ok.headers.get("set-auth-token"), "completed sign-in carries the token");
    } finally {
      await s.close();
    }
  });
}

test("device-authorization with twoFactor is refused: /device/token issues sessions outside the second-factor check", () => {
  const base = { database: new DatabaseSync(":memory:"), secret: "x".repeat(40), baseURL: "http://localhost:3000" };
  assert.throws(() => createBoilAuth({ ...base, plugins: [twoFactor(), deviceAuthorization()] }), /device-authorization/);
  assert.throws(
    () => createBoilAuth({ ...base, plugins: [twoFactor()], betterAuth: { plugins: [deviceAuthorization()] } }),
    /device-authorization/,
  );
  assert.doesNotThrow(() => createBoilAuth({ ...base, plugins: [deviceAuthorization()] }), "without two-factor there is nothing to bypass");
});
