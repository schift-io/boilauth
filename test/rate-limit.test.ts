import { test } from "node:test";
import assert from "node:assert/strict";
import { sendLimits } from "../src/modules/rate-limit.js";
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
  await res.text();
  return res;
}

const LIMITS = { perIpPerHour: 10, perAccountPerHour: 5 };
const mailer = { sendEmail: async () => {} };
const withLimits = (o: Partial<typeof LIMITS> = {}, extra: Record<string, unknown> = {}) =>
  makeAuth({ ...mailer, plugins: [sendLimits({ ...LIMITS, ...o, ...extra })], ...(extra.storage ? { rateLimitStorage: extra.storage as "memory" } : {}) });

test("sends per IP per hour: the 11th reset request from one IP gets 429 with Retry-After; another IP is fine", async () => {
  const auth = await withLimits({ perAccountPerHour: 0 });
  const ip = "10.7.0.1";
  const statuses: number[] = [];
  for (let i = 0; i <= LIMITS.perIpPerHour; i++) {
    statuses.push((await post(auth, "/request-password-reset", { email: `a${i}@example.com` }, ip)).status);
  }
  assert.deepEqual(statuses.slice(0, -1), Array(LIMITS.perIpPerHour).fill(200));
  const over = await post(auth, "/request-password-reset", { email: "z@example.com" }, ip);
  assert.equal(over.status, 429);
  const after = Number(over.headers.get("retry-after"));
  assert.ok(after > 3500 && after <= 3600, `Retry-After ${after}`);
  assert.equal(over.headers.get("x-retry-after"), String(after));
  assert.equal((await post(auth, "/request-password-reset", { email: "z@example.com" }, "10.7.0.2")).status, 200);
});

test("sends per address per hour: 5 from 5 different IPs pass, the 6th from a new IP gets 429 with RateLimit headers", async () => {
  const auth = await withLimits();
  const email = "target@example.com";
  for (let i = 0; i < LIMITS.perAccountPerHour; i++) {
    assert.equal((await post(auth, "/request-password-reset", { email })).status, 200, `send ${i + 1}`);
  }
  const over = await post(auth, "/request-password-reset", { email: "  TARGET@example.com " });
  assert.equal(over.status, 429, "case and spaces normalise to the same address");
  assert.equal(over.headers.get("ratelimit-limit"), "5");
  assert.equal(over.headers.get("ratelimit-remaining"), "0");
  assert.equal(over.headers.get("ratelimit-policy"), "5;w=3600");
  assert.ok(Number(over.headers.get("retry-after")) > 0);
  assert.equal((await post(auth, "/request-password-reset", { email: "other@example.com" })).status, 200, "other address unaffected");
});

test("the per-address bucket is shared by every send endpoint", async () => {
  const auth = await withLimits();
  const email = "shared@example.com";
  await auth.api.signUpEmail({ body: { email, password: "right-password-1", name: "S" } });
  for (let i = 0; i < 3; i++) assert.equal((await post(auth, "/request-password-reset", { email })).status, 200);
  for (let i = 0; i < 2; i++) assert.equal((await post(auth, "/send-verification-email", { email })).status, 200);
  assert.equal((await post(auth, "/send-verification-email", { email })).status, 429);
  assert.equal((await post(auth, "/request-password-reset", { email })).status, 429);
});

test("the per-address window resets after an hour", async () => {
  let t = new Date("2026-01-01T00:00:00Z").getTime();
  const realNow = Date.now;
  Date.now = () => t; // the stored lastRequest and our window check both read the clock
  try {
    const auth = await withLimits({}, { now: () => new Date(t) });
    const email = "clock@example.com";
    for (let i = 0; i < 5; i++) await post(auth, "/request-password-reset", { email });
    assert.equal((await post(auth, "/request-password-reset", { email })).status, 429);
    t += 3601_000;
    assert.equal((await post(auth, "/request-password-reset", { email })).status, 200);
  } finally {
    Date.now = realNow;
  }
});

test("memory storage enforces the same per-address limit", async () => {
  const auth = await withLimits({}, { storage: "memory" });
  const email = `mem-${Date.now()}@example.com`;
  for (let i = 0; i < 5; i++) assert.equal((await post(auth, "/request-password-reset", { email })).status, 200);
  assert.equal((await post(auth, "/request-password-reset", { email })).status, 429);
  const ctx = await auth.$context;
  await assert.rejects(ctx.adapter.count({ model: "rateLimit" }), /not found in schema/, "memory mode keeps no rateLimit table");
});

test("concurrent sends to one address never pass more than the limit", async () => {
  const auth = await withLimits();
  const email = "burst@example.com";
  const res = await Promise.all(Array.from({ length: 12 }, () => post(auth, "/request-password-reset", { email })));
  assert.equal(res.filter((r) => r.status === 200).length, 5);
  assert.equal(res.filter((r) => r.status === 429).length, 7);
});

test("without the module, sends keep Better Auth's per-IP rule and no per-address limit", async () => {
  const auth = await makeAuth(mailer);
  const email = "nomodule@example.com";
  for (let i = 0; i < 8; i++) assert.equal((await post(auth, "/request-password-reset", { email })).status, 200, `send ${i + 1}`);
  const ip = "10.7.3.3";
  const s = [];
  for (let i = 0; i < 4; i++) s.push((await post(auth, "/request-password-reset", { email: `n${i}@example.com` }, ip)).status);
  assert.deepEqual(s, [200, 200, 200, 429], "core preset: 3 per 5 minutes per IP");
});

test("sign-in 429 from Better Auth's limiter now carries the standard Retry-After", async () => {
  const auth = await makeAuth();
  const ip = "10.7.9.9";
  let last: Response | undefined;
  for (let i = 0; i < 11; i++) last = await post(auth, "/sign-in/email", { email: `x${i}@example.com`, password: "whatever-pw" }, ip);
  assert.equal(last!.status, 429);
  assert.equal(last!.headers.get("retry-after"), last!.headers.get("x-retry-after"));
  assert.ok(Number(last!.headers.get("retry-after")) > 0);
});

test("the module's per-IP rule wins over the phone and magic-link plugins' own rules", async () => {
  const { magicLink } = await import("better-auth/plugins");
  const auth = await makeAuth({
    ...mailer,
    phone: { sendSms: async () => {} },
    plugins: [
      magicLink({ sendMagicLink: async () => {} }),
      sendLimits({ perIpPerHour: 2, perAccountPerHour: 0 }),
    ],
  });
  const ip1 = "10.7.4.1";
  const sms = [];
  for (let i = 0; i < 3; i++) sms.push((await post(auth, "/phone-number/send-otp", { phoneNumber: `+8210000000${i}` }, ip1)).status);
  assert.deepEqual(sms, [200, 200, 429], "phone plugin alone would allow 10 per minute");
  const ip2 = "10.7.4.2";
  const links = [];
  for (let i = 0; i < 3; i++) links.push((await post(auth, "/sign-in/magic-link", { email: `m${i}@example.com` }, ip2)).status);
  assert.deepEqual(links, [200, 200, 429], "magic-link plugin alone would allow 5 per minute");
});

test("per-address limit on phone numbers: malformed numbers are refused without using the quota", async () => {
  const auth = await makeAuth({ phone: { sendSms: async () => {} }, plugins: [sendLimits({ perIpPerHour: 10, perAccountPerHour: 2 })] });
  for (let i = 0; i < 3; i++) assert.equal((await post(auth, "/phone-number/send-otp", { phoneNumber: "+82 10-1234-5678" })).status, 400);
  assert.equal((await post(auth, "/phone-number/send-otp", { phoneNumber: "+821012345678" })).status, 200);
  assert.equal((await post(auth, "/phone-number/send-otp", { phoneNumber: "+821012345678" })).status, 200);
  assert.equal((await post(auth, "/phone-number/send-otp", { phoneNumber: "+821012345678" })).status, 429);
});
