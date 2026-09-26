/**
 * F2 (audit 2026-09-27): SMS pumping — many OTP sends to many numbers cost real money.
 * Per IP the send limit applies (and since F1 a rotating X-Forwarded-For no longer resets it);
 * across all IPs a site-wide SMS budget per hour; numbers outside the allowed countries never get an SMS.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { sendLimits } from "../src/modules/rate-limit.js";
import { BASE, makeAuth } from "./helpers.js";
import type { PhoneOptions } from "../src/modules/phone.js";

async function sendOtp(auth: Awaited<ReturnType<typeof makeAuth>>, phoneNumber: string, clientIp: string, headers: Record<string, string> = {}) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/phone-number/send-otp`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE, ...headers },
      body: JSON.stringify({ phoneNumber }),
    }),
    { clientIp },
  );
  await res.text();
  return res.status;
}

function phoneAuth(phone: Partial<PhoneOptions>, perIpPerHour = 10) {
  const sent: string[] = [];
  const auth = makeAuth({
    phone: { sendSms: async (m) => void sent.push(m.to), ...phone },
    plugins: [sendLimits({ perIpPerHour, perAccountPerHour: 5 })],
  });
  return { auth, sent };
}

test("F2: 40 numbers from one socket with rotating X-Forwarded-For: the per-IP limit holds (10 SMS)", async () => {
  const { auth: a, sent } = phoneAuth({});
  const auth = await a;
  for (let i = 0; i < 40; i++) await sendOtp(auth, `+8210${String(10000000 + i)}`, "203.0.113.80", { "x-forwarded-for": `198.51.100.${i}` });
  assert.equal(sent.length, 10);
});

test("F2: a site-wide SMS budget caps sends from many IPs", async () => {
  const { auth: a, sent } = phoneAuth({ smsPerHour: 15 });
  const auth = await a;
  const statuses: number[] = [];
  for (let i = 0; i < 25; i++) statuses.push(await sendOtp(auth, `+8210${String(20000000 + i)}`, `198.51.100.${i + 1}`));
  assert.equal(sent.length, 15, "15 SMS, then the budget is spent");
  assert.equal(statuses.filter((s) => s === 429).length, 10);
});

test("F2: numbers outside the allowed countries get no SMS", async () => {
  const { auth: a, sent } = phoneAuth({ allowedCountryCodes: ["82"] });
  const auth = await a;
  assert.equal(await sendOtp(auth, "+821012345678", "198.51.100.200"), 200);
  assert.equal(await sendOtp(auth, "+2349012345678", "198.51.100.201"), 400);
  assert.deepEqual(sent, ["+821012345678"]);
});

test("F2: refused numbers do not spend the site-wide budget", async () => {
  const { auth: a, sent } = phoneAuth({ smsPerHour: 3, allowedCountryCodes: ["82"] });
  const auth = await a;
  for (let i = 0; i < 10; i++) assert.equal(await sendOtp(auth, `+23490${String(10000000 + i)}`, `198.51.101.${i + 1}`), 400);
  for (let i = 0; i < 3; i++) assert.equal(await sendOtp(auth, `+8210${String(30000000 + i)}`, `198.51.102.${i + 1}`), 200);
  assert.equal(sent.length, 3);
});
