/** F9 (audit 2026-09-27, ASVS 2.2.3): the user hears about security changes on their account. */
import { test } from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { createHmac } from "node:crypto";
import { twoFactor } from "better-auth/plugins";
import { PRESETS, importUsers, type EmailMessage } from "../src/index.js";
import { BASE, makeAuth, signIn } from "./helpers.js";

async function setup(extra: Record<string, unknown> = {}) {
  const mail: EmailMessage[] = [];
  const auth = await makeAuth({ sendEmail: async (m) => void mail.push(m), requireEmailVerification: false, ...extra });
  await auth.api.signUpEmail({ body: { email: "n@example.com", password: "a-long-password-1", name: "N" } });
  mail.length = 0;
  return { auth, mail };
}

const notices = (mail: EmailMessage[]) => mail.filter((m) => m.kind?.startsWith("security."));

async function call(auth: Awaited<ReturnType<typeof makeAuth>>, path: string, body: unknown, cookie?: string, ip = "203.0.113.2") {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE, ...(cookie ? { cookie } : {}) },
      body: JSON.stringify(body),
    }),
    { clientIp: ip },
  );
  return { status: res.status, json: await res.json().catch(() => null) };
}

test("F9: changing the password sends a notice", async () => {
  const { auth, mail } = await setup();
  const s = await signIn(auth, "n@example.com", "a-long-password-1");
  const cookie = s.cookie!.split(";")[0];
  const r = await call(auth, "/change-password", { currentPassword: "a-long-password-1", newPassword: "another-long-password" }, cookie);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(notices(mail).map((m) => [m.to, m.kind]), [["n@example.com", "security.password_changed"]]);
});

test("F9: resetting the password sends a notice", async () => {
  const { auth, mail } = await setup();
  await call(auth, "/request-password-reset", { email: "n@example.com", redirectTo: "/reset" });
  const link = mail.find((m) => m.subject === "Reset your password")!.text;
  const token = new URL(link).pathname.split("/").pop()!;
  assert.equal((await call(auth, "/reset-password", { token, newPassword: "a-brand-new-password" })).status, 200);
  assert.deepEqual(notices(mail).map((m) => m.kind), ["security.password_changed"]);
});

test("F9: the transparent rehash at sign-in is not a password change", async () => {
  const { auth, mail } = await setup();
  await importUsers(auth, "generic", [{ sourceId: "x1", email: "old@example.com", emailVerified: true, passwordHash: bcrypt.hashSync("old-long-password", 4) }]);
  assert.equal((await signIn(auth, "old@example.com", "old-long-password")).status, 200);
  assert.deepEqual(notices(mail), []);
});

function totp(uri: string): string {
  const secret = new URL(uri).searchParams.get("secret")!;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const off = h[h.length - 1] & 15;
  return String((((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1_000_000).padStart(6, "0");
}

test("F9: turning two-factor on and off sends a notice each time", async () => {
  const { auth, mail } = await setup({ plugins: [twoFactor()] });
  const s = await signIn(auth, "n@example.com", "a-long-password-1");
  let cookie = s.cookie!.split(";")[0];
  const en = await call(auth, "/two-factor/enable", { password: "a-long-password-1" }, cookie);
  assert.equal(en.status, 200, JSON.stringify(en.json));
  assert.deepEqual(notices(mail), [], "nothing yet: TOTP is on only after the first code");
  const v = await auth.handler(
    new Request(`${BASE}/api/auth/two-factor/verify-totp`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE, cookie },
      body: JSON.stringify({ code: totp(en.json.totpURI) }),
    }),
    { clientIp: "203.0.113.2" },
  );
  assert.equal(v.status, 200);
  cookie = v.headers.getSetCookie().find((c) => c.startsWith("better-auth.session_token="))?.split(";")[0] ?? cookie;
  assert.equal((await call(auth, "/two-factor/disable", { password: "a-long-password-1" }, cookie)).status, 200);
  assert.deepEqual(notices(mail).map((m) => [m.kind, m.subject]), [
    ["security.mfa_changed", "Two-factor sign-in was turned on"],
    ["security.mfa_changed", "Two-factor sign-in was turned off"],
  ]);
});

test("F9: an account-wide lock sends a notice", async () => {
  const { auth, mail } = await setup();
  for (let i = 0; i < PRESETS.lockout.accountMaxFailures; i++) await signIn(auth, "n@example.com", `wrong-${i}`);
  assert.deepEqual(notices(mail).map((m) => m.kind), ["security.account_locked"]);
});

test("F9: sign-in from a new device sends a notice when switched on; not by default", async () => {
  for (const on of [false, true]) {
    const { auth, mail } = await setup(on ? { securityNotices: { newDevice: true } } : {});
    await signIn(auth, "n@example.com", "a-long-password-1", "203.0.113.60");
    await signIn(auth, "n@example.com", "a-long-password-1", "203.0.113.60");
    await signIn(auth, "n@example.com", "a-long-password-1", "198.51.100.61");
    assert.deepEqual(notices(mail).map((m) => m.kind), on ? ["security.new_device"] : [], `newDevice ${on}`);
  }
});

test("NT-01: dormant account sign-in from an unseen IP sends one new-device notice", async () => {
  let time = new Date("2026-01-01T00:00:00Z").getTime();
  const { auth, mail } = await setup({
    now: () => new Date(time),
    securityNotices: { newDevice: true },
  });

  assert.equal((await signIn(auth, "n@example.com", "a-long-password-1", "203.0.113.60")).status, 200);
  assert.deepEqual(notices(mail), [], "the first sign-in ever stays silent");

  time += (PRESETS.lockout.knownSourceDays + 1) * 86_400_000;
  assert.equal((await signIn(auth, "n@example.com", "a-long-password-1", "198.51.100.61")).status, 200);
  assert.deepEqual(notices(mail).map((m) => m.kind), ["security.new_device"]);
});
