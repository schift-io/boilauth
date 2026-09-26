/** Re-audit findings C5-C8 reproduced over real HTTP. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { medianMs, PW, serve, user, type Served } from "./http.js";
import { accountDeletion } from "../src/modules/deletion.js";
import type { EmailMessage } from "../src/index.js";

async function ageSessions(s: Served, userId: string, minutes: number) {
  const ctx = await s.auth.$context;
  const at = new Date(Date.now() - minutes * 60_000);
  for (const row of await ctx.adapter.findMany<{ id: string }>({ model: "session", where: [{ field: "userId", value: userId }] })) {
    await ctx.adapter.update({ model: "session", where: [{ field: "id", value: row.id }], update: { createdAt: at } });
  }
}

test("C5: attaching a phone number needs a fresh session and sends a notice", async () => {
  const mails: EmailMessage[] = [];
  const sms: { to: string; text: string }[] = [];
  const s = await serve(() => ({ sendEmail: async (m) => void mails.push(m), phone: { sendSms: async (m) => void sms.push(m) } }));
  try {
    const u = await user(s, "p@example.com");
    const c = s.client();
    assert.equal((await c.req("/sign-in/email", { body: { email: u.email, password: PW } })).status, 200);
    await ageSessions(s, u.id, 20);
    const phone = "+821012345678";
    await c.req("/phone-number/send-otp", { body: { phoneNumber: phone } });
    const stale = await c.req("/phone-number/verify", { body: { phoneNumber: phone, code: sms.at(-1)!.text.match(/\d{6}/)![0], updatePhoneNumber: true } });
    assert.equal(stale.status, 403, `stale session attached a number: ${stale.status} ${stale.text}`);
    assert.equal(stale.json?.code, "SESSION_NOT_FRESH");

    const f = s.client();
    assert.equal((await f.req("/sign-in/email", { body: { email: u.email, password: PW } })).status, 200);
    await f.req("/phone-number/send-otp", { body: { phoneNumber: phone } });
    const ok = await f.req("/phone-number/verify", { body: { phoneNumber: phone, code: sms.at(-1)!.text.match(/\d{6}/)![0], updatePhoneNumber: true } });
    assert.equal(ok.status, 200, ok.text);
    assert.ok(mails.some((m) => m.to === u.email && m.kind === "security.phone_changed"), JSON.stringify(mails.map((m) => m.kind)));
  } finally {
    await s.close();
  }
});

test("C6: an admin setting a user's password ends the user's sessions and notifies the user", async () => {
  const mails: EmailMessage[] = [];
  const s = await serve(() => ({ sendEmail: async (m) => void mails.push(m) }));
  try {
    const adminUser = await user(s, "admin@example.com", { role: "admin" });
    const target = await user(s, "t@example.com");
    const t = s.client();
    assert.equal((await t.req("/sign-in/email", { body: { email: target.email, password: PW } })).status, 200);
    const a = s.client();
    assert.equal((await a.req("/sign-in/email", { body: { email: adminUser.email, password: PW } })).status, 200);
    const r = await a.req("/admin/set-user-password", { body: { userId: target.id, newPassword: "a-new-long-password-9" } });
    assert.equal(r.status, 200, r.text);
    assert.equal(await t.session(), null, "the user's old session survived an admin password set");
    assert.ok(mails.some((m) => m.to === target.email && m.kind === "security.password_changed"), JSON.stringify(mails.map((m) => m.kind)));
    assert.ok(await a.session(), "the admin's own session is untouched");
  } finally {
    await s.close();
  }
});

test("C7: a soft-deleted account answers the right and a wrong password the same way", async () => {
  const s = await serve(() => ({ plugins: [accountDeletion({ mode: "soft", exportData: false })], betterAuth: { rateLimit: { enabled: false } } }));
  try {
    const u = await user(s, "gone@example.com");
    const ctx = await s.auth.$context;
    await ctx.internalAdapter.updateUser(u.id, { deletedAt: new Date() });
    const c = s.client();
    const right = await c.req("/sign-in/email", { body: { email: u.email, password: PW } });
    const wrong = await c.req("/sign-in/email", { body: { email: u.email, password: "wrong-password-xx" } });
    assert.equal(right.status, wrong.status, `${right.text} vs ${wrong.text}`);
    assert.equal(right.json?.code, wrong.json?.code);
    const tRight = await medianMs(5, () => c.req("/sign-in/email", { body: { email: u.email, password: PW } }));
    const tWrong = await medianMs(5, () => c.req("/sign-in/email", { body: { email: u.email, password: "wrong-password-xx" } }));
    assert.ok(tRight > tWrong * 0.5 && tRight < tWrong * 2, `right ${tRight.toFixed(1)} ms vs wrong ${tWrong.toFixed(1)} ms`);
  } finally {
    await s.close();
  }
});

function viaProxy(s: Served) {
  return (ip: string, password: string, email: string) =>
    s.client().req("/sign-in/email", { body: { email, password }, headers: { "x-forwarded-for": ip } });
}

const lockout = { maxFailures: 2, accountMaxFailures: 3, lockMinutes: 15, knownSourceDays: 90 };

test("C8: the owner's successful sign-in does not reopen the account-wide lock for other sources", async () => {
  const s = await serve(() => ({ trustedProxies: ["127.0.0.1"], lockout }));
  try {
    const u = await user(s, "owner@example.com");
    const from = viaProxy(s);
    assert.equal((await from("198.51.100.1", PW, u.email)).status, 200, "owner's usual device");
    for (const ip of ["203.0.113.1", "203.0.113.2", "203.0.113.3"]) await from(ip, "wrong-password-xx", u.email);
    assert.equal((await from("203.0.113.9", PW, u.email)).status, 401, "unknown source during the lock");
    assert.equal((await from("198.51.100.1", PW, u.email)).status, 200, "owner still signs in");
    assert.equal((await from("203.0.113.10", PW, u.email)).status, 401, "owner's sign-in cleared the lock for everyone");
  } finally {
    await s.close();
  }
});

test("C8: wrong passwords from the owner's known device do not count toward the account-wide lock", async () => {
  const s = await serve(() => ({ trustedProxies: ["127.0.0.1"], lockout }));
  try {
    const u = await user(s, "typo@example.com");
    const from = viaProxy(s);
    assert.equal((await from("198.51.100.1", PW, u.email)).status, 200);
    await from("198.51.100.1", "wrong-password-xx", u.email); // owner's typo (below the per-source limit)
    await from("203.0.113.1", "wrong-password-xx", u.email);
    await from("203.0.113.2", "wrong-password-xx", u.email);
    assert.equal((await from("203.0.113.9", PW, u.email)).status, 200, "the owner's typo tipped the account lock");
  } finally {
    await s.close();
  }
});
