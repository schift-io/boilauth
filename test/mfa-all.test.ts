/**
 * F11 (audit 2026-09-27): a user with two-factor on must pass it whatever the first factor —
 * magic link, email code, SMS code or OAuth used to hand out a full session.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { emailOTP, magicLink, twoFactor } from "better-auth/plugins";
import type { EmailMessage } from "../src/index.js";
import { BASE, makeAuth } from "./helpers.js";

type Auth = Awaited<ReturnType<typeof makeAuth>>;
type Jar = Map<string, string>;

function totp(uri: string, at = Date.now()): string {
  const secret = new URL(uri).searchParams.get("secret")!;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const off = h[h.length - 1] & 15;
  return String((((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1_000_000).padStart(6, "0");
}

async function call(auth: Auth, path: string, o: { body?: unknown; jar?: Jar; method?: string } = {}) {
  const headers: Record<string, string> = { origin: BASE };
  if (o.body !== undefined) headers["content-type"] = "application/json";
  if (o.jar?.size) headers.cookie = [...o.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  const url = path.startsWith("http") ? path : `${BASE}/api/auth${path}`;
  const res = await auth.handler(
    new Request(url, { method: o.method ?? (o.body === undefined ? "GET" : "POST"), headers, body: o.body === undefined ? undefined : JSON.stringify(o.body), redirect: "manual" }),
    { clientIp: "203.0.113.3" },
  );
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const i = pair.indexOf("=");
    if (!o.jar) continue;
    if (pair.slice(i + 1) === "" || /max-age=0/i.test(c)) o.jar.delete(pair.slice(0, i));
    else o.jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, json, location: res.headers.get("location") };
}

async function setup(extra: Record<string, unknown> = {}) {
  const mail: EmailMessage[] = [];
  const auth = await makeAuth({
    sendEmail: async (m) => void mail.push(m),
    requireEmailVerification: false,
    plugins: [
      twoFactor(),
      magicLink({ sendMagicLink: async ({ email, url }) => void mail.push({ to: email, subject: "link", text: url }) }),
      emailOTP({ sendVerificationOTP: async ({ email, otp }) => void mail.push({ to: email, subject: "code", text: otp }) }),
    ],
    ...extra,
  });
  await auth.api.signUpEmail({ body: { email: "m@example.com", password: "a-long-password-1", name: "M" } });
  const jar: Jar = new Map();
  await call(auth, "/sign-in/email", { body: { email: "m@example.com", password: "a-long-password-1" }, jar });
  const en = await call(auth, "/two-factor/enable", { body: { password: "a-long-password-1" }, jar });
  const uri = en.json.totpURI as string;
  assert.equal((await call(auth, "/two-factor/verify-totp", { body: { code: totp(uri) }, jar })).status, 200);
  return { auth, mail, uri };
}

const sessionOf = async (auth: Auth, jar: Jar) => (await call(auth, "/get-session", { jar })).json;

test("F11: email-code sign-in of a TOTP user asks for the second factor instead of a session", async () => {
  const { auth, mail, uri } = await setup();
  await call(auth, "/email-otp/send-verification-otp", { body: { email: "m@example.com", type: "sign-in" } });
  const jar: Jar = new Map();
  const r = await call(auth, "/sign-in/email-otp", { body: { email: "m@example.com", otp: mail.at(-1)!.text }, jar });
  assert.equal(r.status, 200);
  assert.equal(r.json?.twoFactorRedirect, true, JSON.stringify(r.json));
  assert.equal(await sessionOf(auth, jar), null, "no session before the second factor");
  assert.equal((await call(auth, "/two-factor/verify-totp", { body: { code: totp(uri, Date.now() + 30000) }, jar })).status, 200);
  assert.equal((await sessionOf(auth, jar))?.user?.email, "m@example.com");
});

test("F11: magic-link sign-in of a TOTP user redirects with twoFactorRedirect and no session", async () => {
  const { auth, mail } = await setup();
  await call(auth, "/sign-in/magic-link", { body: { email: "m@example.com", callbackURL: "/dashboard" } });
  const jar: Jar = new Map();
  const r = await call(auth, mail.at(-1)!.text, { jar });
  assert.equal(r.status, 302);
  assert.match(r.location ?? "", /twoFactorRedirect=true/);
  assert.equal(await sessionOf(auth, jar), null);
});

test("F11: can be switched off", async () => {
  const { auth, mail } = await setup({ mfaOnAllSignIns: false });
  await call(auth, "/email-otp/send-verification-otp", { body: { email: "m@example.com", type: "sign-in" } });
  const jar: Jar = new Map();
  await call(auth, "/sign-in/email-otp", { body: { email: "m@example.com", otp: mail.at(-1)!.text }, jar });
  assert.equal((await sessionOf(auth, jar))?.user?.email, "m@example.com");
});
