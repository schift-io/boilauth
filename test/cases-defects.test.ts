import { test } from "node:test";
import assert from "node:assert/strict";
import type { EmailMessage } from "../src/index.js";
import { BASE, freshIp, makeAuth, signIn } from "./helpers.js";

type Auth = Awaited<ReturnType<typeof makeAuth>>;

const PW = "correct-horse-battery-1";

function cookieHeader(setCookie: string | null): string {
  const token = /session_token=([^;]+)/.exec(setCookie ?? "")?.[1];
  if (!token) throw new Error("sign-in did not set a session cookie");
  return `better-auth.session_token=${token}`;
}

async function call(auth: Auth, pathOrUrl: string, options: { readonly body?: unknown; readonly cookie?: string } = {}) {
  const url = pathOrUrl.startsWith("http") ? pathOrUrl : `${BASE}/api/auth${pathOrUrl}`;
  const headers: Record<string, string> = { origin: BASE };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.cookie) headers.cookie = options.cookie;
  const response = await auth.handler(
    new Request(url, {
      method: options.body === undefined ? "GET" : "POST",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      redirect: "manual",
    }),
    { clientIp: freshIp() },
  );
  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    json = null;
  }
  return { status: response.status, text, json };
}

async function verifiedUser(auth: Auth, email: string, role = "user") {
  const created = await auth.api.signUpEmail({ body: { email, password: PW, name: "User" } });
  const ctx = await auth.$context;
  return ctx.internalAdapter.updateUser(created.user.id, { emailVerified: true, role });
}

test("AC-02: email change waits for new-address confirmation and notifies the old address", async () => {
  const mails: EmailMessage[] = [];
  const auth = await makeAuth({ sendEmail: async (mail) => void mails.push(mail), requireEmailVerification: false });
  const oldEmail = "old-address@example.com";
  const newEmail = "new-address@example.com";
  const account = await verifiedUser(auth, oldEmail);
  const signedIn = await signIn(auth, oldEmail, PW);
  assert.equal(signedIn.status, 200);
  const cookie = cookieHeader(signedIn.cookie);

  const requested = await call(auth, "/change-email", { body: { newEmail }, cookie });
  assert.equal(requested.status, 200, requested.text);
  const confirmation = mails.find((mail) => mail.to === newEmail);
  assert.ok(confirmation, `no confirmation mail sent to ${newEmail}: ${JSON.stringify(mails)}`);
  assert.equal(confirmation.kind, "email.change_verification", "the new-address confirmation mail has no kind");

  const ctx = await auth.$context;
  assert.equal((await ctx.internalAdapter.findUserById(account.id))?.email, oldEmail, "email changed before confirmation");
  assert.equal(mails.some((mail) => mail.kind === "security.email_changed"), false, "notice sent before the email changed");

  const confirmed = await call(auth, confirmation.text, { cookie });
  assert.ok(confirmed.status === 200 || confirmed.status === 302, `${confirmed.status} ${confirmed.text}`);
  assert.equal((await ctx.internalAdapter.findUserById(account.id))?.email, newEmail);
  assert.deepEqual(
    mails.filter((mail) => mail.kind === "security.email_changed").map((mail) => [mail.to, mail.kind]),
    [[oldEmail, "security.email_changed"]],
  );
});

test("RL-04: HTTP role changes revoke every target session", async () => {
  const auth = await makeAuth();
  const adminUser = await verifiedUser(auth, "role-admin@example.com", "admin");
  const target = await verifiedUser(auth, "role-target@example.com");
  const firstTarget = cookieHeader((await signIn(auth, target.email, PW)).cookie);
  const secondTarget = cookieHeader((await signIn(auth, target.email, PW)).cookie);
  const adminCookie = cookieHeader((await signIn(auth, adminUser.email, PW)).cookie);

  const changed = await call(auth, "/admin/set-role", { body: { userId: target.id, role: "admin" }, cookie: adminCookie });
  assert.equal(changed.status, 200, changed.text);
  assert.equal((await (await auth.$context).internalAdapter.findUserById(target.id))?.role, "admin");
  assert.equal((await call(auth, "/get-session", { cookie: firstTarget })).json, null, "the target's first session survived the role change");
  assert.equal((await call(auth, "/get-session", { cookie: secondTarget })).json, null, "the target's second session survived the role change");
  assert.ok((await call(auth, "/get-session", { cookie: adminCookie })).json, "the acting admin's session was revoked");
});

test("RL-10: HTTP role changes refuse an unconfigured role without side effects", async () => {
  const auth = await makeAuth();
  const adminUser = await verifiedUser(auth, "guard-admin@example.com", "admin");
  const target = await verifiedUser(auth, "guard-target@example.com");
  const targetCookie = cookieHeader((await signIn(auth, target.email, PW)).cookie);
  const adminCookie = cookieHeader((await signIn(auth, adminUser.email, PW)).cookie);

  const refused = await call(auth, "/admin/set-role", { body: { userId: target.id, role: "root" }, cookie: adminCookie });
  assert.equal(refused.status, 400, refused.text);
  const ctx = await auth.$context;
  assert.equal((await ctx.internalAdapter.findUserById(target.id))?.role, "user");
  assert.ok((await call(auth, "/get-session", { cookie: targetCookie })).json, "a refused role change deleted the target session");
});
