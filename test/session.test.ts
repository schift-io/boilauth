import { test } from "node:test";
import assert from "node:assert/strict";
import { BASE, makeAuth, signIn } from "./helpers.js";

async function getSession(auth: any, cookie: string) {
  const token = /session_token=([^;]+)/.exec(cookie)![1];
  const res = await auth.handler(new Request(`${BASE}/api/auth/get-session`, { headers: { cookie: `better-auth.session_token=${token}` } }));
  return res.json();
}

test("session cookie lives 7 days and each sign-in mints a new token", async () => {
  const auth = await makeAuth();
  await auth.api.signUpEmail({ body: { email: "s@example.com", password: "session-password-1", name: "S" } });
  const a = await signIn(auth, "s@example.com", "session-password-1");
  const b = await signIn(auth, "s@example.com", "session-password-1");
  assert.match(a.cookie!, /Max-Age=604800/);
  assert.match(a.cookie!, /HttpOnly/);
  assert.notEqual(a.body.token, b.body.token);
});

test("password reset ends every existing session", async () => {
  let resetToken = "";
  const auth = await makeAuth({
    betterAuth: {
      emailAndPassword: {
        enabled: true,
        sendResetPassword: async ({ token }: { token: string }) => {
          resetToken = token;
        },
      },
    },
  });
  await auth.api.signUpEmail({ body: { email: "r@example.com", password: "reset-password-1", name: "R" } });
  const before = await signIn(auth, "r@example.com", "reset-password-1");
  assert.equal((await getSession(auth, before.cookie!)).user.email, "r@example.com");

  await auth.api.requestPasswordReset({ body: { email: "r@example.com", redirectTo: "/reset" } });
  assert.ok(resetToken, "reset token captured");
  await auth.api.resetPassword({ body: { newPassword: "reset-password-2", token: resetToken } });

  assert.equal(await getSession(auth, before.cookie!), null, "old session revoked");
  assert.equal((await signIn(auth, "r@example.com", "reset-password-1")).status, 401);
  assert.equal((await signIn(auth, "r@example.com", "reset-password-2")).status, 200);
});
