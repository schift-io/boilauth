/** F17 (audit 2026-09-27): usernames are NFKC-normalised before pattern, reserved list and uniqueness. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BASE, freshIp, makeAuth } from "./helpers.js";

const RULES = { minLength: 3, maxLength: 30, pattern: "^[\\p{L}\\p{N}_.]+$", reserved: ["admin"], caseInsensitive: true, immutable: false };

async function signUp(auth: Awaited<ReturnType<typeof makeAuth>>, username: string, n: number) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ email: `u${n}@example.com`, password: "a-long-password-1", name: "U", username }),
    }),
    { clientIp: freshIp() },
  );
  return { status: res.status, json: await res.json().catch(() => null) };
}

test("F17: a Unicode pattern works, and full-width look-alikes cannot take a reserved name", async () => {
  const auth = await makeAuth({ username: RULES });
  assert.equal((await signUp(auth, "지수_01", 1)).status, 200, "Hangul allowed by \\p{L}");
  assert.notEqual((await signUp(auth, "ａｄｍｉｎ", 2)).status, 200, "full-width admin is admin");
});

test("F17: full-width and ASCII forms are one username", async () => {
  const auth = await makeAuth({ username: RULES });
  assert.equal((await signUp(auth, "alice", 3)).status, 200);
  assert.notEqual((await signUp(auth, "ＡＬＩＣＥ", 4)).status, 200, "ＡＬＩＣＥ collides with alice");
});
