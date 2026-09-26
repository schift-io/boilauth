import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { createBoilAuth, migrate, type BoilAuthOptions, type FirebaseProjectKey } from "../src/index.js";

export const BASE = "http://localhost:3000";
export const SECRET = "test-secret-0123456789abcdef0123456789abcdef";

/** Public sample params from firebase/scrypt README — not a real project key. */
export const FIREBASE_SAMPLE_KEY: FirebaseProjectKey = {
  keyId: "sample-project",
  signerKey: "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
  saltSeparator: "Bw==",
  rounds: 8,
  memCost: 14,
};

export function fixture(name: string): string {
  return readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8");
}

export async function makeAuth(extra: Partial<BoilAuthOptions> = {}, file = ":memory:") {
  const auth = createBoilAuth({
    database: new DatabaseSync(file),
    secret: SECRET,
    baseURL: BASE,
    firebaseKeys: [FIREBASE_SAMPLE_KEY],
    ...extra,
    betterAuth: { logger: { disabled: true }, ...extra.betterAuth },
  });
  await migrate(auth);
  return auth;
}

let ipCounter = 1;
/** A fresh client IP per call unless one is given, so IP rate limits don't leak between assertions. */
export function freshIp(): string {
  ipCounter++;
  return `10.1.${(ipCounter >> 8) & 255}.${ipCounter & 255}`;
}

export async function signIn(
  auth: { handler: (r: Request, info?: { clientIp?: string }) => Promise<Response> },
  email: string,
  password: string,
  ip = freshIp(),
) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ email, password }),
    }),
    { clientIp: ip },
  );
  const body = await res.json().catch(() => null);
  return { status: res.status, body, cookie: res.headers.get("set-cookie") };
}

export async function storedHash(auth: { $context: Promise<any> }, email: string): Promise<string | null> {
  const ctx = await auth.$context;
  const found = await ctx.internalAdapter.findUserByEmail(email.toLowerCase());
  if (!found) return null;
  const acc = await ctx.internalAdapter.findCredentialAccount(found.user.id);
  return acc?.password ?? null;
}
