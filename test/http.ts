/**
 * Real-HTTP harness: the auth instance behind node:http with boilauth/node's
 * toNodeHandler (socket address as the client IP), exercised with fetch.
 * The re-audit asked for its findings to be reproduced over HTTP, not only
 * through auth.handler.
 */
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { createBoilAuth, migrate, type BoilAuthOptions } from "../src/index.js";
import { toNodeHandler } from "../src/node.js";

export const SECRET = "http-test-secret-0123456789abcdef0123456789";
export const PW = "correct-horse-battery-1";

export type Served = Awaited<ReturnType<typeof serve>>;

export async function serve(make: (base: string) => Partial<BoilAuthOptions>) {
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const { port } = server.address() as { port: number };
  const base = `http://127.0.0.1:${port}`;
  const o = make(base);
  const auth = createBoilAuth({
    database: new DatabaseSync(":memory:"),
    secret: SECRET,
    baseURL: base,
    ...o,
    betterAuth: { logger: { disabled: true }, ...o.betterAuth },
  });
  await migrate(auth);
  server.on("request", toNodeHandler(auth));
  return {
    base,
    auth,
    client: () => new Client(base),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

export interface Reply {
  status: number;
  json: any;
  text: string;
  headers: Headers;
}

export class Client {
  readonly jar = new Map<string, string>();
  constructor(readonly base: string) {}

  async req(pathOrUrl: string, o: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<Reply> {
    const url = pathOrUrl.startsWith("http") ? pathOrUrl : `${this.base}/api/auth${pathOrUrl}`;
    const headers: Record<string, string> = { origin: this.base, ...o.headers };
    if (o.body !== undefined) headers["content-type"] = "application/json";
    if (this.jar.size) headers.cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await fetch(url, {
      method: o.method ?? (o.body === undefined ? "GET" : "POST"),
      redirect: "manual",
      headers,
      body: o.body === undefined ? undefined : JSON.stringify(o.body),
    });
    for (const c of res.headers.getSetCookie()) {
      const kv = c.split(";")[0];
      const i = kv.indexOf("=");
      const k = kv.slice(0, i);
      const v = kv.slice(i + 1);
      if (!v || /max-age=0/i.test(c)) this.jar.delete(k);
      else this.jar.set(k, v);
    }
    const text = await res.text();
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {}
    return { status: res.status, json, text, headers: res.headers };
  }

  async session(): Promise<any> {
    return (await this.req("/get-session")).json;
  }
}

/** A verified user with a password, created directly in the database. */
export async function user(s: Served, email: string, extra: Record<string, unknown> = {}) {
  const ctx = await s.auth.$context;
  const u = await ctx.internalAdapter.createUser({ email, name: "U", emailVerified: true, ...extra });
  await ctx.internalAdapter.createAccount({ userId: u.id, providerId: "credential", accountId: u.id, password: await ctx.password.hash(PW) });
  return u as { id: string; email: string };
}

export function totp(uri: string, at = Date.now()): string {
  const secret = new URL(uri).searchParams.get("secret")!;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const off = h[h.length - 1] & 15;
  const n = ((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(n % 1_000_000).padStart(6, "0");
}

/** Signs in with the password and enrolls TOTP; returns the TOTP URI. The client ends signed in. */
export async function enrollTotp(c: Client, email: string): Promise<string> {
  const si = await c.req("/sign-in/email", { body: { email, password: PW } });
  if (si.status !== 200) throw new Error(`sign-in ${si.status} ${si.text}`);
  const en = await c.req("/two-factor/enable", { body: { password: PW } });
  if (en.status !== 200) throw new Error(`enable ${en.status} ${en.text}`);
  const ok = await c.req("/two-factor/verify-totp", { body: { code: totp(en.json.totpURI) } });
  if (ok.status !== 200) throw new Error(`verify-totp ${ok.status} ${ok.text}`);
  return en.json.totpURI;
}

export async function medianMs(n: number, run: () => Promise<unknown>): Promise<number> {
  const xs: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    await run();
    xs.push(performance.now() - t);
  }
  xs.sort((a, b) => a - b);
  return xs[Math.floor(n / 2)];
}
