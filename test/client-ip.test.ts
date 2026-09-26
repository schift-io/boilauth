/**
 * F1/F3 (audit 2026-09-27): which client IP the rate limits, lockout and send limits key on.
 * Default: the socket address the app passes in (auth.handler(req, { clientIp })); forwarded
 * headers count only from trusted proxies or a named platform header.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BASE, makeAuth } from "./helpers.js";

type Handler = (req: Request, info?: { clientIp?: string | null }) => Promise<Response>;

async function wrongSignIn(auth: { handler: Handler }, headers: Record<string, string>, clientIp?: string | null) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE, ...headers },
      body: JSON.stringify({ email: "nobody@example.com", password: "not-the-password" }),
    }),
    clientIp === undefined ? undefined : { clientIp },
  );
  return res.status;
}

async function count429(n: number, attempt: (i: number) => Promise<number>) {
  let hits = 0;
  for (let i = 0; i < n; i++) if ((await attempt(i)) === 429) hits++;
  return hits;
}

test("F1: a spoofed X-Forwarded-For does not change the key; the socket address does", async () => {
  const auth = await makeAuth();
  const hits = await count429(14, (i) => wrongSignIn(auth, { "x-forwarded-for": `198.51.100.${i + 1}` }, "203.0.113.9"));
  assert.ok(hits >= 3, `14 attempts from one socket with rotating XFF must hit the 10/min limit, got ${hits}x429`);
});

test("F1: a client cannot set the internal client-IP header itself", async () => {
  const auth = await makeAuth();
  const hits = await count429(14, (i) => wrongSignIn(auth, { "x-boilauth-client-ip": `198.51.100.${i + 1}` }, "203.0.113.10"));
  assert.ok(hits >= 3, `got ${hits}x429`);
});

test("F3: two clients behind the app do not share one bucket", async () => {
  const auth = await makeAuth();
  const a = await count429(8, () => wrongSignIn(auth, {}, "192.0.2.10"));
  const b = await count429(8, () => wrongSignIn(auth, {}, "192.0.2.11"));
  assert.deepEqual([a, b], [0, 0], "8 attempts each stay under the 10/min per-IP limit");
});

test("F1: behind trusted proxies the right-most untrusted hop is the client; the spoofable left part is ignored", async () => {
  const auth = await makeAuth({ clientIp: { mode: "proxy", trustedProxies: ["10.0.0.0/8"] } });
  const hits = await count429(14, (i) =>
    wrongSignIn(auth, { "x-forwarded-for": `1.2.3.${i + 1}, 198.51.100.7, 10.0.0.2` }, "10.0.0.1"),
  );
  assert.ok(hits >= 3, `got ${hits}x429`);
  // A peer that is not a trusted proxy is the client itself, whatever it forwards.
  const direct = await count429(14, (i) => wrongSignIn(auth, { "x-forwarded-for": `1.2.4.${i + 1}` }, "203.0.113.20"));
  assert.ok(direct >= 3, `untrusted peer: got ${direct}x429`);
});

test("F1: platform header mode trusts only the named header", async () => {
  const auth = await makeAuth({ clientIp: { mode: "header", header: "cf-connecting-ip" } });
  const hits = await count429(14, (i) => wrongSignIn(auth, { "cf-connecting-ip": "198.51.100.40", "x-forwarded-for": `1.2.5.${i + 1}` }));
  assert.ok(hits >= 3, `got ${hits}x429`);
});

test("F1: IPv6 clients are keyed on their /64", async () => {
  const auth = await makeAuth();
  const hits = await count429(14, (i) => wrongSignIn(auth, {}, `2001:db8:1:2::${(i + 1).toString(16)}`));
  assert.ok(hits >= 3, `rotating inside one /64: got ${hits}x429`);
});

test("F3: in production a request with no resolvable client IP is refused, not pooled", async () => {
  const auth = await makeAuth();
  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  try {
    const res = await auth.handler(
      new Request(`${BASE}/api/auth/sign-in/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE, "x-forwarded-for": "198.51.100.1" },
        body: JSON.stringify({ email: "nobody@example.com", password: "x" }),
      }),
    );
    assert.equal(res.status, 500);
    assert.equal((await res.json()).code, "CLIENT_IP_UNAVAILABLE");
  } finally {
    process.env.NODE_ENV = prev;
  }
});

test("F1: boilauth/node passes the socket address over real HTTP; rotating X-Forwarded-For does not help", async () => {
  const { createServer } = await import("node:http");
  const { toNodeHandler } = await import("../src/node.js");
  const auth = await makeAuth();
  const server = createServer(toNodeHandler(auth));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  try {
    let hits = 0;
    for (let i = 0; i < 14; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/api/auth/sign-in/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE, "x-forwarded-for": `198.51.100.${i + 1}` },
        body: JSON.stringify({ email: "nobody@example.com", password: "not-the-password" }),
      });
      await res.text();
      if (res.status === 429) hits++;
    }
    assert.ok(hits >= 3, `got ${hits}x429`);
  } finally {
    server.close();
  }
});
