/**
 * Round-3 audit N1 (C4 reopened) over real HTTP: routes with a path parameter
 * (/callback/:id, /reset-password/:token) made one rate-limit key per distinct
 * value, so one client could mint unbounded counters and stay under the per-IP
 * limit by never repeating a value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { serve } from "./http.js";
import { templateMemory } from "../src/modules/rate-key.js";

async function rowCount(s: Awaited<ReturnType<typeof serve>>): Promise<number> {
  const ctx = await s.auth.$context;
  return (await ctx.adapter.findMany({ model: "rateLimit", limit: 100_000 })).length;
}

test("N1: 150 distinct /reset-password/<token> from one IP make at most one counter and hit the per-IP limit", async () => {
  const s = await serve(() => ({}));
  try {
    const before = await rowCount(s);
    const c = s.client();
    const statuses: number[] = [];
    for (let i = 0; i < 150; i++) statuses.push((await c.req(`/reset-password/tok${i}x${Math.random().toString(36).slice(2)}`)).status);
    const delta = (await rowCount(s)) - before;
    assert.ok(delta <= 1, `rows grew by ${delta} (one per token)`);
    assert.ok(statuses.includes(429), `no 429 across 150 requests from one IP: ${[...new Set(statuses)]}`);
  } finally {
    await s.close();
  }
});

test("N1: /callback/<id> for a provider that is not configured answers 404 before Better Auth; a configured one is served", async () => {
  const s = await serve(() => ({ socialProviders: { google: { clientId: "id", clientSecret: "secret" } } }));
  try {
    const before = await rowCount(s);
    const c = s.client();
    for (let i = 0; i < 150; i++) assert.equal((await c.req(`/callback/rnd${i}`)).status, 404);
    assert.equal((await rowCount(s)) - before, 0, "unconfigured provider ids wrote rateLimit rows");
    const google = await c.req("/callback/google?state=x&code=y");
    assert.notEqual(google.status, 404, "configured provider callback must reach Better Auth");
    for (let i = 0; i < 5; i++) await c.req(`/callback/google?state=s${i}&code=c${i}`);
    assert.ok((await rowCount(s)) - before <= 1, "a configured callback keyed per request");
  } finally {
    await s.close();
  }
});

test("N1: memory storage keeps one counter per IP per route template", async () => {
  const s = await serve(() => ({ rateLimitStorage: "memory" }));
  try {
    const before = templateMemory.size;
    const c = s.client();
    let limited = 0;
    for (let i = 0; i < 150; i++) if ((await c.req(`/reset-password/m${i}`)).status === 429) limited++;
    assert.ok(templateMemory.size - before <= 1, `memory counters grew by ${templateMemory.size - before}`);
    assert.ok(limited > 0, "per-IP limit never reached");
  } finally {
    await s.close();
  }
});

test("N1: a developer's own customStorage receives the template key; keys without a parameter are unchanged", async () => {
  const seen: string[] = [];
  const s = await serve(() => ({
    betterAuth: { rateLimit: { customStorage: { consume: async (key: string) => (seen.push(key), { allowed: true, retryAfter: null }) } } },
  }));
  try {
    const c = s.client();
    for (let i = 0; i < 5; i++) await c.req(`/reset-password/t${i}`);
    await c.req("/get-session");
    const reset = new Set(seen.filter((k) => k.includes("/reset-password")));
    assert.deepEqual([...reset].map((k) => k.split("|")[1]), ["/reset-password/:token"]);
    assert.ok(seen.some((k) => k.endsWith("|/get-session")));
  } finally {
    await s.close();
  }
});

test("N1: expired limiter rows are pruned; boilauth's own counters (no '|') are kept", async () => {
  const s = await serve(() => ({}));
  try {
    const ctx = await s.auth.$context;
    const old = Date.now() - 10 * 86400_000;
    await ctx.adapter.create({ model: "rateLimit", data: { key: "203.0.113.9|/get-session", count: 1, lastRequest: old } });
    await ctx.adapter.create({ model: "rateLimit", data: { key: "boilauth-lock:u1:203.0.113.9", count: 3, lastRequest: old } });
    const storage = (s.auth.options.rateLimit as { customStorage: { consume: (k: string, r: { window: number; max: number }) => Promise<unknown> } }).customStorage;
    for (let i = 0; i < 200; i++) await storage.consume(`198.51.100.${i % 250}|/get-session`, { window: 60, max: 100 });
    const keys = (await ctx.adapter.findMany({ model: "rateLimit", limit: 100_000 })).map((r: { key: string }) => r.key);
    assert.ok(!keys.includes("203.0.113.9|/get-session"), "expired limiter row not pruned");
    assert.ok(keys.includes("boilauth-lock:u1:203.0.113.9"), "boilauth counter was pruned");
  } finally {
    await s.close();
  }
});
