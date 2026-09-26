/**
 * Rate-limit counters per route template (round-3 audit N1).
 *
 * Better Auth keys its limiter on `<ip>|<path>` with the raw path, so a route
 * with a path parameter (/callback/:id, /reset-password/:token) got one
 * counter per distinct value: one client could mint unbounded rows (or memory
 * entries) and, by never repeating a value, never reach the per-IP limit.
 * Better Auth has no key hook; its one extension point is
 * `rateLimit.customStorage`, which receives the key. This storage folds the
 * parameter back into the template (`<ip>|/callback/:id`) and then counts
 * exactly as before: in the rateLimit table with the conditional increment
 * (counter-store.ts), in process memory, in secondary storage, or in the
 * developer's own customStorage.
 */
import { consumeDatabase } from "./counter-store.js";

export type Rule = { window: number; max: number };
export type RateStorage = { consume(key: string, rule: Rule): Promise<{ allowed: boolean; retryAfter: number | null }> };
export type Template = { re: RegExp; template: string };

/** Endpoint paths with a `:param` segment, as matchers over the path below the base path. */
export function paramTemplates(api: Record<string, unknown>): Template[] {
  const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return Object.values(api)
    .map((f) => (typeof f === "function" ? (f as { path?: unknown }).path : undefined))
    .filter((p): p is string => typeof p === "string" && p.includes("/:"))
    .map((template) => ({
      template,
      re: new RegExp(`^${template.split("/").map((seg) => (seg.startsWith(":") ? "[^/]+" : escape(seg))).join("/")}/?$`),
    }));
}

/** `<ip>|/callback/abc` -> `<ip>|/callback/:id`; keys without a parameter are unchanged. */
export function templateKey(key: string, templates: Template[]): string {
  const i = key.indexOf("|");
  if (i < 0) return key;
  const path = key.slice(i + 1);
  const t = templates.find((x) => x.re.test(path));
  return t ? key.slice(0, i + 1) + t.template : key;
}

/** Memory counters for Better Auth's limiter, bounded like Better Auth's own store. */
export const templateMemory = new Map<string, { count: number; lastRequest: number; expiresAt: number }>();
const MEMORY_MAX = 100_000;

function pruneMemory(now: number) {
  if (templateMemory.size <= MEMORY_MAX) return;
  for (const [k, e] of templateMemory) if (now >= e.expiresAt) templateMemory.delete(k);
  let overflow = templateMemory.size - MEMORY_MAX;
  for (const k of templateMemory.keys()) {
    if (overflow-- <= 0) break;
    templateMemory.delete(k);
  }
}

function consumeMemory(key: string, rule: Rule, now: number) {
  pruneMemory(now);
  const windowMs = rule.window * 1000;
  const e = templateMemory.get(key);
  const live = e && now < e.expiresAt ? e : undefined;
  if (!live || now - live.lastRequest >= windowMs) {
    templateMemory.set(key, { count: 1, lastRequest: now, expiresAt: now + windowMs });
    return { allowed: true, retryAfter: null };
  }
  if (live.count >= rule.max) return { allowed: false, retryAfter: Math.ceil((live.lastRequest + windowMs - now) / 1000) };
  templateMemory.set(key, { count: live.count + 1, lastRequest: now, expiresAt: now + windowMs });
  return { allowed: true, retryAfter: null };
}

export interface TemplateStorageLink {
  /** Filled by createBoilAuth once the endpoints exist. */
  templates: Template[];
  /** Filled by createBoilAuth: the database adapter. */
  adapter?: () => Promise<any>;
}

export function templateRateStorage(o: {
  link: TemplateStorageLink;
  storage: "memory" | "database" | "secondary-storage";
  custom?: RateStorage;
  increment?: (key: string, ttl: number) => Promise<number>;
  now?: () => number;
}): RateStorage {
  const now = o.now ?? Date.now;
  let calls = 0;
  let longest = 0;
  return {
    async consume(rawKey, rule) {
      const key = templateKey(rawKey, o.link.templates);
      if (o.custom) return o.custom.consume(key, rule);
      if (o.storage === "memory") return consumeMemory(key, rule, now());
      if (o.storage === "secondary-storage") {
        if (!o.increment) throw new Error("boilauth: secondary-storage rate limiting needs secondaryStorage.increment");
        return (await o.increment(key, rule.window)) <= rule.max ? { allowed: true, retryAfter: null } : { allowed: false, retryAfter: rule.window };
      }
      if (!o.link.adapter) throw new Error("boilauth: rate-limit storage used before createBoilAuth linked the database");
      const db = await o.link.adapter();
      const t = now();
      const d = await consumeDatabase(db, key, rule.max, rule.window, t);
      // Better Auth pruned expired limiter rows itself; keep doing it for limiter keys only
      // (they contain "|"; boilauth's own lockout and send counters do not).
      longest = Math.max(longest, rule.window);
      if (++calls % 200 === 0) {
        await db
          .deleteMany({ model: "rateLimit", where: [{ field: "key", operator: "contains", value: "|" }, { field: "lastRequest", operator: "lt", value: t - longest * 1000 }] })
          .catch(() => undefined);
      }
      return d.allowed ? { allowed: true, retryAfter: null } : { allowed: false, retryAfter: d.retryAfter };
    },
  };
}
