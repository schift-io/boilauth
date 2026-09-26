/**
 * boilauth/rate-limit — limits for the endpoints that send mail or SMS.
 *
 *   plugins: [sendLimits({ perIpPerHour: 10, perAccountPerHour: 5 })]
 *
 * Per IP is Better Auth's own limiter: the plugin contributes rateLimit rules
 * for these paths (createBoilAuth puts it first so its rules win over the
 * magic-link, email-otp and phone plugins' own). Better Auth keys on IP + path
 * and has no per-account key, so the per-address limit is counted here: one
 * bucket per normalised email or phone number shared by every send endpoint,
 * stored where Better Auth stores its own counters (the rateLimit table, or
 * memory), with the same conditional increment Better Auth uses so concurrent
 * requests cannot both pass.
 *
 * withRateLimitHeaders() (used by createBoilAuth for every project) adds the
 * standard Retry-After to Better Auth's 429, which carries only X-Retry-After.
 */
import { createHash } from "node:crypto";
import type { BetterAuthPlugin } from "better-auth";
import { consumeDatabase, consumeMemory } from "./counter-store.js";

/** Send endpoint -> body field that names the destination. */
export const SEND_PATHS: Record<string, "email" | "phoneNumber"> = {
  "/request-password-reset": "email",
  "/send-verification-email": "email",
  "/sign-in/magic-link": "email",
  "/email-otp/send-verification-otp": "email",
  "/email-otp/request-password-reset": "email",
  "/forget-password/email-otp": "email",
  "/phone-number/send-otp": "phoneNumber",
  "/phone-number/request-password-reset": "phoneNumber",
};

export const HOUR = 3600;
export const SEND_LIMIT_PLUGIN_ID = "boilauth-send-limit";

export interface SendLimits {
  /** Sends per IP per hour on each send endpoint (Better Auth's limiter). 0 keeps Better Auth's own per-minute rules. */
  perIpPerHour: number;
  /** Sends per destination address per hour, across all send endpoints and IPs. 0 turns it off. */
  perAccountPerHour: number;
}

/**
 * Emails compare trimmed and lowercased (as Better Auth stores them). Phone numbers count only
 * in the E.164 form the phone plugin accepts; anything else is refused before an SMS goes out,
 * so it must not use up the real number's quota either.
 */
export function normaliseDestination(field: "email" | "phoneNumber", raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  if (field === "phoneNumber") return /^\+[1-9]\d{7,14}$/.test(raw) ? raw : null;
  const v = raw.trim().toLowerCase();
  return v ? v : null;
}

function tooMany(retryAfter: number, max: number, windowS: number): Response {
  const reset = String(Math.max(1, retryAfter));
  return new Response(JSON.stringify({ code: "TOO_MANY_REQUESTS", message: "Too many requests. Please try again later." }), {
    status: 429,
    headers: {
      "content-type": "application/json",
      "Retry-After": reset,
      "X-Retry-After": reset,
      "RateLimit-Limit": String(max),
      "RateLimit-Remaining": "0",
      "RateLimit-Reset": reset,
      "RateLimit-Policy": `${max};w=${windowS}`,
    },
  });
}

export function sendLimits(o: SendLimits & { now?: () => Date }): BetterAuthPlugin {
  const paths = new Set(Object.keys(SEND_PATHS));
  return {
    id: SEND_LIMIT_PLUGIN_ID,
    rateLimit: [
      // With perIpPerHour 0 the rule matches nothing but still tells Better Auth's pruning that
      // rateLimit rows live for an hour, so per-address counters are not deleted early.
      { pathMatcher: (path: string) => o.perIpPerHour > 0 && paths.has(path), window: HOUR, max: Math.max(1, o.perIpPerHour) },
    ],
    async onRequest(req, ctx) {
      if (!o.perAccountPerHour || req.method !== "POST" || !ctx.rateLimit.enabled) return;
      const base = new URL(ctx.baseURL).pathname.replace(/\/$/, "");
      const path = new URL(req.url).pathname.slice(base.length).replace(/\/$/, "");
      const field = SEND_PATHS[path];
      if (!field) return;
      let body: Record<string, unknown>;
      try {
        body = await req.clone().json();
      } catch {
        return;
      }
      const dest = normaliseDestination(field, body?.[field]);
      if (!dest) return;
      const key = "boilauth-send:" + createHash("sha256").update(dest).digest("hex");
      const now = (o.now?.() ?? new Date()).getTime();
      const decision =
        ctx.rateLimit.storage === "memory"
          ? await consumeMemory(key, o.perAccountPerHour, HOUR, now)
          : await consumeDatabase(ctx.adapter, key, o.perAccountPerHour, HOUR, now);
      if (!decision.allowed) return { response: tooMany(decision.retryAfter, o.perAccountPerHour, HOUR) };
    },
  };
}

/** Wraps an auth handler so every 429 also carries the standard Retry-After header. */
export function withRateLimitHeaders<H extends (req: Request, ...rest: any[]) => Promise<Response>>(handler: H): H {
  return (async (req: Request, ...rest: any[]) => {
    const res = await handler(req, ...rest);
    if (res.status !== 429 || res.headers.has("Retry-After")) return res;
    const after = res.headers.get("X-Retry-After");
    if (!after) return res;
    const headers = new Headers(res.headers);
    headers.set("Retry-After", after);
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  }) as H;
}
