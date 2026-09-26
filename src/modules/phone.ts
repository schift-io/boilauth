/**
 * Phone number sign-in presets (spec B5) on Better Auth's `phoneNumber` plugin.
 *
 * createBoilAuth({ phone: { sendSms } }) adds the plugin with these presets:
 *   - numbers must be E.164 (+ and 8..15 digits),
 *   - 6-digit SMS codes, valid 5 minutes, 3 wrong tries spend the code,
 *   - phone + password sign-in only for a verified number.
 *
 * Paths: POST /phone-number/send-otp, POST /phone-number/verify (with
 * updatePhoneNumber: true to attach a number to the signed-in user; without
 * it, a verified code for a known number signs that user in), POST
 * /sign-in/phone-number (number + password; lockout covers it).
 *
 * An SMS-code sign-in has no second step, like magic link: it never
 * satisfies boilauth/mfa's admin requirement.
 *
 * SMS pumping (audit F2): numbers outside `allowedCountryCodes` are refused
 * with 400 before any SMS, and `smsPerHour` caps SMS sends site-wide (all
 * numbers, all IPs) with 429, on top of the per-IP and per-number send limits.
 */
import { randomUUID } from "node:crypto";
import type { BetterAuthPlugin } from "better-auth";
import { phoneNumber } from "better-auth/plugins";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { consume } from "./counter-store.js";

export interface SmsMessage {
  to: string;
  text: string;
}

export interface PhoneOptions {
  sendSms: (msg: SmsMessage) => Promise<void>;
  /** Country calling codes without "+", e.g. ["82", "1"]. Empty or absent: every country. */
  allowedCountryCodes?: string[];
  /** SMS sends per hour across the whole site. 0 or absent: no site-wide cap. */
  smsPerHour?: number;
}

export const E164 = /^\+[1-9]\d{7,14}$/;

const SMS_PATHS = new Set(["/phone-number/send-otp", "/phone-number/request-password-reset"]);
const HOUR = 3600;

export function phoneNumberAllowed(o: Pick<PhoneOptions, "allowedCountryCodes">, n: string): boolean {
  if (!E164.test(n)) return false;
  const codes = o.allowedCountryCodes ?? [];
  return codes.length === 0 || codes.some((c) => n.startsWith("+" + c));
}

/** Site-wide SMS budget: one counter in the rateLimit storage for every SMS send. */
function smsBudget(o: PhoneOptions, perHour: number, now: () => Date): BetterAuthPlugin {
  // Database storage: one budget per database, shared by every instance. Memory storage is per
  // process anyway; key it per instance so two auth instances in one process do not share it.
  const memoryKey = `boilauth-sms-budget:${randomUUID()}`;
  return {
    id: "boilauth-sms-budget",
    // Never matches: keeps Better Auth's pruning from deleting the hourly counter early.
    rateLimit: [{ pathMatcher: () => false, window: HOUR, max: 1 }],
    hooks: {
      before: [
        {
          matcher: (ctx) => SMS_PATHS.has(ctx.path ?? ""),
          handler: createAuthMiddleware(async (ctx) => {
            // A number Better Auth will refuse (400) must not spend everyone's budget.
            const n = typeof ctx.body?.phoneNumber === "string" ? ctx.body.phoneNumber : "";
            if (!phoneNumberAllowed(o, n)) return;
            const storage = ctx.context.rateLimit?.storage === "memory" ? "memory" : "database";
            const key = storage === "memory" ? memoryKey : "boilauth-sms-budget";
            const d = await consume(storage, ctx.context.adapter, key, perHour, HOUR, now().getTime());
            if (!d.allowed) {
              throw new APIError("TOO_MANY_REQUESTS", { code: "SMS_BUDGET_EXCEEDED", message: "Too many SMS sent. Please try again later." }, {
                "Retry-After": String(Math.max(1, d.retryAfter)),
                "X-Retry-After": String(Math.max(1, d.retryAfter)),
              });
            }
          }),
        },
      ],
    },
  };
}

/** Better Auth's phoneNumber plugin with boilauth's presets, plus the SMS budget when set. */
export function phonePlugins(o: PhoneOptions, now: () => Date = () => new Date()): BetterAuthPlugin[] {
  return [phonePlugin(o), ...(o.smsPerHour && o.smsPerHour > 0 ? [smsBudget(o, o.smsPerHour, now)] : [])];
}

export function phonePlugin(o: PhoneOptions) {
  return phoneNumber({
    otpLength: 6,
    expiresIn: 300,
    allowedAttempts: 3,
    requireVerification: true,
    phoneNumberValidator: (n: string) => phoneNumberAllowed(o, n),
    sendOTP: async ({ phoneNumber: to, code }) => o.sendSms({ to, text: `Your code is ${code}. It expires in 5 minutes.` }),
  });
}
