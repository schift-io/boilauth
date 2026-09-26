/**
 * createBoilAuth — Better Auth with boilauth's safe presets.
 *
 * Better Auth is the engine (sessions, cookies, CSRF/origin checks, adapters).
 * We only choose defaults and add the lockout/rehash plugin. Every option can
 * be overridden via `betterAuth` (deep-merged last), so nothing here is a lock-in.
 */
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { admin } from "better-auth/plugins";
import { createPasswordHasher, type Argon2Params, type FirebaseProjectKey } from "./hash/index.js";
import { boilauthPlugin, type LockoutOptions } from "./plugin.js";

export const PRESETS = {
  minPasswordLength: 10,
  maxPasswordLength: 128,
  lockout: { maxFailures: 5, lockMinutes: 15 } satisfies LockoutOptions,
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // rotate expiry at most once a day
    freshAge: 60 * 10, // sensitive actions need a sign-in in the last 10 min
  },
  rateLimit: {
    window: 60,
    max: 100,
    // Better Auth's built-in stricter rule for /sign-in*, /sign-up*,
    // /change-password*, /change-email* (3 per 10 s per IP) stays active.
    customRules: {
      "/sign-in/email": { window: 60, max: 10 },
      "/request-password-reset": { window: 300, max: 3 },
    },
  },
} as const;

export interface BoilAuthOptions {
  /** A Better Auth database: node:sqlite DatabaseSync, better-sqlite3, pg Pool, mysql2, or a Kysely dialect. */
  database: BetterAuthOptions["database"];
  secret: string;
  baseURL: string;
  /** Signer keys for Firebase projects you imported users from. */
  firebaseKeys?: FirebaseProjectKey[];
  argon2?: Partial<Argon2Params>;
  lockout?: Partial<LockoutOptions>;
  /** Require a verified email before password sign-in (default true when sendVerificationEmail is set). */
  requireEmailVerification?: boolean;
  /** Proxy CIDRs whose X-Forwarded-For you trust, so rate limits key on the real client IP. */
  trustedProxies?: string[];
  /** Test hook: fixed clock for lockout. */
  now?: () => Date;
  /** Escape hatch: raw Better Auth options merged over the presets. */
  betterAuth?: Partial<BetterAuthOptions>;
}

export function boilAuthOptions(o: BoilAuthOptions) {
  const hasher = createPasswordHasher({ argon2: o.argon2, firebaseKeys: o.firebaseKeys });
  const extra = o.betterAuth ?? {};
  const sendVerification = extra.emailVerification?.sendVerificationEmail;
  const options = {
    database: o.database,
    secret: o.secret,
    baseURL: o.baseURL,
    ...extra,
    emailAndPassword: {
      enabled: true,
      minPasswordLength: PRESETS.minPasswordLength,
      maxPasswordLength: PRESETS.maxPasswordLength,
      requireEmailVerification: o.requireEmailVerification ?? Boolean(sendVerification),
      revokeSessionsOnPasswordReset: true,
      ...extra.emailAndPassword,
      password: { hash: hasher.hash, verify: hasher.verify },
    },
    session: { ...PRESETS.session, ...extra.session },
    account: {
      ...extra.account,
      accountLinking: {
        enabled: true,
        requireLocalEmailVerified: true,
        ...extra.account?.accountLinking,
      },
    },
    rateLimit: {
      enabled: true,
      storage: "database" as const,
      window: PRESETS.rateLimit.window,
      max: PRESETS.rateLimit.max,
      customRules: { ...PRESETS.rateLimit.customRules },
      ...extra.rateLimit,
    },
    advanced: {
      useSecureCookies: o.baseURL.startsWith("https://"),
      ...extra.advanced,
      ipAddress: {
        ...(o.trustedProxies ? { trustedProxies: o.trustedProxies } : {}),
        ...extra.advanced?.ipAddress,
      },
    },
    plugins: [
      admin(),
      boilauthPlugin({
        hasher,
        lockout: { ...PRESETS.lockout, ...o.lockout },
        now: o.now,
      }),
      ...(extra.plugins ?? []),
    ],
  } satisfies BetterAuthOptions;
  return { options, hasher };
}

export function createBoilAuth(o: BoilAuthOptions) {
  const { options, hasher } = boilAuthOptions(o);
  const auth = betterAuth(options);
  return Object.assign(auth, { boilauth: { hasher, options, input: o } });
}

export type BoilAuth = ReturnType<typeof createBoilAuth>;
