/**
 * createBoilAuth — Better Auth with boilauth's safe presets.
 *
 * Better Auth is the engine (sessions, cookies, CSRF/origin checks, adapters).
 * We choose defaults and add the lockout/rehash plugin. Every option can be
 * overridden via `betterAuth` (merged last), so nothing here is a lock-in.
 *
 * The wizard (`boilauth init`) generates a call to this with the answers as
 * literal values; see docs/EDGE_CASES.md for which key drives which option.
 */
import { betterAuth, type BetterAuthOptions, type BetterAuthPlugin, type User } from "better-auth";
import { admin, username as usernamePlugin } from "better-auth/plugins";
import { createPasswordHasher, type Argon2Params, type FirebaseProjectKey } from "./hash/index.js";
import { boilauthPlugin, type LockoutOptions } from "./plugin.js";
import { normalizeUsername, usernamePluginOptions, type UsernameRules } from "./modules/username.js";

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
    // Better Auth's built-in stricter rule for /sign-up*, /change-password*,
    // /change-email* (3 per 10 s per IP) stays active.
    customRules: {
      "/sign-in/email": { window: 60, max: 10 },
      "/request-password-reset": { window: 300, max: 3 },
    },
  },
} as const;

export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface BoilAuthOptions {
  /** A Better Auth database: node:sqlite DatabaseSync, better-sqlite3, pg Pool, mysql2, or a Kysely dialect. */
  database: BetterAuthOptions["database"];
  secret: string;
  baseURL: string;
  /** Email + password sign-in. Default true. */
  emailPassword?: boolean;
  /** Signer keys for Firebase projects you imported users from. */
  firebaseKeys?: FirebaseProjectKey[];
  argon2?: Partial<Argon2Params>;
  minPasswordLength?: number;
  /** maxFailures 0 turns lockout off. */
  lockout?: Partial<LockoutOptions>;
  rateLimitSignInPerMinute?: number;
  sessionDays?: number;
  /** Require a verified email before password sign-in (default true when an email sender is set). */
  requireEmailVerification?: boolean;
  /** Sends verification and password-reset mail. Without it neither mail goes out. */
  sendEmail?: (msg: EmailMessage) => Promise<void>;
  /** OAuth identity with an existing email: link when both sides are verified, or never. */
  accountLinking?: "verified_only" | "never";
  socialProviders?: BetterAuthOptions["socialProviders"];
  /**
   * Username sign-in (POST /sign-in/username) under these rules, usually from
   * loadUsernameRules("boilauth.username.yaml"). Lockout, rehash and the sign-in
   * rate limit cover this path as they cover /sign-in/email.
   */
  username?: UsernameRules;
  /** Better Auth's admin plugin (role column). Default true; set false for no roles, or pass your own admin() in plugins. */
  admin?: boolean;
  /** Extra plugins, in order, after boilauth's own. */
  plugins?: BetterAuthPlugin[];
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
  const send = o.sendEmail;
  const sendVerification =
    extra.emailVerification?.sendVerificationEmail ??
    (send
      ? async ({ user, url }: { user: User; url: string }) =>
          send({ to: user.email, subject: "Verify your email", text: url })
      : undefined);
  const sendReset =
    extra.emailAndPassword?.sendResetPassword ??
    (send
      ? async ({ user, url }: { user: User; url: string }) =>
          send({ to: user.email, subject: "Reset your password", text: url })
      : undefined);
  const userPlugins = o.plugins ?? [];
  const wantsAdmin = (o.admin ?? true) && !userPlugins.some((p) => p.id === "admin");
  const signInPerMinute = o.rateLimitSignInPerMinute ?? PRESETS.rateLimit.customRules["/sign-in/email"].max;
  const options = {
    database: o.database,
    secret: o.secret,
    baseURL: o.baseURL,
    ...extra,
    socialProviders: { ...extra.socialProviders, ...o.socialProviders },
    emailAndPassword: {
      enabled: o.emailPassword ?? true,
      minPasswordLength: o.minPasswordLength ?? PRESETS.minPasswordLength,
      maxPasswordLength: PRESETS.maxPasswordLength,
      requireEmailVerification: o.requireEmailVerification ?? Boolean(sendVerification),
      revokeSessionsOnPasswordReset: true,
      ...(sendReset ? { sendResetPassword: sendReset } : {}),
      ...extra.emailAndPassword,
      password: { hash: hasher.hash, verify: hasher.verify },
    },
    emailVerification: {
      ...(sendVerification ? { sendVerificationEmail: sendVerification, sendOnSignUp: true } : {}),
      ...extra.emailVerification,
    },
    session: {
      ...PRESETS.session,
      ...(o.sessionDays ? { expiresIn: o.sessionDays * 86400 } : {}),
      ...extra.session,
    },
    account: {
      ...extra.account,
      accountLinking: {
        enabled: o.accountLinking !== "never",
        requireLocalEmailVerified: true,
        ...extra.account?.accountLinking,
      },
    },
    rateLimit: {
      enabled: true,
      storage: "database" as const,
      window: PRESETS.rateLimit.window,
      max: PRESETS.rateLimit.max,
      customRules: {
        ...PRESETS.rateLimit.customRules,
        "/sign-in/email": { window: 60, max: signInPerMinute },
        ...(o.username ? { "/sign-in/username": { window: 60, max: signInPerMinute } } : {}),
      },
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
      boilauthPlugin({
        hasher,
        lockout: { ...PRESETS.lockout, ...o.lockout },
        now: o.now,
        ...(o.username ? { normalizeUsername: (u: string) => normalizeUsername(o.username!, u) } : {}),
      }),
      ...(o.username ? [usernamePlugin(usernamePluginOptions(o.username))] : []),
      ...(wantsAdmin ? [admin()] : []),
      ...userPlugins,
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
