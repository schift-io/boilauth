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
import { admin, bearer, username as usernamePlugin } from "better-auth/plugins";
import { createPasswordHasher, type Argon2Params, type FirebaseProjectKey } from "./hash/index.js";
import { boilauthPlugin, type LockoutOptions } from "./plugin.js";
import { normalizeUsername, usernamePluginOptions, type UsernameRules } from "./modules/username.js";
import { phonePlugins, type PhoneOptions } from "./modules/phone.js";
import { SEND_LIMIT_PLUGIN_ID, withRateLimitHeaders } from "./modules/rate-limit.js";
import { hideAdminRoutes } from "./modules/admin-hide.js";
import { CLIENT_IP_HEADER, withClientIp, type ClientIpConfig } from "./modules/client-ip.js";

export const PRESETS = {
  minPasswordLength: 12, // ASVS 4.0.3 2.1.1
  maxPasswordLength: 128,
  lockout: { maxFailures: 5, lockMinutes: 15, accountMaxFailures: 20, knownSourceDays: 90 } satisfies LockoutOptions,
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // rotate expiry at most once a day
    freshAge: 60 * 10, // sensitive actions need a sign-in in the last 10 min
    absoluteDays: 30, // ASVS 3.3.2: re-authenticate at least every 30 days, even while active
  },
  rateLimit: {
    window: 60,
    max: 100,
    // Better Auth's built-in stricter rule for /sign-up*, /change-password*,
    // /change-email* (3 per 10 s per IP) stays active.
    customRules: {
      "/sign-in/email": { window: 60, max: 10 },
      // Without boilauth/rate-limit; with it, that module's hourly rule applies instead.
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
  /** Where rate-limit counters live. "database" (default) is shared by every instance; "memory" is per process. */
  rateLimitStorage?: "database" | "memory";
  sessionDays?: number;
  /** A session ends this many days after sign-in however active it is (default 30). */
  sessionAbsoluteDays?: number;
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
  /**
   * POST /is-username-available per IP per hour (default 30). 0 removes the endpoint: it
   * answers whether a username is taken to anyone.
   */
  usernameCheckPerIpPerHour?: number;
  /** Phone number sign-in (SMS codes, number + password) with boilauth's presets; see boilauth/phone. */
  phone?: PhoneOptions;
  /** Better Auth's admin plugin (role column). Default true; set false for no roles, or pass your own admin() in plugins. */
  admin?: boolean;
  /** Answer 404 instead of 401/403 on /admin/* to anyone without an admin role. Default false. */
  hideAdminRoutes?: boolean;
  /**
   * Also accept `Authorization: Bearer <token>` (mobile and API clients) via Better Auth's
   * bearer plugin; sign-in responses then carry a `set-auth-token` header. Default false (cookies only).
   */
  bearer?: boolean;
  /** Extra plugins, in order, after boilauth's own. */
  plugins?: BetterAuthPlugin[];
  /**
   * Where the client IP comes from (rate limits, lockout, send limits). Default socket: the
   * address the server adapter passes as auth.handler(request, { clientIp }); forwarded headers
   * are ignored. See boilauth/client-ip.
   */
  clientIp?: ClientIpConfig;
  /** Shorthand for clientIp: { mode: "proxy", trustedProxies }. */
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
  // boilauth/rate-limit goes first so its per-IP rules win over later plugins' own (Better Auth takes the first match).
  const sendLimit = userPlugins.find((p) => p.id === SEND_LIMIT_PLUGIN_ID);
  const usernameChecks = o.username ? (o.usernameCheckPerIpPerHour ?? 30) : 0;
  const requireVerification = o.requireEmailVerification ?? Boolean(sendVerification);
  const { "/request-password-reset": resetRule, ...coreRules } = PRESETS.rateLimit.customRules;
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
      requireEmailVerification: requireVerification,
      // Without required verification Better Auth signs a new user in and tells a duplicate
      // sign-up apart (422); autoSignIn false gives the same answer either way (audit F5).
      ...(requireVerification ? {} : { autoSignIn: false }),
      revokeSessionsOnPasswordReset: true,
      ...(sendReset ? { sendResetPassword: sendReset } : {}),
      ...extra.emailAndPassword,
      password: { hash: hasher.hash, verify: hasher.verify },
    },
    emailVerification: {
      ...(sendVerification ? { sendVerificationEmail: sendVerification, sendOnSignUp: true } : {}),
      ...extra.emailVerification,
    },
    ...(o.username && usernameChecks === 0 ? { disabledPaths: [...(extra.disabledPaths ?? []), "/is-username-available"] } : {}),
    session: {
      expiresIn: PRESETS.session.expiresIn,
      updateAge: PRESETS.session.updateAge,
      freshAge: PRESETS.session.freshAge,
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
      storage: o.rateLimitStorage ?? ("database" as const),
      window: PRESETS.rateLimit.window,
      max: PRESETS.rateLimit.max,
      customRules: {
        ...coreRules,
        ...(sendLimit ? {} : { "/request-password-reset": resetRule }),
        "/sign-in/email": { window: 60, max: signInPerMinute },
        ...(o.username ? { "/sign-in/username": { window: 60, max: signInPerMinute } } : {}),
        ...(usernameChecks > 0 ? { "/is-username-available": { window: 3600, max: usernameChecks } } : {}),
        ...(o.phone ? { "/sign-in/phone-number": { window: 60, max: signInPerMinute } } : {}),
      },
      ...extra.rateLimit,
    },
    advanced: {
      useSecureCookies: o.baseURL.startsWith("https://"),
      ...extra.advanced,
      // boilauth resolves the client IP (withClientIp) and hands it over in one private header.
      ipAddress: {
        ipAddressHeaders: [CLIENT_IP_HEADER],
        ipv6Subnet: 64,
        ...extra.advanced?.ipAddress,
      },
    },
    plugins: [
      ...(sendLimit ? [sendLimit] : []),
      boilauthPlugin({
        hasher,
        lockout: { ...PRESETS.lockout, ...o.lockout },
        now: o.now,
        ...(o.username ? { normalizeUsername: (u: string) => normalizeUsername(o.username!, u) } : {}),
        phoneSignIn: Boolean(o.phone),
        absoluteSessionSeconds: (o.sessionAbsoluteDays ?? PRESETS.session.absoluteDays) * 86400,
      }),
      ...(o.username ? [usernamePlugin(usernamePluginOptions(o.username))] : []),
      ...(o.phone ? phonePlugins(o.phone, o.now) : []),
      ...(o.hideAdminRoutes ? [hideAdminRoutes()] : []),
      ...(o.bearer ? [bearer()] : []),
      ...(wantsAdmin ? [admin()] : []),
      ...userPlugins.filter((p) => p !== sendLimit),
      ...(extra.plugins ?? []),
    ],
  } satisfies BetterAuthOptions;
  return { options, hasher };
}

export function clientIpConfig(o: BoilAuthOptions): ClientIpConfig {
  return o.clientIp ?? (o.trustedProxies ? { mode: "proxy", trustedProxies: o.trustedProxies } : { mode: "socket" });
}

export function createBoilAuth(o: BoilAuthOptions) {
  const { options, hasher } = boilAuthOptions(o);
  const auth = betterAuth(options);
  // Resolve the client IP first; Better Auth's own 429 carries only X-Retry-After, add the standard header.
  const handler = withRateLimitHeaders(withClientIp(auth.handler, clientIpConfig(o)));
  return Object.assign(auth, { handler, boilauth: { hasher, options, input: o } });
}

export type BoilAuth = ReturnType<typeof createBoilAuth>;
