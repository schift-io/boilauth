/**
 * boilauth Better Auth plugin — the part of the "safe presets" that Better
 * Auth does not do on its own:
 *
 * 1. Lockout, in two layers (audit F4: a plain per-account lock let anyone
 *    lock the owner out forever with 5 wrong passwords):
 *    - per source: `maxFailures` wrong passwords for one account from one
 *      client IP (/64 for IPv6) lock that source for `lockMinutes`;
 *    - per account: `accountMaxFailures` wrong passwords from sources that
 *      have not signed in to it successfully in the last `knownSourceDays`
 *      lock the account for `lockMinutes` against those sources; the owner's
 *      usual devices keep working. A known source's own typos do not count
 *      toward it, and a successful sign-in does not clear it: the lock ends
 *      after `lockMinutes`, and the count restarts when a lock engages
 *      (re-audit C8: the owner's sign-in used to hand attackers a fresh count).
 *    While locked, sign-in answers exactly like a wrong password (401
 *    INVALID_EMAIL_OR_PASSWORD) and the password is not checked, so the lock
 *    does not reveal whether the account exists.
 * 2. Transparent rehash. After a successful email/password sign-in, if the
 *    stored hash is not argon2id at the current preset (imported bcrypt or
 *    Firebase scrypt, or weaker argon2 params) it is replaced with a fresh
 *    argon2id hash of the password the user just proved.
 *
 * 3. An admin setting a user's password (POST /admin/set-user-password) ends
 *    that user's sessions and sends the password-changed notice, like a
 *    reset does (re-audit C6).
 *
 * Both cover POST /sign-in/email and, when on, POST /sign-in/username (the
 * account is found by the normalized username) and POST /sign-in/phone-number.
 *
 * The per-source counter uses the rateLimit storage's conditional increment.
 * The account-wide counter is read-modify-write on the user row, so N parallel
 * wrong attempts can count as fewer than N; the per-source lock and the IP rate
 * limiter bound the burst.
 */
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { deleteSessionCookie } from "better-auth/cookies";
import { createHash } from "node:crypto";
import type { PasswordHasher } from "./hash/index.js";
import { clientIpKeyOf } from "./modules/client-ip.js";
import { consume, peek, reset } from "./modules/counter-store.js";
import type { Notify } from "./modules/notify.js";

export interface LockoutOptions {
  /** Wrong passwords per account per source before that source is locked. 0 turns lockout off. */
  maxFailures: number;
  lockMinutes: number;
  /** Wrong passwords per account from all sources before unknown sources are locked out. */
  accountMaxFailures: number;
  /** A source counts as known this long after a successful sign-in. */
  knownSourceDays: number;
}

export interface BoilauthPluginOptions {
  hasher: PasswordHasher;
  lockout: LockoutOptions;
  now?: () => Date;
  /** Set when username sign-in is on: the username plugin's normalization. */
  normalizeUsername?: (username: string) => string;
  /** Phone number sign-in is on: lockout and rehash cover /sign-in/phone-number. */
  phoneSignIn?: boolean;
  /** Absolute session lifetime from sign-in, whatever the activity (audit F10). */
  absoluteSessionSeconds?: number;
  /** Security notices: the account-wide lock engaged, a sign-in from a new source. */
  notify?: Notify;
}

const SIGN_IN = "/sign-in/email";
const SIGN_UP = "/sign-up/email";
/**
 * A sign-up that issues no session (verification required, or autoSignIn off) answers with these
 * user fields only. Better Auth answers a duplicate email with a stand-in user that plugin defaults
 * (the admin role, ...) never touched, so any other field told a taken email apart (re-audit C1).
 */
const SIGN_UP_FIELDS = ["id", "email", "name", "image", "emailVerified", "createdAt", "updatedAt"] as const;
const SIGN_IN_USERNAME = "/sign-in/username";
const SIGN_IN_PHONE = "/sign-in/phone-number";

function invalidCredentials(path: string): APIError {
  if (path === SIGN_IN_USERNAME) return APIError.from("UNAUTHORIZED", { code: "INVALID_USERNAME_OR_PASSWORD", message: "Invalid username or password" });
  if (path === SIGN_IN_PHONE) return APIError.from("UNAUTHORIZED", { code: "INVALID_PHONE_NUMBER_OR_PASSWORD", message: "Invalid phone number or password" });
  return APIError.from("UNAUTHORIZED", { code: "INVALID_EMAIL_OR_PASSWORD", message: "Invalid email or password" });
}

type LockFields = { id: string; failedLoginCount?: number | null; lockedUntil?: Date | null; knownSignInSources?: string | null };

type Known = { s: string; t: number };
const MAX_KNOWN = 10;

function sourceOf(ctx: any): string {
  const ip = clientIpKeyOf(ctx.headers ?? ctx.request?.headers) ?? "unknown";
  return createHash("sha256").update(ip).digest("hex").slice(0, 32);
}

function knownList(raw: string | null | undefined): Known[] {
  try {
    const v = JSON.parse(raw ?? "[]");
    return Array.isArray(v) ? v.filter((k) => typeof k?.s === "string" && typeof k?.t === "number") : [];
  } catch {
    return [];
  }
}

function storageOf(ctx: any): "memory" | "database" {
  return ctx.context.rateLimit?.storage === "memory" ? "memory" : "database";
}

export function boilauthPlugin(opts: BoilauthPluginOptions) {
  const now = opts.now ?? (() => new Date());
  const isSignIn = (path: string | undefined) =>
    path === SIGN_IN || (Boolean(opts.normalizeUsername) && path === SIGN_IN_USERNAME) || (Boolean(opts.phoneSignIn) && path === SIGN_IN_PHONE);
  /** The account a sign-in attempt names, or null. Raw row: lock fields are not returned by default. */
  const target = async (ctx: any): Promise<LockFields | null> => {
    if (ctx.path === SIGN_IN_USERNAME) {
      const name = typeof ctx.body?.username === "string" ? ctx.body.username : "";
      if (!name || !opts.normalizeUsername) return null;
      return ctx.context.adapter.findOne({ model: "user", where: [{ field: "username", value: opts.normalizeUsername(name) }] });
    }
    if (ctx.path === SIGN_IN_PHONE) {
      const phone = typeof ctx.body?.phoneNumber === "string" ? ctx.body.phoneNumber : "";
      return phone ? ctx.context.adapter.findOne({ model: "user", where: [{ field: "phoneNumber", value: phone }] }) : null;
    }
    const email = typeof ctx.body?.email === "string" ? ctx.body.email.toLowerCase() : "";
    if (!email) return null;
    return ((await ctx.context.internalAdapter.findUserByEmail(email))?.user as LockFields | undefined) ?? null;
  };
  const lockKey = (userId: string, source: string) => `boilauth-lock:${userId}:${source}`;
  const absMs = (opts.absoluteSessionSeconds ?? 30 * 86400) * 1000;
  const capOf = (createdAt: Date | string | number | undefined) => new Date(new Date(createdAt ?? now()).getTime() + absMs);
  const capped = (expiresAt: Date | undefined, createdAt: Date | string | number | undefined) =>
    expiresAt && new Date(expiresAt).getTime() > capOf(createdAt).getTime() ? capOf(createdAt) : undefined;
  const lockWindow = opts.lockout.lockMinutes * 60;
  return {
    id: "boilauth",
    // Never matches: tells Better Auth's pruning that rateLimit rows live as long as a lock.
    rateLimit: [{ pathMatcher: () => false, window: Math.max(60, lockWindow), max: 1 }],
    // Absolute session lifetime (audit F10): no write may set expiresAt past createdAt + absolute.
    // On refresh Better Auth has put the loaded session in the endpoint context.
    init: () => ({
      options: {
        databaseHooks: {
          session: {
            create: {
              before: async (s: { expiresAt: Date; createdAt?: Date }) => {
                const c = capped(s.expiresAt, s.createdAt);
                return c ? { data: { ...s, expiresAt: c } } : undefined;
              },
            },
            update: {
              before: async (s: { expiresAt?: Date }, ctx: any) => {
                const createdAt = ctx?.context?.session?.session?.createdAt;
                const c = createdAt ? capped(s.expiresAt, createdAt) : undefined;
                return c ? { data: { ...s, expiresAt: c } } : undefined;
              },
            },
          },
        },
      },
    }),
    schema: {
      user: {
        fields: {
          failedLoginCount: { type: "number", required: false, defaultValue: 0, input: false, returned: false },
          lockedUntil: { type: "date", required: false, input: false, returned: false },
          // Hashed client sources (IP, /64 for IPv6) with a recent successful sign-in, JSON.
          knownSignInSources: { type: "string", required: false, input: false, returned: false },
        },
      },
      // Which boilauth schema modules (and versions) this database carries.
      // Written by migrate(); read by anything that attaches to the schema.
      boilauthModule: {
        fields: {
          name: { type: "string", required: true, unique: true },
          version: { type: "number", required: true },
          installedAt: { type: "date", required: true },
        },
      },
      // Where an imported user came from. One row per (source, sourceId);
      // several rows may point at one user after a verified-email merge.
      importedIdentity: {
        fields: {
          userId: { type: "string", required: true, references: { model: "user", field: "id", onDelete: "cascade" } },
          source: { type: "string", required: true }, // supabase | firebase | auth0
          sourceId: { type: "string", required: true },
          createdAt: { type: "date", required: true },
        },
      },
    },
    hooks: {
      before: [
        {
          // Username and phone sign-in skip the password hash when the account has no password or
          // (phone) does not exist, which tells those accounts apart by timing (audit F6/F16).
          matcher: (ctx) => ctx.path === SIGN_IN_USERNAME || ctx.path === SIGN_IN_PHONE,
          handler: createAuthMiddleware(async (ctx) => {
            if (!isSignIn(ctx.path)) return;
            const u = (await target(ctx)) as (LockFields & { phoneNumberVerified?: boolean }) | null;
            const hasPassword = u ? Boolean((await ctx.context.internalAdapter.findCredentialAccount(u.id))?.password) : false;
            const reachesVerify = u && hasPassword && (ctx.path !== SIGN_IN_PHONE || u.phoneNumberVerified);
            if (!reachesVerify) await opts.hasher.hash(String(ctx.body?.password ?? ""));
          }),
        },
        {
          matcher: (ctx) => isSignIn(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            if (opts.lockout.maxFailures <= 0) return;
            const u = await target(ctx);
            if (!u) return;
            const t = now().getTime();
            const source = sourceOf(ctx);
            const perSource = await peek(storageOf(ctx), ctx.context.adapter, lockKey(u.id, source), lockWindow, t);
            const sourceLocked = (perSource?.count ?? 0) >= opts.lockout.maxFailures;
            const accountLocked =
              Boolean(u.lockedUntil && new Date(u.lockedUntil).getTime() > t) &&
              !knownList(u.knownSignInSources).some((k) => k.s === source && t - k.t < opts.lockout.knownSourceDays * 86_400_000);
            if (sourceLocked || accountLocked) {
              // Spend comparable time so a lock is not a timing oracle.
              await opts.hasher.hash(String(ctx.body?.password ?? ""));
              throw invalidCredentials(ctx.path);
            }
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => ctx.path === "/admin/set-user-password",
          handler: createAuthMiddleware(async (ctx) => {
            const r = ctx.context.returned as { status?: unknown } | undefined;
            const userId = typeof ctx.body?.userId === "string" ? ctx.body.userId : "";
            if (!userId || !r || r instanceof Error || r.status !== true) return;
            await ctx.context.internalAdapter.deleteUserSessions(userId);
            await opts.notify?.("security.password_changed", userId, ctx);
          }),
        },
        {
          matcher: (ctx) => ctx.path === SIGN_UP,
          handler: createAuthMiddleware(async (ctx) => {
            const r = ctx.context.returned as { token?: unknown; user?: Record<string, unknown> } | undefined;
            if (!r || r instanceof APIError || typeof r !== "object" || r.token !== null || !r.user) return;
            const user = Object.fromEntries(SIGN_UP_FIELDS.map((k) => [k, r.user![k] ?? null]));
            return ctx.json({ token: null, user: { ...user, emailVerified: false } });
          }),
        },
        {
          // A session created before this cap (or with a slid expiry) ends at createdAt + absolute.
          matcher: (ctx) => ctx.path === "/get-session",
          handler: createAuthMiddleware(async (ctx) => {
            const r = ctx.context.returned as { session?: { token: string; createdAt: Date | string } } | null | undefined;
            if (!r?.session || now().getTime() < capOf(r.session.createdAt).getTime()) return;
            await ctx.context.internalAdapter.deleteSession(r.session.token);
            deleteSessionCookie(ctx);
            return ctx.json(null);
          }),
        },
        {
          matcher: (ctx) => isSignIn(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const password = typeof ctx.body?.password === "string" ? ctx.body.password : "";
            const session = ctx.context.newSession;
            const ia = ctx.context.internalAdapter;

            if (session) {
              const userId = session.user.id;
              // Read the raw row: these fields are `returned: false`, so they are absent from session.user.
              const u = ((await ia.findUserById(userId)) ?? {}) as LockFields;
              const t = now().getTime();
              const source = sourceOf(ctx);
              const previous = knownList(u.knownSignInSources).filter((k) => t - k.t < opts.lockout.knownSourceDays * 86_400_000);
              const known = [{ s: source, t }, ...previous.filter((k) => k.s !== source)].slice(0, MAX_KNOWN);
              // The first sign-in ever is not a "new device"; a source missing from a non-empty list is.
              if (previous.length && !previous.some((k) => k.s === source)) await opts.notify?.("security.new_device", userId, ctx);
              await ia.updateUser(userId, { knownSignInSources: JSON.stringify(known) });
              if (opts.lockout.maxFailures > 0) await reset(storageOf(ctx), ctx.context.adapter, lockKey(userId, source));
              const account = await ia.findCredentialAccount(userId);
              if (account?.password && password && opts.hasher.needsRehash(account.password)) {
                await ia.updateAccount(account.id, { password: await opts.hasher.hash(password) });
              }
              return;
            }

            const returned = ctx.context.returned as { status?: string; statusCode?: number } | undefined;
            const wasBadPassword =
              returned instanceof APIError && (returned.status === "UNAUTHORIZED" || returned.statusCode === 401);
            if (!wasBadPassword || opts.lockout.maxFailures <= 0) return;
            const u = await target(ctx);
            if (!u) return;
            const t = now().getTime();
            const source = sourceOf(ctx);
            await consume(storageOf(ctx), ctx.context.adapter, lockKey(u.id, source), opts.lockout.maxFailures, lockWindow, t);
            const known = knownList(u.knownSignInSources).some((k) => k.s === source && t - k.t < opts.lockout.knownSourceDays * 86_400_000);
            if (known) return; // the owner's own typo: per-source counter only
            const lockedUntil = u.lockedUntil ? new Date(u.lockedUntil) : null;
            if (lockedUntil && lockedUntil.getTime() > t) return; // account already locked
            const failures = (u.failedLoginCount ?? 0) + 1;
            const lock = failures >= opts.lockout.accountMaxFailures;
            await ia.updateUser(u.id, {
              failedLoginCount: lock ? 0 : failures,
              lockedUntil: lock ? new Date(t + opts.lockout.lockMinutes * 60_000) : null,
            });
            if (lock) await opts.notify?.("security.account_locked", u.id, ctx, { lockMinutes: opts.lockout.lockMinutes });
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
