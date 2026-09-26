/**
 * boilauth Better Auth plugin — the part of the "safe presets" that Better
 * Auth does not do on its own:
 *
 * 1. Per-account lockout. Better Auth's rate limiter is per IP+path, so a
 *    distributed guess attack against one account is not slowed by it. After
 *    `maxFailures` consecutive wrong passwords the account is locked for
 *    `lockMinutes`. While locked, sign-in answers exactly like a wrong
 *    password (401 INVALID_EMAIL_OR_PASSWORD) and the password is not checked,
 *    so the lock does not reveal whether the email exists.
 * 2. Transparent rehash. After a successful email/password sign-in, if the
 *    stored hash is not argon2id at the current preset (imported bcrypt or
 *    Firebase scrypt, or weaker argon2 params) it is replaced with a fresh
 *    argon2id hash of the password the user just proved.
 *
 * Both cover POST /sign-in/email and, when on, POST /sign-in/username (the
 * account is found by the normalized username) and POST /sign-in/phone-number.
 *
 * Known limit: the failure counter is read-modify-write, so N parallel wrong
 * attempts can count as fewer than N. The IP rate limiter bounds the burst.
 */
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import type { PasswordHasher } from "./hash/index.js";

export interface LockoutOptions {
  maxFailures: number;
  lockMinutes: number;
}

export interface BoilauthPluginOptions {
  hasher: PasswordHasher;
  lockout: LockoutOptions;
  now?: () => Date;
  /** Set when username sign-in is on: the username plugin's normalization. */
  normalizeUsername?: (username: string) => string;
  /** Phone number sign-in is on: lockout and rehash cover /sign-in/phone-number. */
  phoneSignIn?: boolean;
}

const SIGN_IN = "/sign-in/email";
const SIGN_IN_USERNAME = "/sign-in/username";
const SIGN_IN_PHONE = "/sign-in/phone-number";

function invalidCredentials(path: string): APIError {
  if (path === SIGN_IN_USERNAME) return APIError.from("UNAUTHORIZED", { code: "INVALID_USERNAME_OR_PASSWORD", message: "Invalid username or password" });
  if (path === SIGN_IN_PHONE) return APIError.from("UNAUTHORIZED", { code: "INVALID_PHONE_NUMBER_OR_PASSWORD", message: "Invalid phone number or password" });
  return APIError.from("UNAUTHORIZED", { code: "INVALID_EMAIL_OR_PASSWORD", message: "Invalid email or password" });
}

type LockFields = { id: string; failedLoginCount?: number | null; lockedUntil?: Date | null };

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
  return {
    id: "boilauth",
    schema: {
      user: {
        fields: {
          failedLoginCount: { type: "number", required: false, defaultValue: 0, input: false, returned: false },
          lockedUntil: { type: "date", required: false, input: false, returned: false },
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
          matcher: (ctx) => isSignIn(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            if (opts.lockout.maxFailures <= 0) return;
            const lockedUntil = (await target(ctx))?.lockedUntil;
            if (lockedUntil && new Date(lockedUntil).getTime() > now().getTime()) {
              // Spend comparable time so a locked account is not a timing oracle.
              await opts.hasher.hash(String(ctx.body?.password ?? ""));
              throw invalidCredentials(ctx.path);
            }
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => isSignIn(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const password = typeof ctx.body?.password === "string" ? ctx.body.password : "";
            const session = ctx.context.newSession;
            const ia = ctx.context.internalAdapter;

            if (session) {
              const userId = session.user.id;
              // Read the raw row: these fields are `returned: false`, so they are absent from session.user.
              const u = ((await ia.findUserById(userId)) ?? {}) as { failedLoginCount?: number | null; lockedUntil?: Date | null };
              if (u.failedLoginCount || u.lockedUntil) {
                await ia.updateUser(userId, { failedLoginCount: 0, lockedUntil: null });
              }
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
            const lockedUntil = u.lockedUntil ? new Date(u.lockedUntil) : null;
            if (lockedUntil && lockedUntil.getTime() > now().getTime()) return; // already locked
            const failures = (u.failedLoginCount ?? 0) + 1;
            const lock = failures >= opts.lockout.maxFailures;
            await ia.updateUser(u.id, {
              failedLoginCount: lock ? 0 : failures,
              lockedUntil: lock ? new Date(now().getTime() + opts.lockout.lockMinutes * 60_000) : null,
            });
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
