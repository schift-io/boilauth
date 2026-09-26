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
}

const SIGN_IN = "/sign-in/email";

function invalidCredentials(): APIError {
  return APIError.from("UNAUTHORIZED", {
    code: "INVALID_EMAIL_OR_PASSWORD",
    message: "Invalid email or password",
  });
}

export function boilauthPlugin(opts: BoilauthPluginOptions) {
  const now = opts.now ?? (() => new Date());
  return {
    id: "boilauth",
    schema: {
      user: {
        fields: {
          failedLoginCount: { type: "number", required: false, defaultValue: 0, input: false, returned: false },
          lockedUntil: { type: "date", required: false, input: false, returned: false },
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
          matcher: (ctx) => ctx.path === SIGN_IN,
          handler: createAuthMiddleware(async (ctx) => {
            const email = typeof ctx.body?.email === "string" ? ctx.body.email.toLowerCase() : "";
            if (!email) return;
            const found = await ctx.context.internalAdapter.findUserByEmail(email);
            const lockedUntil = (found?.user as { lockedUntil?: Date | null } | undefined)?.lockedUntil;
            if (lockedUntil && new Date(lockedUntil).getTime() > now().getTime()) {
              // Spend comparable time so a locked account is not a timing oracle.
              await opts.hasher.hash(String(ctx.body?.password ?? ""));
              throw invalidCredentials();
            }
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => ctx.path === SIGN_IN,
          handler: createAuthMiddleware(async (ctx) => {
            const email = typeof ctx.body?.email === "string" ? ctx.body.email.toLowerCase() : "";
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
            if (!wasBadPassword || !email) return;
            const found = await ia.findUserByEmail(email);
            if (!found) return;
            const u = found.user as { failedLoginCount?: number | null; lockedUntil?: Date | null };
            const lockedUntil = u.lockedUntil ? new Date(u.lockedUntil) : null;
            if (lockedUntil && lockedUntil.getTime() > now().getTime()) return; // already locked
            const failures = (u.failedLoginCount ?? 0) + 1;
            const lock = failures >= opts.lockout.maxFailures;
            await ia.updateUser(found.user.id, {
              failedLoginCount: lock ? 0 : failures,
              lockedUntil: lock ? new Date(now().getTime() + opts.lockout.lockMinutes * 60_000) : null,
            });
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
