/**
 * boilauth/deletion — account deletion and data export (spec D1-D6).
 *
 * hard: turns on Better Auth's POST /delete-user (password or fresh session).
 * soft: POST /boilauth/delete-account (password when the user has one, a fresh
 *       session otherwise) sets user.deletedAt and ends every session; any later
 *       attempt to create a session for that user is refused at the database
 *       hook, so password, magic link and OAuth are all covered.
 *       `purgeDeleted()` (CLI: `boilauth purge-deleted <days>`) finishes later.
 * records = anonymize: instead of removing the user row, the final step keeps
 *       it and strips everything personal (D6), so payment and audit rows that
 *       reference user.id still resolve. With hard, deletion then goes through
 *       POST /boilauth/delete-account too.
 * canDelete: the app's veto (D4), answered as 409 with the app's code.
 * organizations: the last owner of an organization with other members is
 *       refused or replaced by the oldest admin (D5); the user leaves every
 *       organization.
 * export: GET /boilauth/export-account returns the caller's own data, with no
 *       password hashes and no session tokens.
 */
import { getCurrentAdapter, type BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import {
  anonymizeUser,
  leaveOrganizations,
  runCheck,
  settleOwnership,
  type DeletionCheck,
  type LastOwnerPolicy,
} from "./deletion-steps.js";

export { ANONYMIZED_DOMAIN, type DeletionCheck, type DeletionCheckResult, type LastOwnerPolicy } from "./deletion-steps.js";

export interface AccountDeletionOptions {
  mode: "hard" | "soft";
  exportData: boolean;
  /** Final step: remove the user row (default) or keep it anonymized. */
  records?: "delete" | "anonymize";
  /** The app's veto, e.g. while a paid subscription is active. Refusal = 409 with its code. */
  canDelete?: DeletionCheck;
  /** Set with Better Auth's organization plugin: what happens to an organization's last owner. */
  organizations?: { lastOwner: LastOwnerPolicy };
}

export const DELETION_PLUGIN_ID = "boilauth-deletion";

export function accountDeletion(o: AccountDeletionOptions) {
  const soft = o.mode === "soft";
  const anonymize = o.records === "anonymize";
  const ownEndpoint = soft || anonymize;
  // Endpoint generics differ per route; the plugin map is typed loosely on purpose.
  const endpoints: Record<string, any> = {};

  /** D4 + D5, before anything changes. */
  const prepare = async (db: any, user: { id: string; email: string }) => {
    await runCheck(o.canDelete, user);
    if (o.organizations) await settleOwnership(db, user.id, o.organizations.lastOwner);
  };

  if (ownEndpoint) {
    endpoints.boilauthDeleteAccount = createAuthEndpoint(
      "/boilauth/delete-account",
      { method: "POST", use: [sessionMiddleware], body: z.object({ password: z.string().optional() }) },
      async (ctx) => {
        const { user, session } = ctx.context.session;
        const ia = ctx.context.internalAdapter;
        const cred = await ia.findCredentialAccount(user.id);
        if (cred?.password) {
          const ok = ctx.body.password
            ? await ctx.context.password.verify({ hash: cred.password, password: ctx.body.password })
            : false;
          if (!ok) throw APIError.from("BAD_REQUEST", { code: "INVALID_PASSWORD", message: "Invalid password" });
        } else {
          // No password to re-check: same rule as Better Auth's /delete-user, a recent sign-in.
          const freshAge = ctx.context.sessionConfig.freshAge;
          if (freshAge !== 0 && Date.now() - new Date(session.createdAt).getTime() >= freshAge * 1000) {
            throw APIError.from("BAD_REQUEST", { code: "SESSION_EXPIRED", message: "Sign in again to delete the account" });
          }
        }
        const db = await getCurrentAdapter(ctx.context.adapter);
        await prepare(db, user);
        if (o.organizations) await leaveOrganizations(db, user.id);
        if (soft) {
          await ia.updateUser(user.id, { deletedAt: new Date() });
          await ia.deleteUserSessions(user.id);
        } else {
          await anonymizeUser(db, ia, user.id);
        }
        return ctx.json({ success: true });
      },
    );
  }

  if (o.exportData) {
    endpoints.boilauthExportAccount = createAuthEndpoint(
      "/boilauth/export-account",
      { method: "GET", use: [sessionMiddleware] },
      async (ctx) => {
        const { user } = ctx.context.session;
        const ia = ctx.context.internalAdapter;
        const accounts = await ia.findAccounts(user.id);
        const sessions = await ia.listSessions(user.id);
        const identities = await ctx.context.adapter
          .findMany<Record<string, unknown>>({ model: "importedIdentity", where: [{ field: "userId", value: user.id }] })
          .catch(() => []);
        return ctx.json({
          exportedAt: new Date().toISOString(),
          user,
          accounts: accounts.map((a) => ({ providerId: a.providerId, accountId: a.accountId, createdAt: a.createdAt })),
          sessions: sessions.map((s) => ({
            createdAt: s.createdAt,
            expiresAt: s.expiresAt,
            ipAddress: s.ipAddress,
            userAgent: s.userAgent,
          })),
          importedIdentities: identities.map((i) => ({ source: i.source, sourceId: i.sourceId, createdAt: i.createdAt })),
        });
      },
    );
  }

  return {
    id: DELETION_PLUGIN_ID,
    ...(soft
      ? {
          schema: {
            user: { fields: { deletedAt: { type: "date", required: false, input: false, returned: false } } },
          },
        }
      : {}),
    endpoints,
    options: o,
    init: (authCtx) => ({
      options: {
        user: {
          deleteUser: ownEndpoint
            ? { enabled: false }
            : {
                enabled: true,
                // Better Auth checked the password or the session age before calling these.
                beforeDelete: async (user: { id: string; email: string }) => prepare(await getCurrentAdapter(authCtx.adapter), user),
                ...(o.organizations
                  ? { afterDelete: async (user: { id: string }) => leaveOrganizations(await getCurrentAdapter(authCtx.adapter), user.id) }
                  : {}),
              },
        },
        ...(soft
          ? {
              databaseHooks: {
                session: {
                  create: {
                    // Runs for every session insert, inside or outside a request.
                    before: async (session: { userId: string }) => {
                      // getCurrentAdapter joins the running transaction; a plain adapter call would
                      // wait for the connection the transaction holds (single-connection SQLite deadlocks).
                      const db = await getCurrentAdapter(authCtx.adapter);
                      const u = await db.findOne<{ deletedAt?: Date | null }>({
                        model: "user",
                        where: [{ field: "id", value: session.userId }],
                      });
                      if (u?.deletedAt) return false;
                    },
                  },
                },
              },
            }
          : {}),
      },
    }),
  } satisfies BetterAuthPlugin;
}

type AuthLike = { $context: Promise<{ adapter: any; internalAdapter: any }>; options?: { plugins?: { id: string; options?: unknown }[] } };

/**
 * Finish users soft-deleted more than `days` ago: remove their rows, or with
 * records = anonymize keep the rows anonymized. Returns how many were finished.
 */
export async function purgeDeleted(auth: AuthLike, days: number, now = new Date()): Promise<number> {
  const ctx = await auth.$context;
  const plugin = auth.options?.plugins?.find((p) => p.id === DELETION_PLUGIN_ID);
  const anonymize = (plugin?.options as AccountDeletionOptions | undefined)?.records === "anonymize";
  const cutoff = new Date(now.getTime() - days * 86_400_000);
  const rows: { id: string }[] = await ctx.adapter.findMany({
    model: "user",
    where: [{ field: "deletedAt", operator: "lt", value: cutoff }],
  });
  let n = 0;
  for (const r of rows) {
    if (anonymize) {
      if (await anonymizeUser(ctx.adapter, ctx.internalAdapter, r.id)) n++;
    } else {
      await ctx.internalAdapter.deleteUser(r.id);
      n++;
    }
  }
  return n;
}
