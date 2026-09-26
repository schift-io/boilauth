/**
 * boilauth/deletion — account deletion and data export (spec D1, D2, D3).
 *
 * hard: turns on Better Auth's POST /delete-user (password or fresh session).
 * soft: POST /boilauth/delete-account (session + password when the user has
 *       one) sets user.deletedAt and ends every session; any later attempt to
 *       create a session for that user is refused at the database hook, so
 *       password, magic link and OAuth are all covered. `purgeDeleted()`
 *       (CLI: `boilauth purge-deleted <days>`) removes the rows later.
 * export: GET /boilauth/export-account returns the caller's own data, with no
 *       password hashes and no session tokens.
 */
import { getCurrentAdapter, type BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import * as z from "zod";

export interface AccountDeletionOptions {
  mode: "hard" | "soft";
  exportData: boolean;
}

export function accountDeletion(o: AccountDeletionOptions) {
  const soft = o.mode === "soft";
  // Endpoint generics differ per route; the plugin map is typed loosely on purpose.
  const endpoints: Record<string, any> = {};

  if (soft) {
    endpoints.boilauthDeleteAccount = createAuthEndpoint(
      "/boilauth/delete-account",
      { method: "POST", use: [sessionMiddleware], body: z.object({ password: z.string().optional() }) },
      async (ctx) => {
        const { user } = ctx.context.session;
        const ia = ctx.context.internalAdapter;
        const cred = await ia.findCredentialAccount(user.id);
        if (cred?.password) {
          const ok = ctx.body.password
            ? await ctx.context.password.verify({ hash: cred.password, password: ctx.body.password })
            : false;
          if (!ok) throw APIError.from("BAD_REQUEST", { code: "INVALID_PASSWORD", message: "Invalid password" });
        }
        await ia.updateUser(user.id, { deletedAt: new Date() });
        await ia.deleteUserSessions(user.id);
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
    id: "boilauth-deletion",
    ...(soft
      ? {
          schema: {
            user: { fields: { deletedAt: { type: "date", required: false, input: false, returned: false } } },
          },
        }
      : {}),
    endpoints,
    init: (authCtx) => ({
      options: {
        user: { deleteUser: { enabled: !soft } },
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

type AuthLike = { $context: Promise<{ adapter: any; internalAdapter: any }> };

/** Hard-delete users soft-deleted more than `days` ago. Returns how many were removed. */
export async function purgeDeleted(auth: AuthLike, days: number, now = new Date()): Promise<number> {
  const ctx = await auth.$context;
  const cutoff = new Date(now.getTime() - days * 86_400_000);
  const rows: { id: string }[] = await ctx.adapter.findMany({
    model: "user",
    where: [{ field: "deletedAt", operator: "lt", value: cutoff }],
  });
  for (const r of rows) await ctx.internalAdapter.deleteUser(r.id);
  return rows.length;
}
