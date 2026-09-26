/**
 * Admin route hiding (spec G4). Callers without admin rights get 404 on
 * /admin/*, the same answer as a path that does not exist, instead of the
 * admin plugin's 401 (no session) or 403 (not an admin). Admins are not
 * affected; boilauth/mfa still answers them 403 MFA_REQUIRED when it applies.
 *
 * "Admin" is read from the admin plugin's own configuration (audit F14): a
 * user in adminUserIds, a role in adminRoles (default ["admin"]), or, with
 * custom access control, a role that grants anything on the admin plugin's
 * resources (user, session). Explicit `adminRoles` passed here are added.
 */
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";

type AdminPluginOptions = {
  adminRoles?: string | string[];
  adminUserIds?: string[];
  roles?: Record<string, { statements?: Record<string, readonly string[]> }>;
};

function adminCapable(opts: AdminPluginOptions | undefined, extra: Set<string>, user: { id: string; role?: string | null }): boolean {
  if (opts?.adminUserIds?.includes(user.id)) return true;
  const adminRoles = new Set([...(Array.isArray(opts?.adminRoles) ? opts.adminRoles : [opts?.adminRoles ?? "admin"]), ...extra]);
  const roles = String(user.role ?? "").split(",").map((r) => r.trim()).filter(Boolean);
  if (roles.some((r) => adminRoles.has(r))) return true;
  const custom = opts?.roles;
  if (!custom) return false;
  return roles.some((r) => {
    const st = custom[r]?.statements ?? {};
    return ["user", "session"].some((res) => (st[res]?.length ?? 0) > 0);
  });
}

export function hideAdminRoutes(o: { adminRoles?: string[] } = {}) {
  const extra = new Set(o.adminRoles ?? []);
  return {
    id: "boilauth-admin-hide",
    hooks: {
      before: [
        {
          matcher: (ctx) => Boolean(ctx.path?.startsWith("/admin/")),
          handler: createAuthMiddleware(async (ctx) => {
            const s = await getSessionFromCtx(ctx);
            const plugin = (ctx.context.options.plugins ?? []).find((p) => p.id === "admin") as { options?: AdminPluginOptions } | undefined;
            const user = s?.user as { id: string; role?: string | null } | undefined;
            if (!user || !adminCapable(plugin?.options, extra, user)) throw APIError.fromStatus("NOT_FOUND");
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
