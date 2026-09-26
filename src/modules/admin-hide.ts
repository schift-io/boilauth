/**
 * Admin route hiding (spec G4). Callers without an admin role get 404 on
 * /admin/*, the same answer as a path that does not exist, instead of the
 * admin plugin's 401 (no session) or 403 (not an admin). Admins are not
 * affected; boilauth/mfa still answers them 403 MFA_REQUIRED when it applies.
 */
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";

export function hideAdminRoutes(o: { adminRoles?: string[] } = {}) {
  const adminRoles = new Set(o.adminRoles ?? ["admin"]);
  return {
    id: "boilauth-admin-hide",
    hooks: {
      before: [
        {
          matcher: (ctx) => Boolean(ctx.path?.startsWith("/admin/")),
          handler: createAuthMiddleware(async (ctx) => {
            const s = await getSessionFromCtx(ctx);
            const roles = String((s?.user as { role?: string } | undefined)?.role ?? "").split(",");
            if (!roles.some((r) => adminRoles.has(r.trim()))) throw APIError.fromStatus("NOT_FOUND");
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
