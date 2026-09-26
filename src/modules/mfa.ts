/**
 * boilauth/mfa — TOTP required for admins (spec H2).
 *
 * Use together with Better Auth's twoFactor() and admin(). Admin endpoints
 * (/admin/*) answer 403 MFA_REQUIRED unless the caller's session itself
 * passed a TOTP (or backup code) check. Having TOTP enrolled is not enough:
 * a session from magic link or OAuth never went through the TOTP challenge,
 * so it carries no `mfaVerifiedAt` and cannot reach admin endpoints.
 */
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";

const VERIFY_PATHS = new Set(["/two-factor/verify-totp", "/two-factor/verify-backup-code"]);

export interface RequireAdminMfaOptions {
  adminRoles?: string[];
}

export function requireAdminMfa(o: RequireAdminMfaOptions = {}) {
  const adminRoles = new Set(o.adminRoles ?? ["admin"]);
  return {
    id: "boilauth-mfa-admin",
    schema: {
      session: {
        fields: {
          mfaVerifiedAt: { type: "date", required: false, input: false },
        },
      },
    },
    hooks: {
      before: [
        {
          matcher: (ctx) => Boolean(ctx.path?.startsWith("/admin/")),
          handler: createAuthMiddleware(async (ctx) => {
            const s = await getSessionFromCtx(ctx);
            if (!s) return; // admin plugin answers 401
            const roles = String((s.user as { role?: string }).role ?? "").split(",");
            if (!roles.some((r) => adminRoles.has(r.trim()))) return;
            const verified = (s.session as { mfaVerifiedAt?: Date | null }).mfaVerifiedAt;
            if (!(s.user as { twoFactorEnabled?: boolean }).twoFactorEnabled || !verified) {
              throw APIError.from("FORBIDDEN", {
                code: "MFA_REQUIRED",
                message: "Admin access needs a session verified with TOTP",
              });
            }
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => VERIFY_PATHS.has(ctx.path ?? ""),
          handler: createAuthMiddleware(async (ctx) => {
            if (ctx.context.returned instanceof APIError) return;
            // Sign-in challenge → a new session; enrollment → the current one.
            const token = ctx.context.newSession?.session.token ?? (await getSessionFromCtx(ctx))?.session.token;
            if (token) await ctx.context.internalAdapter.updateSession(token, { mfaVerifiedAt: new Date() });
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
