/**
 * boilauth/sessions — session policy switches (spec S2, S3).
 *
 * revokeOnPasswordChange: POST /change-password always ends the user's other
 *   sessions (Better Auth only does it when the client asks with
 *   revokeOtherSessions: true; we set it server-side).
 * devices "single": whenever a request creates a session (password, magic
 *   link, OAuth callback, TOTP verification), the user's other sessions end.
 *   Put this plugin after twoFactor in the plugin list: two-factor clears the
 *   pending session in its own after-hook, and we must not act on that one.
 */
import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";

export interface SessionPolicyOptions {
  devices: "multi" | "single";
  revokeOnPasswordChange: boolean;
}

export function sessionPolicy(o: SessionPolicyOptions) {
  return {
    id: "boilauth-sessions",
    hooks: {
      before: o.revokeOnPasswordChange
        ? [
            {
              matcher: (ctx) => ctx.path === "/change-password",
              handler: createAuthMiddleware(async (ctx) => ({
                context: { body: { ...(ctx.body ?? {}), revokeOtherSessions: true } },
              })),
            },
          ]
        : [],
      after:
        o.devices === "single"
          ? [
              {
                matcher: () => true,
                handler: createAuthMiddleware(async (ctx) => {
                  const created = ctx.context.newSession;
                  if (!created) return;
                  const ia = ctx.context.internalAdapter;
                  const all = await ia.listSessions(created.user.id);
                  const others = all.map((s) => s.token).filter((t) => t !== created.session.token);
                  if (others.length) await ia.deleteSessions(others);
                }),
              },
            ]
          : [],
    },
  } satisfies BetterAuthPlugin;
}
