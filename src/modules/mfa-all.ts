/**
 * Second factor on every sign-in (audit F11, ASVS 2.2.2).
 *
 * Better Auth's twoFactor plugin challenges only password sign-ins
 * (/sign-in/email, /sign-in/username, /sign-in/phone-number). A user with
 * two-factor on still got a full session from a magic link, an email or SMS
 * code, or OAuth — whoever had the mailbox or the SIM skipped the second
 * factor. For those paths this plugin does what twoFactor does for passwords:
 * the new session is deleted and a signed two_factor cookie is set, so
 * /two-factor/verify-totp (or a backup code, or an email second-step code)
 * finishes the sign-in.
 *
 *   JSON routes      answer { twoFactorRedirect: true, twoFactorMethods }
 *   redirect routes  (magic link, OAuth callback) redirect to the same place with
 *                    ?twoFactorRedirect=true; your page shows the code form
 *
 * The trusted-device cookie is not honoured on these paths: a link or code
 * already proves only the mailbox or the phone.
 */
import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { deleteSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";

export const MFA_ALL_PLUGIN_ID = "boilauth-mfa-all-sign-ins";

const PASSWORDLESS = new Set([
  "/magic-link/verify",
  "/sign-in/email-otp",
  "/phone-number/verify",
  "/sign-in/social",
  "/callback/:id",
  "/oauth2/callback/:providerId",
  "/one-tap/callback",
]);

export function mfaOnAllSignIns(o: { challengeSeconds?: number } = {}): BetterAuthPlugin {
  const maxAge = o.challengeSeconds ?? 600;
  return {
    id: MFA_ALL_PLUGIN_ID,
    hooks: {
      after: [
        {
          matcher: (ctx) => PASSWORDLESS.has(ctx.path ?? ""),
          handler: createAuthMiddleware(async (ctx) => {
            const data = ctx.context.newSession;
            if (!data?.user || !(data.user as { twoFactorEnabled?: boolean }).twoFactorEnabled) return;
            deleteSessionCookie(ctx, true);
            await ctx.context.internalAdapter.deleteSession(data.session.token);
            ctx.context.setNewSession(null);
            const cookie = ctx.context.createAuthCookie("two_factor", { maxAge });
            const identifier = `2fa-${generateRandomString(20)}`;
            const expiresAt = new Date(Date.now() + maxAge * 1000);
            await ctx.context.internalAdapter.createVerificationValue({ value: data.user.id, identifier, expiresAt });
            await ctx.context.internalAdapter.createVerificationValue({ value: "0", identifier: `2fa-attempts-${identifier}`, expiresAt });
            await ctx.setSignedCookie(cookie.name, identifier, ctx.context.secret, cookie.attributes);

            // A redirect comes back as an APIError-like object (not always this module's APIError class).
            const returned = ctx.context.returned as { headers?: HeadersInit } | undefined;
            const location = returned && typeof returned === "object" && returned.headers ? new Headers(returned.headers).get("location") : null;
            if (location) {
              const url = new URL(location, ctx.context.baseURL);
              url.searchParams.set("twoFactorRedirect", "true");
              const target = /^https?:\/\//.test(location) ? url.toString() : url.pathname + url.search + url.hash;
              throw ctx.redirect(target);
            }
            const methods: string[] = [];
            const totp = await ctx.context.adapter.findOne<{ verified?: boolean }>({
              model: "twoFactor",
              where: [{ field: "userId", value: data.user.id }],
            });
            if (totp && totp.verified !== false) methods.push("totp");
            return ctx.json({ twoFactorRedirect: true, twoFactorMethods: methods });
          }),
        },
      ],
    },
  };
}
