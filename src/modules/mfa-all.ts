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
 * already proves only the mailbox or the phone. For the same reason the email
 * code of the twoFactor plugin (/two-factor/send-otp, /two-factor/verify-otp)
 * is refused for such a challenge (403 SECOND_FACTOR_NOT_ALLOWED): whoever
 * opened the magic link has the mailbox the code goes to (re-audit C3). TOTP
 * or a backup code finishes it; a password sign-in may still end with the code.
 *
 * Every Better Auth 1.7.6 endpoint that calls setSessionCookie, and why it is
 * or is not in PASSWORDLESS (re-audit L2):
 *   challenged here   /magic-link/verify, /sign-in/email-otp, /phone-number/verify,
 *                     /sign-in/social (idToken), /callback/:id, /oauth2/callback/:providerId,
 *                     /one-tap/callback, /verify-email and /email-otp/verify-email
 *                     (these two sign in only with autoSignInAfterVerification)
 *   twoFactor plugin  /sign-in/email, /sign-in/username, /sign-in/phone-number
 *   already signed in /get-session, /update-session, /update-user, /change-password,
 *                     /change-email, /email-otp/change-email, /organization/set-active,
 *                     /organization/set-active-team, /organization/accept-invitation,
 *                     /two-factor/* (the second factor itself)
 *   new user          /sign-up/email (no second factor can be enrolled yet)
 *   admin action      /admin/impersonate-user, /admin/stop-impersonating
 *   not offered       anonymous, multi-session, one-time-token, oauth-proxy (sessions
 *                     from an existing sign-in or a guest); siwe (/siwe/verify) and
 *                     device-authorization (/device/token: createSession with a bearer
 *                     token, no cookie, so newSession stays empty here) issue a first-
 *                     factor session and are refused at startup with twoFactor
 *                     (createBoilAuth). passkey and sso are separate packages.
 * When the request already carries a valid session of the same user (it passed
 * the second factor then), that session is kept: a refresh passes through, and a
 * second session created next to it is dropped in its favour.
 */
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { deleteSessionCookie, setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";

export const MFA_ALL_PLUGIN_ID = "boilauth-mfa-all-sign-ins";

const EMAIL_SECOND_STEP = new Set(["/two-factor/send-otp", "/two-factor/verify-otp"]);
/** Verification row marking a challenge that began without a password. */
const passwordlessMark = (identifier: string) => `2fa-passwordless-${identifier}`;

const PASSWORDLESS = new Set([
  "/magic-link/verify",
  "/sign-in/email-otp",
  "/phone-number/verify",
  "/sign-in/social",
  "/callback/:id",
  "/oauth2/callback/:providerId",
  "/one-tap/callback",
  "/verify-email",
  "/email-otp/verify-email",
]);

export function mfaOnAllSignIns(o: { challengeSeconds?: number } = {}): BetterAuthPlugin {
  const maxAge = o.challengeSeconds ?? 600;
  return {
    id: MFA_ALL_PLUGIN_ID,
    hooks: {
      before: [
        {
          matcher: (ctx) => EMAIL_SECOND_STEP.has(ctx.path ?? ""),
          handler: createAuthMiddleware(async (ctx) => {
            const cookie = ctx.context.createAuthCookie("two_factor");
            const identifier = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
            if (!identifier) return;
            if (await ctx.context.internalAdapter.findVerificationValue(passwordlessMark(identifier))) {
              throw APIError.from("FORBIDDEN", {
                code: "SECOND_FACTOR_NOT_ALLOWED",
                message: "After a sign-in link or code, finish with your authenticator app or a backup code",
              });
            }
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => PASSWORDLESS.has(ctx.path ?? ""),
          handler: createAuthMiddleware(async (ctx) => {
            const data = ctx.context.newSession;
            if (!data?.user || !(data.user as { twoFactorEnabled?: boolean }).twoFactorEnabled) return;
            const incoming = await currentSession(ctx);
            if (incoming && incoming.user.id === data.user.id) {
              if (incoming.session.token === data.session.token) return; // a refresh of a session that passed
              await ctx.context.internalAdapter.deleteSession(data.session.token);
              await setSessionCookie(ctx, incoming);
              return;
            }
            deleteSessionCookie(ctx, true);
            await ctx.context.internalAdapter.deleteSession(data.session.token);
            ctx.context.setNewSession(null);
            const cookie = ctx.context.createAuthCookie("two_factor", { maxAge });
            const identifier = `2fa-${generateRandomString(20)}`;
            const expiresAt = new Date(Date.now() + maxAge * 1000);
            await ctx.context.internalAdapter.createVerificationValue({ value: data.user.id, identifier, expiresAt });
            await ctx.context.internalAdapter.createVerificationValue({ value: "0", identifier: `2fa-attempts-${identifier}`, expiresAt });
            await ctx.context.internalAdapter.createVerificationValue({ value: ctx.path ?? "", identifier: passwordlessMark(identifier), expiresAt });
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

type Ctx = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];

/** The session the request came in with (cookie, or bearer via Better Auth's plugin), if still valid. */
async function currentSession(ctx: Ctx) {
  const token = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
  if (!token) return null;
  const found = await ctx.context.internalAdapter.findSession(token);
  if (!found || new Date(found.session.expiresAt).getTime() <= Date.now()) return null;
  return found;
}

type Handler = (req: Request, info?: { clientIp?: string | null }) => Promise<Response>;

/**
 * With the bearer plugin, a sign-in that stops at the second factor still carried
 * set-auth-token for the session that was just deleted (re-audit L3). The token
 * was dead, but a challenge should hand out nothing: drop the header whenever the
 * response is a two-factor challenge (JSON twoFactorRedirect or a redirect with
 * ?twoFactorRedirect=true). The completed sign-in (/two-factor/verify-*) keeps it.
 */
export function withoutTokenOnChallenge(handler: Handler): Handler {
  return async (req, info) => {
    const res = await handler(req, info);
    if (!res.headers.has("set-auth-token")) return res;
    const location = res.headers.get("location") ?? "";
    let challenge = /[?&]twoFactorRedirect=true(&|$)/.test(location);
    if (!challenge && (res.headers.get("content-type") ?? "").includes("application/json")) {
      const body = (await res.clone().json().catch(() => null)) as { twoFactorRedirect?: unknown } | null;
      challenge = body?.twoFactorRedirect === true;
    }
    if (!challenge) return res;
    const headers = new Headers(res.headers);
    headers.delete("set-auth-token");
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  };
}
