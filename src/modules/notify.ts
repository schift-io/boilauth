/**
 * Security notices (audit F9, ASVS 2.2.3): the user hears about changes to
 * their account's security through the app's sendEmail.
 *
 *   security.password_changed  change, reset or set password on a user route
 *                              (not the transparent rehash at sign-in, not imports)
 *   security.email_changed     verified email change (sent to the old address)
 *   security.mfa_changed       two-factor turned on or off
 *   security.account_locked    the account-wide lock engaged (see the lockout)
 *   security.new_device        a successful sign-in from a source not seen before
 *                              (off by default)
 *
 * Each message carries `kind` so src/email.ts can render its own template.
 * A failing send is logged and never fails the request.
 */
import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import type { EmailMessage } from "../auth.js";

export interface SecurityNotices {
  passwordChanged: boolean;
  emailChanged: boolean;
  mfaChanged: boolean;
  accountLocked: boolean;
  newDevice: boolean;
  /** A phone number was attached to the account (a new SMS sign-in path). */
  phoneChanged: boolean;
}

export const DEFAULT_SECURITY_NOTICES: SecurityNotices = {
  passwordChanged: true,
  emailChanged: true,
  mfaChanged: true,
  accountLocked: true,
  newDevice: false,
  phoneChanged: true,
};

export type NoticeKind =
  | "security.password_changed"
  | "security.email_changed"
  | "security.mfa_changed"
  | "security.account_locked"
  | "security.new_device"
  | "security.phone_changed";

const PASSWORD_PATHS = new Set([
  "/change-password",
  "/reset-password",
  "/set-password",
  "/email-otp/reset-password",
  "/phone-number/reset-password",
]);

type NoticeDetail = { enabled?: boolean; lockMinutes?: number; to?: string };

export function changeEmailDetails(token: string): { readonly oldEmail: string; readonly newEmail: string } | null {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !("requestType" in parsed) ||
      parsed.requestType !== "change-email-verification" ||
      !("email" in parsed) ||
      typeof parsed.email !== "string" ||
      !("updateTo" in parsed) ||
      typeof parsed.updateTo !== "string"
    ) {
      return null;
    }
    return { oldEmail: parsed.email, newEmail: parsed.updateTo };
  } catch (error) {
    if (error instanceof SyntaxError) return null;
    throw error;
  }
}

export function noticeMail(kind: NoticeKind, to: string, detail: NoticeDetail = {}): EmailMessage {
  const when = new Date().toISOString();
  const tail = "If this was not you, reset your password now and contact support.";
  switch (kind) {
    case "security.password_changed":
      return { to, kind, subject: "Your password was changed", text: `The password for your account was changed at ${when}. ${tail}` };
    case "security.email_changed":
      return { to, kind, subject: "Your email address was changed", text: `The email address for your account was changed at ${when}. ${tail}` };
    case "security.mfa_changed":
      return {
        to,
        kind,
        subject: detail.enabled ? "Two-factor sign-in was turned on" : "Two-factor sign-in was turned off",
        text: `Two-factor sign-in for your account was turned ${detail.enabled ? "on" : "off"} at ${when}. ${tail}`,
      };
    case "security.account_locked":
      return {
        to,
        kind,
        subject: "Many wrong passwords on your account",
        text:
          `There were many wrong password attempts on your account. For the next ${detail.lockMinutes ?? 15} minutes only ` +
          `devices you signed in from before can sign in. If this was not you, your password is still safe; consider changing it.`,
      };
    case "security.new_device":
      return { to, kind, subject: "New sign-in to your account", text: `Your account was signed in to from a new device at ${when}. ${tail}` };
    case "security.phone_changed":
      return { to, kind, subject: "A phone number was added to your account", text: `A phone number was added to your account for sign-in at ${when}. ${tail}` };
  }
}

export type Notify = (kind: NoticeKind, userId: string, ctx: any, detail?: NoticeDetail) => Promise<void>;

/** Looks the user up and sends; errors are logged, never thrown. */
export function notifier(send: ((m: EmailMessage) => Promise<void>) | undefined, flags: SecurityNotices): Notify {
  const on: Record<NoticeKind, boolean> = {
    "security.password_changed": flags.passwordChanged,
    "security.email_changed": flags.emailChanged,
    "security.mfa_changed": flags.mfaChanged,
    "security.account_locked": flags.accountLocked,
    "security.new_device": flags.newDevice,
    "security.phone_changed": flags.phoneChanged,
  };
  return async (kind, userId, ctx, detail) => {
    if (!send || !on[kind]) return;
    try {
      const user = await ctx.context.internalAdapter.findUserById(userId);
      const to = detail?.to ?? user?.email;
      if (user && to && !String(to).endsWith("@deleted.invalid")) await send(noticeMail(kind, String(to), detail));
    } catch (e) {
      ctx.context.logger?.error?.(`boilauth: security notice ${kind} failed`, e);
    }
  };
}

type Ctx = any;

/** The user a password route acts on, read before the route consumes its token. */
async function passwordTarget(ctx: Ctx): Promise<string | null> {
  const ia = ctx.context.internalAdapter;
  switch (ctx.path) {
    case "/change-password":
    case "/set-password":
      return ctx.context.session?.user?.id ?? null;
    case "/reset-password": {
      const token = ctx.body?.token ?? ctx.query?.token;
      if (typeof token !== "string") return null;
      return (await ia.findVerificationValue(`reset-password:${token}`))?.value ?? null;
    }
    case "/email-otp/reset-password":
      return typeof ctx.body?.email === "string" ? ((await ia.findUserByEmail(ctx.body.email.toLowerCase()))?.user?.id ?? null) : null;
    case "/phone-number/reset-password": {
      const n = ctx.body?.phoneNumber;
      if (typeof n !== "string") return null;
      return ((await ctx.context.adapter.findOne({ model: "user", where: [{ field: "phoneNumber", value: n }] })) as { id?: string } | null)?.id ?? null;
    }
  }
  return null;
}

const ok = (ctx: Ctx) => {
  const r = ctx.context.returned;
  return r && !(r instanceof Error) && !(typeof r === "object" && "statusCode" in r && Number(r.statusCode) >= 400);
};

/** Password changes on user routes (not the rehash at sign-in, not imports) and two-factor changes. */
export function securityNotices(notify: Notify): BetterAuthPlugin {
  const TARGET = Symbol("boilauth-password-target");
  const EMAIL_CHANGE = Symbol("boilauth-email-change");
  return {
    id: "boilauth-security-notices",
    hooks: {
      before: [
        {
          matcher: (ctx: Ctx) => PASSWORD_PATHS.has(ctx.path ?? ""),
          handler: createAuthMiddleware(async (ctx: Ctx) => {
            ctx.context[TARGET] = await passwordTarget(ctx);
          }),
        },
        {
          matcher: (ctx: Ctx) => ctx.path === "/verify-email",
          handler: createAuthMiddleware(async (ctx: Ctx) => {
            const token = typeof ctx.query?.token === "string" ? ctx.query.token : "";
            const change = changeEmailDetails(token);
            if (!change) return;
            const found = await ctx.context.internalAdapter.findUserByEmail(change.oldEmail);
            if (typeof found?.user?.id === "string") {
              ctx.context[EMAIL_CHANGE] = { userId: found.user.id, oldEmail: change.oldEmail, newEmail: change.newEmail };
            }
          }),
        },
      ],
      after: [
        {
          matcher: (ctx: Ctx) => PASSWORD_PATHS.has(ctx.path ?? ""),
          handler: createAuthMiddleware(async (ctx: Ctx) => {
            // change/set password: the session is loaded only by the route's own middleware.
            const userId = ctx.context[TARGET] ?? (ctx.path === "/change-password" || ctx.path === "/set-password" ? ctx.context.session?.user?.id : null);
            if (userId && ok(ctx)) await notify("security.password_changed", userId, ctx);
          }),
        },
        {
          matcher: (ctx: Ctx) => ctx.path === "/verify-email",
          handler: createAuthMiddleware(async (ctx: Ctx) => {
            const change: { userId: string; oldEmail: string; newEmail: string } | undefined = ctx.context[EMAIL_CHANGE];
            if (!change) return;
            delete ctx.context[EMAIL_CHANGE];
            const updated = await ctx.context.internalAdapter.findUserById(change.userId);
            if (updated?.email === change.newEmail) await notify("security.email_changed", change.userId, ctx, { to: change.oldEmail });
          }),
        },
      ],
    },
    init: () => ({
      options: {
        databaseHooks: {
          user: {
            update: {
              before: async (data: any, ctx: any) => {
                if (typeof data?.twoFactorEnabled !== "boolean" || !ctx) return;
                const id = ctx.context?.session?.user?.id;
                const current = id ? ((await ctx.context.internalAdapter.findUserById(id)) as { twoFactorEnabled?: boolean } | null) : null;
                if (current && Boolean(current.twoFactorEnabled) !== data.twoFactorEnabled) {
                  ctx.context.boilauthMfaChange = { id, enabled: data.twoFactorEnabled };
                }
              },
              after: async (_user: any, ctx: any) => {
                const change = ctx?.context?.boilauthMfaChange as { id: string; enabled: boolean } | undefined;
                if (!change) return;
                delete ctx.context.boilauthMfaChange;
                await notify("security.mfa_changed", change.id, ctx, { enabled: change.enabled });
              },
            },
          },
        },
      },
    }) as any,
  };
}
