/**
 * Steps shared by every self-service deletion path in boilauth/deletion
 * (spec D4, D5, D6): the app's veto, the last-owner rule for organizations,
 * leaving organizations, and anonymizing the user row.
 *
 * All functions take a Better Auth adapter (the one bound to the running
 * transaction when there is one) so they work from endpoints and from hooks.
 */
import { APIError } from "better-auth/api";

export type DeletionCheckResult = { ok: true } | { ok: false; code: string; message: string };
/** The app's veto on self-service deletion, e.g. while a paid subscription is active. */
export type DeletionCheck = (user: { id: string; email: string; name?: string | null }) => DeletionCheckResult | Promise<DeletionCheckResult>;

export type LastOwnerPolicy = "block" | "transfer_to_oldest_admin";

// Better Auth adapter (or the one bound to the running transaction); typed loosely like the rest of the plugin code.
type Adapter = any;

interface Member {
  id: string;
  organizationId: string;
  userId: string;
  role: string;
  createdAt: Date | string;
}

const hasRole = (m: Member, role: string) => m.role.split(",").some((r) => r.trim() === role);
const time = (d: Date | string) => new Date(d).getTime();

export async function runCheck(check: DeletionCheck | undefined, user: { id: string; email: string }): Promise<void> {
  if (!check) return;
  const r = await check(user);
  if (!r.ok) throw APIError.from("CONFLICT", { code: r.code, message: r.message });
}

/**
 * D5. For every organization where the user is the only owner and other members
 * remain: refuse (409 ORG_OWNER_TRANSFER_REQUIRED), or hand ownership to the
 * member with the admin role who joined first. Every organization is checked
 * before any role changes, so a refusal changes nothing.
 */
export async function settleOwnership(db: Adapter, userId: string, policy: LastOwnerPolicy): Promise<void> {
  const mine = ((await db.findMany({ model: "member", where: [{ field: "userId", value: userId }] })) as Member[]).filter((m) => hasRole(m, "owner"));
  const transfers: Member[] = [];
  for (const m of mine) {
    const others = ((await db.findMany({ model: "member", where: [{ field: "organizationId", value: m.organizationId }] })) as Member[]).filter(
      (o) => o.userId !== userId,
    );
    if (others.length === 0 || others.some((o) => hasRole(o, "owner"))) continue;
    const heir = others.filter((o) => hasRole(o, "admin")).sort((a, b) => time(a.createdAt) - time(b.createdAt))[0];
    if (policy === "block" || !heir) {
      throw APIError.from("CONFLICT", {
        code: "ORG_OWNER_TRANSFER_REQUIRED",
        message: heir
          ? `Transfer ownership of organization ${m.organizationId} before deleting the account`
          : `Organization ${m.organizationId} has no admin to take ownership; transfer it first`,
      });
    }
    transfers.push(heir);
  }
  for (const heir of transfers) await db.update({ model: "member", where: [{ field: "id", value: heir.id }], update: { role: "owner" } });
}

/** The user leaves every organization (member rows removed; invitations they sent stay as history). */
export async function leaveOrganizations(db: Adapter, userId: string): Promise<void> {
  await db.deleteMany({ model: "member", where: [{ field: "userId", value: userId }] });
}

export const ANONYMIZED_DOMAIN = "deleted.invalid";

/**
 * D6. Keeps the user row (so payment and audit rows that reference user.id still
 * resolve) and removes everything that identifies or signs in the person:
 * sessions, credential and OAuth links, imported identities, 2FA secrets, and
 * the personal columns. The email becomes deleted+<id>@deleted.invalid.
 */
export async function anonymizeUser(db: Adapter, ia: { deleteUserSessions: (id: string) => Promise<unknown> }, userId: string): Promise<boolean> {
  const user = (await db.findOne({ model: "user", where: [{ field: "id", value: userId }] })) as Record<string, unknown> | null;
  if (!user) return false;
  if (String(user.email ?? "").endsWith(`@${ANONYMIZED_DOMAIN}`)) return false;
  await ia.deleteUserSessions(userId);
  for (const model of ["account", "importedIdentity", "twoFactor"]) {
    await db.deleteMany({ model, where: [{ field: "userId", value: userId }] }).catch(() => 0);
  }
  const update: Record<string, unknown> = {
    email: `deleted+${userId}@${ANONYMIZED_DOMAIN}`,
    name: "",
    image: null,
    emailVerified: false,
  };
  for (const k of ["username", "displayUsername", "phoneNumber"]) if (k in user) update[k] = null;
  if ("phoneNumberVerified" in user) update.phoneNumberVerified = false;
  if ("twoFactorEnabled" in user) update.twoFactorEnabled = false;
  await db.update({ model: "user", where: [{ field: "id", value: userId }], update });
  return true;
}
