/**
 * Role / admin grant from the server side (CLI, seed scripts).
 *
 * Uses the same `role` column as Better Auth's admin plugin, so the plugin's
 * HTTP endpoints and access checks see the change. Every role change deletes
 * the user's sessions: a privilege change always forces a fresh sign-in, so
 * no session minted under the old role survives.
 */
type AuthLike = { $context: Promise<{ internalAdapter: any }> };

export const ROLE_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

export async function grantRole(auth: AuthLike, emailOrId: string, role: string) {
  if (!ROLE_PATTERN.test(role)) throw new Error(`invalid role "${role}"`);
  const ia = (await auth.$context).internalAdapter;
  const found = emailOrId.includes("@")
    ? (await ia.findUserByEmail(emailOrId.toLowerCase()))?.user
    : await ia.findUserById(emailOrId);
  if (!found) throw new Error(`user not found: ${emailOrId}`);
  const before: string | null = found.role ?? null;
  await ia.updateUser(found.id, { role });
  await ia.deleteUserSessions(found.id);
  return { userId: found.id as string, before, after: role, sessionsRevoked: true };
}
