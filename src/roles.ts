/**
 * Role / admin grant from the server side (CLI, seed scripts).
 *
 * Uses the same `role` column as Better Auth's admin plugin, so the plugin's
 * HTTP endpoints and access checks see the change. Every role change deletes
 * the user's sessions: a privilege change always forces a fresh sign-in, so
 * no session minted under the old role survives.
 */
type PluginLike = { readonly id: string; readonly options?: unknown };
type AuthLike = {
  $context: Promise<{
    internalAdapter: any;
    options: { readonly plugins?: readonly PluginLike[] };
  }>;
};

export const ROLE_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

export function configuredRoleNames(plugins: readonly PluginLike[] | undefined): ReadonlySet<string> {
  const plugin = plugins?.find((candidate) => candidate.id === "admin");
  if (!plugin) return new Set();
  if (typeof plugin.options === "object" && plugin.options !== null && "roles" in plugin.options) {
    const roles = plugin.options.roles;
    if (typeof roles === "object" && roles !== null && !Array.isArray(roles)) return new Set(Object.keys(roles));
  }
  return new Set(["user", "admin"]);
}

export function findUnconfiguredRole(plugins: readonly PluginLike[] | undefined, requested: unknown): string | null {
  const allowed = configuredRoleNames(plugins);
  const roles = Array.isArray(requested) ? requested : [requested];
  const invalid = roles.find((candidate) => typeof candidate === "string" && !allowed.has(candidate));
  return typeof invalid === "string" ? invalid : null;
}

export function roleChangeUserId(returned: unknown): string | null {
  if (typeof returned !== "object" || returned === null || returned instanceof Error || !("user" in returned)) return null;
  const user = returned.user;
  if (typeof user !== "object" || user === null || !("id" in user) || typeof user.id !== "string") return null;
  return user.id;
}

export async function grantRole(auth: AuthLike, emailOrId: string, role: string) {
  if (!ROLE_PATTERN.test(role)) throw new Error(`invalid role "${role}"`);
  const context = await auth.$context;
  if (findUnconfiguredRole(context.options.plugins, role)) throw new Error(`role "${role}" is not configured`);
  const ia = context.internalAdapter;
  const found = emailOrId.includes("@")
    ? (await ia.findUserByEmail(emailOrId.toLowerCase()))?.user
    : await ia.findUserById(emailOrId);
  if (!found) throw new Error(`user not found: ${emailOrId}`);
  const before: string | null = found.role ?? null;
  await ia.updateUser(found.id, { role });
  await ia.deleteUserSessions(found.id);
  return { userId: found.id as string, before, after: role, sessionsRevoked: true };
}
