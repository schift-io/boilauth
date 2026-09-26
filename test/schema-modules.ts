/**
 * How each schema module is produced, shared by the drift test and
 * scripts/write-schema.ts. `base` is what the module's delta is measured
 * against; `plugins` is base + the module.
 */
import { DatabaseSync } from "node:sqlite";
import { admin, organization, twoFactor, username } from "better-auth/plugins";
import type { BetterAuthPlugin } from "better-auth";
import { boilAuthOptions, describeSchema, schemaDelta, type SchemaModule, type TableShape } from "../src/index.js";
import { requireAdminMfa } from "../src/modules/mfa.js";
import { accountDeletion } from "../src/modules/deletion.js";

export function shapeOf(plugins: BetterAuthPlugin[]): TableShape {
  const { options } = boilAuthOptions({
    database: new DatabaseSync(":memory:"),
    secret: "schema-only-secret-0123456789abcdef0123",
    baseURL: "http://localhost:3000",
    admin: false,
    plugins,
  });
  return describeSchema(options).tables;
}

export const MODULE_BUILD: Record<Exclude<SchemaModule, "core">, { base: () => BetterAuthPlugin[]; add: () => BetterAuthPlugin[] }> = {
  admin: { base: () => [], add: () => [admin()] },
  "two-factor": { base: () => [], add: () => [twoFactor()] },
  "mfa-admin": { base: () => [admin(), twoFactor()], add: () => [requireAdminMfa()] },
  organization: { base: () => [], add: () => [organization()] },
  "soft-delete": { base: () => [], add: () => [accountDeletion({ mode: "soft", exportData: false })] },
  username: { base: () => [], add: () => [username()] },
};

export function liveModuleShape(m: SchemaModule): TableShape {
  if (m === "core") return shapeOf([]);
  const b = MODULE_BUILD[m];
  return schemaDelta(shapeOf(b.base()), shapeOf([...b.base(), ...b.add()]));
}
