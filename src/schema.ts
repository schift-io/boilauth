/**
 * Schema version contract + SQLite export/import.
 *
 * The schema is versioned per module. `core` is always present; every module
 * the wizard can switch on that adds tables or columns has its own version
 * and its own pinned delta file, schema/<module>.v<N>.json. `migrate()` writes
 * the enabled modules and versions into the `boilauthModule` table, so a
 * service attaching to a customer database reads the shape instead of
 * guessing. test/schema.test.ts pins every module file to the live shape.
 *
 * Only Better Auth field types that map 1:1 to SQLite storage classes are
 * allowed (string, number, boolean, date). `copyAuthData` moves every row
 * between two boilauth instances (e.g. Postgres -> SQLite file and back).
 */
import { getAuthTables } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";
import type { BetterAuthOptions } from "better-auth";

/** Version of the core module. Kept for 0.1 callers. */
export const SCHEMA_VERSION = 1;

/** Module -> contract version. Bump a module's number when its delta file changes. */
export const MODULE_VERSIONS = {
  core: 1,
  admin: 1,
  "two-factor": 1,
  "mfa-admin": 1,
  organization: 1,
  "soft-delete": 1,
} as const;

export type SchemaModule = keyof typeof MODULE_VERSIONS;

export const SQLITE_EXPORTABLE_TYPES = ["string", "number", "boolean", "date"] as const;

export type TableShape = Record<string, Record<string, { type: string; required: boolean }>>;

export interface SchemaDescription {
  version: number;
  tables: TableShape;
}

export function describeSchema(options: BetterAuthOptions): SchemaDescription {
  const tables = getAuthTables(options);
  const out: TableShape = {};
  for (const key of Object.keys(tables).sort()) {
    const fields: Record<string, { type: string; required: boolean }> = {};
    for (const name of Object.keys(tables[key].fields).sort()) {
      const f = tables[key].fields[name];
      fields[name] = { type: String(f.type), required: f.required !== false };
    }
    out[key] = fields;
  }
  return { version: SCHEMA_VERSION, tables: out };
}

/** Modules whose tables these options create, by plugin id. */
export function enabledModules(options: BetterAuthOptions): SchemaModule[] {
  const plugins = (options.plugins ?? []) as { id: string; schema?: unknown }[];
  const has = (id: string) => plugins.some((p) => p.id === id);
  const out: SchemaModule[] = ["core"];
  if (has("admin")) out.push("admin");
  if (has("two-factor")) out.push("two-factor");
  if (has("boilauth-mfa-admin")) out.push("mfa-admin");
  if (has("organization")) out.push("organization");
  if (plugins.some((p) => p.id === "boilauth-deletion" && p.schema)) out.push("soft-delete");
  return out;
}

/** Tables/columns present in `withModule` but not in `base`. */
export function schemaDelta(base: TableShape, withModule: TableShape): TableShape {
  const out: TableShape = {};
  for (const [t, fields] of Object.entries(withModule)) {
    for (const [n, f] of Object.entries(fields)) {
      if (base[t]?.[n]) continue;
      (out[t] ??= {})[n] = f;
    }
  }
  return out;
}

export function mergeShapes(...shapes: TableShape[]): TableShape {
  const out: TableShape = {};
  for (const s of shapes) for (const [t, fields] of Object.entries(s)) out[t] = { ...out[t], ...fields };
  const sorted: TableShape = {};
  for (const t of Object.keys(out).sort()) {
    sorted[t] = Object.fromEntries(Object.keys(out[t]).sort().map((k) => [k, out[t][k]]));
  }
  return sorted;
}

export function nonExportableFields(desc: SchemaDescription): string[] {
  const bad: string[] = [];
  for (const [t, fields] of Object.entries(desc.tables)) {
    for (const [n, f] of Object.entries(fields)) {
      if (!(SQLITE_EXPORTABLE_TYPES as readonly string[]).includes(f.type)) bad.push(`${t}.${n}:${f.type}`);
    }
  }
  return bad;
}

type MigrateTarget = BetterAuthOptions | { $context: Promise<{ adapter: any; options: BetterAuthOptions }> };

/**
 * Create/upgrade tables. Pass the auth instance (not just options) to also
 * record the enabled modules and their versions in `boilauthModule`.
 * Returns the tables it created.
 */
export async function migrate(target: MigrateTarget): Promise<string[]> {
  const ctx = "$context" in target ? await target.$context : null;
  const options = ctx ? ctx.options : (target as BetterAuthOptions);
  const m = await getMigrations(options, { throwOnUnsafe: true });
  await m.runMigrations();
  if (ctx) {
    await ctx.adapter.deleteMany({ model: "boilauthModule", where: [] });
    for (const name of enabledModules(options)) {
      await ctx.adapter.create({
        model: "boilauthModule",
        data: { name, version: MODULE_VERSIONS[name], installedAt: new Date() },
      });
    }
  }
  return m.toBeCreated.map((t) => t.table);
}

/** Modules and versions recorded in a database by migrate(). */
export async function installedModules(auth: { $context: Promise<{ adapter: any }> }) {
  const ctx = await auth.$context;
  const rows: { name: string; version: number }[] = await ctx.adapter.findMany({ model: "boilauthModule" });
  return Object.fromEntries(rows.map((r) => [r.name, r.version])) as Partial<Record<SchemaModule, number>>;
}

type AuthLike = { $context: Promise<{ adapter: any; options: BetterAuthOptions }> };

/** Tables in foreign-key order (user before account/session). rateLimit is transient and skipped. */
function copyOrder(options: BetterAuthOptions): string[] {
  const tables = getAuthTables(options);
  // rateLimit is transient; boilauthModule is written by migrate() on each side.
  const keys = Object.keys(tables).filter((k) => k !== "rateLimit" && k !== "boilauthModule").sort();
  // Topological order over field references (referenced model first).
  const byModelName = new Map(keys.map((k) => [tables[k].modelName, k]));
  const deps = new Map(
    keys.map((k) => [
      k,
      Object.values(tables[k].fields)
        .map((f) => f.references?.model)
        .filter((m): m is string => Boolean(m))
        .map((m) => byModelName.get(m) ?? m)
        .filter((m) => m !== k && keys.includes(m)),
    ]),
  );
  const out: string[] = [];
  const visit = (k: string, path: Set<string>) => {
    if (out.includes(k)) return;
    if (path.has(k)) throw new Error(`reference cycle at ${k}`);
    path.add(k);
    for (const d of deps.get(k) ?? []) visit(d, path);
    path.delete(k);
    out.push(k);
  };
  for (const k of keys) visit(k, new Set());
  return out;
}

export async function copyAuthData(from: AuthLike, to: AuthLike, pageSize = 500): Promise<Record<string, number>> {
  const src = await from.$context;
  const dst = await to.$context;
  const counts: Record<string, number> = {};
  for (const model of copyOrder(src.options)) {
    let offset = 0;
    counts[model] = 0;
    for (;;) {
      const rows: Record<string, unknown>[] = await src.adapter.findMany({
        model,
        limit: pageSize,
        offset,
        sortBy: { field: "id", direction: "asc" },
      });
      for (const row of rows) {
        await dst.adapter.create({ model, data: row, forceAllowId: true });
      }
      counts[model] += rows.length;
      if (rows.length < pageSize) break;
      offset += pageSize;
    }
  }
  return counts;
}

export async function dumpAll(auth: AuthLike): Promise<Record<string, Record<string, unknown>[]>> {
  const ctx = await auth.$context;
  const out: Record<string, Record<string, unknown>[]> = {};
  for (const model of copyOrder(ctx.options)) {
    const rows: Record<string, unknown>[] = await ctx.adapter.findMany({ model, limit: 1_000_000 });
    // Sort in JS: Postgres collation and SQLite BINARY order mixed-case ids differently.
    out[model] = rows.sort((x, y) => (String(x.id) < String(y.id) ? -1 : String(x.id) > String(y.id) ? 1 : 0));
  }
  return out;
}
