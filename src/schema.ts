/**
 * Schema version contract + SQLite export/import.
 *
 * SCHEMA_VERSION names the set of tables/columns a boilauth install has.
 * Schift services that attach to a customer's auth DB key off this number,
 * so it only changes with a documented migration. `describeSchema()` is the
 * live shape; test/schema-contract.test.ts pins it to schema/v<N>.json.
 *
 * Only Better Auth field types that map 1:1 to SQLite storage classes are
 * allowed (string, number, boolean, date). `copyAuthData` moves every row
 * between two boilauth instances (e.g. Postgres → SQLite file and back).
 */
import { getAuthTables } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";
import type { BetterAuthOptions } from "better-auth";

export const SCHEMA_VERSION = 1;

export const SQLITE_EXPORTABLE_TYPES = ["string", "number", "boolean", "date"] as const;

export interface SchemaDescription {
  version: number;
  tables: Record<string, Record<string, { type: string; required: boolean }>>;
}

export function describeSchema(options: BetterAuthOptions): SchemaDescription {
  const tables = getAuthTables(options);
  const out: SchemaDescription["tables"] = {};
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

export function nonExportableFields(desc: SchemaDescription): string[] {
  const bad: string[] = [];
  for (const [t, fields] of Object.entries(desc.tables)) {
    for (const [n, f] of Object.entries(fields)) {
      if (!(SQLITE_EXPORTABLE_TYPES as readonly string[]).includes(f.type)) bad.push(`${t}.${n}:${f.type}`);
    }
  }
  return bad;
}

/** Create/upgrade tables for these options. Returns the tables it created. */
export async function migrate(options: BetterAuthOptions): Promise<string[]> {
  const m = await getMigrations(options, { throwOnUnsafe: true });
  await m.runMigrations();
  return m.toBeCreated.map((t) => t.table);
}

type AuthLike = { $context: Promise<{ adapter: any; options: BetterAuthOptions }> };

/** Tables in foreign-key order (user before account/session). rateLimit is transient and skipped. */
function copyOrder(options: BetterAuthOptions): string[] {
  const tables = getAuthTables(options);
  const keys = Object.keys(tables).filter((k) => k !== "rateLimit").sort();
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
