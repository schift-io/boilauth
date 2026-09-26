/**
 * boilauth CLI.
 *
 *   boilauth init                                   write boilauth.config.mjs + .env.example
 *   boilauth migrate                                create/upgrade tables
 *   boilauth import supabase <file>                 auth.users export (JSON or CSV)
 *   boilauth import firebase <file> --key-id <id>   firebase auth:export (JSON or CSV)
 *   boilauth import auth0 <file>                    Auth0 password-hash export (NDJSON/JSON)
 *   boilauth grant-role <email|id> <role>           e.g. grant-role ops@acme.io admin
 *   boilauth export-sqlite <out.db>                 copy every row into a new SQLite file
 *   boilauth import-sqlite <in.db>                  copy rows from a boilauth SQLite file
 *   boilauth schema                                 print schema contract as JSON
 *   boilauth check-updates --feed <url>             opt-in advisory check
 *
 * All commands except init read ./boilauth.config.mjs (or --config), whose
 * default export is the object returned by createBoilAuth().
 */
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createBoilAuth, type BoilAuth } from "./auth.js";
import { importUsers } from "./import/common.js";
import { parseAuth0Export, parseFirebaseExport, parseSupabaseExport } from "./import/providers.js";
import { grantRole } from "./roles.js";
import { copyAuthData, describeSchema, migrate } from "./schema.js";
import { checkAdvisories } from "./update-check.js";
import { CONFIG_TEMPLATE, ENV_TEMPLATE } from "./templates.js";

export const VERSION = "0.1.0";

async function loadAuth(configPath: string): Promise<BoilAuth> {
  const p = resolve(configPath);
  if (!existsSync(p)) throw new Error(`config not found: ${p} (run \`boilauth init\`)`);
  const mod = await import(pathToFileURL(p).href);
  const auth = mod.default as BoilAuth;
  if (!auth?.boilauth) throw new Error(`${p} must default-export createBoilAuth(...)`);
  return auth;
}

async function sqliteTwin(auth: BoilAuth, file: string): Promise<BoilAuth> {
  const { DatabaseSync } = await import("node:sqlite");
  const twin = createBoilAuth({ ...auth.boilauth.input, database: new DatabaseSync(file) });
  await migrate(twin.boilauth.options);
  return twin;
}

export async function main(argv: string[], log: (s: string) => void = console.log): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      config: { type: "string", default: "boilauth.config.mjs" },
      "key-id": { type: "string" },
      feed: { type: "string" },
      force: { type: "boolean", default: false },
    },
  });
  const [cmd, a, b] = positionals;

  switch (cmd) {
    case "init": {
      for (const [f, body] of [
        [values.config!, CONFIG_TEMPLATE],
        [".env.example", ENV_TEMPLATE],
      ] as const) {
        if (existsSync(f) && !values.force) {
          log(`skip ${f} (exists; --force to overwrite)`);
          continue;
        }
        await writeFile(f, body);
        log(`wrote ${f}`);
      }
      log("next: copy .env.example to .env, set BOILAUTH_SECRET, then `boilauth migrate`");
      return 0;
    }
    case "migrate": {
      const auth = await loadAuth(values.config!);
      const created = await migrate(auth.boilauth.options);
      log(created.length ? `created tables: ${created.join(", ")}` : "schema up to date");
      return 0;
    }
    case "import": {
      if (!a || !b) throw new Error("usage: boilauth import <supabase|firebase|auth0> <file>");
      const auth = await loadAuth(values.config!);
      const text = await readFile(b, "utf8");
      let records;
      if (a === "supabase") records = parseSupabaseExport(text);
      else if (a === "auth0") records = parseAuth0Export(text);
      else if (a === "firebase") {
        const keyId = values["key-id"];
        const key = auth.boilauth.input.firebaseKeys?.find((k) => k.keyId === keyId);
        if (!key) throw new Error(`--key-id must name an entry in firebaseKeys of your config (got "${keyId ?? ""}")`);
        records = parseFirebaseExport(text, key);
      } else throw new Error(`unknown source "${a}"`);
      const report = await importUsers(auth, a, records);
      log(JSON.stringify({ source: a, created: report.created, merged: report.merged, skipped: report.skipped }));
      for (const o of report.outcomes) if (o.result === "skipped") log(`skipped ${o.sourceId} <${o.email}>: ${o.reason}`);
      return 0;
    }
    case "grant-role": {
      if (!a || !b) throw new Error("usage: boilauth grant-role <email|id> <role>");
      const auth = await loadAuth(values.config!);
      log(JSON.stringify(await grantRole(auth, a, b)));
      return 0;
    }
    case "export-sqlite": {
      if (!a) throw new Error("usage: boilauth export-sqlite <out.db>");
      if (existsSync(a)) throw new Error(`${a} exists; refusing to overwrite`);
      const auth = await loadAuth(values.config!);
      log(JSON.stringify(await copyAuthData(auth, await sqliteTwin(auth, a))));
      return 0;
    }
    case "import-sqlite": {
      if (!a) throw new Error("usage: boilauth import-sqlite <in.db>");
      const auth = await loadAuth(values.config!);
      await migrate(auth.boilauth.options);
      log(JSON.stringify(await copyAuthData(await sqliteTwin(auth, a), auth)));
      return 0;
    }
    case "schema": {
      const auth = await loadAuth(values.config!);
      log(JSON.stringify(describeSchema(auth.boilauth.options), null, 2));
      return 0;
    }
    case "check-updates": {
      if (!values.feed) throw new Error("usage: boilauth check-updates --feed <url>  (nothing is sent unless you run this)");
      const hits = await checkAdvisories(VERSION, values.feed);
      log(hits.length ? JSON.stringify(hits, null, 2) : `boilauth ${VERSION}: no advisories`);
      return hits.some((h) => h.severity === "high" || h.severity === "critical") ? 2 : 0;
    }
    default:
      log("usage: boilauth <init|migrate|import|grant-role|export-sqlite|import-sqlite|schema|check-updates>");
      return cmd ? 1 : 0;
  }
}
