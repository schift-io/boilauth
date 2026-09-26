/**
 * boilauth CLI.
 *
 *   boilauth init [--yes] [--set key=value ...] [--force]
 *                                                   ask the policy questions (docs/EDGE_CASES.md), save
 *                                                   boilauth.answers.json, generate only the chosen modules
 *   boilauth migrate                                create/upgrade tables, record schema modules
 *   boilauth import supabase <file>                 auth.users export (JSON or CSV)
 *   boilauth import firebase <file> --key-id <id>   firebase auth:export (JSON or CSV)
 *   boilauth import auth0 <file>                    Auth0 password-hash export (NDJSON/JSON)
 *   boilauth import generic <file>                  your own CSV/JSON (id, email, email_verified, password_hash)
 *   boilauth grant-role <email|id> <role>           e.g. grant-role ops@acme.io admin
 *   boilauth purge-deleted <days>                   remove soft-deleted users older than <days>
 *   boilauth export-sqlite <out.db>                 copy every row into a new SQLite file
 *   boilauth import-sqlite <in.db>                  copy rows from a boilauth SQLite file
 *   boilauth schema                                 print schema and enabled modules as JSON
 *   boilauth check-updates --feed <url>             opt-in advisory check
 *
 * All commands except init read ./boilauth.config.ts (or .mjs, or --config),
 * whose default export is the object returned by createBoilAuth(). ./.env is
 * loaded first when present; variables already set in the shell win.
 */
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createBoilAuth, type BoilAuth } from "./auth.js";
import { importUsers } from "./import/common.js";
import { parseAuth0Export, parseFirebaseExport, parseGenericExport, parseSupabaseExport } from "./import/providers.js";
import { grantRole } from "./roles.js";
import { copyAuthData, describeSchema, enabledModules, migrate } from "./schema.js";
import { checkAdvisories } from "./update-check.js";
import { purgeDeleted } from "./modules/deletion.js";
import { loadAnswers, saveAnswers } from "./wizard/answers.js";
import { parseOverride, runWizard } from "./wizard/run.js";
import { planProject, writeProject } from "./generate/project.js";

const ANSWERS_FILE = "boilauth.answers.json";

export const VERSION = "0.3.0";

function defaultConfig(): string {
  return existsSync("boilauth.config.ts") ? "boilauth.config.ts" : "boilauth.config.mjs";
}

async function loadAuth(configPath: string | undefined): Promise<BoilAuth> {
  // The generated config reads process.env; ./.env fills what the shell has not set.
  if (existsSync(".env")) process.loadEnvFile(".env");
  const p = resolve(configPath ?? defaultConfig());
  if (!existsSync(p)) throw new Error(`config not found: ${p} (run \`boilauth init\`)`);
  let mod;
  if (p.endsWith(".ts")) {
    const { tsImport } = await import("tsx/esm/api").catch(() => {
      throw new Error("a .ts config needs tsx installed (npm i -D tsx)");
    });
    mod = await tsImport(pathToFileURL(p).href, import.meta.url);
  } else mod = await import(pathToFileURL(p).href);
  const auth = mod.default as BoilAuth;
  if (!auth?.boilauth) throw new Error(`${p} must default-export createBoilAuth(...)`);
  return auth;
}

async function sqliteTwin(auth: BoilAuth, file: string): Promise<BoilAuth> {
  const { DatabaseSync } = await import("node:sqlite");
  const twin = createBoilAuth({ ...auth.boilauth.input, database: new DatabaseSync(file) });
  await migrate(twin);
  return twin;
}

export async function main(argv: string[], log: (s: string) => void = console.log): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      config: { type: "string" },
      yes: { type: "boolean", default: false },
      set: { type: "string", multiple: true },
      "key-id": { type: "string" },
      feed: { type: "string" },
      force: { type: "boolean", default: false },
    },
  });
  const [cmd, a, b] = positionals;

  switch (cmd) {
    case "init": {
      const existing = await loadAnswers(ANSWERS_FILE);
      const overrides = Object.fromEntries((values.set ?? []).map(parseOverride));
      const answers = await runWizard({ yes: values.yes!, existing, overrides });
      await saveAnswers(ANSWERS_FILE, answers);
      log(`${existing ? "updated" : "wrote"} ${ANSWERS_FILE}`);
      for (const line of await writeProject(".", planProject(answers), values.force)) log(line);
      log("next: npm install, cp .env.example .env, npm test, npx boilauth migrate");
      return 0;
    }
    case "migrate": {
      const auth = await loadAuth(values.config);
      const created = await migrate(auth);
      log(created.length ? `created tables: ${created.join(", ")}` : "schema up to date");
      return 0;
    }
    case "import": {
      if (!a || !b) throw new Error("usage: boilauth import <supabase|firebase|auth0|generic> <file>");
      const auth = await loadAuth(values.config);
      const text = await readFile(b, "utf8");
      let records;
      if (a === "supabase") records = parseSupabaseExport(text);
      else if (a === "auth0") records = parseAuth0Export(text);
      else if (a === "generic") records = parseGenericExport(text);
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
      const auth = await loadAuth(values.config);
      log(JSON.stringify(await grantRole(auth, a, b)));
      return 0;
    }
    case "export-sqlite": {
      if (!a) throw new Error("usage: boilauth export-sqlite <out.db>");
      if (existsSync(a)) throw new Error(`${a} exists; refusing to overwrite`);
      const auth = await loadAuth(values.config);
      log(JSON.stringify(await copyAuthData(auth, await sqliteTwin(auth, a))));
      return 0;
    }
    case "import-sqlite": {
      if (!a) throw new Error("usage: boilauth import-sqlite <in.db>");
      const auth = await loadAuth(values.config);
      await migrate(auth);
      log(JSON.stringify(await copyAuthData(await sqliteTwin(auth, a), auth)));
      return 0;
    }
    case "purge-deleted": {
      const days = Number(a);
      if (!a || !Number.isFinite(days) || days < 0) throw new Error("usage: boilauth purge-deleted <days>");
      const auth = await loadAuth(values.config);
      log(JSON.stringify({ purged: await purgeDeleted(auth, days) }));
      return 0;
    }
    case "schema": {
      const auth = await loadAuth(values.config);
      const o = auth.boilauth.options;
      log(JSON.stringify({ modules: enabledModules(o), ...describeSchema(o) }, null, 2));
      return 0;
    }
    case "check-updates": {
      if (!values.feed) throw new Error("usage: boilauth check-updates --feed <url>  (nothing is sent unless you run this)");
      const hits = await checkAdvisories(VERSION, values.feed);
      log(hits.length ? JSON.stringify(hits, null, 2) : `boilauth ${VERSION}: no advisories`);
      return hits.some((h) => h.severity === "high" || h.severity === "critical") ? 2 : 0;
    }
    default:
      log("usage: boilauth <init|migrate|import|grant-role|purge-deleted|export-sqlite|import-sqlite|schema|check-updates>");
      return cmd ? 1 : 0;
  }
}
