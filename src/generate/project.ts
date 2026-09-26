/**
 * The files `boilauth init` writes. "generated" files are rewritten on every
 * init; "owned" files are written once and then belong to the developer.
 */
import { existsSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Answers } from "../wizard/answers.js";
import { authFile, configFile, emailFile, envExample, permissionsFile } from "./auth-file.js";
import { FIXTURES, helpersFile, testFile } from "./test-files.js";
import { usernameRulesYaml } from "../modules/username.js";

export interface PlannedFile {
  path: string;
  content: string;
  owned: boolean;
}

const PKG = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
  version: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};

export function packageJson(a: Answers, name = "my-app"): string {
  const deps: Record<string, string> = {
    boilauth: `^${PKG.version}`,
    "better-auth": PKG.dependencies["better-auth"],
  };
  const dev: Record<string, string> = {
    "@types/node": PKG.devDependencies["@types/node"],
    tsx: PKG.devDependencies.tsx,
    typescript: PKG.devDependencies.typescript,
  };
  if (a.runtime.database === "postgres") {
    deps.pg = PKG.devDependencies.pg;
    dev["@types/pg"] = PKG.devDependencies["@types/pg"];
  }
  return (
    JSON.stringify(
      {
        name,
        private: true,
        type: "module",
        engines: { node: ">=22.5" },
        scripts: {
          test: "node --disable-warning=ExperimentalWarning --import tsx --test test/*.test.ts",
          migrate: "boilauth migrate --config boilauth.config.ts",
        },
        dependencies: deps,
        devDependencies: dev,
      },
      null,
      2,
    ) + "\n"
  );
}

const TSCONFIG = `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "skipLibCheck": true,
    "noEmit": true,
    "types": ["node"]
  },
  "include": ["src", "test", "boilauth.config.ts"]
}
`;

export function planProject(a: Answers): PlannedFile[] {
  const files: PlannedFile[] = [
    { path: "src/auth.ts", content: authFile(a), owned: false },
    { path: "boilauth.config.ts", content: configFile(a), owned: false },
    { path: ".env.example", content: envExample(a), owned: false },
    { path: "test/helpers.ts", content: helpersFile(a), owned: false },
    { path: "test/boilauth.test.ts", content: testFile(a), owned: false },
    { path: "src/email.ts", content: emailFile(), owned: true },
    { path: "package.json", content: packageJson(a), owned: true },
    { path: "tsconfig.json", content: TSCONFIG, owned: true },
  ];
  if (a.roles.mode === "custom") files.push({ path: "src/permissions.ts", content: permissionsFile(a), owned: true });
  if (a.signIn.emailPassword && a.signIn.username) files.push({ path: "boilauth.username.yaml", content: usernameRulesYaml(), owned: true });
  for (const s of a.migration.sources) {
    const f = FIXTURES[s];
    files.push({
      path: `test/fixtures/${f}`,
      content: readFileSync(new URL(`../../fixtures/${f}`, import.meta.url), "utf8"),
      owned: false,
    });
  }
  return files;
}

const NPM_PLACEHOLDER_TEST = 'echo "Error: no test specified" && exit 1';

/**
 * Adds what the generated project needs to a package.json the developer
 * already has (e.g. the one `npm install boilauth` created). Adds missing keys
 * only; an existing value is never changed, except npm's placeholder test script.
 */
export function mergePackageJson(existing: string, generated: string): { text: string; added: string[] } {
  const cur = JSON.parse(existing) as Record<string, any>;
  const gen = JSON.parse(generated) as Record<string, any>;
  const added: string[] = [];
  for (const k of ["type", "engines"]) {
    if (cur[k] === undefined) {
      cur[k] = gen[k];
      added.push(k);
    }
  }
  for (const section of ["scripts", "dependencies", "devDependencies"]) {
    cur[section] ??= {};
    for (const [k, v] of Object.entries(gen[section] as Record<string, string>)) {
      const placeholder = section === "scripts" && k === "test" && cur[section][k] === NPM_PLACEHOLDER_TEST;
      if (cur[section][k] === undefined || placeholder) {
        cur[section][k] = v;
        added.push(`${section}.${k}`);
      }
    }
  }
  return { text: JSON.stringify(cur, null, 2) + "\n", added };
}

export async function writeProject(dir: string, files: PlannedFile[], force = false): Promise<string[]> {
  const log: string[] = [];
  for (const f of files) {
    const p = join(dir, f.path);
    if (f.path === "package.json" && existsSync(p) && !force) {
      const { text, added } = mergePackageJson(await readFile(p, "utf8"), f.content);
      if (added.length) await writeFile(p, text);
      log.push(added.length ? `merged package.json (added ${added.join(", ")})` : "keep package.json (yours)");
      continue;
    }
    if (f.owned && existsSync(p) && !force) {
      log.push(`keep ${f.path} (yours; --force to overwrite)`);
      continue;
    }
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, f.content);
    log.push(`wrote ${f.path}`);
  }
  return log;
}
