/**
 * Generates real projects from answer sets (defaults and non-default answers
 * for every group) and runs each project's own generated tests and a
 * typecheck. Projects live in .gen/<name> (gitignored) with node_modules/boilauth
 * linked to this repo; everything else resolves from this repo's node_modules.
 */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const GEN = join(ROOT, ".gen");
const PG = process.env.BOILAUTH_PG_URL;

const SCENARIOS: Record<string, { answers: Record<string, unknown>; postgres?: boolean }> = {
  defaults: { answers: {} },
  "orgs-totp-firebase-soft": {
    answers: {
      signIn: { emailPassword: true },
      migration: { sources: ["firebase"], firebase: { keyId: "my-project", saltSeparator: "Bw==", rounds: 8, memCost: 14 } },
      email: { verification: "optional" },
      password: { minLength: 12 },
      lockout: { maxFailures: 3, minutes: 5 },
      rateLimit: { signInPerMinute: 5 },
      session: { days: 3, devices: "single" },
      mfa: { mode: "totp_optional" },
      roles: { mode: "organizations", orgCreation: "any_user" },
      deletion: { mode: "soft", export: false },
    },
  },
  "custom-roles-admin-mfa-oauth": {
    answers: {
      signIn: { emailPassword: true, magicLink: true, oauth: ["google", "github", "apple", "kakao", "naver"] },
      migration: { sources: ["supabase", "auth0"] },
      linking: { mode: "never" },
      password: { breachedCheck: "hibp" },
      session: { days: 30, revokeOnPasswordChange: false },
      mfa: { mode: "totp_required_admin" },
      roles: { mode: "custom", custom: ["admin", "editor", "viewer", "user"] },
    },
  },
  "postgres-oauth-only-orgs-admin-only": {
    postgres: true,
    answers: {
      runtime: { database: "postgres" },
      signIn: { emailPassword: false, magicLink: false, oauth: ["github", "kakao"] },
      roles: { mode: "organizations", orgCreation: "admin_only" },
      deletion: { mode: "soft", export: true },
    },
  },
  "magic-link-only-no-roles": {
    answers: {
      signIn: { emailPassword: false, magicLink: true, oauth: [] },
      roles: { mode: "none" },
      session: { devices: "single" },
    },
  },
};

before(() => {
  execFileSync(join(ROOT, "node_modules/.bin/tsc"), ["-p", "tsconfig.json"], { cwd: ROOT, stdio: "inherit" });
  rmSync(GEN, { recursive: true, force: true });
});

for (const [name, sc] of Object.entries(SCENARIOS)) {
  test(`generated project "${name}": init --yes, typecheck, its own tests pass`, { timeout: 180_000 }, (t) => {
    const dir = join(GEN, name);
    mkdirSync(join(dir, "node_modules"), { recursive: true });
    symlinkSync(ROOT, join(dir, "node_modules/boilauth"), "dir");
    writeFileSync(join(dir, "boilauth.answers.json"), JSON.stringify(sc.answers));
    const node = (args: string[], env: Record<string, string> = {}) =>
      spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", ...args], {
        cwd: dir,
        encoding: "utf8",
        // NODE_TEST_CONTEXT would make the child report into this runner instead of printing TAP.
        env: { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== "NODE_TEST_CONTEXT")), ...env },
      });

    const init = node([join(ROOT, "bin/boilauth.mjs"), "init", "--yes"]);
    assert.equal(init.status, 0, init.stderr + init.stdout);

    const tsc = spawnSync(join(ROOT, "node_modules/.bin/tsc"), ["-p", "tsconfig.json"], { cwd: dir, encoding: "utf8" });
    assert.equal(tsc.status, 0, `typecheck failed:\n${tsc.stdout}${tsc.stderr}`);

    const env: Record<string, string> = sc.postgres && PG ? { TEST_DATABASE_URL: PG } : {};
    const run = node(["--import", "tsx", "--test", "--test-reporter=tap", "test/boilauth.test.ts"], env);
    const out = run.stdout + run.stderr;
    const count = (k: string) => Number(new RegExp(`# ${k} (\\d+)`).exec(out)?.[1] ?? NaN);
    const failing = out.split("\n").filter((l) => l.startsWith("not ok")).join("\n");
    assert.equal(run.status, 0, `generated tests failed:\n${failing}\n${out.slice(-4000)}`);
    assert.equal(count("fail"), 0);
    if (sc.postgres && !PG) {
      assert.ok(count("skipped") > 0 && count("pass") === 0, "postgres scenario without BOILAUTH_PG_URL must skip, not pass");
      t.skip("BOILAUTH_PG_URL not set: generated postgres tests skipped, not run");
      return;
    }
    assert.ok(count("pass") >= 5, `only ${count("pass")} generated tests ran`);
    assert.equal(count("skipped"), 0);
  });
}
