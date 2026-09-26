import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION, main } from "../src/cli.js";
import { signIn } from "./helpers.js";

const SRC = fileURLToPath(new URL("../src/index.ts", import.meta.url));
const FIX = fileURLToPath(new URL("../fixtures/", import.meta.url));

function config(dir: string, name: string, db: string) {
  const p = join(dir, name);
  writeFileSync(
    p,
    `import { DatabaseSync } from "node:sqlite";
import { createBoilAuth } from ${JSON.stringify(SRC)};
export default createBoilAuth({
  database: new DatabaseSync(${JSON.stringify(join(dir, db))}),
  secret: "cli-test-secret-0123456789abcdef0123456789",
  baseURL: "http://localhost:3000",
  firebaseKeys: [{ keyId: "sample-project", signerKey: "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==", saltSeparator: "Bw==", rounds: 8, memCost: 14 }],
  betterAuth: { logger: { disabled: true } },
});
`,
  );
  return p;
}

test("CLI: init, migrate, import ×3, grant-role, export-sqlite, import-sqlite into a fresh DB", async () => {
  const dir = mkdtempSync(join(tmpdir(), "boilauth-cli-"));
  const out: string[] = [];
  const log = (s: string) => out.push(s);
  const cwd = process.cwd();
  try {
    process.chdir(dir);
    assert.equal(await main(["init", "--yes"], log), 0);
    for (const f of ["boilauth.answers.json", "boilauth.config.ts", "src/auth.ts", "src/email.ts", ".env.example", "test/boilauth.test.ts"]) {
      assert.ok(existsSync(join(dir, f)), f);
    }

    const cfgA = config(dir, "a.config.mjs", "a.db");
    assert.equal(await main(["migrate", "--config", cfgA], log), 0);
    assert.equal(await main(["import", "supabase", join(FIX, "supabase-users.json"), "--config", cfgA], log), 0);
    assert.equal(await main(["import", "auth0", join(FIX, "auth0-users.ndjson"), "--config", cfgA], log), 0);
    await assert.rejects(main(["import", "firebase", join(FIX, "firebase-users.csv"), "--config", cfgA], log), /--key-id/);
    assert.equal(
      await main(["import", "firebase", join(FIX, "firebase-users.csv"), "--key-id", "sample-project", "--config", cfgA], log),
      0,
    );
    assert.ok(out.some((l) => l.includes("md5user@example.com") && l.includes("unsupported_hash")), out.join("\n"));
    assert.equal(await main(["grant-role", "ada@example.com", "admin", "--config", cfgA], log), 0);

    const exportFile = join(dir, "export.db");
    assert.equal(await main(["export-sqlite", exportFile, "--config", cfgA], log), 0);
    await assert.rejects(main(["export-sqlite", exportFile, "--config", cfgA], log), /refusing to overwrite/);

    const cfgB = config(dir, "b.config.mjs", "b.db");
    assert.equal(await main(["import-sqlite", exportFile, "--config", cfgB], log), 0);
    const b = (await import(cfgB)).default;
    assert.equal((await signIn(b, "ada@example.com", "U*U")).status, 200);
    assert.equal((await signIn(b, "user1@test.com", "user1password")).status, 200);
    assert.equal((await signIn(b, "linus@example.com", "Kk4DQuMMfZL9o")).status, 200);
    const ctx = await b.$context;
    const ada = await ctx.internalAdapter.findUserByEmail("ada@example.com");
    assert.equal(ada.user.role, "admin");
  } finally {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI: check-updates only with an explicit feed; flags affected versions", async () => {
  const dir = mkdtempSync(join(tmpdir(), "boilauth-feed-"));
  try {
    const feed = join(dir, "feed.json");
    writeFileSync(
      feed,
      JSON.stringify({
        advisories: [
          { id: "TEST-1", affected: `<=${VERSION}`, severity: "high", summary: "test advisory" },
          { id: "TEST-2", affected: "<0.0.1", severity: "low", summary: "old" },
        ],
      }),
    );
    const out: string[] = [];
    await assert.rejects(main(["check-updates"], (s) => out.push(s)), /--feed/);
    assert.equal(await main(["check-updates", "--feed", `file://${feed}`], (s) => out.push(s)), 2);
    assert.ok(out.join("").includes("TEST-1") && !out.join("").includes("TEST-2"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
