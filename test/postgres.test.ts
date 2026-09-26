/**
 * Postgres path. Runs only when BOILAUTH_PG_URL points at an EMPTY scratch
 * database (tables are created and dropped). Skipped otherwise — reported as
 * skipped, never as passed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {
  copyAuthData,
  createBoilAuth,
  dumpAll,
  importUsers,
  migrate,
  parseAuth0Export,
  parseFirebaseExport,
  parseSupabaseExport,
} from "../src/index.js";
import { BASE, FIREBASE_SAMPLE_KEY, SECRET, fixture, makeAuth, signIn, storedHash } from "./helpers.js";

const url = process.env.BOILAUTH_PG_URL;

test("postgres: import all three providers, log in, export to SQLite and back", { skip: !url && "BOILAUTH_PG_URL not set" }, async () => {
  const pool = new pg.Pool({ connectionString: url, max: 4 });
  const drop = () =>
    pool.query(`drop table if exists "importedIdentity", "account", "session", "verification", "rateLimit", "user" cascade`);
  try {
    await drop();
    const auth = createBoilAuth({
      database: pool,
      secret: SECRET,
      baseURL: BASE,
      firebaseKeys: [FIREBASE_SAMPLE_KEY],
      betterAuth: { logger: { disabled: true } },
    });
    const created = await migrate(auth.boilauth.options);
    assert.ok(created.includes("user") && created.includes("importedIdentity"), created.join(","));

    await importUsers(auth, "supabase", parseSupabaseExport(fixture("supabase-users.json")));
    await importUsers(auth, "firebase", parseFirebaseExport(fixture("firebase-users.json"), FIREBASE_SAMPLE_KEY));
    await importUsers(auth, "auth0", parseAuth0Export(fixture("auth0-users.ndjson")));

    for (const [email, pw] of [
      ["ada@example.com", "U*U"],
      ["user1@test.com", "user1password"],
      ["linus@example.com", "Kk4DQuMMfZL9o"],
    ]) {
      assert.equal((await signIn(auth, email, pw)).status, 200, email);
      assert.match((await storedHash(auth, email))!, /^\$argon2id\$/, email);
    }

    const sqlite = await makeAuth();
    await copyAuthData(auth, sqlite);
    const back = await makeAuth();
    await copyAuthData(sqlite, back);
    const a = await dumpAll(auth);
    const b = await dumpAll(back);
    for (const t of Object.keys(a)) assert.deepEqual(b[t], a[t], `table ${t}`);
    assert.equal((await signIn(back, "user1@test.com", "user1password")).status, 200);
  } finally {
    await drop();
    await pool.end();
  }
});
