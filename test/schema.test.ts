import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SCHEMA_VERSION,
  copyAuthData,
  describeSchema,
  dumpAll,
  grantRole,
  importUsers,
  nonExportableFields,
  parseFirebaseExport,
  parseSupabaseExport,
} from "../src/index.js";
import { FIREBASE_SAMPLE_KEY, fixture, makeAuth, signIn, storedHash } from "./helpers.js";

test("live schema equals the published contract schema/v1.json", async () => {
  const auth = await makeAuth();
  const pinned = JSON.parse(readFileSync(new URL("../schema/v1.json", import.meta.url), "utf8"));
  const live = describeSchema(auth.boilauth.options);
  assert.equal(live.version, SCHEMA_VERSION);
  assert.ok(Object.keys(live.tables).length > 0, "contract must describe at least one table");
  assert.deepEqual(live, pinned);
});

test("every column type is SQLite-exportable", async () => {
  const auth = await makeAuth();
  const desc = describeSchema(auth.boilauth.options);
  const cols = Object.values(desc.tables).reduce((n, t) => n + Object.keys(t).length, 0);
  assert.ok(cols > 0, "scanned zero columns");
  assert.deepEqual(nonExportableFields(desc), []);
});

test("export → SQLite file → re-import: every row identical, logins still work", async () => {
  const dir = mkdtempSync(join(tmpdir(), "boilauth-rt-"));
  try {
    const a = await makeAuth({}, join(dir, "source.db"));
    await a.api.signUpEmail({ body: { email: "native@example.com", password: "native-password-1", name: "N" } });
    await importUsers(a, "supabase", parseSupabaseExport(fixture("supabase-users.json")));
    await importUsers(a, "firebase", parseFirebaseExport(fixture("firebase-users.json"), FIREBASE_SAMPLE_KEY));
    await grantRole(a, "native@example.com", "admin");
    assert.equal((await signIn(a, "native@example.com", "native-password-1")).status, 200); // leaves a session row

    const exported = await makeAuth({}, join(dir, "export.db"));
    const outCounts = await copyAuthData(a, exported);
    assert.ok(outCounts.user >= 4 && outCounts.session >= 1 && outCounts.importedIdentity >= 3, JSON.stringify(outCounts));

    const c = await makeAuth(); // fresh target
    const inCounts = await copyAuthData(exported, c);
    assert.deepEqual(inCounts, outCounts);

    const before = await dumpAll(a);
    const after = await dumpAll(c);
    for (const table of Object.keys(before)) {
      assert.ok(before[table].length === after[table].length, table);
      assert.deepEqual(after[table], before[table], `table ${table} differs after round trip`);
    }

    // Imported hashes survived byte-for-byte and still verify in the new DB.
    assert.match((await storedHash(c, "user1@test.com"))!, /^\$firebase-scrypt\$/);
    assert.equal((await signIn(c, "user1@test.com", "user1password")).status, 200);
    assert.equal((await signIn(c, "ada@example.com", "U*U")).status, 200);
    assert.equal((await signIn(c, "native@example.com", "native-password-1")).status, 200);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
