import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MODULE_VERSIONS,
  copyAuthData,
  enabledModules,
  installedModules,
  mergeShapes,
  type SchemaModule,
  describeSchema,
  dumpAll,
  grantRole,
  importUsers,
  nonExportableFields,
  parseFirebaseExport,
  parseSupabaseExport,
} from "../src/index.js";
import { FIREBASE_SAMPLE_KEY, fixture, makeAuth, signIn, storedHash } from "./helpers.js";
import { liveModuleShape } from "./schema-modules.js";

function pinned(m: SchemaModule) {
  return JSON.parse(readFileSync(new URL(`../schema/${m}.v${MODULE_VERSIONS[m]}.json`, import.meta.url), "utf8"));
}

test("every schema module matches its pinned contract file", () => {
  const modules = Object.keys(MODULE_VERSIONS) as SchemaModule[];
  assert.ok(modules.length >= 2, "no modules to check");
  for (const m of modules) {
    const file = pinned(m);
    assert.equal(file.version, MODULE_VERSIONS[m], m);
    const live = liveModuleShape(m);
    assert.ok(Object.keys(live).length > 0, `module ${m} adds nothing`);
    assert.deepEqual(live, file.tables, `schema drift in module ${m}`);
  }
});

test("the default instance (core + admin) is exactly the union of its module files, and migrate records it", async () => {
  const auth = await makeAuth();
  const mods = enabledModules(auth.boilauth.options);
  assert.deepEqual(mods, ["core", "admin"]);
  const live = describeSchema(auth.boilauth.options).tables;
  assert.deepEqual(live, mergeShapes(...mods.map((m) => pinned(m).tables)));
  assert.deepEqual(await installedModules(auth), { core: 2, admin: 1 });
});

test("every column type is SQLite-exportable", async () => {
  const auth = await makeAuth();
  const desc = describeSchema(auth.boilauth.options);
  const cols = Object.values(desc.tables).reduce((n, t) => n + Object.keys(t).length, 0);
  assert.ok(cols > 0, "scanned zero columns");
  assert.deepEqual(nonExportableFields(desc), []);
  const all = mergeShapes(...(Object.keys(MODULE_VERSIONS) as SchemaModule[]).map((m) => pinned(m).tables));
  assert.deepEqual(nonExportableFields({ version: 0, tables: all }), [], "a module adds a non-SQLite type");
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
