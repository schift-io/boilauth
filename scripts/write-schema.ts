// Regenerates schema/<module>.v<N>.json from the live Better Auth shapes.
// Run only when you mean to change the contract, then bump MODULE_VERSIONS.
import { writeFileSync } from "node:fs";
import { MODULE_VERSIONS, type SchemaModule } from "../src/index.js";
import { liveModuleShape } from "../test/schema-modules.js";

for (const m of Object.keys(MODULE_VERSIONS) as SchemaModule[]) {
  const version = MODULE_VERSIONS[m];
  const file = new URL(`../schema/${m}.v${version}.json`, import.meta.url);
  writeFileSync(file, JSON.stringify({ module: m, version, tables: liveModuleShape(m) }, null, 2) + "\n");
  console.log(`wrote schema/${m}.v${version}.json`);
}
