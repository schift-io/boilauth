/**
 * boilauth — migration-friendly auth kit on Better Auth.
 *
 * Public surface. Import from "boilauth" only; internal module paths are not
 * part of the contract and may move between minor versions.
 */
export { createBoilAuth, boilAuthOptions, PRESETS, type BoilAuth, type BoilAuthOptions, type EmailMessage } from "./auth.js";
export {
  createPasswordHasher,
  hashKind,
  ARGON2ID_DEFAULTS,
  encodeFirebaseHash,
  decodeFirebaseHash,
  type PasswordHasher,
  type FirebaseProjectKey,
  type HashKind,
} from "./hash/index.js";
export { importUsers, type ImportRecord, type ImportReport, type ImportSource } from "./import/common.js";
export { parseSupabaseExport, parseFirebaseExport, parseAuth0Export } from "./import/providers.js";
export { grantRole } from "./roles.js";
export {
  SCHEMA_VERSION,
  MODULE_VERSIONS,
  enabledModules,
  installedModules,
  schemaDelta,
  mergeShapes,
  type SchemaModule,
  type TableShape,
  describeSchema,
  nonExportableFields,
  migrate,
  copyAuthData,
  dumpAll,
} from "./schema.js";
export { checkAdvisories, checkAdvisoriesIfOptedIn, isAffected, type Advisory } from "./update-check.js";
