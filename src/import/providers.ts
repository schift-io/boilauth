/**
 * Export parsers: provider export file → ImportRecord[].
 *
 * Supabase  — rows of auth.users (JSON array, or CSV with a header row).
 *             Hash column `encrypted_password` is bcrypt ($2a$10$...).
 * Firebase  — `firebase auth:export users.json|users.csv`. Hashes are the
 *             project's modified scrypt; you pass the project's hash params.
 * Auth0     — password-hash export (NDJSON or JSON array). bcrypt.
 */
import { encodeFirebaseHash, type FirebaseProjectKey } from "../hash/index.js";
import { csvObjects, parseCsv, toDate, type ImportRecord } from "./common.js";

/** Keep any non-empty hash; importUsers() rejects formats verify() cannot check. */
function hashOrNull(h: unknown): string | null {
  return typeof h === "string" && h.length > 0 ? h : null;
}

function asRows(text: string): unknown[] {
  const t = text.trim();
  if (t.startsWith("[")) return JSON.parse(t);
  if (t.startsWith("{")) {
    // JSON object with a users array, or NDJSON (one object per line).
    try {
      const obj = JSON.parse(t);
      if (Array.isArray(obj.users)) return obj.users;
      return [obj];
    } catch {
      return t.split(/\r?\n/).filter((l) => l.trim()).map((l) => JSON.parse(l));
    }
  }
  return [];
}

// ---------------------------------------------------------------- Supabase
export function parseSupabaseExport(text: string): ImportRecord[] {
  const t = text.trim();
  const rows = (t.startsWith("[") || t.startsWith("{") ? asRows(t) : csvObjects(t)) as Record<string, any>[];
  return rows.map((r) => {
    let meta = r.raw_user_meta_data;
    if (typeof meta === "string" && meta) {
      try {
        meta = JSON.parse(meta);
      } catch {
        meta = {};
      }
    }
    return {
      sourceId: String(r.id),
      email: String(r.email ?? ""),
      emailVerified: Boolean(r.email_confirmed_at),
      name: meta?.full_name ?? meta?.name ?? null,
      passwordHash: hashOrNull(r.encrypted_password),
      createdAt: toDate(r.created_at),
    };
  });
}

// ---------------------------------------------------------------- Firebase
export function parseFirebaseExport(text: string, key: FirebaseProjectKey): ImportRecord[] {
  const t = text.trim();
  let rows: Record<string, any>[];
  if (t.startsWith("{") || t.startsWith("[")) {
    rows = asRows(t) as Record<string, any>[];
  } else {
    // CSV has no header. Column order per firebase/scrypt README & Firebase CLI docs:
    // uid, email, emailVerified, passwordHash, salt, displayName, ...
    rows = parseCsv(t).map((c) => ({
      localId: c[0],
      email: c[1],
      emailVerified: c[2] === "true",
      passwordHash: c[3],
      salt: c[4],
      displayName: c[5],
    }));
  }
  return rows.map((r) => ({
    sourceId: String(r.localId),
    email: String(r.email ?? ""),
    emailVerified: r.emailVerified === true || r.emailVerified === "true",
    name: r.displayName || null,
    passwordHash:
      r.passwordHash && r.salt
        ? encodeFirebaseHash({
            keyId: key.keyId,
            rounds: key.rounds,
            memCost: key.memCost,
            salt: r.salt,
            saltSeparator: key.saltSeparator,
            hash: r.passwordHash,
          })
        : null,
    createdAt: toDate(r.createdAt),
  }));
}

// ---------------------------------------------------------------- Auth0
export function parseAuth0Export(text: string): ImportRecord[] {
  return (asRows(text) as Record<string, any>[]).map((r) => {
    const id = r.user_id ?? r._id?.$oid ?? r._id;
    return {
      sourceId: String(id),
      email: String(r.email ?? ""),
      emailVerified: r.email_verified === true,
      name: r.name ?? null,
      passwordHash: hashOrNull(r.passwordHash ?? r.password_hash),
      createdAt: toDate(r.created_at),
    };
  });
}
