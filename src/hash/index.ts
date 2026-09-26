/**
 * Password hashing front door.
 *
 * - New hashes are always argon2id (OWASP 2024 minimum: m=19 MiB, t=2, p=1).
 * - verify() accepts argon2id, bcrypt ($2a$/$2b$/$2y$ — Supabase, Auth0) and
 *   Firebase modified scrypt ($firebase-scrypt$...). Anything else → false.
 * - needsRehash() tells the sign-in hook to upgrade the stored hash to the
 *   current argon2id preset after a successful login.
 */
import { hash as argonHash, verify as argonVerify, parseOptions } from "@node-rs/argon2";
import bcrypt from "bcryptjs";
import {
  FIREBASE_PREFIX,
  decodeFirebaseHash,
  verifyFirebaseScrypt,
  type FirebaseProjectKey,
} from "./firebase-scrypt.js";

export {
  encodeFirebaseHash,
  decodeFirebaseHash,
  firebaseScryptHash,
  type FirebaseProjectKey,
  type FirebaseHashParams,
} from "./firebase-scrypt.js";

export interface Argon2Params {
  memoryCost: number; // KiB
  timeCost: number;
  parallelism: number;
}

export const ARGON2ID_DEFAULTS: Argon2Params = { memoryCost: 19456, timeCost: 2, parallelism: 1 };

const ARGON2ID = 2; // @node-rs/argon2 Algorithm.Argon2id (const enum, not importable at runtime)

export type HashKind = "argon2id" | "bcrypt" | "firebase-scrypt" | "unknown";

export function hashKind(stored: string): HashKind {
  if (stored.startsWith("$argon2id$")) return "argon2id";
  if (/^\$2[aby]\$\d{2}\$/.test(stored)) return "bcrypt";
  if (stored.startsWith(FIREBASE_PREFIX)) return "firebase-scrypt";
  return "unknown";
}

export interface PasswordHasherOptions {
  argon2?: Partial<Argon2Params>;
  /** Signer keys for imported Firebase projects, looked up by keyId. */
  firebaseKeys?: FirebaseProjectKey[];
}

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(data: { hash: string; password: string }): Promise<boolean>;
  needsRehash(stored: string): boolean;
}

export function createPasswordHasher(opts: PasswordHasherOptions = {}): PasswordHasher {
  const argon: Argon2Params = { ...ARGON2ID_DEFAULTS, ...opts.argon2 };
  const keys = new Map((opts.firebaseKeys ?? []).map((k) => [k.keyId, k]));

  return {
    hash(password) {
      return argonHash(password, { algorithm: ARGON2ID, ...argon });
    },

    async verify({ hash, password }) {
      switch (hashKind(hash)) {
        case "argon2id":
          return argonVerify(hash, password);
        case "bcrypt":
          // bcrypt only reads the first 72 bytes; the original provider had the
          // same limit, so behaviour is identical to the source system.
          return bcrypt.compare(password, hash);
        case "firebase-scrypt": {
          const decoded = decodeFirebaseHash(hash);
          if (!decoded) return false;
          const key = keys.get(decoded.keyId);
          if (!key) {
            throw new Error(
              `boilauth: no Firebase signer key configured for keyId "${decoded.keyId}" (set firebaseKeys)`,
            );
          }
          return verifyFirebaseScrypt(password, decoded.salt, decoded.hash, {
            signerKey: key.signerKey,
            saltSeparator: decoded.saltSeparator,
            rounds: decoded.rounds,
            memCost: decoded.memCost,
          });
        }
        default:
          return false;
      }
    },

    needsRehash(stored) {
      if (hashKind(stored) !== "argon2id") return true;
      try {
        const p = parseOptions(stored);
        return (
          p.memoryCost < argon.memoryCost ||
          p.timeCost < argon.timeCost ||
          p.parallelism < argon.parallelism
        );
      } catch {
        return true;
      }
    },
  };
}
