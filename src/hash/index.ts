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

const ARGON2ID_ENCODING = /^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$/;
const BCRYPT_ENCODING = /^\$2[aby]\$(?:0[4-9]|[12]\d|3[01])\$[./A-Za-z0-9]{53}$/;

export function hashKind(stored: string): HashKind {
  if (ARGON2ID_ENCODING.test(stored)) {
    try {
      parseOptions(stored);
      return "argon2id";
    } catch {
      return "unknown";
    }
  }
  if (BCRYPT_ENCODING.test(stored)) return "bcrypt";
  if (stored.startsWith(FIREBASE_PREFIX) && decodeFirebaseHash(stored)) return "firebase-scrypt";
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
        case "argon2id": {
          try {
            return await argonVerify(hash, password);
          } catch {
            return false;
          }
        }
        case "bcrypt": {
          // bcrypt only reads the first 72 bytes; the original provider had the
          // same limit, so behaviour is identical to the source system.
          try {
            return await bcrypt.compare(password, hash);
          } catch {
            return false;
          }
        }
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
