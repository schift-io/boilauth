/**
 * Firebase Auth "modified scrypt" verification.
 *
 * Firebase does not store scrypt(password) directly. Per firebase/scrypt
 * (README "Password Hashing"), the stored hash is:
 *
 *   key  = scrypt(password, salt || saltSeparator, N = 2^memCost, r = rounds, p = 1)
 *   hash = AES-256-CTR(key, iv = 0^16).encrypt(signerKey)
 *
 * We only compose node:crypto primitives here — no custom cipher code.
 * Imported hashes are stored in the account row as
 *
 *   $firebase-scrypt$v=1$k=<keyId>,r=<rounds>,m=<memCost>$<salt b64>$<sep b64>$<hash b64>
 *
 * The signer key itself never goes into the database; it is looked up by
 * keyId from the kit config at verify time (see FirebaseProjectKey).
 */
import { createCipheriv, scrypt as scryptCb, timingSafeEqual } from "node:crypto";

export const FIREBASE_PREFIX = "$firebase-scrypt$";

export interface FirebaseHashParams {
  /** Project-level params from Firebase console → Authentication → Password hash parameters. */
  signerKey: string; // base64
  saltSeparator: string; // base64
  rounds: number;
  memCost: number;
}

export interface FirebaseProjectKey extends FirebaseHashParams {
  /** Short id you choose, e.g. the Firebase project id. Stored in each hash row. */
  keyId: string;
}

function b64(s: string): Buffer {
  // Firebase CLI exports standard base64; tolerate url-safe too.
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function scrypt(password: Buffer, salt: Buffer, N: number, r: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, 32, { N, r, p: 1, maxmem: 256 * N * r + 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key),
    );
  });
}

/** Compute the Firebase hash (base64) for a password. Used for verification only. */
export async function firebaseScryptHash(
  password: string,
  saltB64: string,
  params: FirebaseHashParams,
): Promise<Buffer> {
  if (!Number.isInteger(params.rounds) || params.rounds < 1 || params.rounds > 64) {
    throw new Error("firebase-scrypt: rounds out of range");
  }
  if (!Number.isInteger(params.memCost) || params.memCost < 1 || params.memCost > 20) {
    throw new Error("firebase-scrypt: memCost out of range");
  }
  const salt = Buffer.concat([b64(saltB64), b64(params.saltSeparator)]);
  const key = await scrypt(Buffer.from(password, "utf8"), salt, 2 ** params.memCost, params.rounds);
  const cipher = createCipheriv("aes-256-ctr", key, Buffer.alloc(16, 0));
  return Buffer.concat([cipher.update(b64(params.signerKey)), cipher.final()]);
}

export async function verifyFirebaseScrypt(
  password: string,
  saltB64: string,
  expectedHashB64: string,
  params: FirebaseHashParams,
): Promise<boolean> {
  const actual = await firebaseScryptHash(password, saltB64, params);
  const expected = b64(expectedHashB64);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export interface EncodedFirebaseHash {
  keyId: string;
  rounds: number;
  memCost: number;
  salt: string;
  saltSeparator: string;
  hash: string;
}

const SAFE = /^[A-Za-z0-9+/=_-]*$/;

export function encodeFirebaseHash(e: EncodedFirebaseHash): string {
  for (const v of [e.keyId, e.salt, e.saltSeparator, e.hash]) {
    if (!SAFE.test(v) || v.includes("$") || v.includes(",")) {
      throw new Error("firebase-scrypt: invalid character in hash field");
    }
  }
  return `${FIREBASE_PREFIX}v=1$k=${e.keyId},r=${e.rounds},m=${e.memCost}$${e.salt}$${e.saltSeparator}$${e.hash}`;
}

export function decodeFirebaseHash(stored: string): EncodedFirebaseHash | null {
  if (!stored.startsWith(FIREBASE_PREFIX)) return null;
  const parts = stored.slice(FIREBASE_PREFIX.length).split("$");
  if (parts.length !== 5 || parts[0] !== "v=1") return null;
  const kv = Object.fromEntries(parts[1].split(",").map((p) => p.split("=", 2) as [string, string]));
  const rounds = Number(kv.r);
  const memCost = Number(kv.m);
  if (!kv.k || !Number.isInteger(rounds) || !Number.isInteger(memCost)) return null;
  return { keyId: kv.k, rounds, memCost, salt: parts[2], saltSeparator: parts[3], hash: parts[4] };
}
