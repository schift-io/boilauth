# boilauth — behaviour spec (source of truth)

Code cites these ids. A behaviour change starts here, then code, then test.

## [P1] Password verify dispatch — `src/hash/index.ts`

```
verify(stored, password):
  match prefix(stored):
    "$argon2id$"          -> argon2.verify(stored, password)
    "$2a$" | "$2b$" | "$2y$" -> bcrypt.compare(password, stored)      # Supabase, Auth0
    "$firebase-scrypt$"   -> key = firebaseKeys[stored.keyId] or THROW (misconfig, not "wrong password")
                             firebase_scrypt(password, stored.salt, stored.sep, stored.r, stored.m, key.signerKey)
                               == stored.hash   (constant-time)
    else                  -> false
hash(password) -> argon2id(m=19456 KiB, t=2, p=1)
needsRehash(stored) -> not argon2id OR any param below preset
```

## [P2] Firebase modified scrypt — `src/hash/firebase-scrypt.ts`

```
key  = scrypt(password, b64d(salt) || b64d(sep), N=2^memCost, r=rounds, p=1, dkLen=32)
hash = AES-256-CTR(key, iv=0^16).encrypt(b64d(signerKey))
stored row = "$firebase-scrypt$v=1$k=<keyId>,r=<rounds>,m=<memCost>$<salt>$<sep>$<hash>"
```
Signer key is never written to the DB. Vector: firebase/scrypt README sample.

## [L1] Lockout — `src/plugin.ts` (before/after hooks on POST /sign-in/email)

```
before: user = find(email); if user.lockedUntil > now: spend one hash; return 401 INVALID_EMAIL_OR_PASSWORD
after success: reset failedLoginCount, lockedUntil; [R1]
after 401 for an existing user (not already locked):
  n = failedLoginCount + 1
  if n >= maxFailures(5): lockedUntil = now + lockMinutes(15); failedLoginCount = 0
  else failedLoginCount = n
```
Known limit: counter is read-modify-write (parallel failures may under-count). IP rate limit [L2] bounds bursts.

## [L2] Rate limit — Better Auth built-in, preset values in `src/auth.ts`

storage = database. /sign-in/email 10 per 60 s per IP. /request-password-reset 3 per 300 s.
Better Auth's built-in 3 per 10 s stays for /sign-up*, /change-password*, /change-email*.

## [R1] Transparent rehash

After a successful sign-in, if needsRehash(account.password): account.password = hash(body.password).
Failed sign-ins never touch the hash.

## [S1] Sessions

expiresIn 7 d, updateAge 1 d, freshAge 10 min, revokeSessionsOnPasswordReset = true.
A new token is minted on every sign-in (Better Auth). Role change deletes all of the user's sessions [G1].

## [I1] Import — `src/import/common.ts`

```
for rec in records:
  if no email                      -> skipped(no_email)
  if rec.hash and kind == unknown  -> skipped(unsupported_hash)
  if importedIdentity(source, rec.sourceId) exists -> skipped(already_imported)   # idempotent
  existing = user by lower(email)
  if none: create user (+ credential account if hash) ; record identity -> created
  elif existing.emailVerified AND rec.emailVerified:                          [M1]
       if existing has password -> keep it ; elif rec.hash -> attach
       record identity -> merged
  else -> skipped(email_conflict_unverified), nothing written
```

## [M1] Merge only between verified emails

An unverified row is not proof of mailbox ownership. Merging it would hand one party's
account to whoever registered the address first (account pre-hijacking).

## [G1] Role grant — `src/roles.ts`

role matches ^[a-z][a-z0-9_-]{0,31}$ ; update user.role ; delete all sessions of user.

## [X1] Schema contract — `src/schema.ts`, `schema/v1.json`

SCHEMA_VERSION = 1. Column types limited to string|number|boolean|date.
describeSchema(live) must equal schema/v<SCHEMA_VERSION>.json (test). A change to the
column set bumps SCHEMA_VERSION and adds schema/v<N+1>.json + a migration note.

## [X2] Export / re-import

copyAuthData(from, to): all tables except rateLimit, in foreign-key order, ids preserved.
export-sqlite refuses to overwrite an existing file.

## [U1] Advisory check

Only on explicit call or BOILAUTH_UPDATE_CHECK=1 + BOILAUTH_ADVISORY_URL. GET only, no payload.
Version comparison is local. Exit 2 from the CLI when a high/critical advisory matches.
