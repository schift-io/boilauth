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

## [X1] Schema contract — `src/schema.ts`, `schema/<module>.v<N>.json`

Versioned per module (see [X3]); MODULE_VERSIONS holds the numbers. Column types limited to
string|number|boolean|date. Each module's live delta must equal its file (test). Changing a module's
columns bumps its version and adds schema/<module>.v<N+1>.json + a migration note.

## [X2] Export / re-import

copyAuthData(from, to): all tables except rateLimit, in foreign-key order, ids preserved.
export-sqlite refuses to overwrite an existing file.

## [U1] Advisory check

Only on explicit call or BOILAUTH_UPDATE_CHECK=1 + BOILAUTH_ADVISORY_URL. GET only, no payload.
Version comparison is local. Exit 2 from the CLI when a high/critical advisory matches.

---

# Wizard modules (0.2). Policy keys in docs/EDGE_CASES.md point here.

## [B2] Magic link — better-auth `magicLink`
POST /sign-in/magic-link {email} -> mail with /magic-link/verify?token ; GET it -> session. Token single use.

## [B3] OAuth — better-auth `socialProviders` (google, github, apple, kakao, naver)
POST /sign-in/social {provider} -> authorize URL of that provider with our client_id.
Callback exchanges the code; Google's id_token claims give email + email_verified.
Apple also needs trustedOrigins += https://appleid.apple.com (generated).

## [E1] Email verification
required: password sign-in before verifying -> 403 EMAIL_NOT_VERIFIED. optional: 200.
Both: verification mail on sign-up.

## [E2] Account linking
verified_only: accountLinking.enabled, requireLocalEmailVerified -> an OAuth identity joins an existing
user only when the local user is verified and the provider says verified.
never: accountLinking.enabled = false -> the callback refuses (no account row added).

## [F1] Breached passwords — better-auth `haveIBeenPwned`
SHA-1 prefix (5 hex) sent to api.pwnedpasswords.com/range; match -> 400 PASSWORD_COMPROMISED.
Paths: sign-up, change-password, reset-password (and admin create/set-password).

## [S2] Revoke on password change — `boilauth/sessions`
before /change-password: body.revokeOtherSessions = true (server-side, whatever the client sent).

## [S3] Single device — `boilauth/sessions`
after any request that set ctx.context.newSession: delete the user's other sessions.
Runs after twoFactor's after-hook (plugin order), so a pending 2FA sign-in ends nothing.

## [H1] TOTP — better-auth `twoFactor`
/two-factor/enable {password} -> totpURI ; /two-factor/verify-totp {code} activates.
Password sign-in of an enrolled user -> {twoFactorRedirect: true}, no session until verify-totp.
Magic link and OAuth sign-ins are outside this challenge (Better Auth hooks /sign-in/email only).

## [H2] TOTP required for admins — `boilauth/mfa`
after verify-totp / verify-backup-code: session.mfaVerifiedAt = now (new session or current one).
before /admin/*: role in adminRoles AND (not twoFactorEnabled OR session.mfaVerifiedAt empty) -> 403 MFA_REQUIRED.
So a magic-link or OAuth session never reaches admin endpoints.

## [G2] Custom roles — better-auth access control
generated src/permissions.ts: statement = admin defaults + project[create,read,update,delete];
admin = all, user = project.read, every other listed role = project.read+update (edit the file).
admin({ ac, roles, adminRoles:[admin], defaultRole:user }).

## [G3] Organizations — better-auth `organization`
create (any_user | admin_only via allowUserToCreateOrganization) ; invite -> mail with /accept-invitation/<id> ;
accept -> member. Org roles owner/admin/member (plugin defaults); members cannot invite.

## [D1] Hard delete: user.deleteUser.enabled = true (POST /delete-user, password or fresh session).
## [D2] Soft delete — `boilauth/deletion`
POST /boilauth/delete-account {password if the user has one}: user.deletedAt = now, delete all sessions.
db hook session.create.before: user.deletedAt set -> refuse (covers every sign-in method).
Uses the transaction-bound adapter (getCurrentAdapter); a plain adapter call deadlocks single-connection SQLite.
purgeDeleted(days): hard-delete users with deletedAt < now - days. /delete-user stays off.
## [D3] Export: GET /boilauth/export-account (session) -> user, accounts (provider ids only),
sessions (times, ip, user agent; no tokens), imported identities. No hashes.

## [X3] Schema modules
core always ; admin (roles != none) ; two-factor (mfa != off) ; mfa-admin (totp_required_admin) ;
organization (roles = organizations) ; soft-delete (deletion = soft).
Each has schema/<module>.v<N>.json = its delta over its base; migrate(auth) rewrites boilauthModule rows.
