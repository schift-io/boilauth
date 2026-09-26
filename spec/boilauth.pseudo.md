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

## [L3] Send limits — `boilauth/rate-limit` (src/modules/rate-limit.ts)
Engine = Better Auth's limiter; the plugin adds rateLimit rules and is placed first in plugins so its
rules win over magicLink/emailOTP/phoneNumber's own (Better Auth takes the first plugin match).
per IP:      each SEND_PATH, window 3600, max perIpPerHour (Better Auth key = IP + path)
per address: onRequest (after Better Auth's IP check), POST to a SEND_PATH with body.email / body.phoneNumber
             dest = email trimmed+lowercased | phone only when E.164 (malformed is refused before any SMS)
             key = "boilauth-send:" + sha256(dest), one bucket across all send endpoints
             fixed window 3600: row missing -> create count 1; expired -> reset (lastRequest <= seen);
             else incrementOne where lastRequest > now-3600 and count < max; none updated -> 429
             storage follows rateLimit.storage (rateLimit table or process memory)
429 (per address): Retry-After, X-Retry-After, RateLimit-Limit, -Remaining 0, -Reset, -Policy "<max>;w=3600"
429 (Better Auth's own): createBoilAuth wraps handler, copies X-Retry-After into Retry-After
Without the module: core keeps /request-password-reset at 3 per 5 min per IP; other sends keep Better Auth's rules.
The plugin always registers one hour-long rule so Better Auth's row pruning keeps per-address rows for the full hour.

## [L2] Rate limit — Better Auth built-in, preset values in `src/auth.ts`

storage = database (or memory: rateLimit.storage). /sign-in/email 10 per 60 s per IP. /request-password-reset 3 per 300 s
(replaced by the hourly rule when boilauth/rate-limit is on). Every 429 carries Retry-After.
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

## [D4] Deletion guard — `canDelete(user)` from src/deletion-guard.ts
Runs first on every self-service deletion (hard: Better Auth beforeDelete; soft or anonymize:
POST /boilauth/delete-account). {ok:false, code, message} -> 409 {code, message}; nothing changes.

## [D5] Organizations and deletion — `boilauth/deletion` with organizations
for each org where the user holds "owner", no other owner exists and other members remain:
  block -> 409 ORG_OWNER_TRANSFER_REQUIRED
  transfer_to_oldest_admin -> the member with "admin" who joined first becomes "owner"; none -> 409 as above
All orgs are checked before any role changes. The user's member rows are removed (hard: after delete;
soft/anonymize: at deletion). A sole-member org is left with no members.

## [D6] records = anonymize
Final step keeps the user row: sessions ended; account (credential, OAuth), importedIdentity, twoFactor rows
removed; email -> deleted+<id>@deleted.invalid, name "", image/username/displayUsername/phoneNumber null,
emailVerified/phoneNumberVerified/twoFactorEnabled false. hard: immediately via POST /boilauth/delete-account
(Better Auth /delete-user off). soft: purgeDeleted anonymizes instead of removing; already anonymized rows are skipped.
Passwordless users need a session younger than freshAge on /boilauth/delete-account (same rule as /delete-user).

## [S4] Bearer — better-auth `bearer`
Authorization: Bearer <signed session token> is turned into the session cookie for that request;
responses that set the session cookie also send set-auth-token. Unsigned tokens are ignored.

## [G4] Admin route hiding
/admin/* for a caller without an admin role (or without a session) -> 404 before the admin plugin runs.
Admins pass through (boilauth/mfa may still answer 403 MFA_REQUIRED).

## [X3] Schema modules
core always ; admin (roles != none) ; two-factor (mfa != off) ; mfa-admin (totp_required_admin) ;
organization (roles = organizations) ; soft-delete (deletion = soft).
Each has schema/<module>.v<N>.json = its delta over its base; migrate(auth) rewrites boilauthModule rows.

## [B4] One-time code by email — better-auth `emailOTP`
emailOTP({ otpLength 6, expiresIn 300, allowedAttempts 3, storeOTP "hashed", sendVerificationOTP -> d.email }).
POST /email-otp/send-verification-otp {email, type: sign-in} then POST /sign-in/email-otp {email, otp}.
A code works once; after 3 wrong codes it is spent (403 TOO_MANY_ATTEMPTS). No second step: an admin
under totp_required_admin reaching /admin/* from such a session gets 403 MFA_REQUIRED [H2].

## [H3] Backup codes — better-auth `twoFactor` backupCodeOptions.amount (10 = Better Auth default, not emitted)
/two-factor/enable returns the codes; POST /two-factor/verify-backup-code spends one. Satisfies [H2].

## [H4] Email code as second step — better-auth `twoFactor` otpOptions
otpOptions { digits 6, period 5 min, allowedAttempts 3, storeOTP hashed, sendOTP -> d.email }.
POST /two-factor/send-otp then /two-factor/verify-otp. Not in boilauth/mfa VERIFY_PATHS on purpose:
an email code does not satisfy [H2].

## [B5] Phone numbers — `src/modules/phone.ts`, better-auth `phoneNumber`
createBoilAuth({ phone: { sendSms } }) -> phoneNumber({ otpLength 6, expiresIn 300, allowedAttempts 3,
  requireVerification true, phoneNumberValidator E.164, sendOTP -> sendSms }).
Attach: signed in, POST /phone-number/send-otp then /phone-number/verify {updatePhoneNumber: true}.
Sign in: /phone-number/verify for a known number (no second step, like magic link), or
/sign-in/phone-number {phoneNumber, password} (TOTP [H1], lockout [L1], rehash [R1], rate limit [L2]).
Schema module `phone-number` adds user.phoneNumber (unique) and user.phoneNumberVerified.

## [U1] Username sign-in — `src/modules/username.ts`, better-auth `username`
Rules live in boilauth.username.yaml (written once by init, then the developer's):
minLength, maxLength, pattern (whole-name regex), reserved (case-insensitive), caseInsensitive, immutable.
loadUsernameRules() parses with `yaml` and checks with zod at startup; a bad key stops startup, named.
createBoilAuth({ username }) adds username({ min/maxUsernameLength, usernameValidator = pattern && !reserved,
  usernameNormalization = caseInsensitive ? lower : none, immutableUsername }).
Lockout [L1], rehash [R1] and the sign-in rate limit [L2] cover POST /sign-in/username too; the account is
found by the normalized username. TOTP [H1] covers it through Better Auth's own two-factor hook.
Schema module `username` adds user.username (unique) and user.displayUsername.

## [W1] Situation: existing users — `src/wizard/answers.ts` situationDefaults()
Applied only to keys the developer has not answered; every policy question is still asked.
existingUsers and currentSignIn non-empty -> signIn.emailPassword/magicLink/oauth = currentSignIn
existingUsers and currentSignIn has email_password -> ask migration.sources (generic = own CSV/JSON)
existingUsers and sourceVerifiedEmail = no -> email.verification = optional
Import keeps each row's own verified flag either way; merges still need verified on both sides [M1].

## [W2] Situation: audience
b2c -> roles.mode admin (kakao, naver are extras: listed last, never preselected)
b2b -> roles.mode organizations (orgCreation any_user)
internal -> roles.mode admin, mfa.mode totp_required_admin
init --yes = no existing users + b2c = the plain defaults.

## [N1] Client IP — `src/modules/client-ip.ts`
socket (default): ip = the address the server adapter passes (auth.handler(req, { clientIp })); forwarded headers ignored.
proxy: chain = X-Forwarded-For + socket; from the right, skip hops in trustedProxies; first other hop = client; garbage -> null.
header: ip = first value of the named header (platform overwrites it).
The wrapper deletes any client-sent x-boilauth-client-ip, sets it to the resolved ip, and Better Auth reads only that header
(ipv6Subnet 64). boilauth's own counters key on ipKey(ip) (IPv6 -> /64). Production + no ip -> 500 CLIENT_IP_UNAVAILABLE.
