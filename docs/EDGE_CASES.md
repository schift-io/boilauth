# Edge cases: policy key = wizard question = module switch

Every row has a policy key. The key is the wizard question (`src/wizard/questions.ts`,
one question per key), the field in `boilauth.answers.json`, and the switch that decides
which code `boilauth init` generates. Default in **bold**. Behaviour details live in
`spec/boilauth.pseudo.md` under the id in the last column.

Only options verified against Better Auth 1.7.6 source and covered by a generated-project
test are offered. What is left out, and why, is at the end.

## 0. Your situation (asked first)

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Users already exist elsewhere | `situation.existingUsers` | yes / **no** | wizard defaults | W1 |
| How they sign in today | `situation.currentSignIn` | multi: `email_password` `magic_link` `google` `github` `apple` `kakao` `naver`, **`email_password`** | wizard defaults | W1 |
| Did the old system verify emails | `situation.sourceVerifiedEmail` | **`yes`** / `no` (or not sure) | wizard defaults | W1 |
| Who the app is for | `situation.audience` | **`b2c`** / `b2b` / `internal` | wizard defaults | W2 |

These answers generate no code of their own. They set the defaults of the questions below,
which are still asked:

| Answer | Default it sets |
|---|---|
| existing users + how they sign in | `signIn.emailPassword`, `signIn.magicLink`, `signIn.oauth` = the methods they use today |
| existing users + email + password | `migration.sources` is asked here ("where are they now") |
| existing users + old system did not verify | `email.verification` = `optional`, so imported users are not met by a 403 on their next sign-in |
| `b2c` | `roles.mode` = `admin` |
| `b2b` | `roles.mode` = `organizations` (`roles.orgCreation` = `any_user`) |
| `internal` | `roles.mode` = `admin`, `mfa.mode` = `totp_required_admin` |

`init --yes` answers: no existing users, `b2c`.

## A. Runtime

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Where users live | `runtime.database` | **`sqlite`** (node:sqlite) / `postgres` (pg Pool) | config | X1 |
| Which client IP per-IP controls count | `network.clientIp` | **`socket`** (the connection's address; mount with `boilauth/node` or pass `auth.handler(req, { clientIp })`) / `proxy` (X-Forwarded-For walked from the right past your proxies) / `header` (one header your platform overwrites) | `boilauth/client-ip` | N1 |
| Your proxies | `network.trustedProxies` | comma list of IPs/CIDRs, **none** (asked with proxy) | `boilauth/client-ip` | N1 |
| Platform client-IP header | `network.clientIpHeader` | header name, **`cf-connecting-ip`** (asked with header) | `boilauth/client-ip` | N1 |

Adapter is Better Auth's built-in Kysely adapter for both (not asked). Language is TypeScript (not asked).

Forwarded headers are never trusted from an arbitrary client: before 0.3.0 a rotating `X-Forwarded-For`
bypassed every per-IP limit, and behind an appending proxy all clients shared one bucket (audit F1/F3).
IPv6 clients are counted per /64. In production a request with no resolvable IP is refused with 500
`CLIENT_IP_UNAVAILABLE` rather than pooled with everyone else.

## B. Sign-in methods

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Email + password | `signIn.emailPassword` | **yes** / no | core | P1 L1 R1 |
| Username sign-in (needs email + password) | `signIn.username` | yes / **no**; rules in `boilauth.username.yaml` | better-auth `username` + `boilauth/username` | U1 |
| Magic link by email | `signIn.magicLink` | yes / **no** | better-auth `magicLink` | B2 |
| Phone numbers (attach by SMS code; sign in by SMS code, or number + password) | `signIn.phone` | yes / **no** (E.164 only, 6 digits, 5 minutes, 3 tries, verified numbers only; sender in `src/sms.ts`) | better-auth `phoneNumber` + `boilauth/phone` | B5 |
| One-time code by email | `signIn.emailOtp` | yes / **no** (6 digits, 5 minutes, 3 tries, stored hashed) | better-auth `emailOTP` | B4 |
| OAuth providers | `signIn.oauth` | multi: `google` `github` `apple` `kakao` `naver`, **none** | better-auth `socialProviders` | B3 |

At least one of email + password, magic link, email code or OAuth must be on (phone numbers attach to
accounts made another way). The TOTP challenge covers `/sign-in/email`, `/sign-in/username` and
`/sign-in/phone-number`. Magic link, email-code (B4), SMS-code (B5) and OAuth sign-ins have no second
step, even for a user with TOTP enrolled; they never satisfy `totp_required_admin` (H2). Pick those
methods knowing that.

## C. Migration source (only with existing users who sign in with email + password)

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Import users with their hashes | `migration.sources` | multi: `supabase` `firebase` `auth0` `generic` (your own CSV/JSON: `id,email,email_verified,password_hash,name,created_at`; bcrypt or argon2id), **none** | importers + CLI | I1 M1 |
| Firebase key id | `migration.firebase.keyId` | text, **`firebase`** | config | P2 |
| Firebase salt separator | `migration.firebase.saltSeparator` | text, **`Bw==`** | config | P2 |
| Firebase rounds | `migration.firebase.rounds` | number, **8** | config | P2 |
| Firebase mem cost | `migration.firebase.memCost` | number, **14** | config | P2 |

The Firebase signer key is never an answer; it is read from `FIREBASE_SIGNER_KEY`.

## D. Email verification

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Unverified email signs in with a password | `email.verification` | **`required`** (403 until verified) / `optional` | core | E1 |

Either way a verification mail is sent on sign-up. Import merges always need verified emails on both sides (M1), independent of this key.

## E. Account linking (only with OAuth)

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| OAuth identity with an email that already exists | `linking.mode` | **`verified_only`** (link only when the local user and the provider both say verified) / `never` | core | E2 |

## F. Password policy (only with email + password)

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Minimum length | `password.minLength` | number 8..64, **10** | core | P1 |
| Breached password | `password.breachedCheck` | **`off`** / `hibp` (Have I Been Pwned range API, k-anonymity; sign-up, change, reset) | better-auth `haveIBeenPwned` | F1 |

## G. Lockout, rate limit, sessions

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Consecutive wrong passwords | `lockout.maxFailures` | number, **5** (0 = off) | core | L1 |
| Lock duration | `lockout.minutes` | number, **15** | core | L1 |
| Sign-in attempts per IP | `rateLimit.signInPerMinute` | number, **10** | core | L2 |
| Mail/SMS sends per IP (only with a send endpoint) | `rateLimit.sendPerIpPerHour` | number 0..1000, **10** per hour per send endpoint (0 = Better Auth's per-minute rules) | `boilauth/rate-limit` | L3 |
| Mail/SMS sends per address (only with a send endpoint) | `rateLimit.sendPerAccountPerHour` | number 0..1000, **5** per hour per email or phone number, from any IP (0 = off) | `boilauth/rate-limit` | L3 |
| Where counters live | `rateLimit.storage` | **`database`** (shared by every instance) / `memory` (one process) | core | L2 |
| Session lifetime | `session.days` | number 1..90, **7** | core | S1 |
| Password change | `session.revokeOnPasswordChange` | **yes** (other sessions end) / no | `boilauth/sessions` | S2 |
| Devices | `session.devices` | **`multi`** / `single` (a new sign-in ends the other sessions) | `boilauth/sessions` | S3 |
| Mobile and API clients | `session.bearer` | yes / **no** (also accept `Authorization: Bearer <token>`; sign-in answers with `set-auth-token`) | better-auth `bearer` | S4 |

Send endpoints are `/request-password-reset`, `/send-verification-email`, `/sign-in/magic-link`,
`/email-otp/send-verification-otp`, `/email-otp/request-password-reset`, `/forget-password/email-otp`,
`/phone-number/send-otp` and `/phone-number/request-password-reset`. Every 429 carries `Retry-After`;
the per-address 429 also carries `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` and
`RateLimit-Policy`. With both send limits at 0 (or no send endpoint) `boilauth/rate-limit` is not imported.

A fresh session token on every sign-in and ending all sessions on password reset are always on (not asked).

## H. MFA (only with email + password)

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Second factor | `mfa.mode` | **`off`** / `totp_optional` / `totp_required_admin` | better-auth `twoFactor` (+ `boilauth/mfa`) | H1 H2 |
| Backup codes per user | `mfa.backupCodes` | number 5..20, **10** (each usable once) | better-auth `twoFactor` | H3 |
| Code by email as the second step | `mfa.emailOtp` | yes / **no** (6 digits, 5 minutes, 3 tries, stored hashed) | better-auth `twoFactor` otp | H4 |

An email code (H4) is an alternative second step for normal sign-in only; admin endpoints under
`totp_required_admin` still need TOTP or a backup code. Email-code sign-in (B4), like magic link,
has no second step and never satisfies the admin requirement.

`totp_required_admin` is offered only when roles are on. Admin endpoints then need a session that passed TOTP; an admin without TOTP gets 403 `MFA_REQUIRED`.

## I. Roles

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Authorization model | `roles.mode` | `none` / **`admin`** (user + admin) / `custom` (role list + permission checks) / `organizations` (orgs, members, invitations, org roles; plus user + admin) | better-auth `admin`, `organization`, access control | G1 G2 G3 |
| Custom role names | `roles.custom` | comma list, **`admin,editor,user`** (must contain `admin` and `user`) | generated `src/permissions.ts` | G2 |
| Who creates organizations | `roles.orgCreation` | **`any_user`** / `admin_only` | better-auth `organization` | G3 |
| Non-admins on /admin/* | `roles.hideAdmin` | yes (404, as if the route did not exist) / **no** (401 without a session, 403 without the role) | core | G4 |

Stops at roles. No attribute or policy engine.

## J. Account deletion

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| User deletes own account | `deletion.mode` | **`hard`** (rows removed, Better Auth `/delete-user`) / `soft` (`deletedAt` set, sessions ended, sign-in refused, `boilauth purge-deleted` removes later) | `boilauth/deletion` | D1 D2 |
| Data export | `deletion.export` | **yes** (`GET /boilauth/export-account`) / no | `boilauth/deletion` | D3 |
| App vetoes a deletion | `deletion.guard` | yes (generated `src/deletion-guard.ts`; refusal = 409 with your code) / **no** | `boilauth/deletion` | D4 |
| Last owner of an organization with other members | `deletion.lastOrgOwner` | **`block`** (409 `ORG_OWNER_TRANSFER_REQUIRED`) / `transfer_to_oldest_admin` (refused when there is no admin); asked with organizations | `boilauth/deletion` | D5 |
| Final step for the user row | `deletion.records` | **`delete`** / `anonymize` (row kept with `deleted+<id>@deleted.invalid`, no name, no sign-in links, so payment and audit rows keep a valid user id) | `boilauth/deletion` | D6 |

Every self-service deletion needs the password when the user has one, and a session younger than
`session.freshAge` (10 min) otherwise. With organizations the user leaves every organization; invitations
they sent stay as history.

## Wizard question order

1. 0 situation: existing users, how they sign in, where they are now (C `migration.sources`), verified emails, audience
2. A runtime
3. B sign-in methods
4. C Firebase parameters (needs Firebase)
5. D email verification
6. E linking (needs OAuth)
7. F password (needs email + password)
8. G lockout (needs email + password), rate limit, sessions
9. I roles
10. H MFA (needs email + password; `totp_required_admin` needs roles)
11. J deletion

## Schema per module

Each module that changes tables has its own versioned contract file under `schema/`.
`migrate()` records the enabled modules and versions in the `boilauthModule` table so a
service reading the database knows the shape without guessing.

| Module | Enabled by | File |
|---|---|---|
| `core` | always | `schema/core.v1.json` |
| `admin` | `roles.mode` in admin, custom, organizations | `schema/admin.v1.json` |
| `two-factor` | `mfa.mode` not off | `schema/two-factor.v1.json` |
| `mfa-admin` | `mfa.mode = totp_required_admin` | `schema/mfa-admin.v1.json` |
| `organization` | `roles.mode = organizations` | `schema/organization.v1.json` |
| `soft-delete` | `deletion.mode = soft` | `schema/soft-delete.v1.json` |

## Not offered, and why

| Asked for | Status | Reason |
|---|---|---|
| Passkey | not offered | Lives in the separate `@better-auth/passkey` package. A real test needs a browser WebAuthn authenticator (Playwright + Chromium's virtual authenticator); putting that in every generated project is too heavy, and a repo-only test would break "every choice has a generated-project test". |
| Phone sign-up without an email | not offered | Better Auth's `signUpOnVerification` invents a placeholder email per number; the rest of the kit (verification, import merge, export) keys on real emails. |
| Drizzle / Prisma adapters | not offered | Both need the ORM's own schema generation step; no generated-project test covers it yet. The built-in adapter covers SQLite and Postgres. |
| Python | not offered | Later, per owner. |
| Importing users who only sign in with OAuth or magic link | not offered | The importers bring password hashes. Such users sign in again with the same provider; with `linking.mode = verified_only` a verified email links to an imported row only when one exists. |
| Other hash formats in `generic` (md5, sha1, pbkdf2, scrypt) | not offered | `verify()` checks argon2id, bcrypt and Firebase scrypt only; other rows are reported `unsupported_hash` and those users reset their password. |
| "Rotate session on sign-in" as a choice | always on | Better Auth mints a new token on every sign-in; there is nothing to switch off. |
| OAuth callback against real providers | wired, not exercised | Tests check the authorize redirect (host + client id). Token exchange needs live provider apps. |
