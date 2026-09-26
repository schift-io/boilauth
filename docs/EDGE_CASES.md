# Edge cases: policy key = wizard question = module switch

Every row has a policy key. The key is the wizard question (`src/wizard/questions.ts`,
one question per key), the field in `boilauth.answers.json`, and the switch that decides
which code `boilauth init` generates. Default in **bold**. Behaviour details live in
`spec/boilauth.pseudo.md` under the id in the last column.

Only options verified against Better Auth 1.7.6 source and covered by a generated-project
test are offered. What is left out, and why, is at the end.

## A. Runtime

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Where users live | `runtime.database` | **`sqlite`** (node:sqlite) / `postgres` (pg Pool) | config | X1 |

Adapter is Better Auth's built-in Kysely adapter for both (not asked). Language is TypeScript (not asked).

## B. Sign-in methods

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Email + password | `signIn.emailPassword` | **yes** / no | core | P1 L1 R1 |
| Magic link by email | `signIn.magicLink` | yes / **no** | better-auth `magicLink` | B2 |
| OAuth providers | `signIn.oauth` | multi: `google` `github` `apple` `kakao` `naver`, **none** | better-auth `socialProviders` | B3 |

At least one method must be on. Magic link and OAuth sign-ins are outside the TOTP challenge (Better Auth's two-factor hook covers `/sign-in/email`); see H.

## C. Migration source (only with email + password)

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Import users with their hashes | `migration.sources` | multi: `supabase` `firebase` `auth0`, **none** | importers + CLI | I1 M1 |
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
| Session lifetime | `session.days` | number 1..90, **7** | core | S1 |
| Password change | `session.revokeOnPasswordChange` | **yes** (other sessions end) / no | `boilauth/sessions` | S2 |
| Devices | `session.devices` | **`multi`** / `single` (a new sign-in ends the other sessions) | `boilauth/sessions` | S3 |

A fresh session token on every sign-in and ending all sessions on password reset are always on (not asked).

## H. MFA (only with email + password)

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Second factor | `mfa.mode` | **`off`** / `totp_optional` / `totp_required_admin` | better-auth `twoFactor` (+ `boilauth/mfa`) | H1 H2 |

`totp_required_admin` is offered only when roles are on. Admin endpoints then need a session that passed TOTP; an admin without TOTP gets 403 `MFA_REQUIRED`.

## I. Roles

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| Authorization model | `roles.mode` | `none` / **`admin`** (user + admin) / `custom` (role list + permission checks) / `organizations` (orgs, members, invitations, org roles; plus user + admin) | better-auth `admin`, `organization`, access control | G1 G2 G3 |
| Custom role names | `roles.custom` | comma list, **`admin,editor,user`** (must contain `admin` and `user`) | generated `src/permissions.ts` | G2 |
| Who creates organizations | `roles.orgCreation` | **`any_user`** / `admin_only` | better-auth `organization` | G3 |

Stops at roles. No attribute or policy engine.

## J. Account deletion

| Case | Policy key | Choices | Module | Spec |
|---|---|---|---|---|
| User deletes own account | `deletion.mode` | **`hard`** (rows removed, Better Auth `/delete-user`) / `soft` (`deletedAt` set, sessions ended, sign-in refused, `boilauth purge-deleted` removes later) | `boilauth/deletion` | D1 D2 |
| Data export | `deletion.export` | **yes** (`GET /boilauth/export-account`) / no | `boilauth/deletion` | D3 |

## Wizard question order

1. A runtime
2. B sign-in methods
3. C migration (needs email + password)
4. D email verification
5. E linking (needs OAuth)
6. F password (needs email + password)
7. G lockout (needs email + password), rate limit, sessions
8. I roles
9. H MFA (needs email + password; `totp_required_admin` needs roles)
10. J deletion

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
| Passkey | not offered | Lives in the separate `@better-auth/passkey` package; an end-to-end test needs a WebAuthn authenticator emulator we do not have yet. |
| Drizzle / Prisma adapters | not offered | Both need the ORM's own schema generation step; no generated-project test covers it yet. The built-in adapter covers SQLite and Postgres. |
| Python | not offered | Later, per owner. |
| "Rotate session on sign-in" as a choice | always on | Better Auth mints a new token on every sign-in; there is nothing to switch off. |
| OAuth callback against real providers | wired, not exercised | Tests check the authorize redirect (host + client id). Token exchange needs live provider apps. |
