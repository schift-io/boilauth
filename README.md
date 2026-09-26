# boilauth

Part of [Schift](https://schift.io)'s boil series, alongside [boilpayment](https://github.com/schift-io/boilpayment).

Email/password auth that runs in **your** database, with a migration path in.
Bring your users from Supabase, Firebase, Auth0 or your own export **with their existing password
hashes** — they log in with the password they already have, and the hash is
upgraded to argon2id on that first login.

- Engine: [Better Auth](https://better-auth.com) (sessions, cookies, origin checks, DB adapters).
  boilauth does not implement its own auth crypto; it composes argon2id
  (`@node-rs/argon2`), bcrypt (`bcryptjs`) and Node's built-in scrypt/AES.
- Status: **0.2.0, pre-release.** Not published to npm yet.
- License: MIT.

## 5-minute start

Requires Node 22.5+ (for built-in `node:sqlite`).

```bash
npm install boilauth          # after first release; until then: npm install <path-or-git-url>
npx boilauth init             # asks about your situation, then the policy questions below
npm install
cp .env.example .env          # set BOILAUTH_SECRET=$(openssl rand -base64 32)
npm test                      # the generated tests for exactly the options you chose
npx boilauth migrate          # creates tables and records the schema modules
```

`init --yes` takes every default without asking (no existing users, consumer app). Answers are saved to
`boilauth.answers.json`; running `init` again asks only for keys missing from
that file and regenerates the same code. Change one answer with
`npx boilauth init --yes --set roles.mode=organizations`.

Mount the generated instance in your server. It is a normal Better Auth instance:

```ts
import auth from "./boilauth.config.js";
import { toNodeHandler } from "better-auth/node";
import express from "express";

const app = express();
app.all("/api/auth/*splat", toNodeHandler(auth));   // sign-up, sign-in, session, admin …
app.listen(3000);
```

## The wizard

Each question is one policy key. The key is the answers-file field and the switch
that decides which code is generated; the full table with every case, choice and
module is [`docs/EDGE_CASES.md`](docs/EDGE_CASES.md). Defaults in bold.

The wizard starts with your situation. Those answers generate nothing on their own;
they set the defaults of the policy questions, which are all still asked.

| # | Policy key | Choices | Sets the default of |
|---|---|---|---|
| 0 | `situation.existingUsers` | yes / **no** | whether the next three are asked |
| 0 | `situation.currentSignIn` | email_password, magic_link, google, github, apple, kakao, naver (**email_password**) | `signIn.*`: keep today's methods |
| 0 | `migration.sources` | supabase, firebase, auth0, generic (**none**; asked with email + password) | which importers and tests are generated |
| 0 | `situation.sourceVerifiedEmail` | **yes** / no | no: `email.verification` = optional |
| 0 | `situation.audience` | **b2c** / b2b / internal | b2b: organizations; internal: admin + TOTP for admins; b2c: user + admin |

| # | Policy key | Choices |
|---|---|---|
| A | `runtime.database` | **sqlite** / postgres |
| B | `signIn.emailPassword` | **yes** / no |
| B | `signIn.magicLink` | yes / **no** |
| B | `signIn.oauth` | google, github, apple, kakao, naver (**none**) |
| C | `migration.firebase.keyId`, `.saltSeparator`, `.rounds`, `.memCost` | **firebase**, **Bw==**, **8**, **14** (asked only with firebase) |
| D | `email.verification` | **required** / optional |
| E | `linking.mode` | **verified_only** / never (asked only with OAuth) |
| F | `password.minLength` | **10** (8..64) |
| F | `password.breachedCheck` | **off** / hibp |
| G | `lockout.maxFailures`, `lockout.minutes` | **5**, **15** (0 = off) |
| G | `rateLimit.signInPerMinute` | **10** |
| G | `session.days` | **7** (1..90) |
| G | `session.revokeOnPasswordChange` | **yes** / no |
| G | `session.devices` | **multi** / single |
| I | `roles.mode` | none / **admin** / custom / organizations |
| I | `roles.custom` | **admin,editor,user** (asked with custom) |
| I | `roles.orgCreation` | **any_user** / admin_only (asked with organizations) |
| H | `mfa.mode` | **off** / totp_optional / totp_required_admin (the last needs roles) |
| J | `deletion.mode` | **hard** / soft |
| J | `deletion.export` | **yes** / no |

What `init` writes:

| File | Rewritten by init | Contents |
|---|---|---|
| `src/auth.ts` | yes | `createAuth()` importing only the modules your answers turned on |
| `boilauth.config.ts` | yes | the instance: database, secret, OAuth credentials from env |
| `test/boilauth.test.ts`, `test/helpers.ts` | yes | one test block per answered policy (lockout, rate limit, TOTP, org invitations, soft delete …) |
| `.env.example` | yes | only the variables your answers need |
| `src/email.ts` | once | your mail sender (logs in development) |
| `src/permissions.ts` | once | custom roles and their permissions (roles = custom) |
| `package.json`, `tsconfig.json` | once | |

Generated tests run offline: Have I Been Pwned and the Google token endpoint are
mocked, TOTP codes are computed in the test. With Postgres they need
`TEST_DATABASE_URL` pointing at an empty scratch database (each run makes and
drops its own schema) and are reported as skipped without it.

Not offered yet: passkeys (separate `@better-auth/passkey` package; no WebAuthn
authenticator emulator in the tests yet), Drizzle and Prisma adapters (their own
schema generation step is not covered), Python. OAuth callbacks are exercised for
Google with a mocked token endpoint; the other providers are checked up to the
authorize redirect.

Better Auth 1.7.6 plugins the wizard does not offer yet (each needs a generated-project
test before it becomes a choice): `username`, `phone-number`, `email-otp`, two-factor
email/SMS OTP and backup codes, `anonymous`, `bearer`, `jwt`, API keys, `one-time-token`,
`multi-session`, `captcha`, `one-tap`, `siwe`, `device-authorization`, `generic-oauth`
(any OIDC provider), `last-login-method`, `custom-session`, `additional-fields`,
`oauth-proxy`, and the separate passkey and SSO packages. You can still add any of them
to the generated `src/auth.ts` by hand; it is a normal Better Auth config.

## What the presets are

| Area | Default | Where |
|---|---|---|
| New password hashes | argon2id, m=19456 KiB, t=2, p=1 (OWASP minimum) | `createPasswordHasher` |
| Password length | 10–128 | `PRESETS` |
| Per-account lockout | 5 consecutive failures → locked 15 min. Locked looks exactly like a wrong password (same 401, password not checked). | `boilauthPlugin` |
| Per-IP rate limit | on, stored in the DB. `/sign-in/email` 10/min, `/request-password-reset` 3/5 min; Better Auth's 3/10 s on sign-up / change-password / change-email | `PRESETS.rateLimit` |
| Sessions | 7 days, expiry refreshed at most daily, "fresh" = 10 min, all sessions revoked on password reset, new token on every sign-in | `PRESETS.session` |
| Role change | all of the user's sessions are deleted | `grantRole` |
| Account linking | OAuth linking only onto a locally verified email (Better Auth `requireLocalEmailVerified`) | `createBoilAuth` |

**Set the client IP source before production.** Better Auth reads the client IP
from `x-forwarded-for` only. If no usable header arrives (e.g. a bare Node server
with no proxy), every client shares one rate-limit bucket per path, so 10 sign-ins
per minute would be the limit for *everyone*. Behind a proxy, pass
`trustedProxies: ["10.0.0.0/8", …]`; with a different header, set
`betterAuth: { advanced: { ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] } } }`.
Every Better Auth option can still be overridden through `betterAuth: {...}`.

## Migration guides

Each import is idempotent (re-running skips `(source, sourceId)` pairs already
imported) and prints a report of created / merged / skipped rows.

### Supabase

Export `auth.users` (SQL editor → run, then download as CSV or JSON):

```sql
select id, email, encrypted_password, email_confirmed_at, raw_user_meta_data, created_at
from auth.users;
```

```bash
npx boilauth import supabase users.csv      # or users.json
```

`encrypted_password` is bcrypt (`$2a$10$…`). Users without one (OAuth-only) are
created without a password and can use password reset.

### Firebase

1. `firebase auth:export users.json --format=json --project <id>`
2. Console → Authentication → Users → ⋮ → **Password hash parameters**. Put them in
   the config; keep the signer key in an env var:

```js
firebaseKeys: [{
  keyId: "my-firebase-project",               // any id; stored with each imported hash
  signerKey: process.env.FIREBASE_SIGNER_KEY, // never written to the database
  saltSeparator: "Bw==", rounds: 8, memCost: 14,
}],
```

```bash
npx boilauth import firebase users.json --key-id my-firebase-project
```

Keep that `firebaseKeys` entry for as long as any user still has an un-upgraded
Firebase hash: verification needs the signer key. Both `.json` and `.csv` exports work.

### Auth0

Password hashes are not in the Management API; Auth0 provides them through a
support request as NDJSON. boilauth reads `_id.$oid` (or `user_id`), `email`,
`email_verified`, `passwordHash` (or `password_hash`), bcrypt only.

```bash
npx boilauth import auth0 auth0-export.json
```

Rows whose hash is not bcrypt are reported as `unsupported_hash` and not imported.
The field names come from Better Auth's Auth0 guide and the common export shape;
check them against your actual export file before a production run.

### Your own export (generic)

For any other system: export a CSV with a header row, a JSON array or NDJSON with
the columns `id`, `email`, `email_verified`, `password_hash`, `name`, `created_at`.
`password_hash` may be bcrypt (`$2a$`/`$2b$`/`$2y$`) or argon2id (`$argon2id$`), or
empty; users without one are created without a password and can use password reset.

```bash
npx boilauth import generic users.csv
```

Other hash formats are reported as `unsupported_hash` and not imported.

### Account merge rule

If an imported email already exists, the records are merged **only when both
the existing user and the imported record have a verified email**. Otherwise the
row is reported as `email_conflict_unverified` and nothing is written. On merge,
an existing password is kept; if the existing user has none, the imported hash is
attached. The same person imported from two sources ends up as one user with two
`importedIdentity` rows.

### Roles

```bash
npx boilauth grant-role ops@example.com admin
```

Uses Better Auth's admin-plugin `role` column, so the admin endpoints see it.

## Schema version contract

The schema is versioned per module. `core` is always there; each option that adds
tables or columns is its own module with a pinned file:

| Module | On when | File |
|---|---|---|
| core | always | [`schema/core.v1.json`](schema/core.v1.json) |
| admin | roles is admin, custom or organizations | [`schema/admin.v1.json`](schema/admin.v1.json) |
| two-factor | mfa is not off | [`schema/two-factor.v1.json`](schema/two-factor.v1.json) |
| mfa-admin | mfa = totp_required_admin | [`schema/mfa-admin.v1.json`](schema/mfa-admin.v1.json) |
| organization | roles = organizations | [`schema/organization.v1.json`](schema/organization.v1.json) |
| soft-delete | deletion = soft | [`schema/soft-delete.v1.json`](schema/soft-delete.v1.json) |

`migrate` writes the enabled modules and versions into the `boilauthModule` table,
so anything reading your auth database learns the shape from the database itself.
A test fails if any module's live columns drift from its file.

- Column types are limited to string / number / boolean / date, so the whole DB
  exports to SQLite as is:
  `npx boilauth export-sqlite backup.db` and `npx boilauth import-sqlite backup.db`.
  The test suite runs export → re-import and compares every row.
- Changing a module's columns bumps that module's version and ships
  `schema/<module>.v<N>.json` with a migration note.

## Security model

- You run it. Your database holds the users, hashes and sessions.
- Imported hashes are only as strong as the source until the user's first login
  here; after that they are argon2id. Firebase signer keys stay in your config/env.
- Lockout and rate limit are both on by default; lockout does not reveal whether
  an email exists. Known limit: the lockout counter is read-modify-write, so a burst
  of parallel wrong guesses can count as fewer; the IP rate limit bounds that burst.
- Security advisories: `npx boilauth check-updates --feed <url>` fetches an
  advisory JSON and compares versions locally. It runs only when you invoke it
  (or set `BOILAUTH_UPDATE_CHECK=1` and `BOILAUTH_ADVISORY_URL`) and sends nothing
  but the GET. A hosted feed is on the roadmap; for now you supply the URL.
- Report vulnerabilities privately through GitHub security advisories; see
  [SECURITY.md](SECURITY.md).

## Tests

```bash
npm test                                           # SQLite, in-memory; also generates 6 projects and runs their tests
BOILAUTH_PG_URL=postgres://… npm test              # also runs the Postgres paths (empty scratch DB)
```

Hash fixtures are published vectors only (pyca/bcrypt, firebase/scrypt README);
see [`fixtures/README.md`](fixtures/README.md). Behaviour spec:
[`spec/boilauth.pseudo.md`](spec/boilauth.pseudo.md).

## Roadmap (not built)

- Hosted advisory feed and dashboard
- Other source formats (Clerk, Cognito, Auth0 custom hashes, PBKDF2/SHA variants)
- Passkeys, Drizzle / Prisma adapters
- Python package
