# boilauth

Email/password auth that runs in **your** database, with a migration path in.
Bring your users from Supabase, Firebase or Auth0 **with their existing password
hashes** — they log in with the password they already have, and the hash is
upgraded to argon2id on that first login.

- Engine: [Better Auth](https://better-auth.com) (sessions, cookies, origin checks, DB adapters).
  boilauth does not implement its own auth crypto; it composes argon2id
  (`@node-rs/argon2`), bcrypt (`bcryptjs`) and Node's built-in scrypt/AES.
- Status: **0.1.0, pre-release.** Not published to npm. An external security
  review happens before 1.0 — see [Security model](#security-model).
- License: MIT.

## 5-minute start

Requires Node 22.5+ (for built-in `node:sqlite`).

```bash
npm install boilauth          # after first release; until then: npm install <path-or-git-url>
npx boilauth init             # writes boilauth.config.mjs and .env.example
cp .env.example .env          # set BOILAUTH_SECRET=$(openssl rand -base64 32)
npx boilauth migrate          # creates tables (SQLite auth.db by default)
```

Mount the handler in your server. The instance is a normal Better Auth instance:

```ts
import auth from "./boilauth.config.mjs";
import { toNodeHandler } from "better-auth/node";
import express from "express";

const app = express();
app.all("/api/auth/*splat", toNodeHandler(auth));   // sign-up, sign-in, session, admin …
app.listen(3000);
```

```bash
curl -X POST localhost:3000/api/auth/sign-up/email -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -d '{"email":"me@example.com","password":"a-long-password","name":"Me"}'
```

Postgres instead of SQLite: pass `new pg.Pool({ connectionString })` as `database`
in `boilauth.config.mjs`. Everything else is the same.

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

`SCHEMA_VERSION = 1`. The exact tables and columns are in
[`schema/v1.json`](schema/v1.json) (`npx boilauth schema` prints the live shape);
a test fails if the live schema drifts from it. Tables: `user`, `session`,
`account`, `verification`, `rateLimit` (Better Auth + admin plugin) and
`importedIdentity`, plus `user.failedLoginCount` / `user.lockedUntil`.

- Column types are limited to string / number / boolean / date, so the whole DB
  exports to SQLite as is:
  `npx boilauth export-sqlite backup.db` and `npx boilauth import-sqlite backup.db`.
  The test suite runs export → re-import and compares every row.
- A change to the column set bumps `SCHEMA_VERSION` and ships `schema/v<N>.json`
  with a migration note. Tools that read your auth DB can key off the version.

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
- **An independent external security review is required before 1.0.** Until then,
  treat this as pre-release. Report issues per [SECURITY.md](SECURITY.md).

## Tests

```bash
npm test                                           # SQLite, in-memory
BOILAUTH_PG_URL=postgres://… npm test              # also runs the Postgres path (empty scratch DB)
```

Hash fixtures are published vectors only (pyca/bcrypt, firebase/scrypt README);
see [`test/fixtures/README.md`](test/fixtures/README.md). Behaviour spec:
[`spec/boilauth.pseudo.md`](spec/boilauth.pseudo.md).

## Roadmap (not built)

- Hosted advisory feed and dashboard
- Other source formats (Clerk, Cognito, Auth0 custom hashes, PBKDF2/SHA variants)
- Python package
