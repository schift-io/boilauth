# boilauth

Part of [Schift](https://schift.io)'s boil series, alongside [boilpayment](https://github.com/schift-io/boilpayment).

Email/password auth that runs in **your** database, with a migration path in.
Bring your users from Supabase, Firebase, Auth0 or your own export **with their existing password
hashes** — they log in with the password they already have, and the hash is
upgraded to argon2id on that first login.

- Engine: [Better Auth](https://better-auth.com) (sessions, cookies, origin checks, DB adapters).
  boilauth does not implement its own auth crypto; it composes argon2id
  (`@node-rs/argon2`), bcrypt (`bcryptjs`) and Node's built-in scrypt/AES.
- Status: **0.3.0, pre-release.** On npm as `boilauth` (0.2.0 published; 0.3.0 not yet).
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

Mount the generated instance in your server. It is a normal Better Auth instance,
mounted with boilauth's Node adapter so rate limits and lockout see the connection's
address (`network.clientIp = socket`, the default):

```ts
import auth from "./boilauth.config.js";
import { toNodeHandler } from "boilauth/node";
import express from "express";

const app = express();
app.all("/api/auth/*splat", toNodeHandler(auth));   // sign-up, sign-in, session, admin …
app.listen(3000);
```

On other runtimes pass the address yourself: `auth.handler(request, { clientIp })`.
Behind your own proxies answer `proxy` and list them; behind a platform that sets one
header (Cloudflare `cf-connecting-ip`, Fly `fly-client-ip`) answer `header`. Forwarded
headers from anyone else are ignored, and in production a request with no client IP is
refused (500 `CLIENT_IP_UNAVAILABLE`) instead of sharing one rate-limit bucket.

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
| A | `network.clientIp` | **socket** / proxy / header (which client IP per-IP limits and lockout count) |
| A | `network.trustedProxies` | your proxies' IPs/CIDRs (asked with proxy) |
| A | `network.clientIpHeader` | **cf-connecting-ip** (asked with header) |
| B | `signIn.emailPassword` | **yes** / no |
| B | `signIn.username` | yes / **no** (rules in `boilauth.username.yaml`, see below) |
| B | `signIn.magicLink` | yes / **no** |
| B | `signIn.emailOtp` | yes / **no** (6-digit mailed code, 5 min, 3 tries, stored hashed) |
| B | `signIn.phone` | yes / **no** (SMS codes and number + password; your sender in `src/sms.ts`) |
| B | `phone.allowedCountries` | calling codes that may receive SMS (**none** = every country; asked with phone) |
| B | `signIn.oauth` | google, github, apple, kakao, naver (**none**) |
| C | `migration.firebase.keyId`, `.saltSeparator`, `.rounds`, `.memCost` | **firebase**, **Bw==**, **8**, **14** (asked only with firebase) |
| D | `email.verification` | **required** / optional |
| E | `linking.mode` | **verified_only** / never (asked only with OAuth) |
| F | `password.minLength` | **12** (8..64) |
| F | `password.breachedCheck` | **off** / hibp |
| G | `lockout.maxFailures`, `lockout.minutes` | **5**, **15** per source (IP) and account (0 = off) |
| G | `lockout.accountMaxFailures` | **20** from all sources, then only known devices may try |
| G | `rateLimit.signInPerMinute` | **10** |
| G | `rateLimit.sendPerIpPerHour` | **10** per send endpoint (0 = Better Auth's per-minute rules) |
| G | `rateLimit.sendPerAccountPerHour` | **5** per email or phone number, any IP (0 = off) |
| G | `rateLimit.smsPerHour` | **100** SMS per hour site-wide (0 = no cap; asked with phone) |
| G | `rateLimit.usernameCheckPerIpPerHour` | **30** (0 = endpoint removed; asked with username) |
| G | `rateLimit.storage` | **database** / memory |
| G | `session.days` | **7** (1..90) |
| G | `session.absoluteDays` | **30** (sign in again after this, however active) |
| G | `session.revokeOnPasswordChange` | **yes** / no |
| G | `session.devices` | **multi** / single |
| G | `session.bearer` | yes / **no** (also accept `Authorization: Bearer`; sign-in sends `set-auth-token`) |
| I | `roles.mode` | none / **admin** / custom / organizations |
| I | `roles.custom` | **admin,editor,user** (asked with custom) |
| I | `roles.orgCreation` | **any_user** / admin_only (asked with organizations) |
| I | `roles.hideAdmin` | yes / **no** (404 on `/admin/*` for anyone who is not an admin) |
| H | `mfa.mode` | **off** / totp_optional / totp_required_admin (the last needs roles) |
| H | `mfa.backupCodes` | **10** (5..20, each usable once) |
| H | `mfa.emailOtp` | yes / **no** (a mailed code as the second step; admin access still needs TOTP or a backup code) |
| H | `mfa.allSignIns` | **yes** / no (the second factor after magic links, codes and OAuth too) |
| K | `notify.securityChanges` | **yes** / no (mail on password or two-factor change and on an account lock) |
| K | `notify.newDevice` | yes / **no** (mail on sign-in from a device not seen in 90 days) |
| J | `deletion.mode` | **hard** / soft |
| J | `deletion.guard` | yes / **no** (your veto in `src/deletion-guard.ts`, e.g. while a paid subscription is active; 409 with your code) |
| J | `deletion.lastOrgOwner` | **block** / transfer_to_oldest_admin (asked with organizations) |
| J | `deletion.records` | **delete** / anonymize (keep the row without personal data, so payment and audit rows still resolve) |
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
test before it becomes a choice): `anonymous`, `bearer`, `jwt`, API keys, `one-time-token`,
`multi-session`, `captcha`, `one-tap`, `siwe`, `device-authorization`, `generic-oauth`
(any OIDC provider), `last-login-method`, `custom-session`, `additional-fields`,
`oauth-proxy`, and the separate `@better-auth/passkey` and `@better-auth/sso` packages.
You can still add any of them to the generated `src/auth.ts` by hand; it is a normal Better
Auth config. Exceptions: with two-factor on, `createBoilAuth` refuses `device-authorization`
and `siwe` at startup, because their sign-in paths (`/device/token`, `/siwe/verify`) issue a
session without the second factor.

## What the presets are

| Area | Default | Where |
|---|---|---|
| New password hashes | argon2id, m=19456 KiB, t=2, p=1 (OWASP minimum) | `createPasswordHasher` |
| Password length | 12–128 | `PRESETS` |
| Lockout | 5 wrong passwords from one source lock that source for the account for 15 min; 20 from unknown sources lock the account against unknown sources for 15 min. Locked looks exactly like a wrong password (same 401, password not checked). | `boilauthPlugin` |
| Per-IP rate limit | on, stored in the DB. `/sign-in/email` 10/min, `/request-password-reset` 3/5 min; Better Auth's 3/10 s on sign-up / change-password / change-email | `PRESETS.rateLimit` |
| Sessions | 7 days, expiry refreshed at most daily, "fresh" = 10 min, all sessions revoked on password reset, new token on every sign-in | `PRESETS.session` |
| Role change | all of the user's sessions are deleted | `grantRole` |
| Account linking | OAuth linking only onto a locally verified email (Better Auth `requireLocalEmailVerified`) | `createBoilAuth` |

**Set the client IP source before production** (`network.clientIp`, see the wizard table):
`socket` (default) mounts with `toNodeHandler` from `boilauth/node`; behind your own proxy
pass `trustedProxies: ["10.0.0.0/8", …]`; on a platform that sets one client-IP header, use
`clientIp: { mode: "header", header: "cf-connecting-ip" }`. Every Better Auth option can
still be overridden through `betterAuth: {...}`, except the client-IP source:
`betterAuth.advanced.ipAddress.ipAddressHeaders` and `disableIpTracking` are refused at
startup, since they would let a client-sent header decide the rate-limit key.

## Username rules

With `signIn.username` on, `init` writes `boilauth.username.yaml` once; after that it is
your file (init leaves it alone). The generated config loads it at startup, and a bad
value stops startup with the key named. The generated tests read the same file, so they
keep checking whatever you change it to.

```yaml
minLength: 3
maxLength: 30
pattern: "^[a-zA-Z0-9_.]+$"   # whole username, anchored
reserved:                     # compared case-insensitively
  - admin
  - support
caseInsensitive: true         # "Alice" and "alice" are one username; typed casing kept as displayUsername
immutable: false              # true: a username cannot change once set
```

Username, phone + password and email sign-in share one lockout counter per account and
the same per-IP sign-in limit. With `mfa.allSignIns` (default) a user with TOTP passes it
after a magic link, email or SMS code or OAuth too; such a sign-in never satisfies
`totp_required_admin` on its own.

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
| core | always | [`schema/core.v2.json`](schema/core.v2.json) (v2 adds `user.knownSignInSources`) |
| admin | roles is admin, custom or organizations | [`schema/admin.v1.json`](schema/admin.v1.json) |
| two-factor | mfa is not off | [`schema/two-factor.v1.json`](schema/two-factor.v1.json) |
| mfa-admin | mfa = totp_required_admin | [`schema/mfa-admin.v1.json`](schema/mfa-admin.v1.json) |
| organization | roles = organizations | [`schema/organization.v1.json`](schema/organization.v1.json) |
| soft-delete | deletion = soft | [`schema/soft-delete.v1.json`](schema/soft-delete.v1.json) |
| username | signIn.username | [`schema/username.v1.json`](schema/username.v1.json) |
| phone-number | signIn.phone | [`schema/phone-number.v1.json`](schema/phone-number.v1.json) |

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
- Every per-IP control counts the client IP boilauth resolves itself
  (`network.clientIp`): the socket address by default, forwarded headers only from
  your listed proxies or one platform header. A client-sent `X-Forwarded-For` changes
  nothing, IPv6 counts per /64, and in production a request without a resolvable IP is
  refused (500 `CLIENT_IP_UNAVAILABLE`) instead of sharing one bucket with everyone.
- Lockout has two layers: 5 wrong passwords from one source lock that source for the
  account; 20 from all sources lock the account against sources that have not signed in
  to it in the last 90 days, while the owner's known devices keep working. A lock answers
  like a wrong password. The account-wide counter is read-modify-write, so a burst of
  parallel guesses can count as fewer; the per-source lock and the IP rate limit bound it.
- Passwords: minimum 12 characters by default (ASVS 2.1.1); the breached-password check
  (Have I Been Pwned range API) is opt-in because it makes a network call.
- Sessions end 30 days after sign-in however active they are (`session.absoluteDays`).
- A user with two-factor on passes it after every first factor: password, magic link,
  email or SMS code, OAuth, and email verification if you turn on auto sign-in there
  (`mfa.allSignIns`, default on). After a first factor that proves only the mailbox or
  the phone, the email code cannot be the second factor (403 `SECOND_FACTOR_NOT_ALLOWED`):
  TOTP or a backup code finishes it. A two-factor challenge carries no bearer token.
- Lockout counting: a known device's own typos count only toward its own source lock, and
  a successful sign-in does not clear the account-wide lock for other sources.
- A duplicate sign-up answers with the same status, body shape and timing as a new one.
- A soft-deleted account answers the right password exactly like a wrong one.
- Paths that are not endpoints of your instance answer 404 before any rate-limit counter
  is written, so made-up paths cannot fill the rate-limit table or push hot counters out
  of the in-memory store. Routes with a path parameter (`/callback/:id`, `/reset-password/:token`) count per IP
  per route, not per value, and a callback for a provider you have not configured answers 404
  before any counter exists. The in-memory store (`rateLimit.storage = memory`) still holds
  at most 100 000 counters per process and evicts the oldest first; an attacker with many
  addresses can still cycle it. Use `database` (default) when that matters.
- Attaching a phone number needs a sign-in within the last 10 minutes and sends a notice;
  an admin setting a user's password ends that user's sessions and sends a notice.
- `network.clientIp = header`: the header must hold exactly one address. A value with a
  comma (appended to by a proxy, or sent twice) counts as no IP, so point it only at a
  header your edge overwrites.
- The user is mailed when their password (including an admin's reset), two-factor
  setting or phone number changes and when many wrong passwords lock their account
  (`notify.securityChanges`); optionally on sign-in from a new device (`notify.newDevice`).
- Account enumeration: sign-in answers and timings are the same for existing and missing
  accounts on email, username and phone; a duplicate sign-up answers like a new one; the
  username availability check is limited per IP (or removed).
- Mail and SMS sends (reset, verification, magic link, email and SMS codes) are limited per IP
  and per destination address (`boilauth/rate-limit`, default 10 per IP and 5 per address per
  hour), so one address cannot be flooded from many IPs. Trade-off: anyone can use up an
  address's hourly quota, which delays that user's own reset mail for up to an hour. Every 429
  carries `Retry-After`. Counters live in the database by default, so every instance shares them.
  SMS also has a site-wide budget per hour (`rateLimit.smsPerHour`, default 100) and an optional
  country allowlist (`phone.allowedCountries`); phone numbers are E.164 without a trunk 0.
- Admin removal (`/admin/remove-user`) meets the same deletion veto, organization rule and
  records policy as self-service deletion.
- Known limits, not fixed in 0.3.0:
  - the session cookie is `__Secure-` prefixed, not `__Host-` (ASVS 3.4.4): Better Auth 1.7.6
    has no `__Host-` option and imitating it through the cookie name is untested;
  - SMS codes are stored as plain text for their 5 minutes (Better Auth's phoneNumber plugin
    has no hashing option; email codes are hashed);
  - with `email.verification = optional`, someone can pre-register an address with a password;
    no takeover (linking needs a verified local email), but the owner needs support to reclaim it;
  - username look-alikes across scripts (Cyrillic `а` for Latin `a`) are not folded.
- Security advisories: `npx boilauth check-updates --feed <url>` fetches an
  advisory JSON and compares versions locally. It runs only when you invoke it
  (or set `BOILAUTH_UPDATE_CHECK=1` and `BOILAUTH_ADVISORY_URL`) and sends nothing
  but the GET. A hosted feed is on the roadmap; for now you supply the URL.
- Report vulnerabilities privately through GitHub security advisories; see
  [SECURITY.md](SECURITY.md).

## Tests

```bash
npm test                                           # SQLite, in-memory; also generates 8 projects and runs their tests
BOILAUTH_PG_URL=postgres://… npm test              # also runs the Postgres paths (empty scratch DB)
```

Hash fixtures are published vectors only (pyca/bcrypt, firebase/scrypt README);
see [`fixtures/README.md`](fixtures/README.md). Behaviour spec:
[`spec/boilauth.pseudo.md`](spec/boilauth.pseudo.md).

## Roadmap (not built)

- Hosted advisory feed and dashboard
- Other source formats (Clerk, Cognito, Auth0 custom hashes, PBKDF2/SHA variants)
- Passkeys (needs a browser WebAuthn authenticator in the generated tests), Drizzle / Prisma adapters
- Python package
