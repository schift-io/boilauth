# Security policy

boilauth is pre-release (0.x). It runs in your environment against your
database; the auth core is [Better Auth](https://better-auth.com).

## Reporting

Report vulnerabilities privately through GitHub security advisories:
<https://github.com/schift-io/boilauth/security/advisories/new>.
Please do not open a public issue.

## Advisories

Fixed issues are published as GitHub security advisories and as entries in an
advisory feed (`{ advisories: [{ id, affected, fixed, severity, summary }] }`),
which `npx boilauth check-updates --feed <url>` reads on request.

## Scope

In scope: password verification and rehash, import/merge rules, lockout, role
grant, SQLite export/import, and the presets this package sets on Better Auth.
Issues in Better Auth itself should go to the Better Auth project.
