# Security policy

boilauth is pre-release (0.x). An independent external security review is a
release gate for 1.0; until it is done, do not treat this package as reviewed.

## Reporting

Please report vulnerabilities privately — do not open a public issue.
Contact: <SECURITY_CONTACT — to be set before first public release>

## Advisories

Fixed issues are published as entries in an advisory feed
(`{ advisories: [{ id, affected, fixed, severity, summary }] }`), which
`npx boilauth check-updates --feed <url>` reads on request.

## Scope

In scope: password verification and rehash, import/merge rules, lockout, role
grant, SQLite export/import, and the presets this package sets on Better Auth.
Issues in Better Auth itself should go to the Better Auth project.
