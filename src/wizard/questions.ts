/**
 * Declarative question list. One question per policy key in
 * docs/EDGE_CASES.md, in its "Wizard question order". `when` receives the
 * answers so far; a question that does not apply is not asked and keeps its
 * default.
 */
import { DEFAULT_ANSWERS, getPath, type Answers } from "./answers.js";

export type QuestionType = "select" | "multiselect" | "number" | "text" | "confirm";

export interface Question {
  /** Dot path in Answers = policy key. */
  key: string;
  group: string;
  type: QuestionType;
  message: string;
  options?: { value: string; label: string; hint?: string }[];
  when?: (a: Answers) => boolean;
  /** Options that do not apply given earlier answers. */
  hideOption?: (a: Answers, value: string) => boolean;
  /** For text answers stored as a list. */
  parse?: (raw: string) => unknown;
}

const pw = (a: Answers) => a.signIn.emailPassword;
const hasFirebase = (a: Answers) => pw(a) && a.migration.sources.includes("firebase");
const existing = (a: Answers) => a.situation.existingUsers;
const OAUTH_OPTIONS = [
  { value: "google", label: "Google" },
  { value: "github", label: "GitHub" },
  { value: "apple", label: "Apple" },
  { value: "kakao", label: "Kakao", hint: "extra" },
  { value: "naver", label: "Naver", hint: "extra" },
];

export const QUESTIONS: Question[] = [
  // 0. Situation. The answers set the defaults of everything below.
  { key: "situation.existingUsers", group: "0. Your situation", type: "confirm", message: "Do you already have users signing in somewhere else?" },
  {
    key: "situation.currentSignIn", group: "0. Your situation", type: "multiselect", when: existing,
    message: "How do they sign in today? (kept as your sign-in methods)",
    options: [
      { value: "email_password", label: "Email + password" },
      { value: "magic_link", label: "Magic link by email" },
      ...OAUTH_OPTIONS,
    ],
  },
  {
    key: "migration.sources", group: "0. Your situation", type: "multiselect",
    when: (a) => existing(a) && a.situation.currentSignIn.includes("email_password"),
    message: "Where are those users now? Their password hashes come along",
    options: [
      { value: "supabase", label: "Supabase", hint: "auth.users, bcrypt" },
      { value: "firebase", label: "Firebase", hint: "modified scrypt" },
      { value: "auth0", label: "Auth0", hint: "password-hash export, bcrypt" },
      { value: "generic", label: "Other", hint: "your own CSV or JSON: email, email_verified, bcrypt or argon2id hash" },
    ],
  },
  {
    key: "situation.sourceVerifiedEmail", group: "0. Your situation", type: "select", when: existing,
    message: "Did your current system verify their email addresses?",
    options: [
      { value: "yes", label: "Yes", hint: "imported users keep their verified status" },
      { value: "no", label: "No or not sure", hint: "defaults email verification to optional so they can still sign in" },
    ],
  },
  {
    key: "situation.audience", group: "0. Your situation", type: "select",
    message: "Who is the app for?",
    options: [
      { value: "b2c", label: "Consumers", hint: "user + admin" },
      { value: "b2b", label: "Businesses with teams", hint: "organizations" },
      { value: "internal", label: "Internal tool", hint: "user + admin, TOTP required for admins" },
    ],
  },
  // A. Runtime
  {
    key: "runtime.database", group: "A. Runtime", type: "select",
    message: "Database",
    options: [
      { value: "sqlite", label: "SQLite", hint: "node:sqlite, one file" },
      { value: "postgres", label: "Postgres", hint: "pg Pool, DATABASE_URL" },
    ],
  },
  // B. Sign-in methods
  { key: "signIn.emailPassword", group: "B. Sign-in", type: "confirm", message: "Email + password sign-in?" },
  { key: "signIn.magicLink", group: "B. Sign-in", type: "confirm", message: "Magic link sign-in by email?" },
  {
    key: "signIn.oauth", group: "B. Sign-in", type: "multiselect",
    message: "OAuth providers (space to toggle, none is fine)",
    options: OAUTH_OPTIONS,
  },
  // C. Migration
  { key: "migration.firebase.keyId", group: "C. Migration", type: "text", when: hasFirebase, message: "Firebase key id (any name; signer key comes from FIREBASE_SIGNER_KEY)" },
  { key: "migration.firebase.saltSeparator", group: "C. Migration", type: "text", when: hasFirebase, message: "Firebase base64_salt_separator" },
  { key: "migration.firebase.rounds", group: "C. Migration", type: "number", when: hasFirebase, message: "Firebase rounds" },
  { key: "migration.firebase.memCost", group: "C. Migration", type: "number", when: hasFirebase, message: "Firebase mem_cost" },
  // D. Email verification
  {
    key: "email.verification", group: "D. Email verification", type: "select", when: (a) => pw(a),
    message: "Email verification before password sign-in",
    options: [
      { value: "required", label: "Required", hint: "403 until verified" },
      { value: "optional", label: "Optional", hint: "mail is still sent" },
    ],
  },
  // E. Account linking
  {
    key: "linking.mode", group: "E. Account linking", type: "select", when: (a) => a.signIn.oauth.length > 0,
    message: "OAuth sign-in with an email that already has an account",
    options: [
      { value: "verified_only", label: "Link when both sides are verified" },
      { value: "never", label: "Never link" },
    ],
  },
  // F. Password
  { key: "password.minLength", group: "F. Password", type: "number", when: pw, message: "Minimum password length (8..64)" },
  {
    key: "password.breachedCheck", group: "F. Password", type: "select", when: pw,
    message: "Reject breached passwords",
    options: [
      { value: "off", label: "Off" },
      { value: "hibp", label: "Have I Been Pwned", hint: "k-anonymity range API, network call" },
    ],
  },
  // G. Lockout, rate limit, sessions
  { key: "lockout.maxFailures", group: "G. Lockout and sessions", type: "number", when: pw, message: "Lock after how many wrong passwords (0 = off)" },
  { key: "lockout.minutes", group: "G. Lockout and sessions", type: "number", when: (a) => pw(a) && a.lockout.maxFailures > 0, message: "Lock for how many minutes" },
  { key: "rateLimit.signInPerMinute", group: "G. Lockout and sessions", type: "number", message: "Sign-in attempts per IP per minute" },
  { key: "session.days", group: "G. Lockout and sessions", type: "number", message: "Session lifetime in days (1..90)" },
  { key: "session.revokeOnPasswordChange", group: "G. Lockout and sessions", type: "confirm", when: pw, message: "End other sessions when the password changes?" },
  {
    key: "session.devices", group: "G. Lockout and sessions", type: "select",
    message: "Sessions per user",
    options: [
      { value: "multi", label: "Many devices at once" },
      { value: "single", label: "One device", hint: "a new sign-in ends the others" },
    ],
  },
  // I. Roles (asked before MFA because one MFA option needs roles)
  {
    key: "roles.mode", group: "I. Roles", type: "select",
    message: "Roles",
    options: [
      { value: "none", label: "None" },
      { value: "admin", label: "user + admin" },
      { value: "custom", label: "Custom role list with permission checks" },
      { value: "organizations", label: "Organizations", hint: "orgs, members, invitations, org roles" },
    ],
  },
  {
    key: "roles.custom", group: "I. Roles", type: "text", when: (a) => a.roles.mode === "custom",
    message: "Role names, comma separated (must include admin and user)",
    parse: (raw) => raw.split(",").map((s) => s.trim()).filter(Boolean),
  },
  {
    key: "roles.orgCreation", group: "I. Roles", type: "select", when: (a) => a.roles.mode === "organizations",
    message: "Who can create organizations",
    options: [
      { value: "any_user", label: "Any signed-in user" },
      { value: "admin_only", label: "Admins only" },
    ],
  },
  // H. MFA
  {
    key: "mfa.mode", group: "H. MFA", type: "select", when: pw,
    hideOption: (a, v) => v === "totp_required_admin" && a.roles.mode === "none",
    message: "Second factor (TOTP)",
    options: [
      { value: "off", label: "Off" },
      { value: "totp_optional", label: "Optional for everyone" },
      { value: "totp_required_admin", label: "Required for admins", hint: "needs roles" },
    ],
  },
  // J. Deletion
  {
    key: "deletion.mode", group: "J. Account deletion", type: "select",
    message: "When a user deletes their account",
    options: [
      { value: "hard", label: "Delete the rows" },
      { value: "soft", label: "Mark deleted, purge later" },
    ],
  },
  { key: "deletion.export", group: "J. Account deletion", type: "confirm", message: "Offer a self-service data export endpoint?" },
];

export function defaultFor(q: Question): unknown {
  return getPath(DEFAULT_ANSWERS, q.key);
}
