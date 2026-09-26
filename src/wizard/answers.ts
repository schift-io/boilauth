/**
 * Wizard answers = policy keys (docs/EDGE_CASES.md). Saved as
 * boilauth.answers.json and re-read by `boilauth init`, so a second run only
 * asks what is missing and regenerates the same code.
 */
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";

export const OAUTH_PROVIDERS = ["google", "github", "apple", "kakao", "naver"] as const;
export type OAuthProvider = (typeof OAUTH_PROVIDERS)[number];
export const MIGRATION_SOURCES = ["supabase", "firebase", "auth0", "generic"] as const;
export type MigrationSource = (typeof MIGRATION_SOURCES)[number];
export const SIGN_IN_METHODS = ["email_password", "magic_link", ...OAUTH_PROVIDERS] as const;
export type SignInMethod = (typeof SIGN_IN_METHODS)[number];
export const AUDIENCES = ["b2c", "b2b", "internal"] as const;

export interface Answers {
  version: 1;
  /** The developer's situation. Asked first; sets the defaults of the policy questions below. */
  situation: {
    existingUsers: boolean;
    currentSignIn: SignInMethod[];
    sourceVerifiedEmail: "yes" | "no";
    audience: (typeof AUDIENCES)[number];
  };
  runtime: { database: "sqlite" | "postgres" };
  signIn: { emailPassword: boolean; magicLink: boolean; oauth: OAuthProvider[] };
  migration: {
    sources: MigrationSource[];
    firebase: { keyId: string; saltSeparator: string; rounds: number; memCost: number };
  };
  email: { verification: "required" | "optional" };
  linking: { mode: "verified_only" | "never" };
  password: { minLength: number; breachedCheck: "off" | "hibp" };
  lockout: { maxFailures: number; minutes: number };
  rateLimit: { signInPerMinute: number };
  session: { days: number; revokeOnPasswordChange: boolean; devices: "multi" | "single" };
  mfa: { mode: "off" | "totp_optional" | "totp_required_admin" };
  roles: { mode: "none" | "admin" | "custom" | "organizations"; custom: string[]; orgCreation: "any_user" | "admin_only" };
  deletion: { mode: "hard" | "soft"; export: boolean };
}

export const DEFAULT_ANSWERS: Answers = {
  version: 1,
  situation: { existingUsers: false, currentSignIn: ["email_password"], sourceVerifiedEmail: "yes", audience: "b2c" },
  runtime: { database: "sqlite" },
  signIn: { emailPassword: true, magicLink: false, oauth: [] },
  migration: { sources: [], firebase: { keyId: "firebase", saltSeparator: "Bw==", rounds: 8, memCost: 14 } },
  email: { verification: "required" },
  linking: { mode: "verified_only" },
  password: { minLength: 10, breachedCheck: "off" },
  lockout: { maxFailures: 5, minutes: 15 },
  rateLimit: { signInPerMinute: 10 },
  session: { days: 7, revokeOnPasswordChange: true, devices: "multi" },
  mfa: { mode: "off" },
  roles: { mode: "admin", custom: ["admin", "editor", "user"], orgCreation: "any_user" },
  deletion: { mode: "hard", export: true },
};

export type Partialish<T> = { [K in keyof T]?: T[K] extends object ? (T[K] extends unknown[] ? T[K] : Partialish<T[K]>) : T[K] };

export function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined), obj);
}

export function setPath(obj: Record<string, unknown>, path: string, value: unknown): void {
  const keys = path.split(".");
  let o = obj;
  for (const k of keys.slice(0, -1)) {
    if (!o[k] || typeof o[k] !== "object") o[k] = {};
    o = o[k] as Record<string, unknown>;
  }
  o[keys[keys.length - 1]] = value;
}

export const ROLE_NAME = /^[a-z][a-z0-9_-]{0,31}$/;

/** Returns problems; empty means valid. */
export function validateAnswers(a: Answers): string[] {
  const errs: string[] = [];
  const s = a.signIn;
  if (!s.emailPassword && !s.magicLink && s.oauth.length === 0) errs.push("signIn: turn on at least one sign-in method");
  for (const p of s.oauth) if (!OAUTH_PROVIDERS.includes(p)) errs.push(`signIn.oauth: unknown provider ${p}`);
  for (const m of a.situation.currentSignIn) if (!SIGN_IN_METHODS.includes(m)) errs.push(`situation.currentSignIn: unknown ${m}`);
  if (!AUDIENCES.includes(a.situation.audience)) errs.push(`situation.audience: unknown ${a.situation.audience}`);
  for (const m of a.migration.sources) if (!MIGRATION_SOURCES.includes(m)) errs.push(`migration.sources: unknown ${m}`);
  if (a.migration.sources.length && !s.emailPassword) errs.push("migration.sources needs signIn.emailPassword");
  const int = (v: number, lo: number, hi: number, key: string) => {
    if (!Number.isInteger(v) || v < lo || v > hi) errs.push(`${key}: ${v} is outside ${lo}..${hi}`);
  };
  int(a.password.minLength, 8, 64, "password.minLength");
  int(a.lockout.maxFailures, 0, 100, "lockout.maxFailures");
  int(a.lockout.minutes, 1, 1440, "lockout.minutes");
  int(a.rateLimit.signInPerMinute, 1, 1000, "rateLimit.signInPerMinute");
  int(a.session.days, 1, 90, "session.days");
  int(a.migration.firebase.rounds, 1, 64, "migration.firebase.rounds");
  int(a.migration.firebase.memCost, 1, 20, "migration.firebase.memCost");
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(a.migration.firebase.keyId)) errs.push("migration.firebase.keyId: letters, digits, - and _ only");
  if (a.mfa.mode !== "off" && !s.emailPassword) errs.push("mfa needs signIn.emailPassword");
  if (a.mfa.mode === "totp_required_admin" && a.roles.mode === "none") errs.push("mfa.mode totp_required_admin needs roles");
  if (a.roles.mode === "custom") {
    for (const r of a.roles.custom) if (!ROLE_NAME.test(r)) errs.push(`roles.custom: invalid role name "${r}"`);
    for (const need of ["admin", "user"]) if (!a.roles.custom.includes(need)) errs.push(`roles.custom must include "${need}"`);
  }
  return errs;
}

/**
 * Policy defaults that follow from the situation answers. Applied only to keys
 * the developer has not answered, so every one of them is still asked and can
 * be changed.
 */
export function situationDefaults(a: Answers): Record<string, unknown> {
  const s = a.situation;
  const d: Record<string, unknown> = {};
  if (s.existingUsers && s.currentSignIn.length) {
    // Keep existing users signing in the way they do today.
    d["signIn.emailPassword"] = s.currentSignIn.includes("email_password");
    d["signIn.magicLink"] = s.currentSignIn.includes("magic_link");
    d["signIn.oauth"] = s.currentSignIn.filter((m): m is OAuthProvider => (OAUTH_PROVIDERS as readonly string[]).includes(m));
  }
  // An unverified import under `required` would meet a 403 on its next sign-in.
  if (s.existingUsers && s.sourceVerifiedEmail === "no") d["email.verification"] = "optional";
  if (s.audience === "b2b") d["roles.mode"] = "organizations";
  if (s.audience === "internal") {
    d["roles.mode"] = "admin";
    d["mfa.mode"] = "totp_required_admin";
  }
  return d;
}

/** Fills everything missing from defaults and drops values that no longer apply. */
export function normalizeAnswers(input: unknown): Answers {
  const merged = structuredClone(DEFAULT_ANSWERS) as unknown as Record<string, unknown>;
  const walk = (src: unknown, prefix: string) => {
    if (!src || typeof src !== "object" || Array.isArray(src)) return;
    for (const [k, v] of Object.entries(src)) {
      const p = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === "object" && !Array.isArray(v)) walk(v, p);
      else if (getPath(DEFAULT_ANSWERS, p) !== undefined) setPath(merged, p, v);
    }
  };
  walk(input, "");
  const a = merged as unknown as Answers;
  for (const [k, v] of Object.entries(situationDefaults(a))) if (getPath(input, k) === undefined) setPath(merged, k, v);
  if (!a.signIn.emailPassword) {
    a.migration.sources = [];
    a.mfa.mode = "off";
  }
  if (a.roles.mode === "none" && a.mfa.mode === "totp_required_admin") a.mfa.mode = "totp_optional";
  return a;
}

export async function loadAnswers(path: string): Promise<Record<string, unknown> | null> {
  if (!existsSync(path)) return null;
  return JSON.parse(await readFile(path, "utf8"));
}

export async function saveAnswers(path: string, a: Answers): Promise<void> {
  await writeFile(path, JSON.stringify(a, null, 2) + "\n");
}
