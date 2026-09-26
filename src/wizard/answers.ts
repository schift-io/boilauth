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
  /** Where the client IP comes from (rate limits, lockout, send limits). See boilauth/client-ip. */
  network: { clientIp: "socket" | "proxy" | "header"; trustedProxies: string[]; clientIpHeader: string };
  signIn: { emailPassword: boolean; username: boolean; magicLink: boolean; emailOtp: boolean; phone: boolean; oauth: OAuthProvider[] };
  migration: {
    sources: MigrationSource[];
    firebase: { keyId: string; saltSeparator: string; rounds: number; memCost: number };
  };
  email: { verification: "required" | "optional" };
  /** Phone sign-in: country calling codes that may receive SMS (empty = every country). */
  phone: { allowedCountries: string[] };
  linking: { mode: "verified_only" | "never" };
  password: { minLength: number; breachedCheck: "off" | "hibp" };
  lockout: { maxFailures: number; minutes: number; accountMaxFailures: number };
  rateLimit: {
    signInPerMinute: number;
    sendPerIpPerHour: number;
    sendPerAccountPerHour: number;
    smsPerHour: number;
    usernameCheckPerIpPerHour: number;
    storage: "database" | "memory";
  };
  session: { days: number; absoluteDays: number; revokeOnPasswordChange: boolean; devices: "multi" | "single"; bearer: boolean };
  mfa: { mode: "off" | "totp_optional" | "totp_required_admin"; backupCodes: number; emailOtp: boolean };
  roles: { mode: "none" | "admin" | "custom" | "organizations"; custom: string[]; orgCreation: "any_user" | "admin_only"; hideAdmin: boolean };
  /** Security notices by email (audit F9, ASVS 2.2.3). */
  notify: { securityChanges: boolean; newDevice: boolean };
  deletion: {
    mode: "hard" | "soft";
    export: boolean;
    guard: boolean;
    records: "delete" | "anonymize";
    lastOrgOwner: "block" | "transfer_to_oldest_admin";
  };
}

export const DEFAULT_ANSWERS: Answers = {
  version: 1,
  situation: { existingUsers: false, currentSignIn: ["email_password"], sourceVerifiedEmail: "yes", audience: "b2c" },
  runtime: { database: "sqlite" },
  network: { clientIp: "socket", trustedProxies: [], clientIpHeader: "cf-connecting-ip" },
  signIn: { emailPassword: true, username: false, magicLink: false, emailOtp: false, phone: false, oauth: [] },
  migration: { sources: [], firebase: { keyId: "firebase", saltSeparator: "Bw==", rounds: 8, memCost: 14 } },
  email: { verification: "required" },
  phone: { allowedCountries: [] },
  linking: { mode: "verified_only" },
  password: { minLength: 12, breachedCheck: "off" },
  lockout: { maxFailures: 5, minutes: 15, accountMaxFailures: 20 },
  rateLimit: { signInPerMinute: 10, sendPerIpPerHour: 10, sendPerAccountPerHour: 5, smsPerHour: 100, usernameCheckPerIpPerHour: 30, storage: "database" },
  session: { days: 7, absoluteDays: 30, revokeOnPasswordChange: true, devices: "multi", bearer: false },
  mfa: { mode: "off", backupCodes: 10, emailOtp: false },
  roles: { mode: "admin", custom: ["admin", "editor", "user"], orgCreation: "any_user", hideAdmin: false },
  notify: { securityChanges: true, newDevice: false },
  deletion: { mode: "hard", export: true, guard: false, records: "delete", lastOrgOwner: "block" },
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
  if (!s.emailPassword && !s.magicLink && !s.emailOtp && s.oauth.length === 0) errs.push("signIn: turn on at least one sign-in method");
  for (const p of s.oauth) if (!OAUTH_PROVIDERS.includes(p)) errs.push(`signIn.oauth: unknown provider ${p}`);
  for (const m of a.situation.currentSignIn) if (!SIGN_IN_METHODS.includes(m)) errs.push(`situation.currentSignIn: unknown ${m}`);
  if (!AUDIENCES.includes(a.situation.audience)) errs.push(`situation.audience: unknown ${a.situation.audience}`);
  for (const m of a.migration.sources) if (!MIGRATION_SOURCES.includes(m)) errs.push(`migration.sources: unknown ${m}`);
  if (a.migration.sources.length && !s.emailPassword) errs.push("migration.sources needs signIn.emailPassword");
  if (s.username && !s.emailPassword) errs.push("signIn.username needs signIn.emailPassword");
  const int = (v: number, lo: number, hi: number, key: string) => {
    if (!Number.isInteger(v) || v < lo || v > hi) errs.push(`${key}: ${v} is outside ${lo}..${hi}`);
  };
  if (!["socket", "proxy", "header"].includes(a.network.clientIp)) errs.push(`network.clientIp: unknown ${a.network.clientIp}`);
  if (a.network.clientIp === "proxy") {
    if (!a.network.trustedProxies.length) errs.push("network.trustedProxies: list your proxy addresses or CIDRs");
    for (const c of a.network.trustedProxies) if (!/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(c)) errs.push(`network.trustedProxies: not an IP or CIDR: ${c}`);
  }
  if (a.network.clientIp === "header" && !/^[a-z0-9-]{1,64}$/.test(a.network.clientIpHeader)) errs.push("network.clientIpHeader: a lowercase header name");
  int(a.password.minLength, 8, 64, "password.minLength");
  int(a.lockout.maxFailures, 0, 100, "lockout.maxFailures");
  int(a.lockout.minutes, 1, 1440, "lockout.minutes");
  int(a.lockout.accountMaxFailures, 1, 100, "lockout.accountMaxFailures");
  if (a.lockout.maxFailures > a.lockout.accountMaxFailures) errs.push("lockout.accountMaxFailures must be >= lockout.maxFailures");
  int(a.rateLimit.signInPerMinute, 1, 1000, "rateLimit.signInPerMinute");
  int(a.rateLimit.sendPerIpPerHour, 0, 1000, "rateLimit.sendPerIpPerHour");
  int(a.rateLimit.sendPerAccountPerHour, 0, 1000, "rateLimit.sendPerAccountPerHour");
  int(a.rateLimit.smsPerHour, 0, 100000, "rateLimit.smsPerHour");
  int(a.rateLimit.usernameCheckPerIpPerHour, 0, 10000, "rateLimit.usernameCheckPerIpPerHour");
  for (const c of a.phone.allowedCountries) if (!/^[1-9]\d{0,2}$/.test(c)) errs.push(`phone.allowedCountries: not a calling code: ${c}`);
  if (!["database", "memory"].includes(a.rateLimit.storage)) errs.push(`rateLimit.storage: unknown ${a.rateLimit.storage}`);
  if (!["delete", "anonymize"].includes(a.deletion.records)) errs.push(`deletion.records: unknown ${a.deletion.records}`);
  if (!["block", "transfer_to_oldest_admin"].includes(a.deletion.lastOrgOwner)) errs.push(`deletion.lastOrgOwner: unknown ${a.deletion.lastOrgOwner}`);
  int(a.session.days, 1, 90, "session.days");
  int(a.session.absoluteDays, 1, 365, "session.absoluteDays");
  if (a.session.absoluteDays < a.session.days) errs.push("session.absoluteDays must be >= session.days");
  int(a.mfa.backupCodes, 5, 20, "mfa.backupCodes");
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
    a.signIn.username = false;
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
