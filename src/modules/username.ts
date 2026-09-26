/**
 * boilauth/username — username sign-in with rules the developer keeps in a
 * YAML file (spec U1).
 *
 * `boilauth init` writes boilauth.username.yaml once; after that it is the
 * developer's file. The generated config loads it at startup with
 * loadUsernameRules(), and createBoilAuth({ username: rules }) turns the rules
 * into Better Auth's `username` plugin options. A malformed file fails at
 * startup with the key named, never at a user's sign-up.
 *
 * Rules, all enforced by Better Auth's username plugin hooks:
 *   minLength / maxLength  length checks (sign-up, update, sign-in, availability)
 *   pattern                regular expression the whole username must match
 *   reserved               names nobody can take; compared case-insensitively
 *   caseInsensitive        true: "Alice" and "alice" are one username (stored lowercased,
 *                          original casing kept in displayUsername)
 *   immutable              true: a username cannot change once set
 */
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { z } from "zod";

export interface UsernameRules {
  minLength: number;
  maxLength: number;
  pattern: string;
  reserved: string[];
  caseInsensitive: boolean;
  immutable: boolean;
}

export const DEFAULT_USERNAME_RULES: UsernameRules = {
  minLength: 3,
  maxLength: 30,
  pattern: "^[a-zA-Z0-9_.]+$",
  reserved: ["admin", "administrator", "root", "support", "help", "api", "www", "system", "me", "settings"],
  caseInsensitive: true,
  immutable: false,
};

const RulesSchema = z
  .object({
    minLength: z.number().int().min(1).max(64),
    maxLength: z.number().int().min(1).max(64),
    pattern: z.string().min(1).refine((p) => {
      try {
        usernamePattern(p);
        return true;
      } catch {
        return false;
      }
    }, "not a valid regular expression"),
    reserved: z.array(z.string()).default([]),
    caseInsensitive: z.boolean().default(true),
    immutable: z.boolean().default(false),
  })
  .strict()
  .refine((r) => r.minLength <= r.maxLength, { message: "minLength must be <= maxLength", path: ["minLength"] });

/** Parses and checks a rules file; throws with the offending key named. */
export function parseUsernameRules(text: string, source = "username rules"): UsernameRules {
  const raw = parse(text) ?? {};
  const r = RulesSchema.safeParse(raw);
  if (!r.success) {
    const issues = r.error.issues.map((i) => `${i.path.join(".") || "(file)"}: ${i.message}`).join("; ");
    throw new Error(`${source}: ${issues}`);
  }
  return r.data;
}

export function loadUsernameRules(path: string | URL): UsernameRules {
  return parseUsernameRules(readFileSync(path, "utf8"), String(path));
}

/** The file `boilauth init` writes; comments explain each key. */
export function usernameRulesYaml(r: UsernameRules = DEFAULT_USERNAME_RULES): string {
  return `# boilauth username rules. This file is yours: edit it, restart the app, run npm test.
# Read at startup by boilauth.config.ts (loadUsernameRules); a bad value stops startup
# with the key named.

# Length of the username exactly as typed.
minLength: ${r.minLength}
maxLength: ${r.maxLength}

# Regular expression the whole username must match (anchor it with ^ and $).
pattern: ${JSON.stringify(r.pattern)}

# Names nobody can take. Compared case-insensitively.
reserved:
${r.reserved.map((n) => `  - ${n}`).join("\n")}

# true: "Alice" and "alice" are the same username. The typed casing is kept as
# displayUsername. false: they are two different usernames.
caseInsensitive: ${r.caseInsensitive}

# true: a username cannot be changed after it is set.
immutable: ${r.immutable}
`;
}

/**
 * NFKC first (full-width "ａｄｍｉｎ" is "admin"), then the case rule (audit F17). The lockout
 * hook uses it to find the account. Look-alikes from other scripts (Cyrillic "а") are not
 * folded; keep the pattern to the scripts you need.
 */
export function normalizeUsername(r: UsernameRules, username: string): string {
  const n = username.normalize("NFKC");
  return r.caseInsensitive ? n.toLowerCase() : n;
}

/** A pattern using \p{...} or \u{...} needs the unicode flag to mean anything. */
export function usernamePattern(p: string): RegExp {
  return /\\[pPu]\{/.test(p) ? new RegExp(p, "u") : new RegExp(p);
}

/** Better Auth `username` plugin options for these rules. */
export function usernamePluginOptions(r: UsernameRules) {
  const pattern = usernamePattern(r.pattern);
  const reserved = new Set(r.reserved.map((n) => n.normalize("NFKC").toLowerCase()));
  return {
    minUsernameLength: r.minLength,
    maxUsernameLength: r.maxLength,
    usernameValidator: (u: string) => {
      const n = u.normalize("NFKC");
      return pattern.test(n) && !reserved.has(n.toLowerCase());
    },
    usernameNormalization: (u: string) => normalizeUsername(r, u),
    immutableUsername: r.immutable,
  };
}
