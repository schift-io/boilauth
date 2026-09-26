/**
 * Shared import pipeline. Every provider importer normalises its export into
 * ImportRecord[] and hands it to importUsers().
 *
 * Merge rule (the only one): an imported record is merged into an existing
 * user with the same email ONLY if both the existing user and the imported
 * record have a verified email. Anything else is reported as a conflict and
 * nothing is written — an unverified row is not proof of mailbox ownership,
 * and merging it would let whoever created it take over the other account.
 */
import { hashKind } from "../hash/index.js";

export type ImportSource = "supabase" | "firebase" | "auth0";

export interface ImportRecord {
  sourceId: string;
  email: string;
  emailVerified: boolean;
  name?: string | null;
  /** Stored-format hash (bcrypt or $firebase-scrypt$...). null = user must reset password. */
  passwordHash: string | null;
  createdAt?: Date | null;
}

export type ImportOutcome =
  | { sourceId: string; email: string; result: "created"; userId: string; password: boolean }
  | { sourceId: string; email: string; result: "merged"; userId: string; password: "attached" | "kept_existing" | "none" }
  | { sourceId: string; email: string; result: "skipped"; reason: "already_imported" | "email_conflict_unverified" | "no_email" | "unsupported_hash" };

export interface ImportReport {
  source: ImportSource;
  created: number;
  merged: number;
  skipped: number;
  outcomes: ImportOutcome[];
}

type AuthLike = { $context: Promise<{ adapter: any; internalAdapter: any }> };

export async function importUsers(auth: AuthLike, source: ImportSource, records: ImportRecord[]): Promise<ImportReport> {
  const ctx = await auth.$context;
  const ia = ctx.internalAdapter;
  const report: ImportReport = { source, created: 0, merged: 0, skipped: 0, outcomes: [] };
  const push = (o: ImportOutcome) => {
    report.outcomes.push(o);
    if (o.result === "created") report.created++;
    else if (o.result === "merged") report.merged++;
    else report.skipped++;
  };

  for (const rec of records) {
    const email = (rec.email ?? "").trim().toLowerCase();
    const base = { sourceId: rec.sourceId, email };
    if (!email) {
      push({ ...base, result: "skipped", reason: "no_email" });
      continue;
    }
    if (rec.passwordHash && hashKind(rec.passwordHash) === "unknown") {
      push({ ...base, result: "skipped", reason: "unsupported_hash" });
      continue;
    }
    const prior = await ctx.adapter.findOne({
      model: "importedIdentity",
      where: [
        { field: "source", value: source },
        { field: "sourceId", value: rec.sourceId },
      ],
    });
    if (prior) {
      push({ ...base, result: "skipped", reason: "already_imported" });
      continue;
    }

    const existing = await ia.findUserByEmail(email, { includeAccounts: true });
    if (!existing) {
      const user = await ia.createUser({
        email,
        name: rec.name ?? "",
        emailVerified: rec.emailVerified,
        ...(rec.createdAt ? { createdAt: rec.createdAt } : {}),
      });
      if (rec.passwordHash) {
        await ia.createAccount({ userId: user.id, providerId: "credential", accountId: user.id, password: rec.passwordHash });
      }
      await recordIdentity(ctx.adapter, user.id, source, rec.sourceId);
      push({ ...base, result: "created", userId: user.id, password: Boolean(rec.passwordHash) });
      continue;
    }

    if (!(existing.user.emailVerified && rec.emailVerified)) {
      push({ ...base, result: "skipped", reason: "email_conflict_unverified" });
      continue;
    }

    const userId: string = existing.user.id;
    const cred = existing.accounts.find(
      (a: { providerId: string; accountId: string }) => a.providerId === "credential" && a.accountId === userId,
    );
    let password: "attached" | "kept_existing" | "none" = "none";
    if (cred?.password) password = "kept_existing";
    else if (rec.passwordHash) {
      if (cred) await ia.updateAccount(cred.id, { password: rec.passwordHash });
      else await ia.createAccount({ userId, providerId: "credential", accountId: userId, password: rec.passwordHash });
      password = "attached";
    }
    await recordIdentity(ctx.adapter, userId, source, rec.sourceId);
    push({ ...base, result: "merged", userId, password });
  }
  return report;
}

async function recordIdentity(adapter: any, userId: string, source: ImportSource, sourceId: string) {
  await adapter.create({
    model: "importedIdentity",
    data: { userId, source, sourceId, createdAt: new Date() },
  });
}

/** Minimal RFC 4180 CSV parser (quoted fields, "" escapes, CRLF). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
      field = "";
    } else field += c;
  }
  if (field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

export function csvObjects(text: string): Record<string, string>[] {
  const [header, ...rows] = parseCsv(text);
  if (!header) return [];
  return rows.map((r) => Object.fromEntries(header.map((h, i) => [h.trim(), r[i] ?? ""])));
}

export function toDate(v: unknown): Date | null {
  if (v === null || v === undefined || v === "") return null;
  if (typeof v === "object" && v && "$date" in v) return toDate((v as { $date: unknown }).$date);
  const n = typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
  const d = new Date(n as string | number);
  return Number.isNaN(d.getTime()) ? null : d;
}
