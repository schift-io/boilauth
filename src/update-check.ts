/**
 * Consent-based security version signal.
 *
 * Nothing is fetched unless the operator opts in (explicit call, or
 * BOILAUTH_UPDATE_CHECK=1 with BOILAUTH_ADVISORY_URL set). The request sends
 * no user data — only a GET of the advisory feed; the version comparison is
 * done locally. The feed is a JSON document:
 *
 *   { "advisories": [ { "id": "BA-2026-001", "affected": "<0.2.0",
 *                       "fixed": "0.2.0", "severity": "high", "summary": "..." } ] }
 *
 * `affected` supports "<X.Y.Z" and "<=X.Y.Z". A hosted feed is not live yet;
 * until then point the URL at your own copy (or a file:// path for tests).
 */
import { readFile } from "node:fs/promises";

export interface Advisory {
  id: string;
  affected: string;
  fixed?: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
}

function cmp(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

export function isAffected(version: string, range: string): boolean {
  const m = /^(<=?)\s*(\d+\.\d+\.\d+)$/.exec(range.trim());
  if (!m) return false;
  const c = cmp(version, m[2]);
  return m[1] === "<" ? c < 0 : c <= 0;
}

export async function checkAdvisories(version: string, feedUrl: string): Promise<Advisory[]> {
  let text: string;
  if (feedUrl.startsWith("file://")) text = await readFile(new URL(feedUrl), "utf8");
  else {
    const res = await fetch(feedUrl, { headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`advisory feed ${res.status}`);
    text = await res.text();
  }
  const feed = JSON.parse(text) as { advisories?: Advisory[] };
  return (feed.advisories ?? []).filter((a) => isAffected(version, a.affected));
}

/** Runs only when the operator opted in via env. Returns null when not opted in. */
export async function checkAdvisoriesIfOptedIn(version: string, env = process.env) {
  if (env.BOILAUTH_UPDATE_CHECK !== "1" || !env.BOILAUTH_ADVISORY_URL) return null;
  return checkAdvisories(version, env.BOILAUTH_ADVISORY_URL);
}
