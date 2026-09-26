/**
 * Unknown auth paths end here, before Better Auth (re-audit C4).
 *
 * Better Auth rate-limits every request under its base path, keyed by client
 * IP and path, before it knows whether the path exists. Each made-up path
 * (/api/auth/x1, /x2, ...) therefore created a counter: a database row per
 * request, or an entry in the in-memory store, which holds 100 000 entries and
 * drops the oldest when full — so a flood of made-up paths pushed out the
 * counter of a throttled sign-in and reopened it. Answering 404 for anything
 * that is not an endpoint of this instance keeps the key space to real paths.
 */
type Endpoint = { path?: unknown };
type Handler<I> = (req: Request, info?: I) => Promise<Response>;

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Matches a pathname (base path included) against the instance's endpoint paths. */
export function knownPathMatcher(api: Record<string, unknown>, basePath = "/api/auth"): (pathname: string) => boolean {
  const base = basePath.replace(/\/+$/, "");
  const patterns = Object.values(api)
    .map((f) => (typeof f === "function" ? (f as Endpoint).path : undefined))
    .filter((p): p is string => typeof p === "string")
    .map((p) => new RegExp(`^${escape(base)}${p.split("/").map((seg) => (seg.startsWith(":") ? "[^/]+" : escape(seg))).join("/")}$`));
  return (pathname) => {
    const path = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
    return patterns.some((re) => re.test(path));
  };
}

/**
 * `paramOk` checks path parameter values that are cheap to know (a callback for a provider this
 * instance does not have): those end with the same 404, before any rate-limit key exists.
 */
export function withKnownPaths<I>(
  handler: Handler<I>,
  isKnown: (pathname: string) => boolean,
  paramOk: (pathname: string) => Promise<boolean> | boolean = () => true,
): Handler<I> {
  return async (req, info) => {
    const { pathname } = new URL(req.url);
    if (!isKnown(pathname) || !(await paramOk(pathname))) return new Response(null, { status: 404, statusText: "Not Found" });
    return handler(req, info);
  };
}
