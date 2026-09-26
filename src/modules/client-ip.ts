/**
 * The client IP every per-IP control keys on (Better Auth's rate limiter, the
 * lockout, the send limits).
 *
 * Better Auth reads the IP from request headers only, and by default trusts a
 * single-value X-Forwarded-For. Anyone can send that header, so per-IP limits
 * were bypassed by rotating it, and behind a proxy that appends to it every
 * client fell into one shared bucket (audit F1/F3). boilauth resolves the IP
 * itself and hands Better Auth one private header, removing any copy the
 * client sent:
 *
 *   socket  (default) the connection's address, passed by the server adapter:
 *           auth.handler(request, { clientIp: socket.remoteAddress }) —
 *           boilauth/node's toNodeHandler does this. Forwarded headers ignored.
 *   proxy   the connection comes from your proxies: walk X-Forwarded-For plus
 *           the socket address from the right and take the first hop that is
 *           not in trustedProxies.
 *   header  a platform header your edge overwrites on every request
 *           (cf-connecting-ip, fly-client-ip, x-real-ip set by your nginx ...).
 *           It must hold exactly one address: a value with a comma (appended
 *           to, or sent twice) counts as no IP, so a client-chosen first value
 *           never becomes the key.
 *
 * IPv6 addresses are handed over whole; Better Auth keys them on /64
 * (advanced.ipAddress.ipv6Subnet), and boilauth's own counters use ipKey().
 * In production a request whose IP cannot be resolved is refused with 500
 * CLIENT_IP_UNAVAILABLE instead of sharing one bucket with everybody.
 */
import { BlockList, isIP } from "node:net";

export const CLIENT_IP_HEADER = "x-boilauth-client-ip";

export type ClientIpConfig =
  | { mode: "socket" }
  | { mode: "proxy"; trustedProxies: string[] }
  | { mode: "header"; header: string };

export interface RequestInfo {
  /** The connection's remote address (Node: req.socket.remoteAddress). */
  clientIp?: string | null;
}

/** A valid IP with IPv4-mapped IPv6 unwrapped, or null. */
export function cleanIp(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let ip = raw.trim();
  if (ip.startsWith("[") && ip.includes("]")) ip = ip.slice(1, ip.indexOf("]"));
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) ip = mapped[1];
  return isIP(ip) ? ip : null;
}

function expandV6(ip: string): number[] {
  const [head, tail = ""] = ip.split("::");
  const part = (s: string) => (s ? s.split(":") : []);
  let h = part(head);
  let t = part(tail);
  // Embedded IPv4 at the end (e.g. ::1.2.3.4) counts as two groups.
  const fix = (g: string[]) => {
    const last = g[g.length - 1];
    if (last && last.includes(".")) {
      const [a, b, c, d] = last.split(".").map(Number);
      g.splice(g.length - 1, 1, ((a << 8) | b).toString(16), ((c << 8) | d).toString(16));
    }
    return g;
  };
  h = fix(h);
  t = fix(t);
  const fill = ip.includes("::") ? 8 - h.length - t.length : 0;
  return [...h, ...Array(fill).fill("0"), ...t].map((g) => parseInt(g, 16) || 0);
}

/** Counter key for an IP: IPv4 as is, IPv6 as its /64 prefix. */
export function ipKey(ip: string): string {
  if (isIP(ip) !== 6) return ip;
  const g = expandV6(ip);
  return g.slice(0, 4).map((x) => x.toString(16)).join(":") + "::/64";
}

function trustList(cidrs: string[]): BlockList {
  const list = new BlockList();
  for (const c of cidrs) {
    const [addr, bits] = c.split("/");
    const ip = cleanIp(addr);
    if (!ip) throw new Error(`clientIp.trustedProxies: not an IP or CIDR: ${c}`);
    const type = isIP(ip) === 6 ? "ipv6" : "ipv4";
    if (bits === undefined) list.addAddress(ip, type);
    else list.addSubnet(ip, Number(bits), type);
  }
  return list;
}

export function clientIpResolver(cfg: ClientIpConfig = { mode: "socket" }) {
  const trusted = cfg.mode === "proxy" ? trustList(cfg.trustedProxies) : null;
  const isTrusted = (ip: string) => trusted!.check(ip, isIP(ip) === 6 ? "ipv6" : "ipv4");
  return (req: Request, info?: RequestInfo): string | null => {
    const socket = cleanIp(info?.clientIp ?? null);
    if (cfg.mode === "socket") return socket;
    if (cfg.mode === "header") {
      // One address or none: a comma means the header was appended to or repeated (Headers joins
      // repeats with ", "), and the client could have chosen the other value (re-audit L1).
      const value = req.headers.get(cfg.header);
      return value && !value.includes(",") ? cleanIp(value) : null;
    }
    // proxy: [...forwarded, socket], right to left, first hop that is not a trusted proxy.
    const chain = (req.headers.get("x-forwarded-for") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (socket) chain.push(socket);
    for (let i = chain.length - 1; i >= 0; i--) {
      const ip = cleanIp(chain[i]);
      if (!ip) return null; // garbage in the chain from a trusted hop: refuse to guess
      if (!isTrusted(ip)) return ip;
    }
    return null;
  };
}

type Handler = (req: Request) => Promise<Response>;

let warned = false;

/** Wraps Better Auth's handler: resolve the client IP, pass it in CLIENT_IP_HEADER, strip client copies. */
export function withClientIp(handler: Handler, cfg?: ClientIpConfig) {
  const resolve = clientIpResolver(cfg);
  return async (req: Request, info?: RequestInfo): Promise<Response> => {
    const ip = resolve(req, info);
    if (!ip && process.env.NODE_ENV === "production") {
      if (!warned) {
        warned = true;
        console.error(
          "boilauth: no client IP for this request. Mount with boilauth/node's toNodeHandler, pass " +
            "auth.handler(request, { clientIp }), or set clientIp to proxy/header mode.",
        );
      }
      return new Response(JSON.stringify({ code: "CLIENT_IP_UNAVAILABLE", message: "Server misconfiguration: client IP unavailable" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }
    const headers = new Headers(req.headers);
    headers.delete(CLIENT_IP_HEADER);
    if (ip) headers.set(CLIENT_IP_HEADER, ip);
    const init: RequestInit & { duplex?: "half" } = { method: req.method, headers, redirect: req.redirect, signal: req.signal };
    if (req.method !== "GET" && req.method !== "HEAD" && req.body) {
      init.body = req.body;
      init.duplex = "half";
    }
    return handler(new Request(req.url, init));
  };
}

/** The resolved client IP inside a Better Auth hook (set by withClientIp), as a counter key. */
export function clientIpKeyOf(headers: Headers | undefined | null): string | null {
  const ip = cleanIp(headers?.get(CLIENT_IP_HEADER) ?? null);
  return ip ? ipKey(ip) : null;
}
