/**
 * boilauth/node — mount the auth instance on a Node server with the socket
 * address as the client IP (the default clientIp mode). Better Auth's own
 * better-auth/node toNodeHandler does not pass it, so per-IP controls would
 * see no IP.
 *
 *   import { toNodeHandler } from "boilauth/node";
 *   app.all("/api/auth/*splat", toNodeHandler(auth));
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { getRequest, setResponse } from "better-call/node";
import type { RequestInfo } from "./modules/client-ip.js";

type AuthLike = { handler: (req: Request, info?: RequestInfo) => Promise<Response> };

export function toNodeHandler(auth: AuthLike) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const proto = (req.socket as { encrypted?: boolean }).encrypted ? "https" : "http";
    const host = req.headers[":authority"] ?? req.headers.host;
    const request = getRequest({ base: `${proto}://${host}`, request: req });
    await setResponse(res, await auth.handler(request, { clientIp: req.socket.remoteAddress ?? null }));
  };
}
