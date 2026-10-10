// SPDX-License-Identifier: AGPL-3.0-only
// What the Worker checks and forwards of a credential for a session-authenticated method. The Worker
// refuses what can be refused from the headers alone, before any Container wakes; the C# host validates
// the credential against the authoritative store and is the only authority. Nothing here proves a session.
import {
  bearerCredentialPattern as bearerPattern,
  edgeGuard,
  sessionTokenPattern as cookiePattern,
  sessionTokenPattern as csrfPattern,
} from "../tables/cloud-tables.generated.ts";
import { grpcStatus } from "./errors.ts";

export const sessionCookieName = edgeGuard.sessionCookieName;
export const csrfHeader = edgeGuard.csrfHeader;

export type EdgeCredentials =
  { ok: true; headers: Record<string, string> } | { ok: false; code: number; message: string };

const unauthenticated: EdgeCredentials = {
  ok: false,
  code: grpcStatus.unauthenticated,
  message: "auth.unauthenticated",
};
const denied: EdgeCredentials = {
  ok: false,
  code: grpcStatus.permissionDenied,
  message: "perm.resource_denied",
};

/** The one session cookie value; absent, repeated or malformed means no cookie credential. */
function sessionCookie(header: string | null): string | null {
  if (header === null) return null;
  let found: string | null = null;
  for (const pair of header.split(";")) {
    const text = pair.trim();
    const separator = text.indexOf("=");
    if (separator <= 0 || text.slice(0, separator) !== sessionCookieName) continue;
    if (found !== null) return null;
    found = text.slice(separator + 1);
  }
  return found !== null && cookiePattern.test(found) ? found : null;
}

/**
 * Selects exactly one credential and returns the only headers that may reach the Container. A bearer
 * is forwarded as given; a cookie additionally needs the exact configured Origin and a well-formed CSRF
 * token, because every RPC is an unsafe request. Both kinds together are refused as ambiguous.
 */
export function edgeCredentials(
  request: Request,
  allowedOrigin: string | undefined,
): EdgeCredentials {
  const headers = request.headers;
  const authorization = headers.get("authorization");
  const cookie = sessionCookie(headers.get("cookie"));
  if (authorization !== null && cookie !== null) return unauthenticated;
  if (authorization !== null) {
    const match = bearerPattern.exec(authorization);
    return match ? { ok: true, headers: { authorization } } : unauthenticated;
  }
  if (cookie === null) return unauthenticated;
  const origin = headers.get("origin");
  if (allowedOrigin === undefined || allowedOrigin === "" || origin !== allowedOrigin)
    return denied;
  const csrf = headers.get(csrfHeader);
  if (csrf === null || !csrfPattern.test(csrf)) return denied;
  return {
    ok: true,
    headers: { cookie: `${sessionCookieName}=${cookie}`, origin, [csrfHeader]: csrf },
  };
}
