// SPDX-License-Identifier: AGPL-3.0-only
// Public ingress of the isolated proof environment only: the browser session routes of the
// Contracts exception schema and an operator-gated driver surface. Production answers none of it.
import { BodyTooLarge, jsonResponse, readBounded, refusal } from "../private/bounded-body.ts";
import { sha256, sha256Hex } from "../private/encoding.ts";
import { isOperatorAuthorization, verifyOperatorSignature } from "./operator-signature.ts";
import { ContainerCallError, postSigned } from "./container-client.ts";
import {
  foundationContainerName,
  proofEnabled,
  type FoundationEnv,
  type WakeMessage,
} from "./types.ts";

export const sessionCookieName = "__Host-af_session";
export const maxRequestBytes = 16_384;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const scopePattern = /^proof\/[A-Za-z0-9._/-]{1,200}$/u;
const operations = new Set([
  "readiness",
  "exact",
  "guard",
  "session/issue",
  "objects/roundtrip",
  "job/start",
  "job/slice",
  "job/status",
]);

export function isProofPath(pathname: string): boolean {
  return (
    pathname.startsWith("/proof/v1/") ||
    pathname === "/session/v1/bootstrap" ||
    pathname === "/session/v1/logout"
  );
}

async function equalSecrets(provided: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([
    sha256(new TextEncoder().encode(provided)),
    sha256(new TextEncoder().encode(expected)),
  ]);
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  return difference === 0;
}

/** Only the session cookie crosses to the Container; every other cookie is discarded. */
export function sessionCookieOnly(header: string | null): string | null {
  if (!header) return null;
  const matches = header
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${sessionCookieName}=`));
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

async function forwardSession(request: Request, env: FoundationEnv): Promise<Response> {
  const url = new URL(request.url);
  const bootstrap = url.pathname === "/session/v1/bootstrap";
  if (url.search !== "") return refusal(400);
  if (request.method !== (bootstrap ? "GET" : "POST")) return refusal(405);
  const headers = new Headers();
  const cookie = sessionCookieOnly(request.headers.get("cookie"));
  if (cookie) headers.set("cookie", cookie);
  for (const name of ["origin", "x-af-csrf"]) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  // Logout carries no body; any body is refused by the host as well.
  const body =
    request.method === "POST" ? await readBounded(request.body, 1).catch(() => null) : undefined;
  if (body === null) return refusal(400);
  if (body && body.length > 0) return refusal(400);
  let response: Response;
  try {
    response = await env.CLOUD_CONTAINER.getByName(foundationContainerName).fetch(
      new Request(`http://container${url.pathname}`, { method: request.method, headers }),
    );
  } catch {
    return refusal(503);
  }
  let reply: Uint8Array;
  try {
    reply = await readBounded(response.body, maxRequestBytes);
  } catch (error) {
    if (error instanceof BodyTooLarge) return refusal(502);
    throw error;
  }
  const out = new Headers({ "cache-control": "no-store", "x-content-type-options": "nosniff" });
  for (const name of ["content-type", "set-cookie"]) {
    const value = response.headers.get(name);
    if (value !== null) out.set(name, value);
  }
  return new Response(reply as BodyInit, { status: response.status, headers: out });
}

export function newWake(jobId: string, scope: string, eventId: string): WakeMessage {
  return { v: 1, kind: "job.wake", jobId, scope, eventId };
}

async function operatorOperation(request: Request, env: FoundationEnv): Promise<Response> {
  const url = new URL(request.url);
  const operation = url.pathname.slice("/proof/v1/".length);
  const token = env.PROOF_OPERATOR_TOKEN ?? "";
  const publicKey = env.PROOF_OPERATOR_VERIFIER ?? "";
  const tokenEnabled = token.length >= 32;
  // A missing or short operator credential disables the surface instead of weakening it.
  if (!tokenEnabled && publicKey === "") return refusal(503);
  const authorizationHeader = request.headers.get("authorization");
  // A signed request is verified over its body hash, so the bounded body is read first.
  let signedBody: Uint8Array | undefined;
  if (isOperatorAuthorization(authorizationHeader)) {
    if (publicKey === "") return refusal(401);
    try {
      signedBody = await readBounded(request.body, maxRequestBytes);
    } catch (error) {
      if (error instanceof BodyTooLarge) return refusal(401);
      throw error;
    }
    const valid = await verifyOperatorSignature(
      authorizationHeader,
      {
        method: request.method,
        host: url.host,
        pathname: url.pathname,
        bodySha256Hex: await sha256Hex(signedBody),
      },
      publicKey,
      Math.floor(Date.now() / 1000),
    );
    if (!valid) return refusal(401);
  } else {
    const authorization = /^Bearer (\S+)$/u.exec(authorizationHeader ?? "");
    if (!tokenEnabled || !authorization || !(await equalSecrets(authorization[1] ?? "", token)))
      return refusal(401);
  }
  if (url.search !== "") return refusal(400);
  if (request.method !== "POST") return refusal(405);

  if (operation === "container/stop") {
    const stub = env.CLOUD_CONTAINER.getByName(foundationContainerName);
    if (!stub.stop) return refusal(501);
    await stub.stop();
    return jsonResponse(200, { stopped: true });
  }
  const wake = operation === "job/wake";
  if (!wake && !operations.has(operation)) return refusal(404);
  if (
    (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase() !==
    "application/json"
  )
    return refusal(415);
  let body: Uint8Array;
  try {
    body = signedBody ?? (await readBounded(request.body, maxRequestBytes));
  } catch (error) {
    if (error instanceof BodyTooLarge) return refusal(413);
    throw error;
  }
  if (wake) {
    let parsed: { scope?: unknown; jobId?: unknown };
    try {
      parsed = JSON.parse(new TextDecoder().decode(body)) as typeof parsed;
    } catch {
      return refusal(400);
    }
    if (
      typeof parsed.scope !== "string" ||
      !scopePattern.test(parsed.scope) ||
      typeof parsed.jobId !== "string" ||
      !uuid.test(parsed.jobId)
    )
      return refusal(400);
    await env.WAKE_QUEUE.send(newWake(parsed.jobId, parsed.scope, crypto.randomUUID()));
    return jsonResponse(200, { wakeEnqueued: true });
  }
  // Only the Worker interprets autoWake (a job start normally queues its first wake); it never reaches the host.
  let autoWake = true;
  if (operation === "job/start") {
    try {
      const parsed = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
      if ("autoWake" in parsed) {
        if (typeof parsed.autoWake !== "boolean") return refusal(400);
        autoWake = parsed.autoWake;
        delete parsed.autoWake;
        body = new TextEncoder().encode(JSON.stringify(parsed));
      }
    } catch {
      return refusal(400);
    }
  }
  let reply: { status: number; body: Uint8Array };
  try {
    reply = await postSigned(env, operation, body, { requestId: crypto.randomUUID() });
  } catch (error) {
    if (error instanceof ContainerCallError) return jsonResponse(502, { error: "unavailable" });
    return jsonResponse(503, { error: "unavailable" });
  }
  if (operation === "job/start" && reply.status === 200 && !autoWake) {
    try {
      const started = JSON.parse(new TextDecoder().decode(reply.body)) as Record<string, unknown>;
      return jsonResponse(200, { ...started, wakeEnqueued: false });
    } catch {
      return jsonResponse(502, { error: "unavailable" });
    }
  }
  if (operation === "job/start" && reply.status === 200) {
    try {
      const started = JSON.parse(new TextDecoder().decode(reply.body)) as {
        jobId?: unknown;
        scope?: unknown;
      };
      if (
        typeof started.jobId === "string" &&
        uuid.test(started.jobId) &&
        typeof started.scope === "string" &&
        scopePattern.test(started.scope)
      ) {
        await env.WAKE_QUEUE.send(newWake(started.jobId, started.scope, crypto.randomUUID()));
        return new Response(JSON.stringify({ ...started, wakeEnqueued: true }), {
          status: 200,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
        });
      }
    } catch {
      // The job exists but its wake could not be queued: report that honestly.
      return jsonResponse(502, { error: "wake_not_enqueued" });
    }
    return jsonResponse(502, { error: "wake_not_enqueued" });
  }
  return new Response(reply.body as BodyInit, {
    status: reply.status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

export async function handleProof(request: Request, env: FoundationEnv): Promise<Response> {
  if (!proofEnabled(env)) return refusal(404);
  const pathname = new URL(request.url).pathname;
  if (pathname.startsWith("/session/v1/")) return forwardSession(request, env);
  return operatorOperation(request, env);
}
