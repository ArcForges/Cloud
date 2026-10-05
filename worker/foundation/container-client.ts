// SPDX-License-Identifier: AGPL-3.0-only
// Signed Worker-to-Container calls (the w2c direction) to the private foundation routes.
import { sha256Hex } from "../private/encoding.ts";
import { loadKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import { newNonce, sign } from "../private/signing.ts";
import type { ContainerNamespaceLike, WakeMessage } from "./types.ts";
import { foundationContainerName } from "./types.ts";

export const foundationRoutePrefix = "/internal/foundation/v1/";
export const maxReplyBytes = 65_536;

export interface ContainerClientEnv extends PrivateKeyEnv {
  CLOUD_CONTAINER: ContainerNamespaceLike;
}

export class ContainerCallError extends Error {}

/**
 * The body of the private job-slice call. It carries the wake's correlation identity and causation id next to the
 * identifiers it already had (CLOUD.69), as members of the signed JSON body: the signature covers them and the host
 * refuses any value that is not a canonical lowercase UUID. The slice's own direct cause is `eventId`.
 */
export function jobSliceBody(
  wake: WakeMessage,
  limits: { maxItems: number; maxMilliseconds: number },
): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      scope: wake.scope,
      jobId: wake.jobId,
      eventId: wake.eventId,
      correlationId: wake.correlationId,
      causationId: wake.causationId,
      maxItems: limits.maxItems,
      maxMilliseconds: limits.maxMilliseconds,
    }),
  );
}

export async function postSigned(
  env: ContainerClientEnv,
  operation: string,
  body: Uint8Array,
  options: { requestId: string; nowMs?: () => number; signal?: AbortSignal },
): Promise<{ status: number; contentType: string | null; body: Uint8Array }> {
  const keys = loadKeys(env, "W2C");
  if (!keys) throw new ContainerCallError("The Container signing key is not configured.");
  const pathAndQuery = `${foundationRoutePrefix}${operation}`;
  const headers = await sign(
    {
      method: "POST",
      pathAndQuery,
      bodySha256Hex: await sha256Hex(body),
      requestId: options.requestId,
      time: String(Math.floor((options.nowMs ?? Date.now)() / 1000)),
      nonce: newNonce(),
    },
    keys.current,
  );
  const response = await env.CLOUD_CONTAINER.getByName(foundationContainerName).fetch(
    new Request(`http://container${pathAndQuery}`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: body as BodyInit,
      signal: options.signal,
    }),
  );
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxReplyBytes) {
        void reader.cancel().catch(() => {});
        throw new ContainerCallError("The Container reply is too large.");
      }
      chunks.push(value);
    }
  }
  const reply = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    reply.set(chunk, offset);
    offset += chunk.length;
  }
  return {
    status: response.status,
    contentType: response.headers.get("content-type"),
    body: reply,
  };
}
