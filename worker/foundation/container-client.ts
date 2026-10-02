// SPDX-License-Identifier: AGPL-3.0-only
// Signed Worker-to-Container calls (the w2c direction) to the private foundation routes.
import { sha256Hex } from "../private/encoding.ts";
import { loadKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import { newNonce, sign } from "../private/signing.ts";
import type { ContainerNamespaceLike } from "./types.ts";
import { foundationContainerName } from "./types.ts";

export const foundationRoutePrefix = "/internal/foundation/v1/";
export const maxReplyBytes = 65_536;

export interface ContainerClientEnv extends PrivateKeyEnv {
  CLOUD_CONTAINER: ContainerNamespaceLike;
}

export class ContainerCallError extends Error {}

export async function postSigned(
  env: ContainerClientEnv,
  operation: string,
  body: Uint8Array,
  options: { requestId: string; nowMs?: () => number; signal?: AbortSignal },
): Promise<{ status: number; body: Uint8Array }> {
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
  return { status: response.status, body: reply };
}
