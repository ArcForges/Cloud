// SPDX-License-Identifier: AGPL-3.0-only
// What a Container that did not answer tells the Worker. The Containers library answers a request for an
// instance it could not start with a plain-text response of its own (503 when the platform could provide no
// instance, 500 when the start failed, 429 when it was rate limited). Such a response proves the request was
// never forwarded to the host, so the refusal is safe to retry (effect: did not happen). A reply the host
// itself wrote is JSON or gRPC-Web, never this plain text, and a failure after forwarding stays unclassified
// because the effect of a possibly forwarded call is not known (ordinary uncertainty recovery).
import {
  classifiedPrefixBytes,
  readinessTerms,
  retryAfterSeconds,
  type Reason,
} from "../tables/cloud-tables.generated.ts";

/** The start-failure classes; their names are the generated readiness reasons (CLOUD.84 S34). */
export type StartFailure = Extract<
  Reason,
  | typeof readinessTerms.no_instance_available
  | typeof readinessTerms.start_failed
  | typeof readinessTerms.rate_limited
>;

/**
 * The opening of each library message, taken from the locked @cloudflare/containers (container.js). A test reads
 * the installed library and fails when an upgrade changes them, so the classification can never silently degrade
 * (an unrecognized response is simply not classified and keeps the generic unavailable refusal).
 */
export const noInstanceText = "There is no Container instance available at this time.";
export const startFailedText = "Failed to start container:";
export { classifiedPrefixBytes };

/** Classifies a Container response from its status, media type and the first bytes of its body. */
export function classifyStartFailure(
  status: number,
  contentType: string | null,
  prefix: string,
): StartFailure | null {
  if (contentType?.split(";")[0]?.trim().toLowerCase() !== "text/plain") return null;
  if (status === 503 && prefix.startsWith(noInstanceText))
    return readinessTerms.no_instance_available;
  if (status === 500 && prefix.startsWith(startFailedText)) return readinessTerms.start_failed;
  // The library forwards the platform's own rate-limit message; the host never answers 429 as plain text.
  if (status === 429) return readinessTerms.rate_limited;
  return null;
}

async function prefixOf(body: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length < classifiedPrefixBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      length += value.byteLength;
    }
  } finally {
    void reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(Math.min(length, classifiedPrefixBytes));
  let offset = 0;
  for (const chunk of chunks) {
    const part = chunk.subarray(0, bytes.length - offset);
    bytes.set(part, offset);
    offset += part.length;
    if (offset >= bytes.length) break;
  }
  return new TextDecoder().decode(bytes);
}

/** Classifies a response without consuming it: the caller may still read or cancel the original. */
export async function classifyStartFailureResponse(
  response: Response,
): Promise<StartFailure | null> {
  if (response.status !== 503 && response.status !== 500 && response.status !== 429) return null;
  const type = response.headers.get("content-type");
  if (type?.split(";")[0]?.trim().toLowerCase() !== "text/plain") return null;
  return classifyStartFailure(response.status, type, await prefixOf(response.clone().body));
}

/** The one HTTP 503 a public caller gets when the Container could not be used; the text is fixed and never the upstream's. */
export const containerUnavailableText = "Cloud container is temporarily unavailable.";

/**
 * The refusal for a Container that could not be used. A retry hint is attached only when a retry is meaningful: the
 * request never reached the host (a classified start failure); no other path may claim it.
 */
export function containerUnavailable(retryable: boolean): Response {
  const headers = new Headers({
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
  });
  if (retryable) headers.set("retry-after", String(retryAfterSeconds));
  return new Response(containerUnavailableText, { status: 503, headers });
}
