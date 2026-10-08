// SPDX-License-Identifier: AGPL-3.0-only
// The ai.internal outbound handler: the thin transport between the proof-free production container and the Workers AI binding (P2-021 item 1).
// It admits the C# envelope (envelope.ts), calls env.AI.run once with the frozen request, and returns the answer unchanged within the
// C#-supplied response cap. It serves only POST /v1/run on ai.internal, forwards no request header and no token, and calls the binding
// only after every refusal above has passed. A failure after the call is a 502: C# treats it as a possibly dispatched effect.
import { aiHost, aiRunPath, type AiEnvelope, hardByteCap, parseEnvelope } from "./envelope.ts";

/** The subset of the Workers AI binding this handler uses. The model and the inputs are the frozen values, passed unchanged. */
export interface AiBinding {
  run(model: string, inputs: Record<string, unknown>): Promise<unknown>;
}

export interface AiEnv {
  readonly AI?: AiBinding;
}

function jsonError(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const [mediaType = "", ...parameters] = value.split(";").map((part) => part.trim());
  if (mediaType.toLowerCase() !== "application/json") return false;
  return parameters.every((parameter) => /^charset=(?:"?utf-8"?)$/iu.test(parameter));
}

/** Reads the whole body up to a limit; null when it is longer than the limit (the rest is cancelled, never buffered). */
async function readBounded(
  body: ReadableStream<Uint8Array> | null,
  limit: number,
): Promise<Uint8Array | null> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/** Passes stream chunks through unchanged and errors the stream as soon as the C#-supplied response cap is exceeded. */
function capStream(limit: number): TransformStream<Uint8Array, Uint8Array> {
  let seen = 0;
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.byteLength;
      if (seen > limit) {
        controller.error(new Error("ai.response_too_large"));
        return;
      }
      controller.enqueue(chunk);
    },
  });
}

async function runBinding(binding: AiBinding, envelope: AiEnvelope): Promise<unknown> {
  return binding.run(envelope.model, envelope.request);
}

export async function handleAiInternal(request: Request, env: AiEnv): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== aiHost || url.pathname !== aiRunPath) return jsonError(404, "ai.not_found");
  if (request.method !== "POST") return jsonError(405, "ai.method_not_allowed");
  if (!isJsonContentType(request.headers.get("content-type")))
    return jsonError(415, "ai.content_type");

  const body = await readBounded(request.body, hardByteCap);
  if (body === null) return jsonError(413, "ai.body_too_large");
  const parsed = parseEnvelope(body);
  if (!parsed.ok) return jsonError(parsed.status, parsed.code);

  const binding = env.AI;
  if (binding === undefined) return jsonError(503, "ai.binding_missing");

  let result: unknown;
  try {
    result = await runBinding(binding, parsed.value);
  } catch {
    // The binding may have dispatched the call: this is a possibly dispatched effect, reported as such and never retried here.
    return jsonError(502, "ai.upstream_failed");
  }

  if (parsed.value.stream) {
    if (!(result instanceof ReadableStream)) return jsonError(502, "ai.response_invalid");
    return new Response(result.pipeThrough(capStream(parsed.value.maxResponseBytes)), {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  }
  if (result instanceof ReadableStream) return jsonError(502, "ai.response_invalid");
  const text = JSON.stringify(result);
  if (text === undefined) return jsonError(502, "ai.response_invalid");
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength > parsed.value.maxResponseBytes)
    return jsonError(502, "ai.response_too_large");
  return new Response(bytes, { status: 200, headers: { "content-type": "application/json" } });
}
