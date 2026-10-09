// SPDX-License-Identifier: AGPL-3.0-only
// Local opt-in proof 1 of HAR.40 (P2-021 item 5, the Workers AI binding): the real ai.internal handler runs under Node against a FIXTURE
// Workers AI binding. It measures what the adapter itself does: the SSE pass-through (byte-identical, delivered as it is produced), the
// adapter overhead on a JSON answer, the 429 path (a binding failure is a single 502 that is never retried), and every fail-closed refusal
// before the binding is called. It does NOT measure Workers AI: the real binding latency, the gpt-oss tier, the real 429 semantics and any
// pre-dispatch counting need a deployed Worker with the AI binding, which is an operator run recorded in liveNotRun. No credential is read.
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hardByteCap } from "../../worker/ai/internal/envelope.ts";
import { type AiBinding, handleAiInternal } from "../../worker/ai/internal/handler.ts";
import {
  assertLocalOptIn,
  check,
  evidence,
  percentile,
  type ProofCheck,
  type ProofEvidence,
  writeEvidence,
} from "./harness-proof-evidence.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const model = "@cf/openai/gpt-oss-20b";
const frozenRequest = {
  messages: [{ role: "user", content: "Say hello to Ada." }],
  tools: [{ type: "function", function: { name: "say_hello", strict: true } }],
  tool_choice: { type: "function", function: { name: "say_hello" } },
  parallel_tool_calls: false,
  temperature: 0,
  max_tokens: 1024,
  reasoning_effort: "low",
};
const latencySamples = 50;
const sseChunkCount = 40;
const sseIntervalMs = 25;

interface Recorded {
  readonly model: string;
  readonly request: Record<string, unknown>;
}

/** A fixture binding: it records every call so the proof can show that a refusal never reached it. */
class FixtureBinding implements AiBinding {
  readonly calls: Recorded[] = [];
  private readonly behaviour: (request: Record<string, unknown>) => unknown;
  constructor(behaviour: (request: Record<string, unknown>) => unknown) {
    this.behaviour = behaviour;
  }
  async run(callModel: string, inputs: Record<string, unknown>): Promise<unknown> {
    this.calls.push({ model: callModel, request: inputs });
    return this.behaviour(inputs);
  }
}

function envelopeBody(overrides: Record<string, unknown> = {}, request: unknown = frozenRequest) {
  return JSON.stringify({
    v: 1,
    model,
    admittedModels: [model],
    maxBodyBytes: 65_536,
    maxResponseBytes: 262_144,
    request,
    ...overrides,
  });
}

function postEnvelope(body: string | Uint8Array, host = "ai.internal"): Request {
  return new Request(`https://${host}/v1/run`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** The SSE body a streaming Workers AI answer would use; each event is produced after a delay, so pass-through timing is observable. */
function sseSource(): { stream: ReadableStream<Uint8Array>; emitted: Uint8Array[] } {
  const encoder = new TextEncoder();
  const emitted: Uint8Array[] = [];
  let index = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (index >= sseChunkCount) {
        const done = encoder.encode("data: [DONE]\n\n");
        emitted.push(done);
        controller.enqueue(done);
        controller.close();
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, sseIntervalMs));
      const chunk = encoder.encode(
        `data: ${JSON.stringify({ response: `token-${index}`, p: index })}\n\n`,
      );
      index += 1;
      emitted.push(chunk);
      controller.enqueue(chunk);
    },
  });
  return { stream, emitted };
}

async function readAll(
  response: Response,
): Promise<{ bytes: Uint8Array; chunks: number; firstByteMs: number; totalMs: number }> {
  const started = performance.now();
  const reader = response.body?.getReader();
  const parts: Uint8Array[] = [];
  let firstByteMs = Number.NaN;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (Number.isNaN(firstByteMs)) firstByteMs = performance.now() - started;
      parts.push(value);
    }
  }
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }
  return { bytes, chunks: parts.length, firstByteMs, totalMs: performance.now() - started };
}

async function errorBody(response: Response): Promise<string> {
  return ((await response.json()) as { error?: string }).error ?? "";
}

export async function runAiBindingProof(now = new Date()): Promise<ProofEvidence> {
  const checks: ProofCheck[] = [];

  // 1. The frozen request reaches the binding unchanged and the answer comes back unchanged (JSON).
  const jsonAnswer = {
    response: "Hello, Ada.",
    usage: { prompt_tokens: 42, completion_tokens: 7 },
  };
  const jsonBinding = new FixtureBinding(() => jsonAnswer);
  const jsonResponse = await handleAiInternal(postEnvelope(envelopeBody()), { AI: jsonBinding });
  const jsonText = await jsonResponse.text();
  const forwarded = jsonBinding.calls[0];
  checks.push(
    check(
      "frozen-request-forwarded-unchanged",
      jsonResponse.status === 200 &&
        jsonBinding.calls.length === 1 &&
        JSON.stringify(forwarded?.request) === JSON.stringify(frozenRequest) &&
        forwarded?.model === model,
      "one binding call with the frozen request and model",
      `status ${jsonResponse.status}, calls ${jsonBinding.calls.length}`,
    ),
  );
  checks.push(
    check(
      "json-answer-returned-unchanged",
      jsonText === JSON.stringify(jsonAnswer),
      "the binding answer JSON-encoded without alteration",
      jsonText.length > 0 ? `${jsonText.length} bytes` : "empty",
    ),
  );

  // 2. Adapter overhead on a JSON answer (fixture binding: this is the adapter's own cost, not Workers AI latency).
  const samples: number[] = [];
  const latencyBinding = new FixtureBinding(() => jsonAnswer);
  let latencyFailures = 0;
  for (let index = 0; index < latencySamples; index += 1) {
    const started = performance.now();
    const response = await handleAiInternal(postEnvelope(envelopeBody()), { AI: latencyBinding });
    await response.arrayBuffer();
    samples.push(performance.now() - started);
    if (response.status !== 200) latencyFailures += 1;
  }
  samples.sort((left, right) => left - right);
  checks.push(
    check(
      "adapter-overhead-json-answered-every-time",
      latencyFailures === 0,
      `${latencySamples} of ${latencySamples} calls answered 200`,
      `${latencySamples - latencyFailures} of ${latencySamples} answered 200; p50 ${percentile(samples, 0.5).toFixed(3)} ms, p95 ${percentile(samples, 0.95).toFixed(3)} ms (fixture binding)`,
    ),
  );

  // 3. SSE pass-through: byte-identical, and delivered while the binding is still producing (first byte well before the last).
  const source = sseSource();
  const streamBinding = new FixtureBinding(() => source.stream);
  const streamed = await handleAiInternal(
    postEnvelope(envelopeBody({}, { ...frozenRequest, stream: true })),
    { AI: streamBinding },
  );
  const streamedRead = await readAll(streamed);
  const emittedBytes = Buffer.concat(source.emitted.map((part) => Buffer.from(part)));
  const emittedHash = sha256(new Uint8Array(emittedBytes));
  const receivedHash = sha256(streamedRead.bytes);
  checks.push(
    check(
      "sse-pass-through-byte-identical",
      streamed.status === 200 &&
        streamed.headers.get("content-type") === "text/event-stream" &&
        emittedHash === receivedHash,
      `200 text/event-stream; sha256 ${emittedHash.slice(0, 16)}...`,
      `status ${streamed.status}; sha256 ${receivedHash.slice(0, 16)}...; ${streamedRead.bytes.byteLength} bytes in ${streamedRead.chunks} chunks`,
    ),
  );
  checks.push(
    check(
      "sse-first-byte-before-stream-end",
      streamedRead.firstByteMs < streamedRead.totalMs / 2,
      "first byte arrives before half of the producer time (pass-through, not buffered)",
      `first byte ${streamedRead.firstByteMs.toFixed(1)} ms of ${streamedRead.totalMs.toFixed(1)} ms total`,
    ),
  );

  // 4. SSE answer over the C#-supplied response cap is cut off mid-stream, not delivered in full.
  const capSource = sseSource();
  const capped = await handleAiInternal(
    postEnvelope(envelopeBody({ maxResponseBytes: 256 }, { ...frozenRequest, stream: true })),
    { AI: new FixtureBinding(() => capSource.stream) },
  );
  let cutOff = false;
  let cappedBytes = 0;
  try {
    const cappedRead = await readAll(capped);
    cappedBytes = cappedRead.bytes.byteLength;
  } catch {
    cutOff = true;
  }
  checks.push(
    check(
      "sse-over-response-cap-is-cut-off",
      capped.status === 200 && (cutOff || cappedBytes <= 256),
      "the stream errors once the C#-supplied cap is passed; never more than the cap is delivered",
      `status ${capped.status}; ${cutOff ? "stream errored" : `${cappedBytes} bytes delivered`}`,
    ),
  );

  // 5. 429 from the binding: one 502, never retried, reported as a possibly dispatched effect (429 semantics are unverified here).
  const rateBinding = new FixtureBinding(() => {
    throw Object.assign(new Error("Too many requests"), { status: 429 });
  });
  const rate = await handleAiInternal(postEnvelope(envelopeBody()), { AI: rateBinding });
  const rateError = await errorBody(rate);
  checks.push(
    check(
      "binding-429-is-one-502-never-retried",
      rate.status === 502 && rateError === "ai.upstream_failed" && rateBinding.calls.length === 1,
      "502 ai.upstream_failed after exactly one binding call",
      `status ${rate.status}, error ${rateError}, binding calls ${rateBinding.calls.length}`,
    ),
  );

  // 6. Refusals before the binding: nothing is called.
  const refusals: Array<{ name: string; request: Request; status: number; code: string }> = [
    {
      name: "model-outside-admitted-set-refused",
      request: postEnvelope(envelopeBody({ admittedModels: ["@cf/meta/other"] })),
      status: 403,
      code: "ai.model_not_admitted",
    },
    {
      name: "body-over-c-sharp-cap-refused",
      request: postEnvelope(envelopeBody({ maxBodyBytes: 64 })),
      status: 413,
      code: "ai.body_over_cap",
    },
    {
      name: "body-over-hard-ceiling-refused",
      request: postEnvelope(new Uint8Array(hardByteCap + 1)),
      status: 413,
      code: "ai.body_too_large",
    },
    {
      name: "other-host-refused",
      request: postEnvelope(envelopeBody(), "example.com"),
      status: 404,
      code: "ai.not_found",
    },
    {
      name: "get-method-refused",
      request: new Request("https://ai.internal/v1/run", { method: "GET" }),
      status: 405,
      code: "ai.method_not_allowed",
    },
  ];
  for (const refusal of refusals) {
    const binding = new FixtureBinding(() => ({ response: "must not be reached" }));
    const response = await handleAiInternal(refusal.request, { AI: binding });
    const code = await errorBody(response);
    checks.push(
      check(
        refusal.name,
        response.status === refusal.status && code === refusal.code && binding.calls.length === 0,
        `${refusal.status} ${refusal.code} with zero binding calls`,
        `${response.status} ${code} with ${binding.calls.length} binding calls`,
      ),
    );
  }

  return evidence({
    proof: "ai-binding",
    realness: "node-fixture",
    checks,
    liveNotRun: [
      "Workers AI binding latency on the deployed Worker (operator: deploy the proof environment with the AI binding and time ai.internal calls).",
      "gpt-oss tier and its requests-per-minute admission (operator: observe the account tier; no tier is assumed here).",
      "Real 429 semantics, including whether a rate-limited call was counted or dispatched (operator: provoke the limit on the proof account and record the response).",
      "Real SSE pass-through across the Cloudflare edge (operator: stream one answer through the deployed Worker).",
    ],
    notes: [
      "The binding is a fixture (node-fixture realness). The checks prove the adapter's own contract, not Workers AI behaviour.",
      "A 429 is classified as a possibly dispatched effect (502) until the live run shows otherwise; the retry rule (no automatic retry after dispatch) is therefore kept.",
    ],
    environment: { node: process.version, model, sseChunks: String(sseChunkCount) },
    now,
  });
}

export async function main(): Promise<void> {
  assertLocalOptIn();
  const record = await runAiBindingProof();
  const file = await writeEvidence(root, record);
  console.log(`ai-binding: ${record.status} (${record.checks.length} checks) -> ${file}`);
  if (record.status !== "passed") process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await main();
}
