// SPDX-License-Identifier: AGPL-3.0-only
// Pins the ai.internal thin adapter of HAR.40: it admits only the C#-supplied envelope, refuses every violation before the Workers AI
// binding is called, forwards the frozen request unchanged, returns the answer within the C#-supplied cap and never forwards a header
// or a token. The adapter is transport only; the admission and the budget decisions are C# and are tested in ArcForges.Cloud.Tests.
import assert from "node:assert/strict";
import test from "node:test";
import { parseEnvelope } from "../../worker/ai/internal/envelope.ts";
import { type AiBinding, handleAiInternal } from "../../worker/ai/internal/handler.ts";

const model = "@cf/openai/gpt-oss-20b";
const frozenRequest = {
  messages: [{ role: "user", content: '{"name":"Ada"}' }],
  tools: [{ type: "function", function: { name: "say_hello", strict: true } }],
  tool_choice: { type: "function", function: { name: "say_hello" } },
  parallel_tool_calls: false,
  temperature: 0,
  max_tokens: 1024,
  reasoning_effort: "low",
  stream: false,
};

function envelope(
  overrides: Record<string, unknown> = {},
  request: unknown = frozenRequest,
): string {
  return JSON.stringify({
    v: 1,
    model,
    admittedModels: [model],
    maxBodyBytes: 65_536,
    maxResponseBytes: 65_536,
    request,
    ...overrides,
  });
}

interface Recorder extends AiBinding {
  readonly calls: { model: string; inputs: Record<string, unknown> }[];
}

function binding(result: unknown | ((model: string) => unknown)): Recorder {
  const calls: { model: string; inputs: Record<string, unknown> }[] = [];
  return {
    calls,
    async run(name, inputs) {
      calls.push({ model: name, inputs });
      if (typeof result === "function") return (result as (value: string) => unknown)(name);
      return result;
    },
  };
}

function post(
  body: string | Uint8Array,
  headers: Record<string, string> = { "content-type": "application/json" },
) {
  return new Request("http://ai.internal/v1/run", {
    method: "POST",
    headers,
    body: body as BodyInit,
  });
}

async function call(
  request: Request,
  ai?: AiBinding,
): Promise<{ status: number; body: unknown; text: string }> {
  const response = await handleAiInternal(request, ai === undefined ? {} : { AI: ai });
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // A streamed body is returned as text.
  }
  return { status: response.status, body, text };
}

test("an admitted envelope is forwarded to the binding unchanged and its answer is returned unchanged", async () => {
  const answer = { result: { response: "ok" }, success: true };
  const ai = binding(answer);
  const result = await call(post(envelope()), ai);
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, answer);
  assert.equal(ai.calls.length, 1);
  assert.equal(ai.calls[0]?.model, model);
  assert.deepEqual(
    ai.calls[0]?.inputs,
    frozenRequest,
    "the frozen request reaches the binding unchanged",
  );
  assert.equal(result.text, JSON.stringify(answer));
});

test("only the POST method on the exact path and host is served", async () => {
  const ai = binding({});
  assert.equal(
    (await call(new Request("http://ai.internal/v1/run", { method: "GET" }), ai)).status,
    405,
  );
  assert.equal(
    (
      await call(
        new Request("http://ai.internal/v1/other", { method: "POST", body: envelope() }),
        ai,
      )
    ).status,
    404,
  );
  assert.equal(
    (
      await call(
        new Request("http://storage.internal/v1/run", { method: "POST", body: envelope() }),
        ai,
      )
    ).status,
    404,
  );
  assert.equal(ai.calls.length, 0, "no refused route reaches the binding");
});

test("a body that is not JSON, or is not the closed envelope shape, is refused before the binding", async () => {
  const ai = binding({});
  const refused = [
    "not json",
    "[]",
    envelope({ extra: 1 }),
    envelope({ v: 2 }),
    envelope({ model: "bad model" }),
    envelope({ admittedModels: [] }),
    envelope({ admittedModels: Array.from({ length: 17 }, (_, i) => `m${i}`) }),
    envelope({ maxBodyBytes: 0 }),
    envelope({ maxBodyBytes: 1_048_577 }),
    envelope({ maxResponseBytes: 1.5 }),
    envelope({}, [1, 2]),
  ];
  for (const body of refused) {
    const result = await call(post(body), ai);
    assert.equal(result.status, 400, `refused: ${body}`);
  }
  assert.equal(ai.calls.length, 0);
});

test("the content type must be JSON, and a charset other than UTF-8 is refused", async () => {
  const ai = binding({});
  assert.equal((await call(post(envelope(), { "content-type": "text/plain" }), ai)).status, 415);
  assert.equal(
    (await call(post(envelope(), { "content-type": "application/json; charset=latin1" }), ai))
      .status,
    415,
  );
  assert.equal((await call(post(envelope(), {}), ai)).status, 415);
  assert.equal(ai.calls.length, 0);
});

test("a model outside the C#-supplied admitted set is refused fail-closed before the binding", async () => {
  const ai = binding({});
  const result = await call(
    post(envelope({ model: "@cf/other/model", admittedModels: [model] })),
    ai,
  );
  assert.equal(result.status, 403);
  assert.deepEqual(result.body, { error: "ai.model_not_admitted" });
  assert.equal(ai.calls.length, 0);
});

test("a body over the C#-supplied byte cap is refused with 413 before the binding", async () => {
  const ai = binding({});
  const body = envelope({ maxBodyBytes: 200 });
  assert.ok(new TextEncoder().encode(body).byteLength > 200);
  assert.equal((await call(post(body), ai)).status, 413);
  assert.equal(ai.calls.length, 0);
});

test("a body over the hard ceiling is refused before it is decoded", async () => {
  const ai = binding({});
  const oversized = new Uint8Array(1_048_577).fill(0x20);
  assert.equal((await call(post(oversized), ai)).status, 413);
  assert.equal(ai.calls.length, 0);
});

test("a response over the C#-supplied cap is a 502 after the call, which C# reports as possibly dispatched", async () => {
  const ai = binding({ text: "x".repeat(4_000) });
  const result = await call(post(envelope({ maxResponseBytes: 1_000 })), ai);
  assert.equal(result.status, 502);
  assert.deepEqual(result.body, { error: "ai.response_too_large" });
  assert.equal(ai.calls.length, 1);
});

test("a failed binding call is a 502 and is never retried by the adapter", async () => {
  const ai: AiBinding & { calls: number } = {
    calls: 0,
    async run() {
      this.calls += 1;
      throw new Error("provider failure with a secret detail");
    },
  };
  const result = await call(post(envelope()), ai);
  assert.equal(result.status, 502);
  assert.deepEqual(result.body, { error: "ai.upstream_failed" });
  assert.equal(
    result.text.includes("secret"),
    false,
    "the provider detail never reaches the caller",
  );
  assert.equal(ai.calls, 1);
});

test("a missing binding fails closed with 503 and nothing is called", async () => {
  const result = await call(post(envelope()));
  assert.equal(result.status, 503);
  assert.deepEqual(result.body, { error: "ai.binding_missing" });
});

test("a streamed request streams the binding's answer back unchanged within the cap", async () => {
  const chunks = [
    new TextEncoder().encode("data: one\n\n"),
    new TextEncoder().encode("data: two\n\n"),
  ];
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
  const ai = binding(stream);
  const request = { ...frozenRequest, stream: true };
  const response = await handleAiInternal(post(envelope({}, request)), { AI: ai });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/event-stream");
  assert.equal(await response.text(), "data: one\n\ndata: two\n\n");
  assert.deepEqual(ai.calls[0]?.inputs, request);
});

test("a streamed answer over the cap is cut off mid-stream rather than delivered in full", async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("0123456789"));
      controller.enqueue(new TextEncoder().encode("0123456789"));
      controller.close();
    },
  });
  const request = { ...frozenRequest, stream: true };
  const response = await handleAiInternal(post(envelope({ maxResponseBytes: 12 }, request)), {
    AI: binding(stream),
  });
  assert.equal(response.status, 200);
  await assert.rejects(() => response.text());
});

test("a stream is refused as an invalid answer when the request did not ask for one, and a stream answer is never JSON-encoded", async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.close();
    },
  });
  const result = await call(post(envelope()), binding(stream));
  assert.equal(result.status, 502);
  assert.deepEqual(result.body, { error: "ai.response_invalid" });
});

test("no request header, and no token, reaches the binding", async () => {
  const ai = binding({});
  const request = post(envelope(), {
    "content-type": "application/json",
    authorization: "Bearer should-not-forward",
    "x-api-token": "should-not-forward",
  });
  await call(request, ai);
  const forwarded = JSON.stringify(ai.calls);
  assert.equal(forwarded.includes("should-not-forward"), false);
  assert.deepEqual(Object.keys(ai.calls[0] ?? {}).sort(), ["inputs", "model"]);
});

test("the envelope parser refuses every shape it is asked to parse and accepts the exact closed shape", () => {
  const ok = parseEnvelope(new TextEncoder().encode(envelope()));
  assert.equal(ok.ok, true);
  if (ok.ok) {
    assert.equal(ok.value.stream, false);
    assert.deepEqual(ok.value.admittedModels, [model]);
  }
  assert.deepEqual(parseEnvelope(new TextEncoder().encode(envelope({ model: "@cf/x/y" }))), {
    ok: false,
    status: 403,
    code: "ai.model_not_admitted",
  });
});
