// SPDX-License-Identifier: AGPL-3.0-only
// The private storage.internal ingress: routing, signature before body, strict contract bodies.
import assert from "node:assert/strict";
import test from "node:test";
import {
  parseExecutePlanResponseJson,
  serializeExecutePlanRequestJson,
  type ExecutePlanRequest,
} from "@arcforges/ai-internal";
import { base64UrlEncode, sha256Hex } from "../../worker/private/encoding.ts";
import { newNonce, sign } from "../../worker/private/signing.ts";
import {
  executePlanPath,
  handleExecutePlan,
  type StorageEnv,
} from "../../worker/storage/handler.ts";
import { manifestHash } from "../../worker/storage/plans.generated.ts";
import { createSqliteD1 } from "./support/sqlite-d1.ts";
import { fixedNow, planRequest, sc, txt, uuid } from "./support/plan-calls.ts";

const secret = new Uint8Array(32).fill(5);
const env = (overrides: Partial<StorageEnv> = {}): StorageEnv => ({
  DB: createSqliteD1(),
  RECOVERY_GENERATION: "0",
  HMAC_C2W_KEY_ID: "c2w-1",
  HMAC_C2W_SECRET: base64UrlEncode(secret),
  ...overrides,
});
const url = `http://storage.internal${executePlanPath}`;
const now = () => fixedNow;

async function signed(
  body: Uint8Array,
  options: {
    requestId?: string;
    method?: string;
    url?: string;
    time?: number;
    headers?: Record<string, string>;
  } = {},
) {
  const requestId = options.requestId ?? uuid();
  const target = new URL(options.url ?? url);
  const headers = await sign(
    {
      method: options.method ?? "POST",
      pathAndQuery: target.pathname + target.search,
      bodySha256Hex: await sha256Hex(body),
      requestId,
      time: String(options.time ?? Math.floor(fixedNow / 1000)),
      nonce: newNonce(),
    },
    { id: "c2w-1", secret },
  );
  return new Request(target, {
    method: options.method ?? "POST",
    headers: { "content-type": "application/json", ...headers, ...options.headers },
    body: (options.method ?? "POST") === "GET" ? undefined : (body as BodyInit),
  });
}
const readiness = (overrides: Partial<ExecutePlanRequest> = {}) =>
  planRequest("foundation.readiness", [[]], overrides);
const encode = (value: ExecutePlanRequest) => serializeExecutePlanRequestJson(value);
const parse = async (response: Response) =>
  parseExecutePlanResponseJson(new Uint8Array(await response.arrayBuffer()));

test("a signed generated request is executed and answered with the generated reply", async () => {
  const request = readiness();
  const response = await handleExecutePlan(
    await signed(encode(request), { requestId: request.requestId }),
    env(),
    now,
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await parse(response);
  assert.deepEqual(body, {
    requestId: request.requestId,
    manifestHash,
    rows: [[{ kind: "int64", value: "1" }]],
    changes: "0",
  });
});

test("only the exact host, path and method reach the handler", async () => {
  const request = readiness();
  const body = encode(request);
  for (const target of [
    "http://storage.internal/internal/storage/v1/execute-plan/",
    "http://storage.internal/internal/storage/v1/other",
    "http://storage.internal/internal/storage/v1/execute-plan?x=1",
    "http://example.com/internal/storage/v1/execute-plan",
    "http://storage.internal/",
  ])
    assert.equal(
      (await handleExecutePlan(await signed(body, { url: target }), env(), now)).status,
      404,
      target,
    );
  assert.equal(
    (await handleExecutePlan(await signed(new Uint8Array(), { method: "GET" }), env(), now)).status,
    405,
  );
  assert.equal(
    (
      await handleExecutePlan(
        await signed(body, { headers: { "content-type": "text/plain" } }),
        env(),
        now,
      )
    ).status,
    415,
  );
});

test("every authentication failure is the same empty 401 and never executes anything", async () => {
  const request = readiness();
  const body = encode(request);
  const good = await signed(body, { requestId: request.requestId });
  const refusals: Request[] = [
    new Request(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: body as BodyInit,
    }),
    await signed(body, { requestId: request.requestId, time: Math.floor(fixedNow / 1000) + 61 }),
    await signed(body, { requestId: request.requestId, time: Math.floor(fixedNow / 1000) - 61 }),
    await signed(body, { requestId: request.requestId, headers: { "x-af-key-id": "unknown" } }),
    await signed(body, {
      requestId: request.requestId,
      headers: { "x-af-signature": base64UrlEncode(new Uint8Array(32)) },
    }),
    await signed(body, { requestId: request.requestId, headers: { "x-af-request-id": uuid() } }),
    new Request(url, {
      method: "POST",
      headers: Object.fromEntries(good.headers),
      body: encode(readiness()) as BodyInit,
    }),
  ];
  const forbidden = {
    prepare: () => {
      throw new Error("D1 must not be touched");
    },
    batch: () => Promise.reject(new Error("D1 must not be touched")),
  };
  for (const refused of refusals) {
    const response = await handleExecutePlan(refused, env({ DB: forbidden }), now);
    assert.equal(response.status, 401);
    assert.equal(await response.text(), "");
  }
});

test("missing or malformed deployment secrets make the endpoint unavailable, not open", async () => {
  const request = readiness();
  const body = encode(request);
  for (const broken of [
    { HMAC_C2W_KEY_ID: undefined },
    { HMAC_C2W_SECRET: undefined },
    { HMAC_C2W_SECRET: "short" },
    { HMAC_C2W_PREVIOUS_KEY_ID: "c2w-0" },
  ])
    assert.equal(
      (
        await handleExecutePlan(
          await signed(body, { requestId: request.requestId }),
          env(broken),
          now,
        )
      ).status,
      503,
      JSON.stringify(broken),
    );
});

test("a previous key is accepted during rotation", async () => {
  const request = readiness();
  const response = await handleExecutePlan(
    await signed(encode(request), { requestId: request.requestId }),
    env({
      HMAC_C2W_KEY_ID: "c2w-2",
      HMAC_C2W_SECRET: base64UrlEncode(new Uint8Array(32).fill(6)),
      HMAC_C2W_PREVIOUS_KEY_ID: "c2w-1",
      HMAC_C2W_PREVIOUS_SECRET: base64UrlEncode(secret),
    }),
    now,
  );
  assert.equal(response.status, 200);
});

test("oversized bodies are refused by declaration and while streaming", async () => {
  const huge = new Uint8Array(262145).fill(32);
  const declared = await signed(huge, { headers: { "content-length": String(huge.length) } });
  assert.equal((await handleExecutePlan(declared, env(), now)).status, 413);
  const streamed = new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(huge);
        controller.close();
      },
    }),
    duplex: "half",
  } as RequestInit);
  assert.equal((await handleExecutePlan(streamed, env(), now)).status, 413);
});

test("a signed but malformed or mismatched body is an invalid plan carrying the signed request id", async () => {
  const requestId = uuid();
  const malformed = [
    new TextEncoder().encode("{"),
    new TextEncoder().encode('{"planId":"foundation.readiness"}'),
    new TextEncoder().encode(JSON.stringify({ ...readiness(), extra: 1 })),
    new TextEncoder().encode(
      JSON.stringify({
        ...readiness({ requestId }),
        arguments: [[{ kind: "int64", value: "01" }]],
      }),
    ),
  ];
  for (const body of malformed) {
    const response = await handleExecutePlan(await signed(body, { requestId }), env(), now);
    assert.equal(response.status, 200);
    assert.deepEqual(await parse(response), { requestId, manifestHash, failure: "invalidPlan" });
  }
  // The signed request id must equal the body request id.
  const mismatched = await handleExecutePlan(
    await signed(encode(readiness()), { requestId }),
    env(),
    now,
  );
  assert.deepEqual(await parse(mismatched), { requestId, manifestHash, failure: "invalidPlan" });
});

test("failures from the executor are typed replies with the dictionary manifest hash", async () => {
  const stale = readiness({ recoveryGeneration: "9" });
  const response = await handleExecutePlan(
    await signed(encode(stale), { requestId: stale.requestId }),
    env(),
    now,
  );
  assert.deepEqual(await parse(response), {
    requestId: stale.requestId,
    manifestHash,
    failure: "staleGeneration",
  });
  const wrongHash = readiness({ manifestHash: "0".repeat(64) });
  const second = await handleExecutePlan(
    await signed(encode(wrongHash), { requestId: wrongHash.requestId }),
    env(),
    now,
  );
  assert.deepEqual(await parse(second), {
    requestId: wrongHash.requestId,
    manifestHash,
    failure: "invalidPlan",
  });
  const forged = planRequest("foundation.account-load", [[sc("proof/other"), txt("x")]]);
  const third = await handleExecutePlan(
    await signed(encode(forged), { requestId: forged.requestId }),
    env(),
    now,
  );
  assert.deepEqual(await parse(third), {
    requestId: forged.requestId,
    manifestHash,
    failure: "invalidPlan",
  });
});
