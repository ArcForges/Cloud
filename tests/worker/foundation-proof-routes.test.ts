// SPDX-License-Identifier: AGPL-3.0-only
// The proof-only public surface: disabled in production, operator-gated, signed toward the
// Container and narrow about what crosses (cookie, origin, CSRF header only).
import assert from "node:assert/strict";
import test from "node:test";
import { containerEnvironment } from "../../worker/foundation/container-env.ts";
import { isCorrelationId } from "../../worker/ingress/correlation.ts";
import {
  handleProof,
  isProofPath,
  sessionCookieOnly,
} from "../../worker/foundation/proof-routes.ts";
import type {
  ContainerStubLike,
  FoundationEnv,
  WakeMessage,
} from "../../worker/foundation/types.ts";
import { base64UrlEncode, sha256Hex } from "../../worker/private/encoding.ts";
import { loadKeys, verificationKeys } from "../../worker/private/hmac-settings.ts";
import { verify } from "../../worker/private/signing.ts";
import { manifestHash } from "../../worker/storage/plans.generated.ts";
import { createFakeR2 } from "./support/fake-r2.ts";

const operatorToken = "t".repeat(40);
const w2c = base64UrlEncode(new Uint8Array(32).fill(2));
const job = "00000000-0000-4000-8000-000000000900";
interface Recorded {
  request: Request;
  body: Uint8Array;
}

function environment(
  reply: { status?: number; body?: string; headers?: Record<string, string> } = {},
  overrides: Partial<FoundationEnv> = {},
) {
  const recorded: Recorded[] = [];
  const sent: WakeMessage[] = [];
  let stopped = 0;
  const stub: ContainerStubLike = {
    async fetch(request) {
      recorded.push({ request, body: new Uint8Array(await request.clone().arrayBuffer()) });
      return new Response(reply.body ?? "{}", {
        status: reply.status ?? 200,
        headers: reply.headers ?? { "content-type": "application/json" },
      });
    },
    stop() {
      stopped++;
      return Promise.resolve();
    },
  };
  const env: FoundationEnv = {
    FOUNDATION_PROOF: "enabled",
    DB: undefined as never,
    RECOVERY_GENERATION: "0",
    PROOF_OPERATOR_TOKEN: operatorToken,
    HMAC_W2C_KEY_ID: "w2c-1",
    HMAC_W2C_SECRET: w2c,
    OBJECTS: createFakeR2(),
    WAKE_QUEUE: {
      send(message) {
        sent.push(message as WakeMessage);
        return Promise.resolve();
      },
    },
    JOB_COORDINATOR: undefined as never,
    CLOUD_CONTAINER: { getByName: () => stub },
    ...overrides,
  };
  return { env, recorded, sent, stopped: () => stopped };
}
const operator = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`https://proof.example${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${operatorToken}`,
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });

test("production answers none of the proof routes", async () => {
  for (const flag of [undefined, "", "disabled", "ENABLED"]) {
    const { env, recorded } = environment({}, { FOUNDATION_PROOF: flag });
    for (const request of [
      operator("/proof/v1/readiness", {}),
      new Request("https://proof.example/session/v1/bootstrap"),
      new Request("https://proof.example/session/v1/logout", { method: "POST" }),
    ])
      assert.equal((await handleProof(request, env)).status, 404);
    assert.equal(recorded.length, 0);
  }
  assert.equal(isProofPath("/proof/v1/exact"), true);
  assert.equal(isProofPath("/session/v1/bootstrap"), true);
  assert.equal(isProofPath("/session/v1/authentication/begin"), false);
  assert.equal(isProofPath("/api/healthz"), false);
});

test("the operator surface needs the exact operator token", async () => {
  const { env, recorded } = environment();
  const without = new Request("https://proof.example/proof/v1/readiness", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal((await handleProof(without, env)).status, 401);
  for (const header of [
    "Bearer wrong",
    `Bearer ${operatorToken}x`,
    `bearer ${operatorToken}`,
    `Basic ${operatorToken}`,
    `Bearer ${operatorToken} extra`,
    "",
  ])
    assert.equal(
      (await handleProof(operator("/proof/v1/readiness", {}, { authorization: header }), env))
        .status,
      401,
      header,
    );
  assert.equal(recorded.length, 0);
  // A short or missing operator secret disables the surface instead of weakening it.
  for (const token of [undefined, "short", "t".repeat(31)])
    assert.equal(
      (
        await handleProof(
          operator("/proof/v1/readiness", {}),
          environment({}, { PROOF_OPERATOR_TOKEN: token }).env,
        )
      ).status,
      503,
    );
});

test("operations are an exact allowlist with method, content type, query and size bounds", async () => {
  const { env, recorded } = environment();
  assert.equal((await handleProof(operator("/proof/v1/unknown", {}), env)).status, 404);
  assert.equal((await handleProof(operator("/proof/v1/readiness?x=1", {}), env)).status, 400);
  assert.equal(
    (
      await handleProof(
        new Request("https://proof.example/proof/v1/readiness", {
          method: "GET",
          headers: { authorization: `Bearer ${operatorToken}` },
        }),
        env,
      )
    ).status,
    405,
  );
  assert.equal(
    (await handleProof(operator("/proof/v1/readiness", {}, { "content-type": "text/plain" }), env))
      .status,
    415,
  );
  const huge = new Request("https://proof.example/proof/v1/exact", {
    method: "POST",
    headers: { authorization: `Bearer ${operatorToken}`, "content-type": "application/json" },
    body: "x".repeat(16_385),
  });
  assert.equal((await handleProof(huge, env)).status, 413);
  assert.equal(recorded.length, 0);
});

test("an operation is signed with the Worker-to-Container key over the exact path and body hash", async () => {
  const { env, recorded } = environment({ body: '{"ready":true}' });
  const response = await handleProof(operator("/proof/v1/guard", {}), env);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '{"ready":true}');
  assert.equal(response.headers.get("cache-control"), "no-store");
  const call = recorded[0] as Recorded;
  assert.equal(new URL(call.request.url).pathname, "/internal/foundation/v1/guard");
  assert.equal(call.request.method, "POST");
  const keys = loadKeys(env, "W2C");
  assert(keys);
  const verification = await verify(
    {
      method: "POST",
      pathAndQuery: "/internal/foundation/v1/guard",
      bodySha256Hex: await sha256Hex(call.body),
      headers: call.request.headers,
    },
    verificationKeys(keys),
    Math.floor(Date.now() / 1000),
  );
  assert.equal(verification.ok, true);
  // The operator token never travels to the Container.
  assert.equal(call.request.headers.get("authorization"), null);
});

test("the Container status and body are relayed, a Container failure is a 502 or 503", async () => {
  const conflict = environment({ status: 409, body: '{"error":"conflict"}' });
  const relayed = await handleProof(operator("/proof/v1/guard", {}), conflict.env);
  assert.equal(relayed.status, 409);
  assert.equal(await relayed.text(), '{"error":"conflict"}');
  const failing = environment();
  failing.env.CLOUD_CONTAINER = {
    getByName: () => ({ fetch: () => Promise.reject(new Error("down")) }),
  };
  assert.equal((await handleProof(operator("/proof/v1/guard", {}), failing.env)).status, 503);
  const unsigned = environment({}, { HMAC_W2C_SECRET: undefined });
  assert.equal((await handleProof(operator("/proof/v1/guard", {}), unsigned.env)).status, 502);
  const oversized = environment({ body: "x".repeat(70_000) });
  assert.equal((await handleProof(operator("/proof/v1/guard", {}), oversized.env)).status, 502);
});

test("starting a job enqueues exactly one wake hint that carries identifiers only", async () => {
  const { env, sent } = environment({
    body: JSON.stringify({ jobId: job, scope: "proof/run-1", total: "5" }),
  });
  const response = await handleProof(
    operator("/proof/v1/job/start", { scope: "proof/run-1", total: "5" }),
    env,
  );
  assert.equal(response.status, 200);
  const started = (await response.json()) as { correlationId: string };
  assert.deepEqual(started, {
    jobId: job,
    scope: "proof/run-1",
    total: "5",
    wakeEnqueued: true,
    correlationId: started.correlationId,
  });
  assert.equal(isCorrelationId(started.correlationId), true);
  assert.equal(sent.length, 1);
  assert.deepEqual(Object.keys(sent[0] as WakeMessage).sort(), [
    "causationId",
    "correlationId",
    "eventId",
    "jobId",
    "kind",
    "scope",
    "v",
  ]);
  // The wake carries the chain's identity that the reply names, and the request that started it as its cause.
  assert.equal(sent[0]?.correlationId, started.correlationId);
  assert.equal(isCorrelationId(sent[0]?.causationId), true);
  assert.notEqual(sent[0]?.causationId, sent[0]?.eventId);
  assert.equal(sent[0]?.jobId, job);
  // A failed start enqueues nothing; an unusable reply is reported, not hidden.
  const failed = environment({ status: 409, body: '{"error":"conflict"}' });
  assert.equal((await handleProof(operator("/proof/v1/job/start", {}), failed.env)).status, 409);
  assert.equal(failed.sent.length, 0);
  const odd = environment({ body: JSON.stringify({ jobId: "bad", scope: "proof/x" }) });
  assert.equal((await handleProof(operator("/proof/v1/job/start", {}), odd.env)).status, 502);
  assert.equal(odd.sent.length, 0);
});

test("a wake can be requested only for a well-formed job and scope", async () => {
  const { env, sent } = environment();
  assert.equal(
    (await handleProof(operator("/proof/v1/job/wake", { scope: "proof/r", jobId: job }), env))
      .status,
    200,
  );
  assert.equal(sent.length, 1);
  assert.equal(isCorrelationId(sent[0]?.correlationId), true);
  for (const body of [
    { scope: "proof/r", jobId: job, correlationId: "not-a-uuid" },
    { scope: "proof/r", jobId: job, correlationId: "00000000-0000-0000-0000-000000000000" },
    { scope: "proof/r", jobId: job, correlationId: 7 },
    { scope: "other", jobId: job },
    { scope: "proof/r", jobId: "x" },
    { scope: 1, jobId: job },
    {},
  ])
    assert.equal((await handleProof(operator("/proof/v1/job/wake", body), env)).status, 400);
  assert.equal(sent.length, 1);
});

test("a stated correlation identity starts the chain, never reaches the host, and is validated like a client's", async () => {
  const chain = "0f8fad5b-d9cb-469f-a165-70867728950e";
  const { env, sent, recorded } = environment({
    body: JSON.stringify({ jobId: job, scope: "proof/run-1", total: "5" }),
  });
  const response = await handleProof(
    operator("/proof/v1/job/start", {
      scope: "proof/run-1",
      total: "5",
      autoWake: true,
      correlationId: chain,
    }),
    env,
  );
  assert.equal(response.status, 200);
  assert.equal(((await response.json()) as { correlationId: string }).correlationId, chain);
  assert.equal(sent[0]?.correlationId, chain);
  // The host's job-start request is closed: the Worker interprets the chain's identity and strips it.
  assert.deepEqual(JSON.parse(new TextDecoder().decode(recorded[0]?.body)), {
    scope: "proof/run-1",
    total: "5",
  });
  // Without autoWake the chain is still named in the reply, and nothing is queued.
  const quiet = environment({ body: JSON.stringify({ jobId: job, scope: "proof/run-1" }) });
  const named = await handleProof(
    operator("/proof/v1/job/start", {
      scope: "proof/run-1",
      autoWake: false,
      correlationId: chain,
    }),
    quiet.env,
  );
  assert.equal(((await named.json()) as { correlationId: string }).correlationId, chain);
  assert.equal(quiet.sent.length, 0);
  for (const bad of [
    "x",
    chain.toUpperCase(),
    "00000000-0000-0000-0000-000000000000",
    chain.replaceAll("-", ""),
    `${chain}\r\ninjected: 1`,
    7,
    null,
  ]) {
    const refused = environment();
    assert.equal(
      (
        await handleProof(
          operator("/proof/v1/job/start", { scope: "proof/run-1", total: "5", correlationId: bad }),
          refused.env,
        )
      ).status,
      400,
    );
    assert.equal(refused.recorded.length, 0);
    assert.equal(refused.sent.length, 0);
  }
  const wake = environment();
  const woken = await handleProof(
    operator("/proof/v1/job/wake", { scope: "proof/r", jobId: job, correlationId: chain }),
    wake.env,
  );
  assert.deepEqual(await woken.json(), { wakeEnqueued: true, correlationId: chain });
  assert.equal(wake.sent[0]?.correlationId, chain);
  assert.notEqual(wake.sent[0]?.causationId, chain);
});

test("the Container can be stopped to prove restart, and only by the operator", async () => {
  const { env, stopped } = environment();
  assert.equal((await handleProof(operator("/proof/v1/container/stop", {}), env)).status, 200);
  assert.equal(stopped(), 1);
  assert.equal(
    (
      await handleProof(
        operator("/proof/v1/container/stop", {}, { authorization: "Bearer no" }),
        env,
      )
    ).status,
    401,
  );
  assert.equal(stopped(), 1);
});

test("session routes forward only the session cookie, origin and CSRF header", async () => {
  assert.equal(sessionCookieOnly(null), null);
  assert.equal(sessionCookieOnly("a=1; b=2"), null);
  assert.equal(sessionCookieOnly("a=1; __Host-af_session=abc; b=2"), "__Host-af_session=abc");
  assert.equal(
    sessionCookieOnly("__Host-af_session=abc; __Host-af_session=def"),
    null,
    "duplicates are ambiguous",
  );
  assert.equal(sessionCookieOnly("x__Host-af_session=abc"), null);
  const { env, recorded } = environment({
    body: '{"authenticated":false}',
    headers: {
      "content-type": "application/json",
      "set-cookie": "x=1",
      "x-secret-internal": "leak",
    },
  });
  const request = new Request("https://proof.example/session/v1/bootstrap", {
    headers: {
      cookie: "tracking=1; __Host-af_session=abc",
      origin: "https://account.proof.arcforges.test",
      "x-af-csrf": "csrf",
      authorization: "Bearer should-not-cross",
      "x-forwarded-for": "1.2.3.4",
    },
  });
  const response = await handleProof(request, env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("set-cookie"), "x=1");
  assert.equal(response.headers.get("x-secret-internal"), null);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const forwarded = (recorded[0] as Recorded).request.headers;
  assert.deepEqual([...forwarded.keys()].sort(), ["cookie", "origin", "x-af-csrf"]);
  assert.equal(forwarded.get("cookie"), "__Host-af_session=abc");
  assert.equal((recorded[0] as Recorded).request.method, "GET");
});

test("session routes accept exactly bootstrap by GET and logout by bodyless POST", async () => {
  const { env, recorded } = environment();
  const call = (method: string, path: string, body?: string, search = "") =>
    handleProof(new Request(`https://proof.example${path}${search}`, { method, body }), env);
  assert.equal((await call("POST", "/session/v1/bootstrap")).status, 405);
  assert.equal((await call("GET", "/session/v1/logout")).status, 405);
  assert.equal((await call("GET", "/session/v1/bootstrap", undefined, "?x=1")).status, 400);
  assert.equal((await call("POST", "/session/v1/logout", "x")).status, 400);
  assert.equal((await call("POST", "/session/v1/logout", "xx")).status, 400);
  assert.equal(recorded.length, 0);
  assert.equal((await call("POST", "/session/v1/logout")).status, 200);
  assert.equal(recorded.length, 1);
});

test("the Container environment carries proof secrets only when the proof is enabled", () => {
  assert.deepEqual(containerEnvironment({ HMAC_C2W_SECRET: "x", FOUNDATION_PROOF: undefined }), {});
  assert.deepEqual(
    containerEnvironment({ HMAC_C2W_SECRET: "x", FOUNDATION_PROOF: "disabled" }),
    {},
  );
  const forwarded = containerEnvironment({
    FOUNDATION_PROOF: "enabled",
    HMAC_C2W_KEY_ID: "c2w-1",
    HMAC_C2W_SECRET: "a",
    HMAC_W2C_KEY_ID: "w2c-1",
    HMAC_W2C_SECRET: "b",
    CSRF_SECRET: "c",
    ALLOWED_ORIGIN: "https://o.example",
    REALM_ID: "proof",
    RECOVERY_GENERATION: "0",
    PROOF_OPERATOR_TOKEN: "never forwarded",
    HMAC_C2W_PREVIOUS_SECRET: "never forwarded",
  });
  assert.deepEqual(Object.keys(forwarded).sort(), [
    "AF_ALLOWED_ORIGIN",
    "AF_CSRF_SECRET",
    "AF_HMAC_C2W_KEY_ID",
    "AF_HMAC_C2W_SECRET",
    "AF_HMAC_W2C_KEY_ID",
    "AF_HMAC_W2C_SECRET",
    "AF_REALM_ID",
    "AF_RECOVERY_GENERATION",
    "ARCFORGES_FOUNDATION_PROOF",
  ]);
});

test("the entry sends only proof paths to the proof surface and only when it is enabled", async () => {
  const { fetchEntry, queueEntry } = await import("../../worker/foundation/entry.ts");
  const context = { waitUntil: () => {} };
  const enabled = environment().env;
  const proof = await fetchEntry(
    new Request("https://proof.example/proof/v1/readiness", { method: "POST" }),
    enabled as never,
    context,
  );
  assert.equal(proof.status, 401, "proof paths reach the operator gate");
  const hello = await fetchEntry(
    new Request("https://proof.example/nothing"),
    enabled as never,
    context,
  );
  assert.equal(hello.status, 404);
  assert.match(await hello.text(), /Unknown API method/u);
  const production = environment({}, { FOUNDATION_PROOF: undefined }).env;
  assert.equal(
    (
      await fetchEntry(
        new Request("https://x.example/proof/v1/readiness", { method: "POST" }),
        production as never,
        context,
      )
    ).status,
    404,
  );
  // Outside the proof environment a queue message is deferred, never processed.
  const retried: (number | undefined)[] = [];
  await queueEntry(
    {
      messages: [
        {
          body: {},
          attempts: 1,
          ack: () => assert.fail("must not ack"),
          retry: (o) => retried.push(o?.delaySeconds),
        },
      ],
    },
    production as never,
  );
  assert.deepEqual(retried, [60]);
});

test("a job can be started without its automatic wake, and autoWake never reaches the host", async () => {
  const { env, sent, recorded } = environment({
    body: JSON.stringify({ jobId: job, scope: "proof/run-1", total: 5 }),
  });
  const response = await handleProof(
    operator("/proof/v1/job/start", { scope: "proof/run-1", total: 5, autoWake: false }),
    env,
  );
  assert.equal(response.status, 200);
  const quiet = (await response.json()) as { correlationId: string };
  assert.deepEqual(quiet, {
    jobId: job,
    scope: "proof/run-1",
    total: 5,
    wakeEnqueued: false,
    correlationId: quiet.correlationId,
  });
  assert.equal(isCorrelationId(quiet.correlationId), true);
  assert.equal(sent.length, 0);
  assert.deepEqual(JSON.parse(new TextDecoder().decode((recorded[0] as Recorded).body)), {
    scope: "proof/run-1",
    total: 5,
  });
  const explicit = environment({
    body: JSON.stringify({ jobId: job, scope: "proof/run-1", total: 5 }),
  });
  const queued = await handleProof(
    operator("/proof/v1/job/start", { scope: "proof/run-1", total: 5, autoWake: true }),
    explicit.env,
  );
  assert.equal(((await queued.json()) as { wakeEnqueued: boolean }).wakeEnqueued, true);
  assert.equal(explicit.sent.length, 1);
  for (const bad of ["yes", 1, null])
    assert.equal(
      (
        await handleProof(
          operator("/proof/v1/job/start", { scope: "proof/r", total: 1, autoWake: bad }),
          env,
        )
      ).status,
      400,
    );
  assert.equal(sent.length, 0);
});

test("a single slice can be driven by the operator through the signed path", async () => {
  const { env, recorded } = environment({ body: '{"state":"running"}' });
  const response = await handleProof(operator("/proof/v1/job/slice", { scope: "proof/r" }), env);
  assert.equal(response.status, 200);
  assert.equal(
    new URL((recorded[0] as Recorded).request.url).pathname,
    "/internal/foundation/v1/job/slice",
  );
});

test("the egress probe is an operator operation signed toward the Container and nothing else is", async () => {
  const { env, recorded } = environment({ body: '{"blocked":true}' });
  const response = await handleProof(operator("/proof/v1/egress/probe", {}), env);
  assert.equal(response.status, 200);
  assert.equal(
    new URL((recorded[0] as Recorded).request.url).pathname,
    "/internal/foundation/v1/egress/probe",
  );
  // Without the operator credential the probe is refused like every other operation.
  const anonymous = new Request("https://proof.example/proof/v1/egress/probe", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal((await handleProof(anonymous, env)).status, 401);
  assert.equal(recorded.length, 1);
  assert.equal((await handleProof(operator("/proof/v1/egress/other", {}), env)).status, 404);
});

// ---- readiness (CLOUD.08) ----

const readyHost = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    ready: true,
    manifestHash,
    schemaVersion: "1",
    revision: "r".repeat(40),
    components: { d1: { state: "ready" } },
    ...overrides,
  });

/** A complete proof environment: every binding present, and the Container answers as stated. */
function readinessEnvironment(
  reply: { status?: number; body?: string; headers?: Record<string, string> },
  overrides: Partial<FoundationEnv> = {},
) {
  const built = environment(reply, {
    DB: { prepare: () => ({}), batch: async () => [] } as never,
    JOB_COORDINATOR: {
      getByName: () => ({ readPoison: async () => ({ attempts: [], deadLetter: null }) }),
    } as never,
    HMAC_C2W_KEY_ID: "c2w-1",
    HMAC_C2W_SECRET: base64UrlEncode(new Uint8Array(32).fill(1)),
    CSRF_SECRET: "c".repeat(43),
    ALLOWED_ORIGIN: "https://proof.example",
    REALM_ID: "proof",
    ...overrides,
  });
  Object.assign(built.env, {
    SOURCE_REVISION: "x",
    HELLO_RATE_LIMITER: { limit: async () => ({}) },
  });
  return built;
}

test("the operator readiness operation reports every component, signed toward the Container once", async () => {
  const lines: string[] = [];
  const { env, recorded } = readinessEnvironment({ body: readyHost() });
  const response = await handleProof(operator("/proof/v1/readiness", {}), env, (line) =>
    lines.push(line),
  );
  assert.equal(response.status, 200);
  const body = (await response.json()) as Record<string, unknown> & {
    components: Record<string, { state: string }>;
  };
  assert.equal(body.ready, true);
  assert.equal(body.status, "ready");
  assert.equal(body.manifestHash, manifestHash);
  assert.equal(body.schemaVersion, "1");
  assert.equal(body.revision, "r".repeat(40));
  assert.deepEqual(Object.keys(body.components), [
    "ingress",
    "container",
    "d1",
    "durableObject",
    "r2",
    "queue",
  ]);
  assert.equal(recorded.length, 1);
  assert.equal(
    new URL((recorded[0] as Recorded).request.url).pathname,
    "/internal/foundation/v1/readiness",
  );
  assert.equal((recorded[0] as Recorded).request.headers.get("authorization"), null);
  // One closed log line, no content.
  assert.equal(lines.length, 1);
  assert.equal((JSON.parse(lines[0] as string) as { event: string }).event, "cloud.readiness");
});

test("the operator readiness operation fails readiness for a mismatching plan manifest", async () => {
  const { env } = readinessEnvironment({ body: readyHost({ manifestHash: "b".repeat(64) }) });
  const response = await handleProof(operator("/proof/v1/readiness", {}), env, () => {});
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), null);
  const body = (await response.json()) as {
    ready: boolean;
    components: Record<string, { state: string; reason?: string }>;
  };
  assert.equal(body.ready, false);
  assert.equal(body.components.d1?.reason, "plan_hash_mismatch");
});

test("the operator readiness operation fails readiness for a missing binding without waking the Container", async () => {
  const { env, recorded } = readinessEnvironment(
    { body: readyHost() },
    { OBJECTS: undefined as never },
  );
  const response = await handleProof(operator("/proof/v1/readiness", {}), env, () => {});
  assert.equal(response.status, 503);
  const body = (await response.json()) as {
    status: string;
    components: Record<string, { state: string; missing?: string[] }>;
  };
  assert.equal(body.status, "misconfigured");
  assert.deepEqual(body.components.r2?.missing, ["OBJECTS"]);
  assert.equal(body.components.container?.state, "ready", "components fail independently");
  assert.equal(recorded.length, 1);
});

test("a Container the platform could not start is reported, with retry guidance, not relayed", async () => {
  const { env } = readinessEnvironment({
    status: 503,
    body: "There is no Container instance available at this time.\nmore text",
    headers: { "content-type": "text/plain;charset=UTF-8" },
  });
  const response = await handleProof(operator("/proof/v1/readiness", {}), env, () => {});
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), "2");
  const text = await response.text();
  const body = JSON.parse(text) as {
    components: Record<string, { state: string; reason?: string }>;
  };
  assert.equal(body.components.container?.reason, "no_instance_available");
  assert.equal(body.components.d1?.state, "unknown");
  assert.equal(text.includes("There is no Container"), false);
});

test("the readiness operation takes an empty object and nothing else", async () => {
  const { env, recorded } = readinessEnvironment({ body: readyHost() });
  for (const body of [{ x: 1 }, [], "text", null])
    assert.equal(
      (
        await handleProof(
          new Request("https://proof.example/proof/v1/readiness", {
            method: "POST",
            headers: {
              authorization: `Bearer ${operatorToken}`,
              "content-type": "application/json",
            },
            body: JSON.stringify(body),
          }),
          env,
          () => {},
        )
      ).status,
      400,
    );
  assert.equal(recorded.length, 0);
});

test("a session request whose Container could not be started is a retryable empty 503 with no library text", async () => {
  const { env, recorded } = environment({
    status: 503,
    body: "There is no Container instance available at this time.\nmore",
    headers: { "content-type": "text/plain;charset=UTF-8" },
  });
  const response = await handleProof(
    new Request("https://proof.example/session/v1/bootstrap"),
    env,
  );
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), "2");
  assert.equal(await response.text(), "");
  assert.equal(recorded.length, 1, "one attempt, no replay");
  // The host's own 503 stays what it answered, with no retry guidance (it may have processed the request).
  const host = environment({
    status: 503,
    body: '{"error":"unavailable"}',
    headers: { "content-type": "application/json" },
  });
  const own = await handleProof(
    new Request("https://proof.example/session/v1/bootstrap"),
    host.env,
  );
  assert.equal(own.status, 503);
  assert.equal(own.headers.get("retry-after"), null);
});
