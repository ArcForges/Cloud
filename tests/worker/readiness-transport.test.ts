// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's half of readiness (WP-21.07, CLOUD.84 S39(1)): what the Worker observes and forwards, the classification of a Container
// that could not answer, the bounded waits, and the strict reading of the host's reply. The verdict on the whole report is the C# evaluator's
// (tests/ArcForges.Cloud.Tests/Readiness); these cases pin what the Worker does with its own observations and with that verdict.
import assert from "node:assert/strict";
import test from "node:test";
import {
  bindingObservations,
  missingBindings,
  requiredComponents,
} from "../../worker/readiness/bindings.ts";
import { readinessResponse } from "../../worker/readiness/http.ts";
import { parseHostReport } from "../../worker/readiness/report.ts";
import {
  classifyHostReply,
  durableObjectProbeName,
  evaluateReadiness,
  r2ProbeKey,
  type HostReply,
  type ReadinessDeps,
} from "../../worker/readiness/transport.ts";
import {
  hostReply,
  hostReport,
  libraryNoInstance,
  libraryStartFailed,
  manifest,
  otherManifest,
  productionEnvironment,
  proofEnvironment,
  reply,
  secretMaterial,
} from "./support/readiness-fixtures.ts";

/** The observations the Worker forwarded on the signed call. */
interface Forwarded {
  environment: string;
  workerRevision: string;
  manifestHash: string;
  bindings: Record<string, boolean>;
  durableObject: { outcome: string; elapsedMs: number } | null;
  r2: { outcome: string; elapsedMs: number } | null;
}

function deps(host: (signal: AbortSignal) => Promise<HostReply>, waitMs = 2_000) {
  const calls = { host: 0, forwarded: [] as Forwarded[] };
  const result: Partial<ReadinessDeps> = {
    callHost: (_env, body, signal) => {
      calls.host++;
      calls.forwarded.push(JSON.parse(new TextDecoder().decode(body)) as Forwarded);
      return host(signal);
    },
    manifestHash: manifest,
    waitMs,
    now: (() => {
      let tick = 0;
      return () => (tick += 5);
    })(),
  };
  return { deps: result, calls };
}

const healthy = () => Promise.resolve(hostReply());

test("a complete proof environment forwards every observation once and passes the host's report through", async () => {
  const { env, calls } = proofEnvironment();
  const host = deps(healthy);
  const report = await evaluateReadiness(env, host.deps);
  assert.equal(report.status, "ready");
  assert.equal(report.ready, true);
  assert.equal(report.environment, "proof");
  assert.equal(report.host?.manifestHash, manifest);
  assert.equal(host.calls.host, 1);
  const [forwarded] = host.calls.forwarded;
  assert.equal(forwarded?.manifestHash, manifest, "the Worker forwards its own manifest hash");
  assert.equal(forwarded?.environment, "proof");
  assert.equal(forwarded?.bindings.DB, true);
  assert.equal(forwarded?.durableObject?.outcome, "ready");
  assert.equal(forwarded?.r2?.outcome, "ready");
  // The probes are reads: one Durable Object read of a fixed name, one R2 head of an absent key, and no enqueued work.
  assert.deepEqual(calls.durableObject, [durableObjectProbeName]);
  assert.deepEqual(calls.r2, [r2ProbeKey]);
  assert.equal(calls.queueSends, 0, "readiness never enqueues work");
  assert.equal(readinessResponse(report).status, 200);
});

test("the production Worker declares only the ingress and the Container, and a Hello host without the route is not ready", async () => {
  const env = productionEnvironment();
  assert.deepEqual([...requiredComponents("production")].sort(), ["container", "ingress"]);
  // The production host has no readiness route: the Hello container answers 404 and is not reported ready.
  const hello = await evaluateReadiness(env, deps(() => Promise.resolve(reply(404, ""))).deps);
  assert.equal(hello.environment, "production");
  assert.equal(hello.components.container.state, "misconfigured");
  assert.equal(hello.components.container.reason, "host_route_missing");
  assert.equal(hello.ready, false);
  for (const id of ["d1", "durableObject", "r2", "queue"] as const)
    assert.equal(hello.components[id].state, "not_required", id);
});

test("a missing binding is forwarded as not met, and only the Container binding stops the call", async () => {
  // Every declared binding except the Container is forwarded and judged by the host, the one that owns each verdict.
  const forwarded = [
    "SOURCE_REVISION",
    "HELLO_RATE_LIMITER",
    "ALLOWED_ORIGIN",
    "CSRF_SECRET",
    "DB",
    "RECOVERY_GENERATION",
    "JOB_COORDINATOR",
    "OBJECTS",
    "REALM_ID",
    "WAKE_QUEUE",
  ];
  for (const name of forwarded) {
    const { env } = proofEnvironment({ [name]: undefined });
    const host = deps(healthy);
    await evaluateReadiness(env, host.deps);
    assert.equal(host.calls.host, 1, `${name}: the host judges the whole report`);
    assert.equal(host.calls.forwarded[0]?.bindings[name], false, name);
  }
  // Without the Container binding there is no call to make: the report names it and judges nothing else.
  const { env } = proofEnvironment({ CLOUD_CONTAINER: undefined });
  const host = deps(healthy);
  const report = await evaluateReadiness(env, host.deps);
  assert.equal(host.calls.host, 0, "CLOUD_CONTAINER: no Container call");
  assert.equal(report.components.container.state, "unavailable");
  assert.equal(report.components.container.reason, "unreachable");
  assert.deepEqual(report.components.container.missing, ["CLOUD_CONTAINER"]);
  assert.equal(report.components.container.elapsedMs, undefined, "nothing was awaited");
  assert.equal(report.components.d1.state, "unknown", "D1 cannot be judged without the Container");
  assert.equal(report.components.d1.reason, "container_not_ready");
  assert.equal(report.status, "unavailable");
  assert.equal(report.ready, false);
  assert.equal(readinessResponse(report).headers.get("retry-after"), "2");
});

test("a missing CSRF secret reaches the host, which judges it as the Container's key_missing", async () => {
  // The host's own report for a deployment without the secret: the verdict is its, and the Worker passes it through.
  const judged = JSON.parse(hostReport()) as Record<string, unknown>;
  const judgedComponents = judged.components as Record<string, unknown>;
  const body = JSON.stringify({
    ...judged,
    status: "misconfigured",
    ready: false,
    components: {
      ...judgedComponents,
      container: { state: "misconfigured", reason: "key_missing", missing: ["CSRF_SECRET"] },
    },
  });
  const host = deps(() => Promise.resolve(reply(503, body)));
  const report = await evaluateReadiness(
    proofEnvironment({ CSRF_SECRET: undefined }).env,
    host.deps,
  );
  assert.equal(host.calls.host, 1);
  assert.equal(host.calls.forwarded[0]?.bindings.CSRF_SECRET, false);
  assert.equal(report.components.container.state, "misconfigured");
  assert.equal(report.components.container.reason, "key_missing");
  assert.deepEqual(report.components.container.missing, ["CSRF_SECRET"]);
  assert.equal(report.status, "misconfigured");
  assert.equal(readinessResponse(report).headers.get("retry-after"), null);
});

test("a binding of the wrong shape is not met, and so is a recovery generation outside the unsigned 64-bit range", () => {
  for (const wrong of [{}, "binding", 7, null]) {
    const { env } = proofEnvironment({ OBJECTS: wrong, WAKE_QUEUE: wrong });
    assert.deepEqual(missingBindings(env, "r2"), ["OBJECTS"]);
    assert.equal(bindingObservations(env).OBJECTS, false);
    assert.equal(bindingObservations(env).WAKE_QUEUE, false);
  }
  for (const generation of ["", "01", "-1", "1.5", "18446744073709551616", "abc"]) {
    const { env } = proofEnvironment({ RECOVERY_GENERATION: generation });
    assert.deepEqual(missingBindings(env, "d1"), ["RECOVERY_GENERATION"], generation);
  }
  for (const generation of ["0", "7", "18446744073709551615"])
    assert.deepEqual(
      missingBindings(proofEnvironment({ RECOVERY_GENERATION: generation }).env, "d1"),
      [],
    );
});

test("a missing signing key is not forwarded: no call is made, and the report names the key", async () => {
  const host = deps(healthy);
  const w2c = await evaluateReadiness(
    proofEnvironment({ HMAC_W2C_SECRET: undefined }).env,
    host.deps,
  );
  assert.equal(host.calls.host, 0, "nothing can be signed, so nothing is forwarded");
  assert.equal(w2c.components.container.state, "unavailable");
  assert.equal(w2c.components.container.reason, "unreachable");
  assert.deepEqual(w2c.components.container.missing, ["HMAC_W2C_KEY"]);
  assert.equal(w2c.components.d1.state, "unknown", "D1 cannot be judged without the Container");
  assert.equal(w2c.ready, false);
});

test("a missing return-direction key is forwarded, and the host's D1 verdict is passed through", async () => {
  const host = deps(() =>
    Promise.resolve(hostReply({ state: "misconfigured", reason: "key_missing" })),
  );
  const report = await evaluateReadiness(
    proofEnvironment({ HMAC_C2W_KEY_ID: undefined }).env,
    host.deps,
  );
  assert.equal(host.calls.host, 1);
  assert.equal(host.calls.forwarded[0]?.bindings.HMAC_C2W_KEY, false);
  assert.equal(report.components.d1.state, "misconfigured");
  assert.equal(report.components.d1.reason, "key_missing");
});

test("a half-configured previous key makes the direction unusable instead of being ignored", async () => {
  const host = deps(healthy);
  const report = await evaluateReadiness(
    proofEnvironment({ HMAC_W2C_PREVIOUS_KEY_ID: "w2c-0" }).env,
    host.deps,
  );
  assert.equal(host.calls.host, 0, "the direction is unusable, so nothing is signed or forwarded");
  assert.equal(report.components.container.state, "unavailable");
  assert.deepEqual(report.components.container.missing, ["HMAC_W2C_KEY"]);
  assert.equal(report.ready, false);
});

test("the Worker forwards its plan manifest and never compares it: the host's verdict on a mismatch is passed through", async () => {
  const host = deps(() =>
    Promise.resolve(
      hostReply(
        { state: "misconfigured", reason: "plan_hash_mismatch" },
        { host: { manifestHash: otherManifest, schemaVersion: "1" } },
      ),
    ),
  );
  const report = await evaluateReadiness(proofEnvironment().env, host.deps);
  assert.equal(host.calls.forwarded[0]?.manifestHash, manifest);
  assert.equal(report.components.d1.reason, "plan_hash_mismatch");
  assert.equal(report.status, "misconfigured");
  assert.equal(report.ready, false);
  assert.equal(readinessResponse(report).status, 503);
  assert.equal(readinessResponse(report).headers.get("retry-after"), null);
});

test("a Container the platform could not start is unavailable, never ready, and D1 is not judged", async () => {
  const cases: [HostReply, string][] = [
    [libraryNoInstance, "no_instance_available"],
    [libraryStartFailed, "start_failed"],
    [reply(429, "rate limited", "text/plain"), "rate_limited"],
  ];
  for (const [answer, reason] of cases) {
    const report = await evaluateReadiness(
      proofEnvironment().env,
      deps(() => Promise.resolve(answer)).deps,
    );
    assert.equal(report.components.container.state, "unavailable", reason);
    assert.equal(report.components.container.reason, reason);
    assert.equal(report.components.d1.state, "unknown");
    assert.equal(report.status, "unavailable");
    assert.equal(report.ready, false);
    assert.equal(report.host, undefined);
    assert.equal(readinessResponse(report).headers.get("retry-after"), "2");
  }
});

test("other host answers are classified, and none of them is ready", () => {
  const cases: [HostReply, string, string][] = [
    [reply(401, "", null), "misconfigured", "key_mismatch"],
    [reply(404, "", null), "misconfigured", "host_route_missing"],
    [reply(502, "x", "text/plain"), "unavailable", "host_error"],
    [reply(500, "", null), "unavailable", "host_error"],
    [reply(503, "not json"), "unavailable", "host_error"],
    [reply(200, "not json"), "unavailable", "host_reply_invalid"],
    [reply(200, "{}"), "unavailable", "host_reply_invalid"],
    // A report that says not ready under a 200, or ready under a 503: the two statements disagree and are not believed.
    [
      reply(200, hostReport({ state: "misconfigured", reason: "d1_unavailable" })),
      "unavailable",
      "host_reply_invalid",
    ],
    [reply(503, hostReport()), "unavailable", "host_error"],
    // The old host shape, with one component, seen during a rollout, fails closed.
    [
      reply(
        200,
        JSON.stringify({
          ready: true,
          manifestHash: manifest,
          schemaVersion: "1",
          revision: "r",
          components: { d1: { state: "ready" } },
        }),
      ),
      "unavailable",
      "host_reply_invalid",
    ],
  ];
  for (const [answer, state, reason] of cases) {
    const classified = classifyHostReply(answer);
    assert.equal(classified.kind, "transport", `${answer.status} ${reason}`);
    if (classified.kind !== "transport") continue;
    assert.equal(classified.container.state, state, `${answer.status} ${reason}`);
    assert.equal(classified.container.reason, reason, `${answer.status} ${reason}`);
  }
});

test("the host reply is read strictly: only the closed report is believed", () => {
  const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const valid = JSON.parse(hostReport()) as Record<string, unknown>;
  assert.notEqual(parseHostReport(bytes(valid)), null);
  const components = valid.components as Record<string, unknown>;
  const withD1 = (value: unknown) => ({ ...components, d1: value });
  const invalid: unknown[] = [
    null,
    [],
    { ...valid, ready: "true" },
    { ...valid, ready: false },
    { ...valid, status: "ready", ready: false },
    { ...valid, schema: "cloud.readiness.v0" },
    { ...valid, environment: "staging" },
    { ...valid, workerRevision: "x".repeat(81) },
    { ...valid, extra: 1 },
    { ...valid, host: { manifestHash: "short", schemaVersion: "1" } },
    { ...valid, host: { manifestHash: manifest.toUpperCase(), schemaVersion: "1" } },
    { ...valid, host: { manifestHash: manifest, schemaVersion: 1 } },
    { ...valid, host: { manifestHash: manifest, schemaVersion: "1", revision: 5 } },
    {
      ...valid,
      host: { manifestHash: manifest, schemaVersion: "1", revision: "x".repeat(81) },
    },
    { ...valid, host: undefined },
    { ...valid, components: null },
    { ...valid, components: {} },
    { ...valid, components: { ...components, extra: { state: "ready" } } },
    { ...valid, components: { ...components, d1: undefined } },
    { ...valid, components: withD1({ state: "made_up" }) },
    { ...valid, components: withD1({ state: "ready", reason: "free text" }) },
    { ...valid, components: withD1({ state: "ready", evidence: "guess" }) },
    { ...valid, components: withD1({ state: "ready", missing: [1] }) },
    { ...valid, components: withD1({ state: "ready", elapsedMs: 1.5 }) },
    { ...valid, components: withD1({ state: "ready", elapsedMs: 60_001 }) },
    { ...valid, components: withD1({ state: "ready", value: "secret" }) },
  ];
  for (const value of invalid)
    assert.equal(parseHostReport(bytes(value)), null, JSON.stringify(value).slice(0, 120));
  assert.equal(parseHostReport(new Uint8Array([0xff, 0xfe])), null);
});

test("a Container that does not answer within the bounded wait is starting, and the call is aborted", async () => {
  let aborted = false;
  const host = deps(
    (signal) =>
      new Promise<HostReply>((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("aborted"));
        });
      }),
    30,
  );
  const started = Date.now();
  const report = await evaluateReadiness(proofEnvironment().env, host.deps);
  assert(Date.now() - started < 1_500, "the wait is bounded");
  assert.equal(aborted, true);
  assert.equal(report.components.container.state, "starting");
  assert.equal(report.components.container.reason, "no_answer_in_wait");
  assert.equal(report.components.d1.state, "unknown");
  assert.equal(report.status, "starting");
  assert.equal(readinessResponse(report).headers.get("retry-after"), "2");
});

test("a call that ignores the abort signal is still ended at the bound", async () => {
  const host = deps(() => new Promise<HostReply>(() => {}), 20);
  const report = await evaluateReadiness(proofEnvironment().env, host.deps);
  assert.equal(report.components.container.reason, "no_answer_in_wait");
});

test("a Container call that throws is unavailable, and its error text is never reported", async () => {
  const host = deps(() =>
    Promise.reject(new Error("connection reset with details nobody should log")),
  );
  const report = await evaluateReadiness(proofEnvironment().env, host.deps);
  assert.equal(report.components.container.state, "unavailable");
  assert.equal(report.components.container.reason, "unreachable");
  assert(!JSON.stringify(report).includes("details"));
});

test("a transport-only report judges nothing but the Container: the probes are not reported as verdicts", async () => {
  const failing = proofEnvironment({
    JOB_COORDINATOR: { getByName: () => ({ readPoison: () => Promise.reject(new Error("x")) }) },
    OBJECTS: {
      head: () => new Promise(() => {}),
      get: async () => null,
      put: async () => null,
      delete: async () => {},
    },
  });
  const report = await evaluateReadiness(
    failing.env,
    deps(() => Promise.reject(new Error("down")), 20).deps,
  );
  assert.equal(report.components.container.state, "unavailable");
  assert.equal(report.components.container.reason, "unreachable");
  for (const id of ["ingress", "d1", "durableObject", "r2", "queue"] as const) {
    assert.equal(report.components[id].state, "unknown", id);
    assert.equal(report.components[id].reason, "container_not_ready", id);
    assert.equal(report.components[id].elapsedMs, undefined, `${id} carries no timing`);
  }
  assert.equal(report.status, "unavailable");
});

test("the forwarded probes carry the outcome of each bounded read", async () => {
  const failing = proofEnvironment({
    JOB_COORDINATOR: { getByName: () => ({ readPoison: () => Promise.reject(new Error("x")) }) },
    OBJECTS: {
      head: () => new Promise(() => {}),
      get: async () => null,
      put: async () => null,
      delete: async () => {},
    },
  });
  const host = deps(healthy, 20);
  await evaluateReadiness(failing.env, host.deps);
  assert.equal(host.calls.forwarded[0]?.durableObject?.outcome, "unreachable");
  assert.equal(host.calls.forwarded[0]?.r2?.outcome, "no_answer_in_wait");
});

test("nothing in the report or its wire form carries a secret, a value or an error text", async () => {
  const { env } = proofEnvironment({ DB: undefined });
  const report = await evaluateReadiness(
    env,
    deps(() => Promise.reject(new Error("boom with a secret"))).deps,
  );
  const text = JSON.stringify(report) + (await readinessResponse(report).text());
  for (const secret of Object.values(secretMaterial)) assert.equal(text.includes(secret), false);
  assert.equal(text.includes("boom"), false);
});

test("the real default wiring reports a missing deployment instead of throwing", async () => {
  const report = await evaluateReadiness({});
  assert.equal(report.environment, "production");
  // Without the Container binding the Worker makes no call: the status is the Container's class, and the missing names are its observations.
  assert.equal(report.status, "unavailable");
  assert.equal(report.ready, false);
  assert.equal(report.components.ingress.state, "unknown");
  assert.deepEqual(report.components.ingress.missing, ["SOURCE_REVISION", "HELLO_RATE_LIMITER"]);
  assert.deepEqual(report.components.container.missing, ["CLOUD_CONTAINER"]);
});

test("a binding that throws before it returns a promise is unreachable, not an escaping error", async () => {
  const throwing = proofEnvironment({
    JOB_COORDINATOR: {
      getByName: () => {
        throw new Error("not a real namespace");
      },
    },
    OBJECTS: {
      head: () => {
        throw new Error("not a real bucket");
      },
      get: async () => null,
      put: async () => null,
      delete: async () => {},
    },
  });
  const host = deps(healthy);
  await evaluateReadiness(throwing.env, host.deps);
  assert.equal(host.calls.forwarded[0]?.durableObject?.outcome, "unreachable");
  assert.equal(host.calls.forwarded[0]?.r2?.outcome, "unreachable");
});
