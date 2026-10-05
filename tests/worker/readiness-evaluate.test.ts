// SPDX-License-Identifier: AGPL-3.0-only
// WP-21.07: each component is reported separately, and a missing binding, a plan-manifest mismatch or a recovery-
// generation mismatch fails readiness instead of letting a partially configured deployment look successful.
import assert from "node:assert/strict";
import test from "node:test";
import { missingBindings, requiredComponents } from "../../worker/readiness/bindings.ts";
import {
  assessHostReply,
  evaluateReadiness,
  parseHostBody,
  r2ProbeKey,
  durableObjectProbeName,
  type HostReply,
  type ReadinessDeps,
} from "../../worker/readiness/evaluate.ts";
import { readinessResponse } from "../../worker/readiness/http.ts";
import { componentIds, type ComponentId } from "../../worker/readiness/model.ts";
import {
  hostBody,
  libraryNoInstance,
  libraryStartFailed,
  manifest,
  otherManifest,
  productionEnvironment,
  proofEnvironment,
  reply,
  secretMaterial,
} from "./support/readiness-fixtures.ts";

function deps(host: (signal: AbortSignal) => Promise<HostReply>, waitMs = 2_000) {
  const calls = { host: 0 };
  const result: Partial<ReadinessDeps> = {
    callHost: (_env, signal) => {
      calls.host++;
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
const healthy = () => Promise.resolve(reply(200, hostBody()));

test("a complete proof environment reports every component ready, separately", async () => {
  const { env, calls } = proofEnvironment();
  const host = deps(healthy);
  const report = await evaluateReadiness(env, host.deps);
  assert.equal(report.status, "ready");
  assert.equal(report.ready, true);
  assert.equal(report.environment, "proof");
  for (const id of componentIds) assert.equal(report.components[id].state, "ready", id);
  assert.equal(
    report.components.queue.evidence,
    "bound",
    "a Queue binding is checked for shape only",
  );
  assert.equal(report.components.container.evidence, "probed");
  assert.equal(report.host?.manifestHash, manifest);
  assert.equal(report.host?.revision, "fedcba9876543210fedcba9876543210fedcba98");
  // The probes are reads: one host call, one Durable Object read of a fixed name, one R2 head of an absent key.
  assert.equal(host.calls.host, 1);
  assert.deepEqual(calls.durableObject, [durableObjectProbeName]);
  assert.deepEqual(calls.r2, [r2ProbeKey]);
  assert.equal(calls.queueSends, 0, "readiness never enqueues work");
  assert.equal(readinessResponse(report).status, 200);
});

test("the production Worker declares only the ingress and the Container", async () => {
  const env = productionEnvironment();
  assert.deepEqual([...requiredComponents("production")].sort(), ["container", "ingress"]);
  const host = deps(() => Promise.resolve(reply(200, hostBody())));
  const report = await evaluateReadiness(env, host.deps);
  assert.equal(report.environment, "production");
  assert.equal(report.status, "ready");
  for (const id of ["d1", "durableObject", "r2", "queue"] as const)
    assert.equal(report.components[id].state, "not_required", id);
  // The Container here is the Hello host: it has no readiness route, so it must not be reported ready.
  const hello = await evaluateReadiness(env, deps(() => Promise.resolve(reply(404, ""))).deps);
  assert.equal(hello.components.container.state, "misconfigured");
  assert.equal(hello.ready, false);
});

const bindingCases: [string, ComponentId][] = [
  ["SOURCE_REVISION", "ingress"],
  ["HELLO_RATE_LIMITER", "ingress"],
  ["ALLOWED_ORIGIN", "ingress"],
  ["CLOUD_CONTAINER", "container"],
  ["CSRF_SECRET", "container"],
  ["DB", "d1"],
  ["RECOVERY_GENERATION", "d1"],
  ["JOB_COORDINATOR", "durableObject"],
  ["OBJECTS", "r2"],
  ["REALM_ID", "r2"],
  ["WAKE_QUEUE", "queue"],
];

for (const [name, component] of bindingCases)
  test(`a missing ${name} fails readiness in the ${component} component and nothing else`, async () => {
    const { env } = proofEnvironment({ [name]: undefined });
    assert.deepEqual(missingBindings(env, component), [name]);
    const report = await evaluateReadiness(env, deps(healthy).deps);
    assert.equal(report.status, "misconfigured");
    assert.equal(report.ready, false);
    assert.equal(report.components[component].state, "misconfigured");
    assert.deepEqual(report.components[component].missing, [name]);
    assert.equal(
      report.components[component].reason,
      name === "CSRF_SECRET" ? "key_missing" : "binding_missing",
    );
    for (const other of componentIds.filter((id) => id !== component))
      if (other !== "d1" || component !== "container")
        assert.notEqual(report.components[other].state, "misconfigured", other);
    const response = readinessResponse(report);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("retry-after"), null);
  });

test("a binding of the wrong shape counts as missing", async () => {
  for (const wrong of [{}, "binding", 7, null]) {
    const { env } = proofEnvironment({ OBJECTS: wrong, WAKE_QUEUE: wrong });
    const report = await evaluateReadiness(env, deps(healthy).deps);
    assert.equal(report.components.r2.state, "misconfigured");
    assert.equal(report.components.queue.state, "misconfigured");
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

test("a missing signing key fails the Container and D1 components without calling the Container", async () => {
  const w2c = await evaluateReadiness(
    proofEnvironment({ HMAC_W2C_SECRET: undefined }).env,
    (() => {
      const host = deps(healthy);
      return host.deps;
    })(),
  );
  assert.equal(w2c.components.container.state, "misconfigured");
  assert.equal(w2c.components.container.reason, "key_missing");
  assert.deepEqual(w2c.components.container.missing, ["HMAC_W2C_KEY"]);
  assert.equal(w2c.components.d1.state, "unknown", "D1 cannot be judged without the Container");
  assert.equal(w2c.components.d1.reason, "container_not_ready");
  assert.equal(w2c.ready, false);

  const host = deps(healthy);
  const c2w = await evaluateReadiness(
    proofEnvironment({ HMAC_C2W_KEY_ID: undefined }).env,
    host.deps,
  );
  assert.equal(c2w.components.d1.state, "misconfigured");
  assert.deepEqual(c2w.components.d1.missing, ["HMAC_C2W_KEY"]);
  assert.equal(host.calls.host, 1);

  const neither = deps(healthy);
  const none = await evaluateReadiness(
    proofEnvironment({ CLOUD_CONTAINER: undefined }).env,
    neither.deps,
  );
  assert.equal(neither.calls.host, 0, "no Container call without a Container binding");
  assert.equal(none.components.container.reason, "binding_missing");
});

test("a half-configured previous key makes the direction unusable instead of being ignored", async () => {
  const report = await evaluateReadiness(
    proofEnvironment({ HMAC_W2C_PREVIOUS_KEY_ID: "w2c-0" }).env,
    deps(healthy).deps,
  );
  assert.equal(report.components.container.state, "misconfigured");
  assert.equal(report.components.container.reason, "key_missing");
});

test("a plan-manifest mismatch fails readiness even when the host says it is ready", async () => {
  const { env } = proofEnvironment();
  const report = await evaluateReadiness(
    env,
    deps(() =>
      Promise.resolve(reply(200, hostBody({ state: "ready" }, { manifestHash: otherManifest }))),
    ).deps,
  );
  assert.equal(report.components.d1.state, "misconfigured");
  assert.equal(report.components.d1.reason, "plan_hash_mismatch");
  assert.equal(report.components.container.state, "ready", "the Container itself answered");
  assert.equal(report.status, "misconfigured");
  assert.equal(report.ready, false);
  assert.equal(readinessResponse(report).status, 503);
});

test("a mismatch the host detects itself is reported as misconfigured, not as an outage", async () => {
  for (const reason of [
    "plan_hash_mismatch",
    "recovery_generation_mismatch",
    "schema_mismatch",
    "key_mismatch",
  ]) {
    const report = await evaluateReadiness(
      proofEnvironment().env,
      deps(() => Promise.resolve(reply(503, hostBody({ state: "misconfigured", reason })))).deps,
    );
    assert.equal(report.components.d1.state, "misconfigured", reason);
    assert.equal(report.components.d1.reason, reason);
    assert.equal(report.status, "misconfigured");
  }
  const outage = await evaluateReadiness(
    proofEnvironment().env,
    deps(() =>
      Promise.resolve(reply(503, hostBody({ state: "unavailable", reason: "d1_unavailable" }))),
    ).deps,
  );
  assert.equal(outage.components.d1.state, "unavailable");
  assert.equal(outage.status, "unavailable");
  assert.equal(readinessResponse(outage).headers.get("retry-after"), "2");
});

test("a schema version other than the Worker's fails a ready D1", () => {
  const assessed = assessHostReply(
    reply(200, hostBody({ state: "ready" }, { schemaVersion: "2" })),
    manifest,
  );
  assert.equal(assessed.d1.state, "misconfigured");
  assert.equal(assessed.d1.reason, "schema_mismatch");
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

test("other host answers are classified and none of them is ready", () => {
  const cases: [HostReply, string, string][] = [
    [reply(401, "", null), "misconfigured", "key_mismatch"],
    [reply(404, "", null), "misconfigured", "host_route_missing"],
    [reply(502, "x", "text/plain"), "unavailable", "host_error"],
    [reply(500, "", null), "unavailable", "host_error"],
    [reply(503, "not json"), "unavailable", "host_error"],
    [reply(200, "not json"), "unavailable", "host_reply_invalid"],
    [reply(200, "{}"), "unavailable", "host_reply_invalid"],
    // A reply whose two statements disagree is not believed.
    [
      reply(
        200,
        JSON.stringify({
          ready: true,
          manifestHash: manifest,
          schemaVersion: "1",
          components: { d1: { state: "unavailable" } },
        }),
      ),
      "unavailable",
      "host_reply_invalid",
    ],
    [
      reply(
        503,
        JSON.stringify({
          ready: false,
          manifestHash: manifest,
          schemaVersion: "1",
          components: { d1: { state: "ready" } },
        }),
      ),
      "unavailable",
      "host_error",
    ],
    // The old host shape without components, seen during a rollout, fails closed.
    [
      reply(
        200,
        JSON.stringify({ ready: true, manifestHash: manifest, schemaVersion: "1", revision: "r" }),
      ),
      "unavailable",
      "host_reply_invalid",
    ],
  ];
  for (const [answer, state, reason] of cases) {
    const assessed = assessHostReply(answer, manifest);
    assert.equal(assessed.container.state, state, `${answer.status} ${reason}`);
    assert.equal(assessed.container.reason, reason, `${answer.status} ${reason}`);
    assert.equal(assessed.d1.state, "unknown");
    assert.equal(assessed.host, undefined);
  }
});

test("the host reply is read strictly", () => {
  const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const valid = {
    ready: true,
    manifestHash: manifest,
    schemaVersion: "1",
    components: { d1: { state: "ready" } },
  };
  assert.notEqual(parseHostBody(bytes(valid)), null);
  const invalid: unknown[] = [
    null,
    [],
    { ...valid, ready: "true" },
    { ...valid, manifestHash: "short" },
    { ...valid, manifestHash: manifest.toUpperCase() },
    { ...valid, schemaVersion: 1 },
    { ...valid, revision: 5 },
    { ...valid, revision: "x".repeat(81) },
    { ...valid, components: null },
    { ...valid, components: {} },
    { ...valid, components: { d1: { state: "starting" } } },
    { ...valid, components: { d1: { state: "ready", reason: "free text" } } },
  ];
  for (const value of invalid)
    assert.equal(parseHostBody(bytes(value)), null, JSON.stringify(value));
  assert.equal(parseHostBody(new Uint8Array([0xff, 0xfe])), null);
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

test("a Container call that throws is unavailable", async () => {
  const host = deps(() =>
    Promise.reject(new Error("connection reset with details nobody should log")),
  );
  const report = await evaluateReadiness(proofEnvironment().env, host.deps);
  assert.equal(report.components.container.state, "unavailable");
  assert.equal(report.components.container.reason, "unreachable");
  assert(!JSON.stringify(report).includes("details"));
});

test("the Durable Object and R2 are judged by their own bounded reads", async () => {
  const failing = proofEnvironment({
    JOB_COORDINATOR: { getByName: () => ({ readPoison: () => Promise.reject(new Error("x")) }) },
    OBJECTS: {
      head: () => new Promise(() => {}),
      get: async () => null,
      put: async () => null,
      delete: async () => {},
    },
  });
  const report = await evaluateReadiness(failing.env, deps(healthy, 20).deps);
  assert.equal(report.components.durableObject.state, "unavailable");
  assert.equal(report.components.durableObject.reason, "unreachable");
  assert.equal(report.components.r2.state, "unavailable");
  assert.equal(report.components.r2.reason, "no_answer_in_wait");
  assert.equal(report.components.container.state, "ready", "components fail independently");
  assert.equal(report.components.d1.state, "ready");
  assert.equal(report.status, "unavailable");
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
  assert.equal(report.status, "misconfigured");
  assert.deepEqual(report.components.ingress.missing, ["SOURCE_REVISION", "HELLO_RATE_LIMITER"]);
  assert.deepEqual(report.components.container.missing, ["CLOUD_CONTAINER"]);
});

test("a binding that throws before it returns a promise is unavailable, not an escaping error", async () => {
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
  const report = await evaluateReadiness(throwing.env, deps(healthy).deps);
  assert.equal(report.components.durableObject.state, "unavailable");
  assert.equal(report.components.durableObject.reason, "unreachable");
  assert.equal(report.components.r2.state, "unavailable");
  assert.equal(report.components.r2.reason, "unreachable");
  assert.equal(report.status, "unavailable");
});
