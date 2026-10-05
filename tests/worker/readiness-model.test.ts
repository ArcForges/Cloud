// SPDX-License-Identifier: AGPL-3.0-only
// The readiness model: the whole is ready only when every required component is, a retry hint exists only for a
// transient failure, and neither the response nor the log line can carry anything outside the closed vocabulary.
import assert from "node:assert/strict";
import test from "node:test";
import { readinessLogEvent, readinessResponse, wireOf } from "../../worker/readiness/http.ts";
import {
  componentIds,
  componentStates,
  isTransient,
  readinessSchema,
  summarize,
  type ComponentId,
  type ComponentState,
  type Components,
  type ReadinessReport,
} from "../../worker/readiness/model.ts";

const states = (choose: (id: ComponentId) => ComponentState): Components =>
  Object.fromEntries(
    componentIds.map((id) => [id, { state: choose(id) }]),
  ) as unknown as Components;
const everyone = (state: ComponentState) => states(() => state);

function report(components: Components, extra: Partial<ReadinessReport> = {}): ReadinessReport {
  const status = summarize(components);
  return {
    schema: readinessSchema,
    status,
    ready: status === "ready",
    environment: "proof",
    workerRevision: "rev",
    components,
    ...extra,
  };
}

test("every combination of component states is ready only when each is ready or not required", () => {
  let combinations = 0;
  const walk = (chosen: ComponentState[]) => {
    if (chosen.length === componentIds.length) {
      combinations++;
      const components = states((id) => chosen[componentIds.indexOf(id)] as ComponentState);
      const expected = chosen.every((state) => state === "ready" || state === "not_required");
      assert.equal(summarize(components) === "ready", expected, chosen.join(","));
      return;
    }
    for (const state of componentStates) walk([...chosen, state]);
  };
  walk([]);
  assert.equal(combinations, componentStates.length ** componentIds.length);
});

test("the status follows a fixed order: misconfigured, unavailable, starting, then an undetermined component", () => {
  const only = (changes: Partial<Record<ComponentId, ComponentState>>) =>
    states((id) => changes[id] ?? "ready");
  assert.equal(summarize(everyone("ready")), "ready");
  assert.equal(summarize(only({ queue: "misconfigured", d1: "unavailable" })), "misconfigured");
  assert.equal(summarize(only({ container: "starting", r2: "unavailable" })), "unavailable");
  assert.equal(summarize(only({ container: "starting", d1: "unknown" })), "starting");
  assert.equal(summarize(only({ d1: "unknown" })), "unavailable");
  assert.equal(summarize(everyone("not_required")), "ready");
});

test("only a transient status is worth retrying", () => {
  assert.deepEqual(
    (["ready", "starting", "unavailable", "misconfigured"] as const).map(isTransient),
    [false, true, true, false],
  );
});

test("a ready report is 200 and every other status is 503 with retry guidance only when waiting can help", async () => {
  const ready = readinessResponse(report(everyone("ready")));
  assert.equal(ready.status, 200);
  assert.equal(ready.headers.get("retry-after"), null);
  assert.equal(ready.headers.get("cache-control"), "no-store");

  const starting = readinessResponse(
    report({ ...everyone("ready"), container: { state: "starting" } }),
  );
  assert.equal(starting.status, 503);
  assert.equal(starting.headers.get("retry-after"), "2");

  const unavailable = readinessResponse(
    report({ ...everyone("ready"), r2: { state: "unavailable", reason: "unreachable" } }),
  );
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.headers.get("retry-after"), "2");

  const broken = readinessResponse(
    report({ ...everyone("ready"), d1: { state: "misconfigured", reason: "plan_hash_mismatch" } }),
  );
  assert.equal(broken.status, 503);
  assert.equal(broken.headers.get("retry-after"), null, "a retry cannot repair a misconfiguration");
  const body = (await broken.json()) as { ready: boolean; status: string };
  assert.equal(body.ready, false);
  assert.equal(body.status, "misconfigured");
});

test("the wire form keeps the names the operator scenarios read, from the host reply only", () => {
  const without = wireOf(report(everyone("ready")));
  assert.deepEqual(Object.keys(without).sort(), [
    "components",
    "environment",
    "ready",
    "schema",
    "status",
    "workerRevision",
  ]);
  const withHost = wireOf(
    report(everyone("ready"), { host: { manifestHash: "h", schemaVersion: "1", revision: "r" } }),
  );
  assert.equal(withHost.manifestHash, "h");
  assert.equal(withHost.schemaVersion, "1");
  assert.equal(withHost.revision, "r");
});

test("the log line holds the status and one closed token per component, and nothing else", () => {
  const line = readinessLogEvent(
    report(
      {
        ingress: { state: "ready", evidence: "bound" },
        container: { state: "unavailable", reason: "no_instance_available", elapsedMs: 31_000 },
        d1: { state: "unknown", reason: "container_not_ready" },
        durableObject: {
          state: "misconfigured",
          reason: "binding_missing",
          missing: ["JOB_COORDINATOR"],
        },
        r2: { state: "not_required" },
        queue: { state: "ready", evidence: "bound" },
      },
      { workerRevision: "secret-looking-revision" },
    ),
  );
  assert.deepEqual(line, {
    event: "cloud.readiness",
    status: "misconfigured",
    environment: "proof",
    components: {
      ingress: "ready",
      container: "unavailable:no_instance_available",
      d1: "unknown:container_not_ready",
      durableObject: "misconfigured:binding_missing",
      r2: "not_required",
      queue: "ready",
    },
  });
  const text = JSON.stringify(line);
  for (const forbidden of ["JOB_COORDINATOR", "31000", "secret-looking-revision"])
    assert.equal(text.includes(forbidden), false, forbidden);
});
