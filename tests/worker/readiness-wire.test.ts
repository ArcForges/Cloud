// SPDX-License-Identifier: AGPL-3.0-only
// The HTTP and log form of a readiness report (WP-21.07): a ready report is 200, every other status is 503 with retry guidance only when
// waiting can help, the wire form keeps the names the operator scenarios read, and the log line carries nothing outside the closed
// vocabulary. The whole's status is the C# evaluator's; these cases use reports whose status is stated.
import assert from "node:assert/strict";
import test from "node:test";
import { readinessLogEvent, readinessResponse, wireOf } from "../../worker/readiness/http.ts";
import type { Components, ReadinessReport } from "../../worker/readiness/report.ts";
import {
  readinessComponentIds,
  readinessSchema,
} from "../../worker/tables/cloud-tables.generated.ts";

const readyComponents: Components = {
  ingress: { state: "ready", evidence: "bound" },
  container: { state: "ready", evidence: "probed" },
  d1: { state: "ready", evidence: "probed" },
  durableObject: { state: "ready", evidence: "probed" },
  r2: { state: "ready", evidence: "probed" },
  queue: { state: "ready", evidence: "bound" },
};

function report(
  status: ReadinessReport["status"],
  components: Partial<Components> = {},
  extra: Partial<ReadinessReport> = {},
): ReadinessReport {
  return {
    schema: readinessSchema,
    status,
    ready: status === "ready",
    environment: "proof",
    workerRevision: "rev",
    components: { ...readyComponents, ...components },
    ...extra,
  };
}

test("a ready report is 200 and every other status is 503 with retry guidance only when waiting can help", async () => {
  const ready = readinessResponse(report("ready"));
  assert.equal(ready.status, 200);
  assert.equal(ready.headers.get("retry-after"), null);
  assert.equal(ready.headers.get("cache-control"), "no-store");

  const starting = readinessResponse(
    report("starting", { container: { state: "starting", reason: "no_answer_in_wait" } }),
  );
  assert.equal(starting.status, 503);
  assert.equal(starting.headers.get("retry-after"), "2");

  const unavailable = readinessResponse(
    report("unavailable", { r2: { state: "unavailable", reason: "unreachable" } }),
  );
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.headers.get("retry-after"), "2");

  const broken = readinessResponse(
    report("misconfigured", {
      d1: { state: "misconfigured", reason: "plan_hash_mismatch" },
    }),
  );
  assert.equal(broken.status, 503);
  assert.equal(broken.headers.get("retry-after"), null, "a retry cannot repair a misconfiguration");
  const body = (await broken.json()) as { ready: boolean; status: string };
  assert.equal(body.ready, false);
  assert.equal(body.status, "misconfigured");
});

test("the wire form keeps the names the operator scenarios read, and lifts the host's own values only when the host answered", () => {
  const without = wireOf(report("ready"));
  assert.deepEqual(Object.keys(without).sort(), [
    "components",
    "environment",
    "ready",
    "schema",
    "status",
    "workerRevision",
  ]);
  const withHost = wireOf(
    report("ready", {}, { host: { manifestHash: "h", schemaVersion: "1", revision: "r" } }),
  );
  assert.equal(withHost.manifestHash, "h");
  assert.equal(withHost.schemaVersion, "1");
  assert.equal(withHost.revision, "r");
});

test("the log line holds the status and one closed token per component, and nothing else", () => {
  const line = readinessLogEvent(
    report(
      "misconfigured",
      {
        container: { state: "unavailable", reason: "no_instance_available", elapsedMs: 31_000 },
        d1: { state: "unknown", reason: "container_not_ready" },
        durableObject: {
          state: "misconfigured",
          reason: "binding_missing",
          missing: ["JOB_COORDINATOR"],
        },
        r2: { state: "not_required" },
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
  assert.deepEqual(Object.keys((line.components as Record<string, unknown>) ?? {}), [
    ...readinessComponentIds,
  ]);
  const text = JSON.stringify(line);
  for (const forbidden of ["JOB_COORDINATOR", "31000", "secret-looking-revision"])
    assert.equal(text.includes(forbidden), false, forbidden);
});
