// SPDX-License-Identifier: AGPL-3.0-only
// Offline tests of the pure helpers of the HAR.40 local proof drivers. The drivers themselves (the fixture AI proof, the dotnet crash run and
// the live capacity probe) are local opt-in and never run in CI; these tests pin the rules that decide whether a proof may claim a pass:
// the CI refusal, observations never counting as passes, the probe URL bounds and the parsing of the test summary.
import assert from "node:assert/strict";
import test from "node:test";
import {
  assertLocalOptIn,
  check,
  evidence,
  percentile,
  summarise,
} from "../../eng/verification/harness-proof-evidence.ts";
import {
  configurationChecks,
  containerValues,
  launchTarget,
  validProbeUrl,
} from "../../eng/verification/harness-proof-capacity.ts";
import { executorChecks, parseSummary } from "../../eng/verification/harness-proof-executor.ts";

test("the proof drivers refuse to run under CI and run locally", () => {
  assert.throws(() => assertLocalOptIn({ CI: "true" }), /never run under CI/u);
  assert.throws(() => assertLocalOptIn({ GITHUB_ACTIONS: "true" }), /never run under CI/u);
  assert.doesNotThrow(() => assertLocalOptIn({}));
  assert.doesNotThrow(() => assertLocalOptIn({ CI: "false" }));
});

test("a failed check fails the proof, and observations alone never pass it", () => {
  assert.equal(summarise([check("a", true, "x", "x"), check("b", false, "x", "y")]), "failed");
  assert.equal(summarise([check("a", true, "x", "x"), check("b", true, "x", "x")]), "passed");
  const observed = { name: "o", status: "observed" as const, expected: "e", observed: "o" };
  assert.equal(summarise([observed]), "not-run");
  assert.equal(summarise([]), "not-run");
  assert.equal(summarise([observed, check("c", true, "x", "x")]), "passed");
});

test("evidence records the task, the realness and a complete check list", () => {
  const record = evidence({
    proof: "unit-shape",
    realness: "node-fixture",
    checks: [check("a", true, "one", "one")],
    liveNotRun: ["operator step"],
    notes: ["note"],
    environment: { node: "test" },
    now: new Date("2026-10-08T00:00:00.000Z"),
  });
  assert.equal(record.schemaVersion, 1);
  assert.equal(record.task, "HAR.40");
  assert.equal(record.status, "passed");
  assert.equal(record.realness, "node-fixture");
  assert.equal(record.generatedAt, "2026-10-08T00:00:00.000Z");
  assert.deepEqual(record.liveNotRun, ["operator step"]);
});

test("the container configuration is only observed and never passes the capacity proof", () => {
  const wrangler = {
    containers: [
      {
        class_name: "CloudContainer",
        image: "./Dockerfile",
        max_instances: 1,
        instance_type: "lite",
      },
      {
        class_name: "FoundationContainer",
        image: "./Dockerfile",
        max_instances: 4,
        instance_type: "lite",
      },
    ],
  };
  assert.deepEqual(containerValues(wrangler)[0], {
    className: "CloudContainer",
    maxInstances: 1,
    instanceType: "lite",
  });
  const checks = configurationChecks(wrangler);
  assert.ok(checks.length > 0);
  assert.ok(
    checks.every((entry) => entry.status === "observed"),
    "configuration must never be a pass",
  );
  assert.equal(summarise(checks), "not-run");
  const target = checks.find((entry) => entry.name === "production-launch-target-applied");
  assert.match(target?.observed ?? "", /target not yet applied/u);
  assert.equal(launchTarget.instanceType, "standard-2");
  assert.deepEqual(containerValues({}), []);
});

test("the live probe accepts only an https origin with no query, fragment or userinfo", () => {
  assert.equal(validProbeUrl("https://proof.arcforges.com").hostname, "proof.arcforges.com");
  assert.throws(() => validProbeUrl("http://proof.arcforges.com"), /must be an https origin/u);
  assert.throws(() => validProbeUrl("https://proof.arcforges.com/?token=1"), /no query/u);
  assert.throws(() => validProbeUrl("https://proof.arcforges.com/#frag"), /no query/u);
  assert.throws(() => validProbeUrl("https://user:secret@proof.arcforges.com"), /no query/u);
});

test("the dotnet summary is parsed and any failure, empty run or non-zero exit fails the proof", () => {
  const output = [
    "Test run summary: Passed!",
    "  total: 58",
    "  failed: 0",
    "  succeeded: 58",
    "  skipped: 0",
  ].join("\n");
  assert.deepEqual(parseSummary(output), { total: 58, failed: 0, succeeded: 58 });
  assert.equal(parseSummary("no summary here"), null);
  assert.equal(summarise(executorChecks({ exitCode: 0, output })), "passed");
  assert.equal(
    summarise(executorChecks({ exitCode: 2, output: output.replace("failed: 0", "failed: 1") })),
    "failed",
  );
  assert.equal(summarise(executorChecks({ exitCode: 0, output: "" })), "failed");
  assert.equal(
    summarise(executorChecks({ exitCode: 0, output: "  total: 0\n  failed: 0\n  succeeded: 0" })),
    "failed",
  );
});

test("percentiles use the nearest rank of a sorted sample", () => {
  const sample = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  assert.equal(percentile(sample, 0.5), 5);
  assert.equal(percentile(sample, 0.95), 10);
  assert.equal(percentile(sample, 0.1), 1);
  assert.ok(Number.isNaN(percentile([], 0.5)));
});
