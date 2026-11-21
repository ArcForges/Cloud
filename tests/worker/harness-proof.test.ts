// SPDX-License-Identifier: AGPL-3.0-only
// Offline tests for the HAR.40 AI binding and capacity drivers. They pin the accepted proof names, CI refusal, evidence
// status and probe URL bounds.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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

test("npm exposes the current local AI binding and capacity proofs", () => {
  const { scripts } = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { scripts: Record<string, string> };
  const proofs = Object.entries(scripts).filter(([name]) => name.startsWith("test:harness:"));
  assert.deepEqual(Object.fromEntries(proofs), {
    "test:harness:ai": "node eng/verification/harness-proof.ts ai-binding",
    "test:harness:capacity": "node eng/verification/harness-proof.ts container-capacity",
  });
});

test("percentiles use the nearest rank of a sorted sample", () => {
  const sample = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  assert.equal(percentile(sample, 0.5), 5);
  assert.equal(percentile(sample, 0.95), 10);
  assert.equal(percentile(sample, 0.1), 1);
  assert.ok(Number.isNaN(percentile([], 0.5)));
});
