// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import {
  candidateArtifactName,
  candidateJobName,
  repository,
  workflowPath,
} from "../eng/verification/proof-gate.ts";
import { scratchDirectory } from "../tests/worker/support/scratch.ts";
import {
  evaluateFixtureProducer,
  evaluateFixtureTarget,
  preflight,
  type DeploymentFixture,
} from "./cloudflare.ts";
import { readJson, root } from "./process.ts";
import type { WorkerConfig } from "./project.ts";

const configuration = await readJson<WorkerConfig>(path.join(root, "wrangler.json"));
const recorded = await readJson<{ sha: string; responses: Record<string, unknown> }>(
  path.join(root, "tests/worker/fixtures/proof-gate-9085b12.json"),
);
const schemaVersion = (await readdir(path.join(root, "center/internal/schema/migrations"))).filter(
  (name) => /^\d{4}_[a-z0-9_]+\.sql$/u.test(name),
).length;
const liveVersion = "771aef7b-179c-4fb8-9223-2e221b2c6900";
const otherVersion = "771aef7b-179c-4fb8-9223-2e221b2c6901";

function fixture(revision = recorded.sha): DeploymentFixture {
  return {
    source: "external-fixture",
    schema: 1,
    github: { dispatch: recorded.sha, responses: structuredClone(recorded.responses) },
    d1: { target: "production", revision, status: "not-applicable" },
    postgres: {
      target: "production",
      revision,
      status: "passed",
      version: schemaVersion,
      database: "fixture_center",
      runtimeRole: "fixture_center_runtime",
    },
    databaseRoles: {
      migration: "fixture_owner",
      hello: "fixture_owner",
      database: "fixture_center",
    },
    worker: {
      deployments: { versions: [{ version_id: liveVersion, percentage: 100 }] },
      versions: { [liveVersion]: { annotations: { "workers/message": "runtime-slot=a" } } },
    },
  };
}

function command(...args: string[]) {
  return spawnSync(process.execPath, [path.join(root, "tooling/cloudflare.ts"), ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 120_000,
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
  });
}

test("preflight uses the existing exact producer gate and refuses stale main and missing inventory", () => {
  const evidence = fixture();
  const input = evaluateFixtureProducer(evidence);
  assert.equal(input.sha, recorded.sha);
  assert.equal(input.runId, 41866820816);
  assert.match(input.artifactDigest, /^sha256:[a-f0-9]{64}$/u);
  const ref = "repos/ArcForges/Cloud/git/ref/heads/main";
  evidence.github.responses[ref] = {
    ref: "refs/heads/main",
    object: { type: "commit", sha: "0".repeat(40) },
  };
  assert.throws(() => evaluateFixtureProducer(evidence), /not the head of main/u);
  delete evidence.github.responses[ref];
  assert.throws(() => evaluateFixtureProducer(evidence), /fixture response is missing/u);
});

test("only the explicit official Go candidate and matching target/schema/credential evidence may plan rotation", async () => {
  const evidence = fixture();
  assert.deepEqual(
    await evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    {
      schemaVersion,
      protectedSlot: "a",
      candidateSlot: "b",
    },
  );
  for (const runtime of [undefined, "", "csharp", "unknown"]) {
    const config = structuredClone(configuration);
    config.vars.ARCFORGES_HELLO_RUNTIME = runtime;
    await assert.rejects(
      evaluateFixtureTarget(evidence, config, recorded.sha, schemaVersion),
      /explicit Go Center/u,
    );
  }
  const preview = structuredClone(configuration);
  preview.preview_urls = true;
  await assert.rejects(
    evaluateFixtureTarget(evidence, preview, recorded.sha, schemaVersion),
    /preview URLs/u,
  );
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, "0".repeat(40), schemaVersion),
    /another revision/u,
  );
  evidence.postgres.version = schemaVersion - 1;
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    /schema version/u,
  );
  evidence.postgres.version = schemaVersion;
  evidence.databaseRoles.hello = "another_owner";
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    /another role than the migration role/u,
  );
});

test("ambiguous and unreadable Worker inventories cannot produce a replacement slot", async () => {
  const evidence = fixture();
  evidence.worker.deployments = {
    versions: [
      { version_id: liveVersion, percentage: 50 },
      { version_id: otherVersion, percentage: 50 },
    ],
  };
  evidence.worker.versions[otherVersion] = { annotations: { "workers/message": "runtime-slot=b" } };
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    /use both runtime slots/u,
  );
  delete evidence.worker.versions[otherVersion];
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    /slot evidence is unavailable/u,
  );
  evidence.worker.deployments = {
    versions: [{ version_id: liveVersion, percentage: 50 }, { version_id: otherVersion }],
  };
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    /rollout percentage is invalid/u,
  );
  evidence.worker.deployments = { versions: [{ version_id: liveVersion, percentage: 50 }] };
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    /rollout is incomplete/u,
  );
  evidence.worker.deployments = fixture().worker.deployments;
  evidence.worker.versions[liveVersion] = {
    annotations: { "workers/message": "runtime-slot=a runtime-slot=b" },
  };
  await assert.rejects(
    evaluateFixtureTarget(evidence, configuration, recorded.sha, schemaVersion),
    /slot evidence is unavailable/u,
  );
});

test("dry run refuses a missing local seal without exposing fixture contents or writing any gate", async (t) => {
  const work = scratchDirectory("arcforges-h03-preflight-", t);
  const evidencePath = path.join(work, "fixture.json");
  const data = JSON.stringify({ ...fixture(), inertMarker: "must-not-enter-a-receipt" });
  await writeFile(evidencePath, data, { mode: 0o600 });
  const result = command("preflight", work, evidencePath);
  assert.equal(result.status, 1, result.error?.message ?? "Expected a preflight refusal.");
  assert.match(result.stderr, /Deployment preflight refused/u);
  assert.doesNotMatch(result.stderr + result.stdout, /must-not-enter-a-receipt/u);
  assert.deepEqual(await readdir(work), ["fixture.json"]);
  assert.equal(await readFile(evidencePath, "utf8"), data);
});

test("CI preflight requires the selected producer's exact artifact attempt", async (t) => {
  const evidence = fixture();
  const producer = evaluateFixtureProducer(evidence);
  const { responses } = evidence.github;
  const repo = `repos/${repository}`;
  const runPath = `${repo}/actions/runs/${producer.runId}`;
  const runs = responses[
    `${repo}/actions/workflows/${workflowPath.split("/").at(-1)}/runs?event=push&branch=main&head_sha=${producer.sha}&exclude_pull_requests=true&per_page=100`
  ] as { workflow_runs: { id: number; run_attempt: number }[] };
  const jobs = responses[`${runPath}/jobs?filter=latest&per_page=100`] as {
    jobs: { name: string; run_attempt: number }[];
  };
  const artifacts = responses[`${runPath}/artifacts?per_page=100`] as {
    artifacts: { id: number; name: string }[];
  };
  const run = runs.workflow_runs.find((entry) => entry.id === producer.runId);
  const job = jobs.jobs.find((entry) => entry.name === candidateJobName);
  const artifact = artifacts.artifacts.find((entry) => entry.id === producer.artifactId);
  assert(run && job && artifact);
  run.run_attempt = job.run_attempt = 2;
  artifact.name = candidateArtifactName(producer.runId, 2);
  assert.equal(evaluateFixtureProducer(evidence).candidateAttempt, 2);
  const directory = scratchDirectory("arcforges-h03-preflight-", t);
  const version = `0.1.0-ci.${producer.runNumber}.1`;
  await writeFile(path.join(directory, "manifest.json"), JSON.stringify({ version }));
  await assert.rejects(preflight(directory, evidence), /exact fixture producer attempt/u);
});

test("the live command's security-successor stop precedes candidate or provider operations", () => {
  const result = command("deploy");
  assert.equal(result.status, 1, result.error?.message ?? "Expected a deployment refusal.");
  assert.match(result.stderr, /security bridge successor is not yet bound/u);
});

// The normal candidate build provides real package/image/Worker bytes for this local run; only external inventories are fixtures.
const stagedCandidate = process.env.ARCFORGES_HOST03_CANDIDATE;
if (stagedCandidate) {
  test("read-only official preflight checks every member of the real clean local candidate", async (t) => {
    const work = scratchDirectory("arcforges-h03-preflight-", t);
    const candidate = path.resolve(stagedCandidate);
    const manifest = await readJson<{ revision: string }>(path.join(candidate, "manifest.json"));
    const evidencePath = path.join(work, "fixture.json");
    await writeFile(evidencePath, JSON.stringify(fixture(manifest.revision)), { mode: 0o600 });
    const before = await readdir(candidate);
    const result = command("preflight", candidate, evidencePath);
    assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    const report = JSON.parse(result.stdout) as {
      producer: string;
      archiveCustody: string;
      authority: string;
      applied: boolean;
    };
    assert.equal(report.producer, "local_unpublished");
    assert.equal(report.archiveCustody, "not_assessed");
    assert.equal(report.authority, "not_assessed");
    assert.equal(report.applied, false);
    t.diagnostic(result.stdout.trim());
    assert.deepEqual(await readdir(candidate), before);
    assert.deepEqual(await readdir(work), ["fixture.json"]);
  });
}
