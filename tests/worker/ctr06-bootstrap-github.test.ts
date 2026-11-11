// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  inspectGithubBootstrapMetadata,
  inspectGithubPublishedRelease,
} from "../../tooling/ctr06-bootstrap-github.ts";
import { approval, githubFixture, target } from "./support/ctr06-bootstrap-mock.ts";

type Answers = Record<string, unknown>;
function get(answers: Answers) {
  return async (path: string) => {
    assert(path in answers, `unexpected GitHub path ${path}`);
    return structuredClone(answers[path]);
  };
}
function record(value: unknown): Record<string, unknown> {
  assert(value && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}

test("public metadata parser binds real-shaped run, merge, host statuses, gate jobs and ZIP identity", async () => {
  const request = target();
  const answers = githubFixture(request);
  const result = await inspectGithubBootstrapMetadata(get(answers), request, approval);
  assert.equal(result.run, request.run);
  assert.equal(result.artifactZipDigest, request.artifactApiDigest);
  assert.notEqual(result.artifactZipDigest, request.artifactDigest);
  assert.equal(result.jobs["Require authenticated bootstrap authority evidence"], 100);
  assert.equal(result.statuses.length, 2);
});

test("open or unreviewed merge, failed or missing jobs and wrong ZIP metadata fail closed", async () => {
  const request = target();
  for (const mutate of [
    (data: Answers) => {
      record(data["/pulls/155"]).merged = false;
    },
    (data: Answers) => {
      record(data["/pulls/155"]).merge_commit_sha = "0".repeat(40);
    },
    (data: Answers) => {
      record(data[`/git/commits/${request.producer}`]).tree = { sha: "0".repeat(40) };
    },
    (data: Answers) => {
      record(data["/git/ref/heads/main"]).object = { sha: "0".repeat(40) };
    },
    (data: Answers) => {
      record(data[`/actions/runs/${request.run}/attempts/${request.attempt}`]).status = "completed";
      record(data[`/actions/runs/${request.run}/attempts/${request.attempt}`]).conclusion =
        "failure";
    },
    (data: Answers) => {
      const list = record(
        data[`/actions/runs/${request.run}/attempts/${request.attempt}/jobs?per_page=100&page=1`],
      );
      const jobs = list.jobs as Record<string, unknown>[];
      assert(jobs[0]);
      jobs[0].conclusion = "skipped";
    },
    (data: Answers) => {
      const list = record(
        data[`/actions/runs/${request.run}/attempts/${request.attempt}/jobs?per_page=100&page=1`],
      );
      list.total_count = 101;
    },
    (data: Answers) => {
      record(data[`/actions/artifacts/${request.artifactId}`]).digest =
        `sha256:${request.artifactDigest}`;
    },
    (data: Answers) => {
      record(data[`/actions/artifacts/${request.artifactId}`]).expired = true;
    },
    (data: Answers) => {
      data[`/commits/${approval.approvedHead}/statuses?per_page=100&page=1`] = [];
    },
  ]) {
    const answers = githubFixture(request);
    mutate(answers);
    await assert.rejects(inspectGithubBootstrapMetadata(get(answers), request, approval));
  }
});

test("public published release requires exact two uploaded assets and never treats 404 as absence", async () => {
  const request = target();
  const carrier = `arcforges-ctr06-security-bridge-0.1.0-ci.${request.runNumber}.${request.attempt}.tar.gz`;
  const release = {
    id: 9001,
    tag_name: request.release,
    target_commitish: request.producer,
    draft: false,
    prerelease: true,
    published_at: "2026-11-11T12:00:00Z",
    assets: [
      {
        id: 9002,
        name: carrier,
        state: "uploaded",
        digest: `sha256:${request.artifactDigest}`,
        size: Number(request.artifactSize),
      },
      {
        id: 9003,
        name: "bootstrap-receipt.json",
        state: "uploaded",
        digest: `sha256:${request.receiptDigest}`,
        size: Number(request.receiptSize),
      },
    ],
  };
  const releaseGet =
    (value: unknown, refCommit = request.producer) =>
    async (path: string) => {
      if (path.startsWith("/releases/tags/")) return structuredClone(value);
      if (path.startsWith("/git/ref/tags/"))
        return { ref: `refs/tags/${request.release}`, object: { type: "commit", sha: refCommit } };
      if (path.startsWith("/releases/9001/assets?")) return structuredClone(record(value).assets);
      throw new Error("unexpected release read");
    };
  const result = await inspectGithubPublishedRelease(releaseGet(release), request);
  assert.equal(result.state, "present");
  assert.equal(result.releaseId, "9001");
  assert.equal(result.assetId, "9002");
  assert.equal(result.receiptAssetId, "9003");
  assert.equal((await inspectGithubPublishedRelease(async () => null, request)).state, "unknown");
  await assert.rejects(inspectGithubPublishedRelease(releaseGet(release, "0".repeat(40)), request));
  for (const modified of [
    { ...release, draft: true },
    { ...release, tag_name: "other" },
    { ...release, target_commitish: "main" },
    { ...release, assets: [release.assets[0]] },
    { ...release, assets: [...release.assets, release.assets[0]] },
    {
      ...release,
      assets: [{ ...release.assets[0], digest: `sha256:${"0".repeat(64)}` }, release.assets[1]],
    },
    { ...release, assets: [release.assets[0], { ...release.assets[1], size: 1 }] },
  ])
    await assert.rejects(inspectGithubPublishedRelease(releaseGet(modified), request));
});
