// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  bridgeIdentity,
  bridgeSource,
  collectBridgeFacts,
  securityBridgeDockerfile,
  securityBridgeGoArchive,
  validateBridgeProducer,
  verifySecurityGoArchive,
  type ProducerFacts,
} from "../../tooling/ctr06-security-bridge-source.ts";
import { childEnvironment } from "../../tooling/ctr06-security-bridge-producer.ts";
import { root } from "../../tooling/process.ts";
import { scratchDirectory } from "./support/scratch.ts";

const producerCommit = "a".repeat(40);
const fixtureEnv: NodeJS.ProcessEnv = {
  GITHUB_ACTIONS: "true",
  GITHUB_EVENT_NAME: "push",
  GITHUB_REPOSITORY: "ArcForges/Cloud",
  GITHUB_SERVER_URL: "https://github.com",
  GITHUB_REF: "refs/heads/main",
  GITHUB_REF_PROTECTED: "true",
  GITHUB_WORKFLOW_REF: "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main",
  GITHUB_WORKFLOW_SHA: producerCommit,
  GITHUB_SHA: producerCommit,
  GITHUB_RUN_ID: "123456",
  GITHUB_RUN_NUMBER: "42",
  GITHUB_RUN_ATTEMPT: "2",
};
const fixtureEvent = {
  ref: "refs/heads/main",
  after: producerCommit,
  deleted: false,
  repository: { full_name: "ArcForges/Cloud", default_branch: "main" },
};
const fixtureFacts: ProducerFacts = {
  head: producerCommit,
  tree: "b".repeat(40),
  clean: true,
  sourceCommit: bridgeSource.commit,
  sourceTree: bridgeSource.tree,
  sourceEpoch: bridgeSource.epoch,
  sourceArchiveSha256: bridgeSource.archiveSha256,
  sourceIsAncestor: true,
};

test("the bridge binds the actual producer separately from its fixed historical source", () => {
  const result = validateBridgeProducer(fixtureEnv, fixtureEvent, fixtureFacts);
  assert.equal(result.producer.commit, producerCommit);
  assert.equal(result.source.commit, bridgeSource.commit);
  assert.notEqual(result.producer.commit, result.source.commit);
  assert.equal(result.version, "0.1.0-ci.42.2");
  assert.equal(
    result.producer.pipelineRun,
    "https://github.com/ArcForges/Cloud/actions/runs/123456",
  );
});

test("wrong event, producer, run, source and archive reject before construction", () => {
  const environments: NodeJS.ProcessEnv[] = [
    { GITHUB_ACTIONS: "false" },
    { GITHUB_EVENT_NAME: "workflow_dispatch" },
    { GITHUB_REPOSITORY: "other/repo" },
    { GITHUB_SERVER_URL: "https://example.com" },
    { GITHUB_REF: "refs/heads/other" },
    { GITHUB_REF_PROTECTED: "false" },
    { GITHUB_WORKFLOW_REF: "ArcForges/Cloud/.github/workflows/other.yml@refs/heads/main" },
    { GITHUB_WORKFLOW_SHA: "c".repeat(40) },
    { GITHUB_SHA: "not-a-commit" },
    { GITHUB_RUN_ID: "0" },
    { GITHUB_RUN_NUMBER: "01" },
    { GITHUB_RUN_ATTEMPT: "9007199254740992" },
  ];
  for (const changed of environments)
    assert.throws(() =>
      validateBridgeProducer({ ...fixtureEnv, ...changed }, fixtureEvent, fixtureFacts),
    );
  for (const changed of [
    { ref: "refs/heads/other" },
    { after: "c".repeat(40) },
    { deleted: true },
    { repository: { full_name: "other/repo", default_branch: "main" } },
    { repository: { full_name: "ArcForges/Cloud", default_branch: "other" } },
  ])
    assert.throws(() =>
      validateBridgeProducer(fixtureEnv, { ...fixtureEvent, ...changed }, fixtureFacts),
    );
  for (const changed of [
    { head: "c".repeat(40) },
    { tree: "invalid" },
    { clean: false },
    { sourceCommit: "c".repeat(40) },
    { sourceTree: "c".repeat(40) },
    { sourceEpoch: 1 },
    { sourceArchiveSha256: "c".repeat(64) },
    { sourceIsAncestor: false },
  ])
    assert.throws(() =>
      validateBridgeProducer(fixtureEnv, fixtureEvent, { ...fixtureFacts, ...changed }),
    );
});

test("the actual Git source object has the pinned tree and archive", () => {
  const facts = collectBridgeFacts(root);
  assert.equal(facts.sourceCommit, bridgeSource.commit);
  assert.equal(facts.sourceTree, bridgeSource.tree);
  assert.equal(facts.sourceEpoch, bridgeSource.epoch);
  assert.equal(facts.sourceArchiveSha256, bridgeSource.archiveSha256);
  assert.equal(facts.sourceIsAncestor, true);
});

test("identity uses the old source axes and actual run inputs without changing GITHUB_SHA", (t) => {
  const scratch = scratchDirectory("ctr06-source-identity-", t);
  const tar = path.join(scratch, "source.tar");
  writeFileSync(
    tar,
    execFileSync("git", ["archive", "--format=tar", bridgeSource.commit], {
      cwd: root,
      maxBuffer: 128 * 1024 * 1024,
    }),
  );
  execFileSync("tar", ["-xf", tar, "-C", scratch]);
  const producer = validateBridgeProducer(fixtureEnv, fixtureEvent, fixtureFacts);
  const identity = bridgeIdentity(scratch, producer);
  assert.deepEqual(identity.artifact, { id: "Cloud", version: "0.1.0-ci.42.2" });
  assert.equal(identity.build.sourceCommit, bridgeSource.commit);
  assert.equal(identity.build.buildId, "123456.2");
  assert.equal(identity.build.sourceDateEpoch, bridgeSource.epoch);
  assert.equal(fixtureEnv.GITHUB_SHA, producerCommit);
  const historicalDockerfile = readFileSync(path.join(scratch, "Dockerfile"), "utf8");
  const dockerfile = securityBridgeDockerfile(historicalDockerfile);
  assert(dockerfile.includes("COPY --from=bridge_go_archive /go.tar.gz /tmp/go.tar.gz"));
  assert(dockerfile.includes(securityBridgeGoArchive.sha256));
  assert(dockerfile.includes("COPY --chmod=0644 LICENSE ./LICENSE"));
  assert(dockerfile.includes("go version go1.27.4 linux/amd64"));
  assert(!dockerfile.includes("go1.27.3.linux-amd64.tar.gz"));
  assert.throws(() =>
    securityBridgeDockerfile(historicalDockerfile.replace("go1.27.3", "go1.27.2")),
  );
  assert.throws(() => verifySecurityGoArchive(Buffer.from("wrong Go archive")));
  const properties = path.join(scratch, "Directory.Packages.props");
  writeFileSync(
    properties,
    readFileSync(properties, "utf8").replace("1.0.0-ci.287.1", "1.0.0-ci.450.1"),
  );
  assert.throws(() => bridgeIdentity(scratch, producer));
});

test("bridge children retain Windows cache location but not owner credentials or legacy compiler selectors", () => {
  const saved = { ...process.env };
  try {
    process.env.LOCALAPPDATA = "synthetic-local-cache";
    process.env.GH_TOKEN = "synthetic-private";
    process.env.NEON_DATABASE_URL = "synthetic-private";
    process.env.CLOUDFLARE_API_TOKEN = "synthetic-private";
    process.env.ARCFORGES_CTR06_BRIDGE_GO = "synthetic-old-go";
    const child = childEnvironment();
    assert.equal(Reflect.get(child, "LOCALAPPDATA"), "synthetic-local-cache");
    for (const key of [
      "GH_TOKEN",
      "NEON_DATABASE_URL",
      "CLOUDFLARE_API_TOKEN",
      "ARCFORGES_CTR06_BRIDGE_GO",
    ])
      assert.equal(Object.hasOwn(child, key), false);
  } finally {
    for (const key of [
      "LOCALAPPDATA",
      "GH_TOKEN",
      "NEON_DATABASE_URL",
      "CLOUDFLARE_API_TOKEN",
      "ARCFORGES_CTR06_BRIDGE_GO",
    ]) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
});
