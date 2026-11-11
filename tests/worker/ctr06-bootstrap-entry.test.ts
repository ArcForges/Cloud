// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { runProductionBroker } from "../../tooling/ctr06-bootstrap-broker.ts";
import { BootstrapJournal } from "../../tooling/ctr06-bootstrap-journal.ts";
import { target } from "./support/ctr06-bootstrap-mock.ts";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  checkedBootstrapProducer,
  inspectLocalSealedCarrier,
} from "../../tooling/ctr06-bootstrap-entry.ts";
import { requireReviewedAuthorityProfile } from "../../tooling/ctr06-bootstrap-profile.ts";
import { bridgeSource, type ProducerFacts } from "../../tooling/ctr06-security-bridge-source.ts";
import { scratchDirectory } from "./support/scratch.ts";

const commit = "a".repeat(40);
const env: NodeJS.ProcessEnv = {
  GITHUB_ACTIONS: "true",
  GITHUB_EVENT_NAME: "push",
  GITHUB_REPOSITORY: "ArcForges/Cloud",
  GITHUB_SERVER_URL: "https://github.com",
  GITHUB_REF: "refs/heads/main",
  GITHUB_REF_PROTECTED: "true",
  GITHUB_WORKFLOW_REF: "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main",
  GITHUB_WORKFLOW_SHA: commit,
  GITHUB_SHA: commit,
  GITHUB_RUN_ID: "123456",
  GITHUB_RUN_NUMBER: "42",
  GITHUB_RUN_ATTEMPT: "2",
};
const event = {
  ref: "refs/heads/main",
  after: commit,
  deleted: false,
  repository: { full_name: "ArcForges/Cloud", default_branch: "main" },
};
const facts: ProducerFacts = {
  head: commit,
  tree: "b".repeat(40),
  clean: true,
  sourceCommit: bridgeSource.commit,
  sourceTree: bridgeSource.tree,
  sourceEpoch: bridgeSource.epoch,
  sourceArchiveSha256: bridgeSource.archiveSha256,
  sourceIsAncestor: true,
};
const sha = (data: Buffer) => createHash("sha256").update(data).digest("hex");

test("real context validation is separate from an unconfigured authority profile", () => {
  const producer = checkedBootstrapProducer(env, event, facts);
  assert.equal(producer.producer.commit, commit);
  assert.equal(producer.source.commit, bridgeSource.commit);
  assert.throws(() =>
    checkedBootstrapProducer({ ...env, GITHUB_REF: "refs/heads/other" }, event, facts),
  );
  assert.throws(() => checkedBootstrapProducer(env, event, { ...facts, clean: false }));
  assert.throws(() => requireReviewedAuthorityProfile(), /NOT PROVEN/);
});

test("local sealed receipt checks producer, original source, version, same bytes and hash", async (t) => {
  const root = scratchDirectory("ctr06-entry-", t);
  const producer = checkedBootstrapProducer(env, event, facts);
  const carrierName = `arcforges-ctr06-security-bridge-${producer.version}.tar.gz`;
  const bytes = Buffer.from("synthetic carrier, never publication evidence");
  const carrierPath = path.join(root, carrierName);
  const receiptPath = path.join(root, "bootstrap-receipt.json");
  const receipt = {
    schema: "arcforges.ctr06-security-bridge-bootstrap.v1",
    producer: producer.producer,
    source: producer.source,
    version: producer.version,
    carrier: { name: carrierName, sha256: sha(bytes), size: bytes.length, members: 1 },
    manifestSha256: "e".repeat(64),
  };
  writeFileSync(carrierPath, bytes);
  writeFileSync(receiptPath, JSON.stringify(receipt));
  assert.equal((await inspectLocalSealedCarrier(root, producer)).artifactSha256, sha(bytes));
  for (const changed of [
    { ...receipt, producer: { ...receipt.producer, commit: "c".repeat(40) } },
    { ...receipt, source: { ...receipt.source, tree: "c".repeat(40) } },
    { ...receipt, version: "0.1.0-ci.42.1" },
    { ...receipt, carrier: { ...receipt.carrier, name: "../outside" } },
    { ...receipt, carrier: { ...receipt.carrier, sha256: "0".repeat(64) } },
    { ...receipt, carrier: { ...receipt.carrier, size: bytes.length + 1 } },
    { ...receipt, extra: true },
  ]) {
    writeFileSync(receiptPath, JSON.stringify(changed));
    await assert.rejects(inspectLocalSealedCarrier(root, producer));
  }
  writeFileSync(receiptPath, '{"schema":"x","schema":"y"}');
  await assert.rejects(inspectLocalSealedCarrier(root, producer));
  writeFileSync(receiptPath, JSON.stringify(receipt));
  writeFileSync(carrierPath, Buffer.from("tampered"));
  await assert.rejects(inspectLocalSealedCarrier(root, producer));
});

if (process.platform === "linux") {
  test("the actual production broker refuses without a reviewed profile before recording or issuing", async (t) => {
    const root = scratchDirectory("ctr06-entry-broker-", t);
    const journal = new BootstrapJournal(root);
    await assert.rejects(runProductionBroker(journal, target()), /NOT PROVEN/);
    assert.deepEqual(journal.read(), []);
    journal.close();
  });
}
