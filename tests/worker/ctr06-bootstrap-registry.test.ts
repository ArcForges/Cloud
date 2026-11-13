// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { BootstrapJournal } from "../../tooling/ctr06-bootstrap-journal.ts";
import {
  BootstrapRegistry,
  type ApprovedBootstrap,
  type AttemptTarget,
} from "../../tooling/ctr06-bootstrap-registry.ts";
import { scratchDirectory } from "./support/scratch.ts";

const approval: ApprovedBootstrap = {
  approvedHead: "a".repeat(40),
  approvedTree: "b".repeat(40),
  merge: "c".repeat(40),
  originalRun: "123",
  eventDigest: "d".repeat(64),
};
function target(attempt: string): AttemptTarget {
  return {
    run: "123",
    runNumber: "456",
    attempt,
    producer: approval.merge,
    eventDigest: approval.eventDigest,
    gateDigest: "e".repeat(64),
    gateChallenge: "1".repeat(64),
    artifactId: "789",
    artifactDigest: "f".repeat(64),
    artifactApiDigest: "2".repeat(64),
    receiptDigest: "3".repeat(64),
    receiptSize: "100",
    artifactSize: "100",
    release: `ctr06-security-bridge-cloud-0.1.0-ci.456.${attempt}`,
  };
}

if (process.platform === "linux") {
  test("one authorization and immutable per-attempt target survive restart", (t) => {
    const root = scratchDirectory("ctr06-registry-", t);
    let journal = new BootstrapJournal(root);
    let registry = new BootstrapRegistry(journal);
    const first = target("1");
    assert.equal(registry.reserve(approval, first), "ready");
    assert.equal(registry.reserve(approval, first), "ready");
    assert.throws(
      () => registry.reserve(approval, { ...first, artifactDigest: "0".repeat(64) }),
      /target differs/,
    );
    assert.throws(() => registry.reserve(approval, { ...first, release: "unrelated" }));
    assert.throws(
      () => registry.issueIntent({ ...first, artifactDigest: "0".repeat(64) }, "issue-one"),
      /target differs/,
    );
    assert.throws(
      () =>
        registry.reserve(
          { ...approval, merge: "1".repeat(40) },
          { ...first, producer: "1".repeat(40) },
        ),
      /not authorized/,
    );
    assert.equal(registry.reserve(approval, { ...first, run: "124" }), "association-required");
    assert.throws(
      () =>
        registry.reserve(approval, {
          ...target("2"),
          runNumber: "457",
          release: "ctr06-security-bridge-cloud-0.1.0-ci.457.2",
        }),
      /Run number changed/,
    );
    journal.close();
    journal = new BootstrapJournal(root);
    registry = new BootstrapRegistry(journal);
    assert.equal(registry.reserve(approval, first), "ready");
    assert.throws(
      () => registry.reserve(approval, { ...first, artifactId: "790" }),
      /target differs/,
    );
    journal.close();
  });

  test("unknown and usable prior credential block another attempt across restart", (t) => {
    const root = scratchDirectory("ctr06-registry-", t);
    let journal = new BootstrapJournal(root);
    let registry = new BootstrapRegistry(journal);
    const first = target("1");
    const second = target("2");
    registry.reserve(approval, first);
    registry.issueIntent(first, "issue-one");
    registry.issueResult(first, "issue-one", { status: "issued", capabilityId: "credential-one" });
    assert.equal(registry.reserve(approval, second), "reconcile");
    assert.throws(() => registry.issueIntent(second, "issue-two"), /not safe/);
    registry.publicationIntent(first, "issue-one");
    registry.publication(first, { status: "unknown" });
    journal.close();
    journal = new BootstrapJournal(root);
    registry = new BootstrapRegistry(journal);
    assert.equal(registry.reserve(approval, second), "reconcile");
    assert.throws(() => registry.issueIntent(second, "issue-two"), /not safe/);
    journal.close();
  });

  test("a recorded publication demands readback and never relabels the requested target", (t) => {
    const root = scratchDirectory("ctr06-registry-", t);
    const journal = new BootstrapJournal(root);
    const registry = new BootstrapRegistry(journal);
    const first = target("1");
    registry.reserve(approval, first);
    registry.issueIntent(first, "issue-one");
    registry.issueResult(first, "issue-one", { status: "issued", capabilityId: "credential-one" });
    registry.publicationIntent(first, "issue-one");
    assert.throws(
      () => registry.publication(first, { status: "published", observedDigest: "0".repeat(64) }),
      /differs/,
    );
    registry.publication(first, { status: "published", observedDigest: first.artifactDigest });
    assert.equal(registry.reserve(approval, target("2")), "readback");
    assert.throws(() => registry.issueIntent(target("2"), "issue-two"), /not safe/);
    journal.close();
  });
} else {
  test("the Linux-only registry is not a Windows publication authorization", () => {
    assert.throws(() => new BootstrapJournal("C:\\not-created"), /only on Linux/);
  });
}
