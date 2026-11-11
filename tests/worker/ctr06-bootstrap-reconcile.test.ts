// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { assessObservedReconciliation } from "../../tooling/ctr06-bootstrap-reconcile.ts";

// These are synthetic external observations. This test exercises only the real decision, not source authenticity or provider fencing.
const now = 1794400000;
const expected = {
  tag: "ctr06-security-bridge-cloud-0.1.0-ci.456.1",
  merge: "a".repeat(40),
  artifactDigest: "b".repeat(64),
  artifactSize: 100,
  receiptDigest: "c".repeat(64),
  receiptSize: 1000,
  run: "123",
  runNumber: "456",
  attempt: "1",
  sourceArtifactId: "789",
};
function fixture() {
  return {
    github: {
      state: "absent",
      observedAt: now,
      tag: null,
      merge: null,
      artifactDigest: null,
      artifactSize: null,
      receiptDigest: null,
      receiptSize: null,
      run: null,
      runNumber: null,
      attempt: null,
      sourceArtifactId: null,
      releaseId: null,
      assetId: null,
      receiptAssetId: null,
    },
    credentials: [{ issueId: "issue-one", state: "revoked", observedAt: now, expiresAt: now + 60 }],
    operations: [{ issueId: "issue-one", state: "no_effect", observedAt: now }],
  };
}

test("reconciliation requires absence, terminal publisher and every credential revoked or issuer-observed expired", () => {
  assert.deepEqual(assessObservedReconciliation(fixture(), ["issue-one"], expected, now), {
    kind: "safe-empty",
  });
  const expired = fixture();
  expired.credentials[0] = {
    issueId: "issue-one",
    state: "expired",
    observedAt: now,
    expiresAt: now - 1,
  };
  assert.deepEqual(assessObservedReconciliation(expired, ["issue-one"], expected, now), {
    kind: "safe-empty",
  });
  for (const state of ["active", "unknown"]) {
    const f = fixture();
    f.credentials[0] = {
      ...f.credentials[0],
      issueId: "issue-one",
      state,
      observedAt: now,
      expiresAt: now + 60,
    };
    assert.deepEqual(assessObservedReconciliation(f, ["issue-one"], expected, now), {
      kind: "unknown",
    });
  }
  for (const state of ["inflight", "unknown", "published"]) {
    const f = fixture();
    f.operations[0] = { issueId: "issue-one", state, observedAt: now };
    assert.deepEqual(assessObservedReconciliation(f, ["issue-one"], expected, now), {
      kind: "unknown",
    });
  }
  const badExpiry = fixture();
  badExpiry.credentials[0] = {
    issueId: "issue-one",
    state: "expired",
    observedAt: now,
    expiresAt: now + 1,
  };
  assert.throws(
    () => assessObservedReconciliation(badExpiry, ["issue-one"], expected, now),
    /Expiry/,
  );
});

test("existing publication identifies the actual asset; mismatched or unavailable reads do not fabricate success", () => {
  const f = fixture();
  const present = {
    state: "present",
    observedAt: now,
    ...expected,
    releaseId: "9001",
    assetId: "9002",
    receiptAssetId: "9003",
  };
  assert.equal(
    assessObservedReconciliation({ ...f, github: present }, ["issue-one"], expected, now).kind,
    "published",
  );
  const active = fixture();
  active.credentials[0] = {
    issueId: "issue-one",
    state: "active",
    observedAt: now,
    expiresAt: now + 60,
  };
  assert.equal(
    assessObservedReconciliation({ ...active, github: present }, ["issue-one"], expected, now).kind,
    "unknown",
  );
  const inflight = fixture();
  inflight.operations[0] = { issueId: "issue-one", state: "inflight", observedAt: now };
  assert.equal(
    assessObservedReconciliation({ ...inflight, github: present }, ["issue-one"], expected, now)
      .kind,
    "unknown",
  );
  assert.throws(() =>
    assessObservedReconciliation(
      { ...f, github: { ...present, artifactDigest: "c".repeat(64) } },
      ["issue-one"],
      expected,
      now,
    ),
  );
  assert.throws(() =>
    assessObservedReconciliation(
      { ...f, github: { ...present, tag: "other" } },
      ["issue-one"],
      expected,
      now,
    ),
  );
  assert.deepEqual(
    assessObservedReconciliation(
      { ...f, github: { ...f.github, state: "unknown" } },
      ["issue-one"],
      expected,
      now,
    ),
    { kind: "unknown" },
  );
  assert.throws(() =>
    assessObservedReconciliation(
      { ...f, github: { ...f.github, observedAt: now - 121 } },
      ["issue-one"],
      expected,
      now,
    ),
  );
  assert.throws(() => assessObservedReconciliation(f, ["issue-one", "issue-two"], expected, now));
});
