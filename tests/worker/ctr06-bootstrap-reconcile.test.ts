// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  assessObservedReconciliation,
  verifyAuthenticatedHistoryWithKey,
  type PublishedRelease,
} from "../../tooling/ctr06-bootstrap-reconcile.ts";

// External observations are fixtures; the real parser and reconciliation decisions run unchanged.
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
const actual = { ...expected, releaseId: "9001", assetId: "9002", receiptAssetId: "9003" };
const blank = {
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
};
type View = { state: string; observedAt: number } & {
  [K in keyof PublishedRelease]: PublishedRelease[K] | null;
};
type Fixture = {
  privateGithub: View;
  publicGithub: View;
  credentials: { issueId: string; state: string; observedAt: number; expiresAt: number }[];
  operations: {
    issueId: string;
    state: string;
    observedAt: number;
    publication: PublishedRelease | null;
  }[];
};
function fixture(): Fixture {
  return {
    privateGithub: { state: "absent", observedAt: now, ...blank },
    publicGithub: { state: "unknown", observedAt: now, ...blank },
    credentials: [{ issueId: "issue-one", state: "revoked", observedAt: now, expiresAt: now + 60 }],
    operations: [
      {
        issueId: "issue-one",
        state: "no_effect",
        observedAt: now,
        publication: null as typeof actual | null,
      },
    ],
  };
}
function present() {
  return { state: "present", observedAt: now, ...actual };
}
function decide(value: ReturnType<typeof fixture>, issues = ["issue-one"]) {
  return assessObservedReconciliation(value, issues, expected, now);
}

test("safe retry requires authenticated private complete absence, public UNKNOWN, no in-flight operations and no live credentials", () => {
  assert.deepEqual(decide(fixture()), { kind: "safe-empty" });
  const expired = fixture();
  expired.credentials[0] = {
    issueId: "issue-one",
    state: "expired",
    observedAt: now,
    expiresAt: now - 1,
  };
  assert.deepEqual(decide(expired), { kind: "safe-empty" });
  for (const state of ["active", "unknown"]) {
    const f = fixture();
    f.credentials[0] = { issueId: "issue-one", state, observedAt: now, expiresAt: now + 60 };
    assert.deepEqual(decide(f), { kind: "unknown" });
  }
  for (const state of ["inflight", "unknown"]) {
    const f = fixture();
    f.operations[0] = { issueId: "issue-one", state, observedAt: now, publication: null };
    assert.deepEqual(decide(f), { kind: "unknown" });
  }
  const privateUnknown = fixture();
  privateUnknown.privateGithub.state = "unknown";
  assert.deepEqual(decide(privateUnknown), { kind: "unknown" });
  const publicPresent = fixture();
  publicPresent.publicGithub = present();
  assert.deepEqual(decide(publicPresent), { kind: "unknown" });
  const badExpiry = fixture();
  badExpiry.credentials[0] = {
    issueId: "issue-one",
    state: "expired",
    observedAt: now,
    expiresAt: now + 1,
  };
  assert.throws(() => decide(badExpiry), /Expiry/);
  const publicAbsent = fixture();
  publicAbsent.publicGithub.state = "absent";
  assert.throws(() => decide(publicAbsent), /Unsupported release/);
});

test("published requires matching authenticated private, public and actual publisher operation identity", () => {
  const f = fixture();
  f.privateGithub = present();
  f.publicGithub = present();
  for (const state of ["not_started", "no_effect"]) {
    f.operations[0] = { issueId: "issue-one", state, observedAt: now, publication: null };
    assert.deepEqual(decide(f), { kind: "unknown" });
  }
  f.operations[0] = {
    issueId: "issue-one",
    state: "published",
    observedAt: now,
    publication: actual,
  };
  assert.deepEqual(decide(f), { kind: "published", ...actual });
  const conflict = structuredClone(f);
  conflict.privateGithub.assetId = "9099";
  assert.deepEqual(decide(conflict), { kind: "unknown" });
  const wrongOperation = structuredClone(f);
  const wrongRow = wrongOperation.operations[0];
  assert(wrongRow?.publication);
  wrongRow.publication.assetId = "9099";
  assert.deepEqual(decide(wrongOperation), { kind: "unknown" });
  const missingPublic = structuredClone(f);
  missingPublic.publicGithub = { state: "unknown", observedAt: now, ...blank };
  assert.deepEqual(decide(missingPublic), { kind: "unknown" });
  const missingPrivate = structuredClone(f);
  missingPrivate.privateGithub = { state: "absent", observedAt: now, ...blank };
  assert.deepEqual(decide(missingPrivate), { kind: "unknown" });
  const liveCredential = structuredClone(f);
  const liveRow = liveCredential.credentials[0];
  assert(liveRow);
  liveRow.state = "active";
  assert.deepEqual(decide(liveCredential), { kind: "unknown" });
  const stale = structuredClone(f);
  stale.publicGithub.observedAt = now - 121;
  assert.throws(() => decide(stale));
});

test("multiple issue histories allow one associated publication and settled no-effects only", () => {
  const f = fixture();
  f.privateGithub = present();
  f.publicGithub = present();
  f.operations[0] = {
    issueId: "issue-one",
    state: "published",
    observedAt: now,
    publication: actual,
  };
  f.operations.push({
    issueId: "issue-two",
    state: "no_effect",
    observedAt: now,
    publication: null,
  });
  f.credentials.push({
    issueId: "issue-two",
    state: "revoked",
    observedAt: now,
    expiresAt: now + 60,
  });
  assert.equal(decide(f, ["issue-one", "issue-two"]).kind, "published");
  f.operations[1] = {
    issueId: "issue-two",
    state: "published",
    observedAt: now,
    publication: actual,
  };
  assert.deepEqual(decide(f, ["issue-one", "issue-two"]), { kind: "unknown" });
  f.operations[1] = { issueId: "issue-two", state: "inflight", observedAt: now, publication: null };
  assert.deepEqual(decide(f, ["issue-one", "issue-two"]), { kind: "unknown" });
});

test("private history signature binds exact source bytes, target and every issue", () => {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const targetDigest = "d".repeat(64);
  const data = fixture();
  const payload = Buffer.from(
    JSON.stringify({
      schema: "arcforges.ctr06.private-history.v1",
      targetDigest,
      issueIds: ["issue-one"],
      privateGithub: data.privateGithub,
      credentials: data.credentials,
      operations: data.operations,
    }),
  );
  const signature = sign("RSA-SHA256", payload, pair.privateKey).toString("base64url");
  assert.deepEqual(
    verifyAuthenticatedHistoryWithKey(payload, signature, pair.publicKey, targetDigest, [
      "issue-one",
    ]),
    {
      privateGithub: data.privateGithub,
      credentials: data.credentials,
      operations: data.operations,
    },
  );
  assert.throws(() =>
    verifyAuthenticatedHistoryWithKey(
      Buffer.concat([payload, Buffer.from(" ")]),
      signature,
      pair.publicKey,
      targetDigest,
      ["issue-one"],
    ),
  );
  assert.throws(() =>
    verifyAuthenticatedHistoryWithKey(payload, signature, pair.publicKey, "e".repeat(64), [
      "issue-one",
    ]),
  );
  assert.throws(() =>
    verifyAuthenticatedHistoryWithKey(payload, signature, pair.publicKey, targetDigest, [
      "issue-one",
      "issue-two",
    ]),
  );
  assert.throws(() =>
    verifyAuthenticatedHistoryWithKey(
      payload,
      Buffer.alloc(256).toString("base64url"),
      pair.publicKey,
      targetDigest,
      ["issue-one"],
    ),
  );
});
