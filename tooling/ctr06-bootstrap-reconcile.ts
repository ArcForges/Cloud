// SPDX-License-Identifier: AGPL-3.0-only
// This is a decision over observations, not an authenticated source or a live publication permit.
import assert from "node:assert/strict";
import { object } from "./provenance.ts";

const idPattern = /^[A-Za-z0-9._:-]{1,128}$/u;
const digestPattern = /^[a-f0-9]{64}$/u;
const commitPattern = /^[a-f0-9]{40}$/u;
export type ExpectedRelease = {
  tag: string;
  merge: string;
  artifactDigest: string;
  artifactSize: number;
  receiptDigest: string;
  receiptSize: number;
  run: string;
  runNumber: string;
  attempt: string;
  sourceArtifactId: string;
};
export type PublishedRelease = ExpectedRelease & {
  releaseId: string;
  assetId: string;
  receiptAssetId: string;
};
export type ReconciliationDecision =
  { kind: "unknown" } | { kind: "safe-empty" } | ({ kind: "published" } & PublishedRelease);
function name(value: unknown): string {
  assert(typeof value === "string" && idPattern.test(value));
  return value;
}
function observedTime(value: unknown, now: number): number {
  assert(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= 0 &&
      value <= now + 30 &&
      now - value <= 120,
  );
  return value;
}

/**
 * Computes whether *these* supplied observations would permit recovery. Before this result can have
 * authority, a production caller must independently authenticate each source, prove complete issuer and
 * publisher history, real no-inflight fencing, provider coverage and an enforced current lease. A signed
 * self-reported JSON graph, an HTTP 404, a local timeout or this function alone does none of those things.
 */
export function assessObservedReconciliation(
  input: unknown,
  expectedIssues: string[],
  expected: ExpectedRelease,
  now: number,
): ReconciliationDecision {
  assert(Number.isSafeInteger(now) && now >= 0);
  assert(
    idPattern.test(expected.tag) &&
      commitPattern.test(expected.merge) &&
      digestPattern.test(expected.artifactDigest),
  );
  assert(Number.isSafeInteger(expected.artifactSize) && expected.artifactSize > 0);
  assert(
    digestPattern.test(expected.receiptDigest) &&
      Number.isSafeInteger(expected.receiptSize) &&
      expected.receiptSize > 0 &&
      expected.receiptSize <= 64 * 1024,
  );
  const numeric = /^[1-9][0-9]{0,14}$/u;
  assert(
    [expected.run, expected.runNumber, expected.attempt, expected.sourceArtifactId].every(
      (value) => numeric.test(value) && Number.isSafeInteger(Number(value)),
    ),
  );
  assert(
    expectedIssues.length > 0 &&
      expectedIssues.length <= 1000 &&
      expectedIssues.every((id) => idPattern.test(id)),
  );
  assert.equal(new Set(expectedIssues).size, expectedIssues.length);
  const data = object(input, "github credentials operations");
  assert(Array.isArray(data.credentials) && Array.isArray(data.operations));
  assert.equal(data.credentials.length, expectedIssues.length);
  assert.equal(data.operations.length, expectedIssues.length);
  const expectedSet = new Set(expectedIssues);
  const credentialIds = new Set<string>();
  const operationIds = new Set<string>();
  let safe = true;
  let credentialSafe = true;
  let operationSettled = true;
  for (const raw of data.credentials) {
    const row = object(raw, "issueId state observedAt expiresAt");
    const id = name(row.issueId);
    assert(expectedSet.has(id) && !credentialIds.has(id));
    credentialIds.add(id);
    const seen = observedTime(row.observedAt, now);
    assert(
      typeof row.expiresAt === "number" &&
        Number.isSafeInteger(row.expiresAt) &&
        row.expiresAt >= 0,
    );
    assert(["revoked", "expired", "active", "unknown"].includes(String(row.state)));
    if (row.state === "expired") assert(row.expiresAt <= seen, "Expiry not observed by issuer");
    if (row.state !== "revoked" && row.state !== "expired") {
      safe = false;
      credentialSafe = false;
    }
  }
  for (const raw of data.operations) {
    const row = object(raw, "issueId state observedAt");
    const id = name(row.issueId);
    assert(expectedSet.has(id) && !operationIds.has(id));
    operationIds.add(id);
    observedTime(row.observedAt, now);
    assert(
      ["not_started", "no_effect", "inflight", "unknown", "published"].includes(String(row.state)),
    );
    if (row.state !== "not_started" && row.state !== "no_effect") safe = false;
    if (row.state === "inflight" || row.state === "unknown") operationSettled = false;
  }
  const github = object(
    data.github,
    "state observedAt tag merge artifactDigest artifactSize receiptDigest receiptSize run runNumber attempt sourceArtifactId releaseId assetId receiptAssetId",
  );
  observedTime(github.observedAt, now);
  assert(["absent", "present", "unknown"].includes(String(github.state)));
  if (github.state === "present") {
    assert.equal(github.tag, expected.tag);
    assert.equal(github.merge, expected.merge);
    assert.equal(github.artifactDigest, expected.artifactDigest);
    assert.equal(github.artifactSize, expected.artifactSize);
    assert.equal(github.receiptDigest, expected.receiptDigest);
    assert.equal(github.receiptSize, expected.receiptSize);
    assert.equal(github.run, expected.run);
    assert.equal(github.runNumber, expected.runNumber);
    assert.equal(github.attempt, expected.attempt);
    assert.equal(github.sourceArtifactId, expected.sourceArtifactId);
    assert(
      typeof github.releaseId === "string" &&
        numeric.test(github.releaseId) &&
        Number.isSafeInteger(Number(github.releaseId)),
    );
    assert(
      typeof github.assetId === "string" &&
        numeric.test(github.assetId) &&
        Number.isSafeInteger(Number(github.assetId)),
    );
    assert(
      typeof github.receiptAssetId === "string" &&
        numeric.test(github.receiptAssetId) &&
        Number.isSafeInteger(Number(github.receiptAssetId)) &&
        github.receiptAssetId !== github.assetId,
    );
    if (credentialSafe && operationSettled)
      return {
        kind: "published",
        ...expected,
        releaseId: github.releaseId,
        assetId: github.assetId,
        receiptAssetId: github.receiptAssetId,
      };
    return { kind: "unknown" };
  }
  assert(
    github.tag === null &&
      github.merge === null &&
      github.artifactDigest === null &&
      github.artifactSize === null &&
      github.receiptDigest === null &&
      github.receiptSize === null &&
      github.run === null &&
      github.runNumber === null &&
      github.attempt === null &&
      github.sourceArtifactId === null &&
      github.releaseId === null &&
      github.assetId === null &&
      github.receiptAssetId === null,
    "Absent release cannot contain invented asset facts",
  );
  if (github.state === "absent" && safe) return { kind: "safe-empty" };
  return { kind: "unknown" };
}
