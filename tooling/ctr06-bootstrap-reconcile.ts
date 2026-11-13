// SPDX-License-Identifier: AGPL-3.0-only
// A decision over independently authenticated observations, never an authority source by itself.
import assert from "node:assert/strict";
import { verify, type KeyObject } from "node:crypto";
import { object, parseDocument } from "./provenance.ts";

const idPattern = /^[A-Za-z0-9._:-]{1,128}$/u;
const digestPattern = /^[a-f0-9]{64}$/u;
const commitPattern = /^[a-f0-9]{40}$/u;
const numeric = /^[1-9][0-9]{0,14}$/u;
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
const releaseFields =
  "tag merge artifactDigest artifactSize receiptDigest receiptSize run runNumber attempt sourceArtifactId releaseId assetId receiptAssetId";
const releaseKeys = releaseFields.split(" ") as (keyof PublishedRelease)[];
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
function releaseIdentity(raw: unknown): PublishedRelease {
  const value = object(raw, releaseFields);
  assert(typeof value.tag === "string" && idPattern.test(value.tag));
  assert(typeof value.merge === "string" && commitPattern.test(value.merge));
  assert(typeof value.artifactDigest === "string" && digestPattern.test(value.artifactDigest));
  assert(typeof value.receiptDigest === "string" && digestPattern.test(value.receiptDigest));
  assert(
    typeof value.artifactSize === "number" &&
      Number.isSafeInteger(value.artifactSize) &&
      value.artifactSize > 0,
  );
  assert(
    typeof value.receiptSize === "number" &&
      Number.isSafeInteger(value.receiptSize) &&
      value.receiptSize > 0 &&
      value.receiptSize <= 64 * 1024,
  );
  for (const key of [
    "run",
    "runNumber",
    "attempt",
    "sourceArtifactId",
    "releaseId",
    "assetId",
    "receiptAssetId",
  ] as const) {
    const item = value[key];
    assert(typeof item === "string" && numeric.test(item) && Number.isSafeInteger(Number(item)));
  }
  assert.notEqual(value.assetId, value.receiptAssetId);
  return value as PublishedRelease;
}
function equalRelease(a: PublishedRelease, b: PublishedRelease): boolean {
  return releaseKeys.every((key) => a[key] === b[key]);
}
function matchesExpected(a: PublishedRelease, expected: ExpectedRelease): boolean {
  return (Object.keys(expected) as (keyof ExpectedRelease)[]).every(
    (key) => a[key] === expected[key],
  );
}
function releaseObservation(raw: unknown, now: number, privateSource: boolean) {
  const data = object(raw, `state observedAt ${releaseFields}`);
  observedTime(data.observedAt, now);
  assert(
    ["present", "unknown", ...(privateSource ? ["absent"] : [])].includes(String(data.state)),
    "Unsupported release observation",
  );
  if (data.state === "present") {
    const fields = Object.fromEntries(releaseKeys.map((key) => [key, data[key]]));
    return { state: "present" as const, release: releaseIdentity(fields) };
  }
  assert(
    releaseKeys.every((key) => data[key] === null),
    "Absent or unknown release carries invented facts",
  );
  return { state: data.state as "absent" | "unknown", release: undefined };
}

/** Authenticates exact private-history bytes and their target/issue binding using a key selected by a
 * reviewed source adapter. This verifies the signature, not source coverage, fencing or completeness. */
export function verifyAuthenticatedHistoryWithKey(
  payload: Buffer,
  signature: string,
  key: KeyObject,
  targetDigest: string,
  expectedIssues: string[],
): { privateGithub: unknown; credentials: unknown; operations: unknown } {
  assert(payload.length > 0 && payload.length <= 1024 * 1024);
  const modulus = key.asymmetricKeyDetails?.modulusLength;
  assert(
    key.type === "public" &&
      key.asymmetricKeyType === "rsa" &&
      typeof modulus === "number" &&
      modulus >= 2048 &&
      modulus <= 8192,
    "Unsupported private-history verification key",
  );
  assert(typeof signature === "string" && /^[A-Za-z0-9_-]+$/u.test(signature));
  const signed = Buffer.from(signature, "base64url");
  assert(signed.length > 0 && signed.length <= 1024 && signed.toString("base64url") === signature);
  assert(verify("RSA-SHA256", payload, key, signed), "Private history signature differs");
  const data = object(
    parseDocument(payload),
    "schema targetDigest issueIds privateGithub credentials operations",
  );
  assert.equal(data.schema, "arcforges.ctr06.private-history.v1");
  assert.equal(data.targetDigest, targetDigest, "Private history target differs");
  assert(Array.isArray(data.issueIds) && data.issueIds.length === expectedIssues.length);
  const ids = data.issueIds.map(name);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(
    [...ids].sort(),
    [...expectedIssues].sort(),
    "Private history issue set differs",
  );
  return {
    privateGithub: data.privateGithub,
    credentials: data.credentials,
    operations: data.operations,
  };
}

/** The private provider must independently authenticate complete release, issuer and publisher history,
 * including private and draft releases and no-inflight fencing. Public 404 is always UNKNOWN. */
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
  const data = object(input, "privateGithub publicGithub credentials operations");
  assert(Array.isArray(data.credentials) && Array.isArray(data.operations));
  assert.equal(data.credentials.length, expectedIssues.length);
  assert.equal(data.operations.length, expectedIssues.length);
  const expectedSet = new Set(expectedIssues);
  const credentialIds = new Set<string>();
  const operationIds = new Set<string>();
  let credentialSafe = true;
  let operationsSafe = true;
  const published: PublishedRelease[] = [];
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
    if (row.state !== "revoked" && row.state !== "expired") credentialSafe = false;
  }
  for (const raw of data.operations) {
    const row = object(raw, "issueId state observedAt publication");
    const id = name(row.issueId);
    assert(expectedSet.has(id) && !operationIds.has(id));
    operationIds.add(id);
    observedTime(row.observedAt, now);
    assert(
      ["not_started", "no_effect", "inflight", "unknown", "published"].includes(String(row.state)),
    );
    if (row.state === "published") published.push(releaseIdentity(row.publication));
    else assert.equal(row.publication, null, "Non-published operation has publication facts");
    if (row.state === "inflight" || row.state === "unknown") operationsSafe = false;
  }
  const privateView = releaseObservation(data.privateGithub, now, true);
  const publicView = releaseObservation(data.publicGithub, now, false);
  if (!credentialSafe || !operationsSafe) return { kind: "unknown" };
  if (privateView.state === "absent" && publicView.state === "unknown" && published.length === 0)
    return { kind: "safe-empty" };
  if (
    privateView.state === "present" &&
    publicView.state === "present" &&
    privateView.release &&
    publicView.release &&
    published.length === 1
  ) {
    const operation = published[0];
    assert(operation);
    if (
      matchesExpected(privateView.release, expected) &&
      equalRelease(privateView.release, publicView.release) &&
      equalRelease(privateView.release, operation)
    )
      return { kind: "published", ...privateView.release };
  }
  return { kind: "unknown" };
}
