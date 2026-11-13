// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  inspectMockAuthority,
  type MockContext,
} from "../../eng/verification/ctr06-security-bridge-mock-authority.ts";

const keys = generateKeyPairSync("ed25519");
const now = 1794380000;
const context: MockContext = {
  repository: "ArcForges/Cloud",
  ref: "refs/heads/main",
  workflow: "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main",
  producerCommit: "a".repeat(40),
  runId: "123456",
  runAttempt: 1,
  sourceCommit: "8e5f6e26aa97b123d9f60b91f780364a094e74cd",
  sourceTree: "4a315ea6b47d96c3262e8111fcc26ad1957097f2",
  sourceArchiveSha256: "ea07d57bdc0acf43c2e58bdc3666d8334185600f46e903e2d5a109547e59293c",
  nonce: "b".repeat(32),
};
function fixture() {
  return {
    schema: "arcforges.ctr06.mock-authority.v1",
    issuer: "test-only",
    audience: "test-only-security-bridge",
    subject: "runner",
    context,
    issuedAt: now - 1,
    expiresAt: now + 60,
    principals: [
      { id: "runner", capabilities: ["metadata", "publication"] },
      { id: "notification-only-app", capabilities: ["unknown"] },
    ],
    edges: [{ from: "runner", to: "notification-only-app", kind: "notification" }],
  };
}
function inspect(input: unknown, expected = context, at = now) {
  const payload = Buffer.from(JSON.stringify(input));
  return inspectMockAuthority(
    payload,
    sign(null, payload, keys.privateKey),
    keys.publicKey,
    expected,
    at,
  );
}

test("mock signed notification is not itself a callable delegation", () => {
  assert.deepEqual(inspect(fixture()).reachable, ["runner"]);
});

test("mock signature, context, lifetime, and schema are checked", () => {
  const original = fixture();
  const bytes = Buffer.from(JSON.stringify(original));
  assert.throws(() => inspectMockAuthority(bytes, randomBytes(64), keys.publicKey, context, now));
  assert.throws(() => inspect(original, { ...context, sourceCommit: "c".repeat(40) }));
  assert.throws(() => inspect(original, { ...context, nonce: "c".repeat(32) }));
  assert.throws(() => inspect(original, context, now + 61));
  assert.throws(() => inspect({ ...original, issuedAt: now - 1, expiresAt: now + 121 }));
  assert.throws(() => inspect({ ...original, issuer: "untrusted" }));
  assert.throws(() => inspect({ ...original, other: true }));
  const duplicate = Buffer.from('{"schema":"x","schema":"y"}');
  assert.throws(() =>
    inspectMockAuthority(
      duplicate,
      sign(null, duplicate, keys.privateKey),
      keys.publicKey,
      context,
      now,
    ),
  );
});

test("real mock-graph predicate rejects direct, inherited, exchanged and unknown authority", () => {
  for (const capability of ["database", "rollout", "deployment", "activation", "unknown"]) {
    const f = fixture();
    f.principals[0] = { id: "runner", capabilities: [capability] };
    assert.throws(() => inspect(f));
    for (const kind of ["assume", "exchange", "delegate", "invoke", "credential"]) {
      const g = fixture();
      g.principals.push({ id: "forbidden", capabilities: [capability] });
      g.edges.push({ from: "runner", to: "forbidden", kind });
      assert.throws(() => inspect(g));
    }
  }
  const bad = fixture();
  bad.edges.push({ from: "runner", to: "missing", kind: "exchange" });
  assert.throws(() => inspect(bad));
});

test("the production authority gate remains unreachable by mock claims or caller flags", () => {
  for (const env of [
    {},
    { ARCFORGES_SECURITY_BRIDGE_AUTHORIZED: "true" },
    { ARCFORGES_SECURITY_BRIDGE_PROOF: JSON.stringify(fixture()) },
    {
      ARCFORGES_SECURITY_BRIDGE_URL: "https://invalid.example",
      ARCFORGES_SECURITY_BRIDGE_KEY: "synthetic",
    },
  ]) {
    const workflow = readFileSync(
      new URL("../../.github/workflows/ci.yml", import.meta.url),
      "utf8",
    );
    const job = workflow
      .split("  ctr06-security-bridge-authority:\n")[1]
      ?.split("\n  ctr06-security-bridge-linux:")[0];
    assert.match(job ?? "", /node tooling\/ctr06-bootstrap-entry\.ts authority/u);
    const result = spawnSync(process.execPath, ["tooling/ctr06-bootstrap-entry.ts", "authority"], {
      cwd: new URL("../..", import.meta.url),
      env: { ...process.env, ...env },
      encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /NOT PROVEN/);
    assert.equal(result.stdout, "");
  }
});
