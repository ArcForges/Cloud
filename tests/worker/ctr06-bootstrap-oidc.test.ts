// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { verifyCollectorIdentityWithKeys } from "../../tooling/ctr06-bootstrap-oidc.ts";

// The external issuer is a software test key. Signature, payload binding, parsing and identity checks are real.
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKey = pair.publicKey.export({ format: "jwk" });
const keys = Buffer.from(
  JSON.stringify({ keys: [{ ...publicKey, kid: "fixture", use: "sig", alg: "RS256" }] }),
);
const at = 1794400000;
const sourceSha = "a".repeat(40);
const identity = { sourceSha, runId: "12345", runAttempt: "2" };
const payload = Buffer.from(JSON.stringify({ schema: "test", nonce: "b".repeat(64) }));
const audience = `arcforges:ctr06:bootstrap-authority:v1:${createHash("sha256").update(payload).digest("hex")}`;
const encode = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
function claims() {
  return {
    iss: "https://token.actions.githubusercontent.com",
    aud: audience,
    sub: "repo:ArcForges/Cloud:ref:refs/heads/main",
    repository: "ArcForges/Cloud",
    repository_id: "1372264358",
    repository_owner_id: "279581753",
    ref: "refs/heads/main",
    ref_protected: "true",
    workflow_ref: "ArcForges/Cloud/.github/workflows/ctr06-authority-collector.yml@refs/heads/main",
    workflow_sha: sourceSha,
    sha: sourceSha,
    event_name: "workflow_dispatch",
    run_id: identity.runId,
    run_attempt: identity.runAttempt,
    runner_environment: "github-hosted",
    jti: "fixture-jti",
    iat: at - 5,
    nbf: at - 5,
    exp: at + 60,
  };
}
function token(
  c = claims(),
  h: Record<string, string> = { alg: "RS256", kid: "fixture", typ: "JWT" },
) {
  const start = `${encode(h)}.${encode(c)}`;
  return `${start}.${sign("RSA-SHA256", Buffer.from(start), pair.privateKey).toString("base64url")}`;
}

test("collector signature binds exact payload and pinned workflow/source/run", () => {
  verifyCollectorIdentityWithKeys(payload, token(), identity, at, keys);
  assert.throws(() =>
    verifyCollectorIdentityWithKeys(
      Buffer.concat([payload, Buffer.from(" ")]),
      token(),
      identity,
      at,
      keys,
    ),
  );
  assert.throws(() =>
    verifyCollectorIdentityWithKeys(
      payload,
      token(),
      { ...identity, sourceSha: "b".repeat(40) },
      at,
      keys,
    ),
  );
  assert.throws(() =>
    verifyCollectorIdentityWithKeys(payload, token(), { ...identity, runId: "12346" }, at, keys),
  );
  assert.throws(() => verifyCollectorIdentityWithKeys(payload, token(), identity, at + 61, keys));
});

test("collector rejects forged, wrong issuer, changed authority identity and unsafe lifetime", () => {
  for (const [key, value] of [
    ["iss", "https://invalid.example"],
    ["aud", "wrong"],
    ["sub", "wrong"],
    ["repository_id", "1"],
    ["repository_owner_id", "1"],
    ["workflow_ref", "wrong"],
    ["workflow_sha", "b".repeat(40)],
    ["event_name", "push"],
    ["run_attempt", "3"],
    ["runner_environment", "self-hosted"],
    ["exp", at + 600],
  ] as const) {
    assert.throws(
      () =>
        verifyCollectorIdentityWithKeys(
          payload,
          token({ ...claims(), [key]: value }),
          identity,
          at,
          keys,
        ),
      key,
    );
  }
  assert.throws(() =>
    verifyCollectorIdentityWithKeys(payload, token(), identity, at, Buffer.from('{"keys":[]}')),
  );
  const parts = token().split(".");
  assert.throws(() =>
    verifyCollectorIdentityWithKeys(
      payload,
      `${parts[0]}.${parts[1]}.${Buffer.alloc(256).toString("base64url")}`,
      identity,
      at,
      keys,
    ),
  );
  assert.throws(() =>
    verifyCollectorIdentityWithKeys(
      payload,
      token(claims(), { alg: "none", kid: "fixture" }),
      identity,
      at,
      keys,
    ),
  );
  assert.throws(() =>
    verifyCollectorIdentityWithKeys(
      payload,
      token(claims(), { alg: "RS256", kid: "fixture", jku: "https://invalid.example" }),
      identity,
      at,
      keys,
    ),
  );
});

test("duplicate JSON, unsafe keys and noncanonical signatures fail closed", () => {
  const start = `${encode({ alg: "RS256", kid: "fixture" })}.${Buffer.from('{"iss":"a","iss":"b"}').toString("base64url")}`;
  const duplicate = `${start}.${sign("RSA-SHA256", Buffer.from(start), pair.privateKey).toString("base64url")}`;
  assert.throws(() => verifyCollectorIdentityWithKeys(payload, duplicate, identity, at, keys));
  assert.throws(() => verifyCollectorIdentityWithKeys(payload, `${token()}=`, identity, at, keys));
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({
    format: "jwk",
  });
  const untrusted = Buffer.from(
    JSON.stringify({ keys: [{ ...other, kid: "fixture", use: "sig", alg: "RS256" }] }),
  );
  assert.throws(() => verifyCollectorIdentityWithKeys(payload, token(), identity, at, untrusted));
});
