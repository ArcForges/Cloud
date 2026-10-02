// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the proof-environment deployment helpers and the live-run guards. The
// deployment itself needs an operator with Cloudflare access and is not exercised here.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { main as liveMain } from "../../eng/verification/foundation-live.ts";
import {
  buildProofConfig,
  collectSecrets,
  proofWorkerName,
  secretSources,
  type CandidateConfig,
} from "../../eng/verification/proof-deploy.ts";
import { expectedJobChecksum } from "../../eng/verification/foundation-scenarios.ts";

const wrangler = JSON.parse(
  readFileSync(path.resolve(import.meta.dirname, "../../wrangler.json"), "utf8"),
) as CandidateConfig;
const digest = `registry.example/arcforges-cloud@sha256:${"a".repeat(64)}`;
const account = "0".repeat(32);

test("the checked-in proof environment is isolated from the production Worker", () => {
  const proof = wrangler.env.proof;
  assert.equal(wrangler.name, "arcforges-cloud");
  assert.equal(proof.name, proofWorkerName);
  assert.deepEqual(proof.routes, [], "the proof Worker owns no route");
  assert.equal(proof.workers_dev, true);
  assert.equal(proof.vars.FOUNDATION_PROOF, "enabled");
  // Production keeps the Hello-only bindings.
  const top = wrangler as unknown as Record<string, unknown>;
  for (const key of ["d1_databases", "r2_buckets", "queues"])
    assert.equal(top[key], undefined, key);
  assert.equal((top.vars as Record<string, string>).FOUNDATION_PROOF, undefined);
  // No resource name is shared with another environment.
  const names = JSON.stringify(proof);
  assert(!names.includes('"arcforges-cloud"'));
  // Variables carry key identifiers, never secret values.
  assert.deepEqual(
    Object.keys(proof.vars).filter((key) => /SECRET|TOKEN/u.test(key)),
    [],
  );
});

test("the proof config pins the registry digest, revision and account and nothing else", () => {
  const config = buildProofConfig(wrangler, {
    account,
    imageDigest: digest,
    revision: "b".repeat(40),
    main: "./candidate/worker.js",
  });
  assert.equal(config.main, "./candidate/worker.js");
  assert.equal(config.env.proof.containers[0]?.image, digest);
  assert.equal(config.env.proof.vars.SOURCE_REVISION, "b".repeat(40));
  assert.equal((config as Record<string, unknown>).account_id, account);
  assert.equal(config.env.proof.d1_databases[0]?.database_id, undefined);
  assert.equal(wrangler.env.proof.containers[0]?.image, "./Dockerfile", "the input is not mutated");
  const withDatabase = buildProofConfig(wrangler, {
    account,
    imageDigest: digest,
    revision: "b".repeat(40),
    main: "./candidate/worker.js",
    databaseId: "11111111-1111-4111-8111-111111111111",
  });
  assert.equal(
    withDatabase.env.proof.d1_databases[0]?.database_id,
    "11111111-1111-4111-8111-111111111111",
  );
  for (const bad of [
    { account: "short" },
    { imageDigest: "arcforges-cloud:latest" },
    { databaseId: "not-a-uuid" },
  ])
    assert.throws(() =>
      buildProofConfig(wrangler, {
        account,
        imageDigest: digest,
        revision: "b".repeat(40),
        main: "x",
        ...bad,
      }),
    );
  assert.throws(() =>
    buildProofConfig(
      { ...wrangler, env: { proof: { ...wrangler.env.proof, name: "arcforges-cloud" } } },
      {
        account,
        imageDigest: digest,
        revision: "b".repeat(40),
        main: "x",
      },
    ),
  );
});

const goodSecrets = () => ({
  PROOF_OPERATOR_TOKEN: randomBytes(32).toString("base64url"),
  PROOF_HMAC_C2W_SECRET: randomBytes(32).toString("base64url"),
  PROOF_HMAC_W2C_SECRET: randomBytes(32).toString("base64url"),
  PROOF_CSRF_SECRET: randomBytes(32).toString("base64url"),
});

test("deployment secrets come from named variables, are format-checked and never echoed", () => {
  const secrets = goodSecrets();
  const collected = collectSecrets(secrets);
  assert.deepEqual(Object.keys(collected).sort(), [
    "CSRF_SECRET",
    "HMAC_C2W_SECRET",
    "HMAC_W2C_SECRET",
    "PROOF_OPERATOR_TOKEN",
  ]);
  for (const source of secretSources) {
    const missing: Record<string, string | undefined> = {
      ...secrets,
      [source.variable]: undefined,
    };
    assert.throws(
      () => collectSecrets(missing),
      (error: Error) => error.message.includes(source.variable),
    );
    const malformed = { ...secrets, [source.variable]: "short" };
    assert.throws(
      () => collectSecrets(malformed),
      (error: Error) => error.message.includes(source.variable) && !error.message.includes("short"),
    );
  }
  const duplicated = { ...secrets, PROOF_CSRF_SECRET: secrets.PROOF_HMAC_C2W_SECRET };
  assert.throws(() => collectSecrets(duplicated), /distinct/u);
});

test("the live runner refuses CI and an unusable target before any request", async () => {
  const previous = { ...process.env };
  try {
    process.env.CI = "true";
    await assert.rejects(liveMain(), /local opt-in/u);
    process.env.CI = "";
    process.env.PROOF_BASE_URL = "http://insecure.example";
    process.env.PROOF_OPERATOR_TOKEN = "x".repeat(40);
    await assert.rejects(liveMain(), /PROOF_BASE_URL/u);
    process.env.PROOF_BASE_URL = "https://proof.example";
    process.env.PROOF_OPERATOR_TOKEN = "short";
    await assert.rejects(liveMain(), /PROOF_OPERATOR_TOKEN/u);
  } finally {
    process.env = previous;
  }
});

test("the expected job checksum is computed exactly beyond 2^53", () => {
  assert.equal(expectedJobChecksum(1), 4_611_686_018_427n);
  assert.equal(expectedJobChecksum(250), 4_611_686_018_427n * 31_375n);
  assert(expectedJobChecksum(250) > BigInt(Number.MAX_SAFE_INTEGER));
});
