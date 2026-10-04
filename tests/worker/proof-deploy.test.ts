// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the proof-environment deployment helpers and the live-run guards. The
// deployment itself needs an operator with Cloudflare access and is not exercised here.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { main as liveMain } from "../../eng/verification/foundation-live.ts";
import {
  buildProofConfig,
  generateSecrets,
  proofHostname,
  proofWorkerName,
  secretSources,
  type CandidateConfig,
} from "../../eng/verification/proof-deploy.ts";
import {
  egressProbe,
  expectedJobChecksum,
  runAll,
  runScenarios,
} from "../../eng/verification/foundation-scenarios.ts";

const wrangler = JSON.parse(
  readFileSync(path.resolve(import.meta.dirname, "../../wrangler.json"), "utf8"),
) as CandidateConfig;
const digest = `registry.example/arcforges-cloud@sha256:${"a".repeat(64)}`;
const account = "0".repeat(32);

test("the checked-in proof environment is isolated from the production Worker", () => {
  const proof = wrangler.env.proof;
  assert.equal(wrangler.name, "arcforges-cloud");
  assert.equal(proof.name, proofWorkerName);
  // The only ingress is the dedicated custom domain; workers.dev and preview URLs stay disabled and
  // the production route arcforges.com/api/* is not referenced.
  assert.deepEqual(proof.routes, [{ pattern: proofHostname, custom_domain: true }]);
  assert.equal(proofHostname, "proof.arcforges.com");
  assert.equal(proof.workers_dev, false);
  assert.equal(proof.preview_urls, false);
  assert(!JSON.stringify(proof).includes("arcforges.com/api"));
  assert.equal(proof.vars.ALLOWED_ORIGIN, `https://${proofHostname}`);
  assert.match(String(proof.vars.PROOF_OPERATOR_VERIFIER), /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(proof.vars.FOUNDATION_PROOF, "enabled");
  // Production keeps the Hello-only bindings.
  const top = wrangler as unknown as Record<string, unknown>;
  for (const key of ["d1_databases", "r2_buckets", "queues"])
    assert.equal(top[key], undefined, key);
  assert.equal((top.vars as Record<string, string>).FOUNDATION_PROOF, undefined);
  // Production binds the unchanged Hello Container class; only the proof environment binds the
  // subclass that registers outbound interception.
  const classes = (value: unknown) => JSON.stringify(value).match(/"class_name":"[^"]+"/gu);
  assert.deepEqual(classes(top.containers), ['"class_name":"CloudContainer"']);
  assert.deepEqual(classes(top.durable_objects), ['"class_name":"CloudContainer"']);
  assert.deepEqual(top.migrations, [{ tag: "v1", new_sqlite_classes: ["CloudContainer"] }]);
  assert.deepEqual(classes(proof.containers), ['"class_name":"FoundationContainer"']);
  assert.deepEqual(
    JSON.stringify(proof.migrations).includes('"CloudContainer"'),
    false,
    "the proof environment never references the production class",
  );
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

test("deployment secrets are generated fresh, well formed, distinct and carry no operator token", () => {
  const first = generateSecrets();
  assert.deepEqual(Object.keys(first).sort(), [
    "CSRF_SECRET",
    "HMAC_C2W_SECRET",
    "HMAC_W2C_SECRET",
  ]);
  for (const source of secretSources) assert.match(first[source.worker] ?? "", source.pattern);
  const second = generateSecrets();
  for (const name of Object.keys(first)) assert.notEqual(first[name], second[name]);
  assert.equal(new Set(Object.values(first)).size, 3);
  // A broken random source is refused without echoing a value.
  assert.throws(
    () => generateSecrets(() => new Uint8Array(32)),
    (error: Error) => /distinct/u.test(error.message) && !error.message.includes("AAAA"),
  );
  assert.throws(() => generateSecrets(() => new Uint8Array(8)), /required shape/u);
});

test("the proof config carries the migrations directory and refuses an unsafe environment", () => {
  const config = buildProofConfig(wrangler, {
    account,
    imageDigest: digest,
    revision: "b".repeat(40),
    main: "./candidate/worker.js",
    migrationsDir: "../worker/proof-migrations",
  });
  assert.equal(
    (config.env.proof.d1_databases[0] as { migrations_dir?: string }).migrations_dir,
    "../worker/proof-migrations",
  );
  for (const unsafe of [
    { workers_dev: true },
    { preview_urls: true },
    { routes: [] },
    { routes: [{ pattern: "arcforges.com/api/*", zone_name: "arcforges.com" }] },
  ])
    assert.throws(() =>
      buildProofConfig(
        { ...wrangler, env: { proof: { ...wrangler.env.proof, ...unsafe } } },
        { account, imageDigest: digest, revision: "b".repeat(40), main: "x" },
      ),
    );
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
    // Without a token the operator key file signs the requests; a missing file is refused.
    process.env.PROOF_OPERATOR_TOKEN = "";
    process.env.PROOF_OPERATOR_KEY_FILE = path.join(
      import.meta.dirname,
      "no-such-operator-key.pem",
    );
    await assert.rejects(liveMain(), /No operator key file/u);
  } finally {
    process.env = previous;
  }
});

test("the expected job checksum is computed exactly beyond 2^53", () => {
  assert.equal(expectedJobChecksum(1), 4_611_686_018_427n);
  assert.equal(expectedJobChecksum(250), 4_611_686_018_427n * 31_375n);
  assert(expectedJobChecksum(250) > BigInt(Number.MAX_SAFE_INTEGER));
});

test("a failing scenario never hides the others and its evidence row names the cause", async () => {
  const original = globalThis.fetch;
  const roundtrip = {
    fullMatches: true,
    rangeMatches: true,
    existingMismatchRejected: false,
    existingMismatchStatus: 200,
    freshMismatchRejected: true,
    freshMismatchStatus: 422,
    mismatchRejected: false,
  };
  globalThis.fetch = (async (input: unknown) => {
    const url = String(input);
    return url.endsWith("/objects/roundtrip")
      ? Response.json(roundtrip)
      : new Response("{}", { status: 503 });
  }) as typeof fetch;
  try {
    const rows = await runScenarios(
      {
        baseUrl: "https://proof.example",
        origin: "https://proof.example",
        operatorToken: "t".repeat(40),
      },
      "0".repeat(64),
      { stopContainer: false },
    );
    assert.deepEqual(
      rows.map((row) => row.scenario),
      [
        "readiness",
        "exact-values",
        "guard-rollback",
        "session-csrf-revoke",
        "r2-objects",
        "checkpoint-restart",
        "public-denial",
      ],
    );
    assert(rows.every((row) => !row.ok && typeof row.detail.ms === "number"));
    const objects = rows.find((row) => row.scenario === "r2-objects");
    assert.match(String(objects?.detail.error), /existing-key mismatching PUT status 200/u);
    await assert.rejects(
      runAll(
        {
          baseUrl: "https://proof.example",
          origin: "https://proof.example",
          operatorToken: "t".repeat(40),
        },
        "0".repeat(64),
        { stopContainer: false },
      ),
      /Scenario failures: readiness/u,
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("the egress scenario passes only when every attempt is refused and the control answered", async () => {
  const original = globalThis.fetch;
  const target = {
    baseUrl: "https://proof.example",
    origin: "https://proof.example",
    operatorToken: "t".repeat(40),
  };
  const blocked = {
    blocked: true,
    controlOk: true,
    attempts: [
      { host: "example.com", outcome: "connection_failed" },
      { host: "1.1.1.1", outcome: "connection_failed" },
    ],
  };
  const answer = (value: unknown, status = 200) => {
    globalThis.fetch = (async () => Response.json(value, { status })) as typeof fetch;
  };
  try {
    answer(blocked);
    assert.equal((await egressProbe(target)).scenario, "egress-blocked");
    const failing = [
      { ...blocked, controlOk: false },
      { ...blocked, blocked: false },
      { ...blocked, attempts: [blocked.attempts[0]] },
      {
        ...blocked,
        attempts: [blocked.attempts[0], { host: "1.1.1.1", outcome: "http_response", status: 200 }],
      },
      { ...blocked, attempts: [blocked.attempts[0], { host: "1.1.1.1", outcome: "timeout" }] },
    ];
    for (const reply of failing) {
      answer(reply);
      await assert.rejects(egressProbe(target));
    }
    answer({ error: "unavailable" }, 502);
    await assert.rejects(egressProbe(target));
  } finally {
    globalThis.fetch = original;
  }
});
