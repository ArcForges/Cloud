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
  deployedRevision,
  egressProbe,
  expectedJobChecksum,
  helloIngress,
  queueRetryDeadLetter,
  sessionExpiry,
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
  // HarnessRunAlarm (HAR.40) is the wake-only alarm adapter: it holds a wake handle and no run state.
  assert.deepEqual(classes(top.durable_objects), [
    '"class_name":"CloudContainer"',
    '"class_name":"HarnessRunAlarm"',
  ]);
  // The live script recorded the discarded build's capacity-pacer-v1 tag; that history is kept
  // and the class it added is retired. Only the deletion is applied after the live tag.
  assert.deepEqual(top.migrations, [
    { tag: "v1", new_sqlite_classes: ["CloudContainer"] },
    { tag: "capacity-pacer-v1", new_sqlite_classes: ["CapacityJobPacer"] },
    { tag: "retire-capacity-pacer-v1", deleted_classes: ["CapacityJobPacer"] },
    { tag: "harness-run-alarm-v1", new_sqlite_classes: ["HarnessRunAlarm"] },
  ]);
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

test("the retired CapacityJobPacer class has no binding, export or proof migration", () => {
  // The deletion migration is valid only while nothing binds or exports the class.
  const top = wrangler as unknown as Record<string, unknown>;
  const { migrations: _migrations, env: _env, ...production } = top;
  assert(!JSON.stringify(production).includes("CapacityJobPacer"));
  assert(!JSON.stringify(wrangler.env.proof).includes("CapacityJobPacer"));
  const worker = readFileSync(path.resolve(import.meta.dirname, "../../worker/index.ts"), "utf8");
  assert(!worker.includes("CapacityJobPacer"));
});

test("production clears the discarded cron schedule while the proof environment keeps none", () => {
  // Wrangler replaces a Worker's schedules only when triggers.crons is declared, and an environment
  // inherits the top-level triggers unless it declares its own. Production declares an empty list so
  // the discarded every-minute schedule is removed; the proof environment declares an empty object so
  // it inherits nothing and its schedules are never touched, exactly as before.
  const top = wrangler as unknown as Record<string, unknown>;
  assert.deepEqual(top.triggers, { crons: [] });
  assert.deepEqual((wrangler.env.proof as unknown as Record<string, unknown>).triggers, {});
  const worker = readFileSync(path.resolve(import.meta.dirname, "../../worker/index.ts"), "utf8");
  assert(!/\bscheduled\b/u.test(worker), "the Worker has no scheduled handler");
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
        "session-expiry",
        "queue-retry-dlq",
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

test("the egress scenario passes on no HTTP response for every attempt and fails on any answer", async () => {
  const original = globalThis.fetch;
  const target = {
    baseUrl: "https://proof.example",
    origin: "https://proof.example",
    operatorToken: "t".repeat(40),
  };
  const observed = {
    blocked: true,
    controlOk: true,
    attempts: [
      { host: "example.com", outcome: "timeout", elapsedMs: 8002 },
      { host: "1.1.1.1", outcome: "reached_then_failed", elapsedMs: 1 },
    ],
  };
  const answer = (value: unknown, status = 200) => {
    globalThis.fetch = (async () => Response.json(value, { status })) as typeof fetch;
  };
  try {
    // The platform's observed behavior (timeout and accepted-then-dropped) is the accepted block, as is a refusal.
    answer(observed);
    assert.equal((await egressProbe(target)).scenario, "egress-blocked");
    answer({
      ...observed,
      attempts: [
        { host: "example.com", outcome: "connection_failed" },
        { host: "1.1.1.1", outcome: "connection_failed" },
      ],
    });
    assert.equal((await egressProbe(target)).scenario, "egress-blocked");
    const answered = (status: number) => ({
      ...observed,
      blocked: true,
      attempts: [observed.attempts[0], { host: "1.1.1.1", outcome: "http_response", status }],
    });
    const failing = [
      { ...observed, controlOk: false },
      { ...observed, blocked: false },
      { ...observed, attempts: [observed.attempts[0]] },
      {
        ...observed,
        attempts: [observed.attempts[0], { host: "example.org", outcome: "timeout" }],
      },
      { ...observed, attempts: [observed.attempts[0], { host: "1.1.1.1", outcome: "unknown" }] },
      answered(200),
      answered(404),
      answered(520),
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

test("the runner waits for the Hello signal, then verifies the restarted foundation instance and fails closed", async () => {
  const original = globalThis.fetch;
  const expected = "a".repeat(40);
  const stale = "b".repeat(40);
  const target = {
    baseUrl: "https://proof.example",
    origin: "https://proof.example",
    operatorToken: "t".repeat(40),
    expectedRevision: expected,
    revisionWaitMs: 600,
    revisionPollMs: 10,
    queueWaitMs: 30,
    pollIntervalMs: 5,
  };
  const calls: string[] = [];
  interface Script {
    hello: { container: string; worker: string | null }[];
    stopStatus: number;
    foundation: (string | null)[];
  }
  const serve = (script: Script) => {
    let hello = 0;
    let foundation = 0;
    calls.length = 0;
    globalThis.fetch = (async (input: unknown) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/api/healthz")) {
        const step = script.hello[
          Math.min(hello++, script.hello.length - 1)
        ] as Script["hello"][number];
        return Response.json(
          { revision: step.container },
          { headers: step.worker === null ? {} : { "x-arcforges-worker-revision": step.worker } },
        );
      }
      if (url.endsWith("/proof/v1/container/stop"))
        return Response.json({ stopped: true }, { status: script.stopStatus });
      const revision = script.foundation[Math.min(foundation++, script.foundation.length - 1)];
      return revision === null
        ? Response.json({ error: "unavailable" }, { status: 500 })
        : Response.json({ ready: true, revision });
    }) as typeof fetch;
  };
  try {
    // Stale and half-updated Hello answers are waited out; the stop must succeed; the restarted foundation instance must report
    // the expected revision (a stale or unavailable instance is polled again).
    serve({
      hello: [
        { container: stale, worker: stale },
        { container: expected, worker: stale },
        { container: expected, worker: null },
        { container: expected, worker: expected },
      ],
      stopStatus: 200,
      foundation: [null, stale, expected],
    });
    const row = await deployedRevision(target);
    assert.equal(row.scenario, "deployed-revision");
    assert.equal(row.detail.foundationRevision, expected);
    assert(calls.some((call) => call.endsWith("/proof/v1/container/stop")));
    // The stop must be delivered: a failing stop fails the row (the Hello signal alone is not enough).
    serve({
      hello: [{ container: expected, worker: expected }],
      stopStatus: 500,
      foundation: [expected],
    });
    await assert.rejects(deployedRevision(target), /could not be stopped/u);
    // A foundation instance that keeps reporting another revision fails, even though Hello reports the expected one.
    serve({
      hello: [{ container: expected, worker: expected }],
      stopStatus: 200,
      foundation: [stale],
    });
    await assert.rejects(deployedRevision(target), /did not report revision/u);
    // Hello never reaches the expected revision.
    serve({
      hello: [{ container: stale, worker: stale }],
      stopStatus: 200,
      foundation: [expected],
    });
    await assert.rejects(deployedRevision(target), /did not serve revision/u);
    await assert.rejects(
      deployedRevision({ ...target, expectedRevision: "short" }),
      /expected revision/u,
    );
    // Every scenario run starts with the wait when a revision is expected, and records its failure.
    const rows = await runScenarios(target, "0".repeat(64), { stopContainer: false });
    assert.equal(rows[0]?.scenario, "deployed-revision");
    assert.equal(rows[0]?.ok, false);
    assert.equal(rows.length, 10);
  } finally {
    globalThis.fetch = original;
  }
});

test("the Hello ingress scenario retries thrown errors within its deadline", async () => {
  const original = globalThis.fetch;
  let healthCalls = 0;
  globalThis.fetch = (async (input: unknown) => {
    const url = String(input);
    if (url.endsWith("/api/healthz")) {
      healthCalls++;
      if (healthCalls < 3) throw new TypeError("fetch failed");
      return new Response("{}", { status: 200 });
    }
    return new Response(new TextEncoder().encode("\u0000Hello, proof!"), {
      status: 200,
      headers: { "x-arcforges-worker-revision": "r" },
    });
  }) as typeof fetch;
  try {
    const row = await helloIngress({
      baseUrl: "https://proof.example",
      origin: "https://proof.example",
      helloPollMs: 5,
    });
    assert.equal(row.detail.attempts, 3);
    assert.equal(row.detail.sayHelloStatus, 200);
  } finally {
    globalThis.fetch = original;
  }
});

test("only the proof environment may run more than one Container instance", () => {
  const top = wrangler as unknown as { containers: { max_instances: number }[] };
  assert.equal(top.containers[0]?.max_instances, 1, "production keeps one instance");
  // CLOUD.71: with a ceiling of 2 the provider ran only one of the two named instances (hello, foundation) at a
  // time; the ceiling leaves headroom so both can run at once. It is a ceiling, not a minimum: two names exist.
  assert.equal(
    (wrangler.env.proof.containers[0] as { max_instances?: number }).max_instances,
    4,
    "the proof Hello instance and the foundation instance must be able to run at the same time",
  );
});

test("the queue scenario passes only after one delivery plus six retries and a later dead letter", async () => {
  const original = globalThis.fetch;
  const target = {
    baseUrl: "https://proof.example",
    origin: "https://proof.example",
    operatorToken: "t".repeat(40),
    queueWaitMs: 150,
    pollIntervalMs: 5,
  };
  const attempts = (count: number) =>
    Array.from({ length: count }, (_, index) => ({ attempt: index + 1, atMs: 100 + index }));
  const serve = (observations: unknown[]) => {
    let polled = 0;
    globalThis.fetch = (async (input: unknown) => {
      if (String(input).endsWith("/queue/poison"))
        return Response.json({ probeId: "00000000-0000-4000-8000-0000000000cc" });
      return Response.json(observations[Math.min(polled++, observations.length - 1)]);
    }) as typeof fetch;
  };
  try {
    serve([
      { attempts: attempts(2), deadLetter: null },
      { attempts: attempts(7), deadLetter: { attempt: 1, atMs: 200 } },
    ]);
    const row = await queueRetryDeadLetter(target);
    assert.equal(row.detail.deliveries, 7);
    assert.equal(row.detail.retries, 6);
    // Too few retries, an out-of-order record, a dead letter before the last attempt and no dead letter all fail.
    serve([{ attempts: attempts(3), deadLetter: { attempt: 1, atMs: 200 } }]);
    await assert.rejects(queueRetryDeadLetter(target), /max_retries/u);
    serve([{ attempts: attempts(7).reverse(), deadLetter: { attempt: 1, atMs: 200 } }]);
    await assert.rejects(queueRetryDeadLetter(target), /max_retries/u);
    serve([{ attempts: attempts(7), deadLetter: { attempt: 1, atMs: 50 } }]);
    await assert.rejects(queueRetryDeadLetter(target), /follows the last retry/u);
    serve([{ attempts: attempts(7), deadLetter: null }]);
    await assert.rejects(queueRetryDeadLetter(target), /not dead-lettered in time/u);
  } finally {
    globalThis.fetch = original;
  }
});

test("the session scenario passes only when both expiries and the default lifetime behave", async () => {
  const original = globalThis.fetch;
  const target = {
    baseUrl: "https://proof.example",
    origin: "https://proof.example",
    operatorToken: "t".repeat(40),
    sessionIdleSeconds: 0.2,
    sessionAbsoluteSeconds: 0.5,
    sessionSlackSeconds: 0.1,
  };
  interface Session {
    handle: string;
    idleUntil: number;
    absoluteUntil: number;
    revoked: boolean;
  }
  const serve = (honor: { idle: boolean; absolute: boolean }) => {
    const sessions = new Map<string, Session>();
    let counter = 0;
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      const now = Date.now();
      if (url.endsWith("/proof/v1/session/issue")) {
        const body = JSON.parse(String(init?.body)) as {
          idleSeconds?: number;
          absoluteSeconds?: number;
        };
        const handle = `h${counter++}`;
        const absolute = now + (body.absoluteSeconds ?? 1e6) * 1_000;
        const idle = now + (body.idleSeconds ?? 1e6) * 1_000;
        sessions.set(handle, {
          handle,
          idleUntil: honor.idle ? idle : 1e15,
          absoluteUntil: honor.absolute ? absolute : 1e15,
          revoked: false,
        });
        return Response.json({ handle, csrfToken: `c-${handle}` });
      }
      const headers = new Headers(init?.headers);
      const session = sessions.get((headers.get("cookie") ?? "").split("=")[1] ?? "");
      const live =
        session && !session.revoked && now < session.idleUntil && now < session.absoluteUntil;
      if (url.endsWith("/session/v1/bootstrap")) {
        // An authenticated bootstrap renews the idle window (here: leaves it as issued, capped by absolute).
        return Response.json({ authenticated: Boolean(live) });
      }
      if (url.endsWith("/session/v1/logout")) {
        if (!live || !session) return new Response(null, { status: 401 });
        session.revoked = true;
        return Response.json({ effect: "happened" });
      }
      return new Response(null, { status: 404 });
    }) as typeof fetch;
  };
  try {
    serve({ idle: true, absolute: true });
    // The stub does not renew idle windows on bootstrap, so the in-use session needs an idle window longer than
    // its absolute lifetime for the scenario's active-use step: the scenario passes it a long idle window by default.
    assert.equal((await sessionExpiry(target)).scenario, "session-expiry");
    serve({ idle: false, absolute: true });
    await assert.rejects(sessionExpiry(target), /unused idle session must have expired/u);
    serve({ idle: true, absolute: false });
    await assert.rejects(sessionExpiry(target), /absolute lifetime/u);
  } finally {
    globalThis.fetch = original;
  }
});
