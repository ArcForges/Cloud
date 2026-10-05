// SPDX-License-Identifier: AGPL-3.0-only
// CLOUD.70: the gated D1 migration step of the deployment jobs, offline. The deployment caller (eng/migrations/deploy.ts) runs
// against the SQLite oracle directly and through a fake Cloudflare REST endpoint that is backed by the same oracle. Proved here:
// the order of the step, the receipts and compatibility record in its output, the plan read from the release manifest, a contract
// refused without consent and before its soak, a build the horizons exclude refused, a failing step that stops promotion, no
// secret in any output, the pull-request and fork refusal, and the shape of the workflow. SQLite is not D1 and a fake endpoint is
// not Cloudflare: the proof-environment run (RES-cloud-deployment) is a separate, recorded live check.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { loadCatalog, type Migration } from "../../eng/migrations/catalog.ts";
import { SqliteMigrationClient } from "../../eng/migrations/clients.ts";
import {
  databaseNameFor,
  deployStep,
  dryRun,
  formatReport,
  GateRefusal,
  gateFile,
  releasePlan,
  requireContext,
  requireGatePassed,
  resolveDatabaseId,
  runGate,
  scrub,
  type GateInput,
  type WranglerLike,
} from "../../eng/migrations/deploy.ts";
import { applyPending } from "../../eng/migrations/runner.ts";
import { checksumOf, parseHeader, splitStatements } from "../../eng/migrations/sql.ts";

const repository = path.resolve(import.meta.dirname, "../..");
const baseline = loadCatalog();
const wrangler = JSON.parse(
  readFileSync(path.join(repository, "wrangler.json"), "utf8"),
) as WranglerLike;
const workflow = readFileSync(path.join(repository, ".github/workflows/ci.yml"), "utf8");

const token = "cf-test-token-0123456789abcdef";
const account = "0123456789abcdef0123456789abcdef";
const databaseId = "11111111-2222-3333-4444-555555555555";
const revision = "0123456789abcdef0123456789abcdef01234567";

function synthetic(
  sequence: number,
  mode: Migration["mode"],
  body: string,
  header = "",
): Migration {
  const text = `-- af-migration: module=scratch mode=${mode}${header}\n${body}\n`;
  return {
    sequence,
    file: `${String(sequence).padStart(4, "0")}_scratch__test-${sequence}.sql`,
    module: "scratch",
    mode,
    options: parseHeader(text).options,
    sha256: checksumOf(text),
    text,
    statements: mode === "backfill" ? [] : splitStatements(text),
  };
}

const table = `CREATE TABLE "scratch_item" (
  "id" TEXT NOT NULL,
  "legacy" TEXT NOT NULL,
  "converted" TEXT,
  "rev" INTEGER NOT NULL CHECK ("rev" >= 0),
  CONSTRAINT "pk_scratch_item" PRIMARY KEY ("id")
) STRICT;`;
const backfill = `-- af-backfill: {"target":"scratch_item","key":"id","pageSize":100}
-- section: page
SELECT "id", CAST("rev" AS TEXT) FROM "scratch_item" WHERE "id" > ? AND "converted" IS NULL ORDER BY "id" LIMIT ?
-- section: apply
UPDATE "scratch_item" SET "converted" = upper("legacy") WHERE "id" = ? AND "rev" = CAST(? AS INTEGER) AND "converted" IS NULL
-- section: verify
SELECT COUNT(*) FROM "scratch_item" WHERE "converted" IS NULL OR "converted" <> upper("legacy")`;

/** 0 bookkeeping, 1 expand, 2 backfill, 3 cutover (read horizon 1, write horizon 3), 4 contract after the cutover with a soak. */
const chain: Migration[] = [
  baseline[0] as Migration,
  synthetic(1, "expand", table),
  synthetic(2, "backfill", backfill),
  synthetic(
    3,
    "cutover",
    `UPDATE "scratch_item" SET "rev" = "rev" WHERE 0;`,
    " requires=2 readHorizon=1 writeHorizon=3",
  ),
  synthetic(
    4,
    "contract",
    `ALTER TABLE "scratch_item" DROP COLUMN "legacy";`,
    " after=3 soak=3600",
  ),
];

function clock(start = 1_790_000_000_000) {
  const state = { now: start };
  return { read: () => state.now, advance: (ms: number) => (state.now += ms) };
}

function gate(
  client: SqliteMigrationClient,
  manifest: GateInput["manifest"],
  time: { read: () => number },
  migrations = chain,
): GateInput {
  return {
    client,
    migrations,
    manifest,
    runner: "gh-1-1-deploy",
    now: time.read,
    compatibility: {
      sourceRevision: revision,
      planManifestHash: "p".repeat(8),
      abi: "abi-1",
      runtime: "net10.0",
    },
  };
}

const refusal = (code: string) => (error: unknown) =>
  error instanceof GateRefusal && error.code === code;

// ----------------------------------------------------------------------------------------------------- target selection

test("production declares no business database and proof names its reserved one; the selection reads wrangler.json", () => {
  assert.equal(databaseNameFor(wrangler, "production"), null);
  assert.equal(databaseNameFor(wrangler, "proof"), "arcforges-proof-business");
  assert.throws(
    () =>
      databaseNameFor(
        {
          d1_databases: [
            { binding: "DB", database_name: "a" },
            { binding: "DB", database_name: "b" },
          ],
        },
        "production",
      ),
    refusal("ambiguous-database"),
  );
  assert.throws(
    () =>
      databaseNameFor({ d1_databases: [{ binding: "OTHER", database_name: "a" }] }, "production"),
    refusal("ambiguous-database"),
  );
});

function lookup(result: unknown, status = 200): typeof fetch {
  return (async () =>
    new Response(JSON.stringify({ success: status === 200, result }), { status })) as typeof fetch;
}

test("the database id comes from an exact-name lookup; a missing, duplicated or failed lookup refuses and nothing is created", async () => {
  const base = { accountId: account, token, name: "arcforges-proof-business" };
  assert.equal(
    await resolveDatabaseId({
      ...base,
      fetch: lookup([
        { uuid: databaseId, name: base.name },
        { uuid: "x", name: "other" },
      ]),
    }),
    databaseId,
  );
  await assert.rejects(
    resolveDatabaseId({ ...base, fetch: lookup([]) }),
    refusal("database-missing"),
  );
  await assert.rejects(
    resolveDatabaseId({
      ...base,
      fetch: lookup([
        { uuid: databaseId, name: base.name },
        { uuid: databaseId.replace("1", "2"), name: base.name },
      ]),
    }),
    refusal("database-missing"),
  );
  await assert.rejects(
    resolveDatabaseId({ ...base, fetch: lookup(null, 500) }),
    refusal("lookup-failed"),
  );
  await assert.rejects(
    resolveDatabaseId({ ...base, override: "not-an-id" }),
    refusal("bad-database-id"),
  );
  const methods: string[] = [];
  await resolveDatabaseId({
    ...base,
    fetch: (async (_url: unknown, init?: RequestInit) => {
      methods.push(init?.method ?? "GET");
      return new Response(
        JSON.stringify({ success: true, result: [{ uuid: databaseId, name: base.name }] }),
      );
    }) as typeof fetch,
  });
  assert.deepEqual(methods, ["GET"]);
});

// --------------------------------------------------------------------------------------------------- the release plan

test("without a manifest plan only expand migrations are applied and the step stops before backfill, cutover and contract", async () => {
  const client = new SqliteMigrationClient();
  const report = await runGate(gate(client, {}, clock()));
  assert.equal(report.plan.source, "default");
  assert.equal(report.plan.through, 1);
  assert.deepEqual(
    report.run.applied.map((entry) => entry.mode),
    ["expand"],
  );
  assert.equal(report.after.schemaVersion, 1);
  assert.deepEqual(report.after.pending, [chain[2]?.file, chain[3]?.file, chain[4]?.file]);
  assert.equal(report.compatibility.canWrite, true);
  // A second deployment of the same release has nothing to do.
  const again = await runGate(gate(client, {}, clock()));
  assert.equal(again.run.alreadyCurrent, true);
});

test("the manifest names the backfill and the cutover; a contract needs consent and the soak", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  const cutover = await runGate(gate(client, { migrations: { through: 3 } }, time));
  assert.deepEqual(
    cutover.run.applied.map((entry) => entry.mode),
    ["expand", "backfill", "cutover"],
  );
  assert.equal(cutover.after.writeHorizon, 3);
  // The plan that reaches the contract without consent is refused before the database is touched.
  const before = JSON.stringify(await applyStatusOnly(client));
  await assert.rejects(
    runGate(gate(client, { migrations: { through: 4 } }, time)),
    refusal("contract-refused"),
  );
  assert.equal(JSON.stringify(await applyStatusOnly(client)), before);
  // With consent the runner still waits for the soak that follows the cutover.
  await assert.rejects(
    runGate(gate(client, { migrations: { through: 4, allowContract: true } }, time)),
    (error: unknown) =>
      (error as { code?: string }).code === "contract-refused" &&
      /soak/u.test((error as Error).message),
  );
  time.advance(3_600_000 + 1);
  const done = await runGate(
    gate(client, { migrations: { through: 4, allowContract: true } }, time),
  );
  assert.equal(done.after.schemaVersion, 4);
  assert.equal(done.plan.allowContract, true);
});

async function applyStatusOnly(client: SqliteMigrationClient) {
  return client.database
    .prepare("SELECT schema_version, read_horizon, write_horizon FROM platform_schema_state")
    .get();
}

test("a malformed or unknown plan is refused", () => {
  const bad = (migrations: unknown) => () => releasePlan({ migrations }, chain, -1);
  assert.throws(bad("x"), refusal("bad-plan"));
  assert.throws(bad({ through: 1.5 }), refusal("bad-plan"));
  assert.throws(bad({ through: 99 }), refusal("bad-plan"));
  assert.throws(bad({ through: -1 }), refusal("bad-plan"));
  assert.throws(bad({ through: 1, allowContract: "yes" }), refusal("bad-plan"));
  assert.throws(bad({ through: 1, extra: true }), refusal("bad-plan"));
  assert.equal(releasePlan({ migrations: { through: 1 } }, chain, -1).source, "manifest");
});

// ------------------------------------------------------------------------------ the compatible-rollback rule

test("a build the horizons exclude is refused before anything is written, and a database ahead of the build is refused", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  await runGate(gate(client, { migrations: { through: 3 } }, time));
  const state = () =>
    JSON.stringify(client.database.prepare("SELECT * FROM platform_schema_state").get());
  const before = state();
  // The build of schema 2 predates the cutover: its write horizon (3) excludes it.
  await assert.rejects(
    runGate(gate(client, { migrations: { through: 2 } }, time)),
    refusal("build-excluded"),
  );
  assert.equal(state(), before, "the refusal wrote nothing, not even a lease");
  // The shorter catalog of an older release finds receipts it does not contain.
  await assert.rejects(
    runGate(gate(client, {}, time, chain.slice(0, 2))),
    refusal("database-ahead"),
  );
  assert.equal(state(), before);
});

// ------------------------------------------------------------------------------------ the REST path and no secret

interface Fake {
  fetch: typeof fetch;
  requests: { url: string; authorization: string | null }[];
  failBatchWith?: string;
}

/** A fake Cloudflare: the database lookup and the D1 query endpoint, the latter backed by the SQLite oracle. */
function fakeCloudflare(
  client: SqliteMigrationClient,
  options: { name?: string; failBatchWith?: string } = {},
): Fake {
  const fake: Fake = {
    requests: [],
    ...(options.failBatchWith === undefined ? {} : { failBatchWith: options.failBatchWith }),
    fetch: (async (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      fake.requests.push({ url: String(url), authorization: headers.get("authorization") });
      if (String(url).includes("/d1/database?")) {
        return new Response(
          JSON.stringify({
            success: true,
            result: [{ uuid: databaseId, name: options.name ?? "arcforges-proof-business" }],
          }),
        );
      }
      assert.match(String(url), new RegExp(`/d1/database/${databaseId}/query$`, "u"));
      if (fake.failBatchWith !== undefined)
        return new Response(
          JSON.stringify({ success: false, errors: [{ message: fake.failBatchWith }] }),
          { status: 500 },
        );
      const body = JSON.parse(String(init?.body)) as {
        batch: { sql: string; params: (string | number | null)[] }[];
      };
      try {
        const results = await client.batch(body.batch);
        return new Response(
          JSON.stringify({
            success: true,
            result: results.map((entry) => ({
              results: entry.rows.map((row) =>
                Object.fromEntries(row.map((value, index) => [`c${index}`, value])),
              ),
              meta: { changes: entry.changes },
            })),
          }),
        );
      } catch (error) {
        return new Response(
          JSON.stringify({ success: false, errors: [{ message: (error as Error).message }] }),
          { status: 400 },
        );
      }
    }) as typeof fetch,
  };
  return fake;
}

function stage(manifest: object = { revision }): {
  root: string;
  env: Record<string, string>;
  cleanup: () => void;
} {
  const root = mkdtempSync(path.join(tmpdir(), "af-gate-"));
  mkdirSync(path.join(root, "artifacts", "candidate"), { recursive: true });
  writeFileSync(
    path.join(root, "artifacts", "candidate", "manifest.json"),
    JSON.stringify({ revision, ...manifest }),
  );
  writeFileSync(path.join(root, "wrangler.json"), JSON.stringify(wrangler));
  return {
    root,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
    env: {
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "ArcForges/Cloud",
      GITHUB_REF: "refs/heads/main",
      GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_SHA: revision,
      GITHUB_RUN_ID: "42",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_JOB: "deploy-proof",
      CLOUDFLARE_ACCOUNT_ID: account,
      CLOUDFLARE_API_TOKEN: token,
    },
  };
}

test("the proof step migrates the real catalog through the REST client, prints receipts and the compatibility record, and no secret", async () => {
  const client = new SqliteMigrationClient();
  const fake = fakeCloudflare(client);
  const staged = stage();
  try {
    let output = "";
    const code = await deployStep("proof", staged.env, {
      out: (text) => (output += text),
      fetch: fake.fetch,
      root: staged.root,
    });
    assert.equal(code, 0, output);
    assert.match(output, /"status": "passed"/u);
    assert.match(output, /"fence": 1/u);
    assert.match(output, /"receipts"/u);
    assert.match(output, /"compatibility"/u);
    assert.match(output, new RegExp(baseline[baseline.length - 1]?.file ?? "", "u"));
    assert.equal(output.includes(token), false);
    assert.ok(
      fake.requests.every((entry) => entry.authorization === `Bearer ${token}`),
      "the token travels only in the header",
    );
    assert.equal(
      fake.requests.some((entry) => entry.url.includes(token)),
      false,
    );
    assert.equal(requireGatePassed("proof", revision, staged.root).status, "passed");
    // The runner identity names the run, and its lease was released at the end.
    const lease = client.database
      .prepare("SELECT lease_holder FROM platform_schema_state")
      .get() as { lease_holder: string | null };
    assert.equal(lease.lease_holder, null);
    const receipt = client.database
      .prepare("SELECT runner FROM platform_migration_receipt ORDER BY sequence LIMIT 1")
      .get() as { runner: string };
    assert.equal(receipt.runner, "gh-42-1-deploy-proof");
  } finally {
    staged.cleanup();
  }
});

test("a failing migration step stops promotion: exit code 1, a refused gate record, and no promotion without a passed record", async () => {
  const client = new SqliteMigrationClient();
  const fake = fakeCloudflare(client, { failBatchWith: `permission denied for ${token}` });
  const staged = stage();
  try {
    let output = "";
    const code = await deployStep("proof", staged.env, {
      out: (text) => (output += text),
      fetch: fake.fetch,
      root: staged.root,
    });
    assert.equal(code, 1);
    assert.match(output, /REFUSED/u);
    assert.match(output, /Nothing is promoted/u);
    assert.equal(output.includes(token), false, "an error that echoes the token is scrubbed");
    const record = JSON.parse(readFileSync(gateFile("proof", staged.root), "utf8")) as {
      status: string;
    };
    assert.equal(record.status, "refused");
    assert.throws(() => requireGatePassed("proof", revision, staged.root), refusal("gate-failed"));
    // A missing record, a record of another revision and a record of another target never allow promotion.
    rmSync(gateFile("proof", staged.root));
    assert.throws(() => requireGatePassed("proof", revision, staged.root), refusal("gate-missing"));
    writeFileSync(
      gateFile("proof", staged.root),
      JSON.stringify({ target: "proof", revision: "f".repeat(40), status: "passed", detail: "" }),
    );
    assert.throws(() => requireGatePassed("proof", revision, staged.root));
    assert.throws(
      () => requireGatePassed("production", revision, staged.root),
      refusal("gate-missing"),
    );
  } finally {
    staged.cleanup();
  }
});

test("a build excluded by the horizons or a contract without consent fails the step and stops promotion", async () => {
  const client = new SqliteMigrationClient();
  // The database is past the cutover of a later catalog; this release's catalog is the real baseline.
  await applyPending({
    client,
    migrations: chain,
    runner: "earlier",
    now: clock().read,
    compatibility: { sourceRevision: "local", planManifestHash: "", abi: "", runtime: "" },
    stopAfter: 3,
  });
  const staged = stage();
  try {
    let output = "";
    const code = await deployStep("proof", staged.env, {
      out: (text) => (output += text),
      fetch: fakeCloudflare(client).fetch,
      root: staged.root,
    });
    assert.equal(code, 1);
    assert.match(output, /REFUSED/u);
    assert.throws(() => requireGatePassed("proof", revision, staged.root), refusal("gate-failed"));
  } finally {
    staged.cleanup();
  }
});

test("production declares no database: the step reports not applicable and records it, with no network call", async () => {
  const staged = stage();
  try {
    const env = { ...staged.env, GITHUB_EVENT_NAME: "push", GITHUB_JOB: "deploy" };
    let output = "";
    let calls = 0;
    const code = await deployStep("production", env, {
      out: (text) => (output += text),
      fetch: (async () => {
        calls++;
        return new Response("{}");
      }) as typeof fetch,
      root: staged.root,
    });
    assert.equal(code, 0);
    assert.equal(calls, 0);
    assert.match(output, /not applicable/u);
    assert.equal(requireGatePassed("production", revision, staged.root).status, "not-applicable");
  } finally {
    staged.cleanup();
  }
});

test("the live step refuses a pull request, a fork, another branch, another repository and a candidate of another commit", async () => {
  const staged = stage();
  try {
    const base = staged.env;
    const refused = (
      changes: Record<string, string | undefined>,
      target: "proof" | "production" = "proof",
    ) => assert.throws(() => requireContext({ ...base, ...changes }, target), refusal("context"));
    refused({ GITHUB_EVENT_NAME: "pull_request" });
    refused({ GITHUB_EVENT_NAME: "pull_request_target" });
    refused({ GITHUB_REPOSITORY: "someone/Cloud" });
    refused({ GITHUB_REF: "refs/pull/7/merge" });
    refused({ GITHUB_REF: "refs/heads/feature" });
    refused({ GITHUB_ACTIONS: undefined });
    refused({ GITHUB_EVENT_NAME: "workflow_dispatch" }, "production");
    refused({ GITHUB_EVENT_NAME: "push" }, "proof");
    for (const changes of [
      { GITHUB_EVENT_NAME: "pull_request" },
      { CLOUDFLARE_API_TOKEN: "" },
      { GITHUB_SHA: "e".repeat(40) },
      { CLOUDFLARE_ACCOUNT_ID: "nope" },
    ]) {
      let output = "";
      let calls = 0;
      const code = await deployStep(
        "proof",
        { ...base, ...changes },
        {
          out: (text) => (output += text),
          fetch: (async () => {
            calls++;
            return new Response("{}");
          }) as typeof fetch,
          root: staged.root,
        },
      );
      assert.equal(code, 1, JSON.stringify(changes));
      assert.equal(calls, 0, "no request is sent when the context is refused");
      assert.equal(output.includes(token), false);
    }
  } finally {
    staged.cleanup();
  }
});

test("scrub removes a secret wherever it appears and ignores empty values", () => {
  assert.equal(scrub(`a ${token} b ${token}`, [token, undefined, ""]), "a [redacted] b [redacted]");
});

// ------------------------------------------------------------------------------------------------ offline dry run

test("the dry run applies the real catalog to an in-memory database with the same gated flow", async () => {
  const report = await dryRun();
  assert.equal(report.status, "passed");
  assert.equal(report.after.schemaVersion, baseline.length - 1);
  assert.equal(report.plan.source, "default");
  const text = formatReport(report);
  assert.match(text, /"applied"/u);
  assert.equal(JSON.parse(text).compatibility.canWrite, true);
});

// ---------------------------------------------------------------------------------------------------- the workflow

function jobs(): Map<string, string> {
  const result = new Map<string, string>();
  const parts = workflow.split(/^jobs:\n/mu)[1]?.split(/^ {2}([a-z][a-z-]*):\n/mu) ?? [];
  for (let index = 1; index < parts.length; index += 2)
    result.set(parts[index] as string, parts[index + 1] as string);
  return result;
}

test("the migration step is in exactly the two gated deployment jobs, before promotion, and cannot be skipped by a failure", () => {
  const all = jobs();
  for (const [name, promotion, target] of [
    ["deploy", "npm run deploy\n", "production"],
    ["deploy-proof", "npm run deploy:proof\n", "proof"],
  ] as const) {
    const job = all.get(name) as string;
    const step = `run: node eng/migrations/deploy.ts deploy --target ${target}`;
    assert.ok(job.includes(step), `${name} has the migration step`);
    assert.ok(
      job.indexOf(step) < job.indexOf(`run: ${promotion}`),
      `${name}: the migration step runs before promotion`,
    );
    // A step that follows a failed step does not run unless it says so; neither the migration step nor the promotion may.
    const between = job.slice(job.indexOf(step) - 400, job.indexOf(`run: ${promotion}`) + 200);
    assert.equal(
      /continue-on-error|if:\s*(always|failure|\$\{\{ ?always)/u.test(between),
      false,
      `${name}: no escape around the migration step`,
    );
  }
  assert.equal((workflow.match(/eng\/migrations\/deploy\.ts/gu) ?? []).length, 2);
});

test("pull-request jobs hold no secret and no migration step", () => {
  const all = jobs();
  const gated = new Set(["deploy", "deploy-proof", "proof-access"]);
  for (const [name, body] of all) {
    if (gated.has(name)) continue;
    assert.equal(
      /secrets\.|CLOUDFLARE_API_TOKEN|migrations\/deploy/u.test(body),
      false,
      `${name} holds no secret or migration step`,
    );
  }
  for (const name of gated) {
    const job = all.get(name) as string;
    assert.match(job, /environment: cloudflare/u, `${name} is bound to the cloudflare environment`);
    assert.match(job, /github\.ref == 'refs\/heads\/main'/u, `${name} runs on main only`);
    assert.equal(
      /pull_request/u.test(job.split("steps:")[0] ?? ""),
      false,
      `${name} is not a pull-request job`,
    );
  }
  assert.match(workflow, /^permissions:\n {2}contents: read/mu);
});

test("production promotion is also code-gated: the deployment script requires the gate record before it pushes anything", () => {
  const source = readFileSync(path.join(repository, "tooling/cloudflare.ts"), "utf8");
  const gateAt = source.indexOf('requireGatePassed("production"');
  assert.ok(gateAt > 0);
  assert.ok(gateAt < source.indexOf('"containers", "push"'));
  assert.ok(gateAt < source.indexOf('wrangler,\n    "deploy"'));
});
