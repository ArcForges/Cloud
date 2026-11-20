// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { candidateDir, readJson, root, run, wrangler, writeJson } from "./process.ts";
import { verifyCandidate, type Candidate, type WorkerConfig } from "./project.ts";
import { proofProcessEnvironment, runSensitive } from "./sensitive-process.ts";
import { runProbe, waitForHealth } from "./protocol.ts";
import { neonRuntimeSecret, withNeonRuntimeSecret } from "./neon-runtime.ts";
import {
  loadCandidateImage,
  centerVariables,
  checkHelloCredential,
  chooseLiveSlot,
  directUrlSecret,
  promotionRuntimeRole,
  readGate,
  readLiveSlots,
  slotLabel,
  type GateRecord,
  withRuntimeCredential,
} from "./postgres-deploy.ts";
import {
  checkCheckout,
  evaluateGate,
  type FetchInput,
  type GateResult,
} from "../eng/verification/proof-gate.ts";
import { requireSecurityBridgeSuccessor } from "./ctr06-security-bridge-gate.ts";

import { expectedIdentity, verifyHealthIdentity } from "./build-identity.ts";
import { centerSurfaces } from "../worker/ingress/routes.ts";

const productionBase = "https://arcforges.com/api";
const deploymentFile = path.join(root, "artifacts", "deployment.json");

type D1Gate = { target?: string; revision?: string; status?: string };
type DeploymentWorkerConfig = WorkerConfig & { vars: { ARCFORGES_CENTER_MODE?: string } };

// CLOUD.84 U10: the sealed C# migrator makes the decision. Promotion checks its exact target and commit.
function requireGatePassed(
  record: D1Gate | undefined,
  target: "production" | "proof",
  revision: string,
): void {
  assert(record, "the migration step did not run; nothing is promoted");
  assert.equal(record.target, target, "the gate record is for another target");
  assert.equal(record.revision, revision, "the gate record is for another revision");
  if (record.status !== "passed" && record.status !== "not-applicable")
    throw new Error("the migration step did not pass; nothing is promoted");
}

function readD1Gate(target: "production" | "proof"): D1Gate | undefined {
  try {
    return JSON.parse(
      readFileSync(path.join(root, "artifacts", `migration-gate-${target}.json`), "utf8"),
    ) as D1Gate;
  } catch {
    return undefined;
  }
}

function requireFlagshipConfig(config: DeploymentWorkerConfig): void {
  assert.equal(
    config.vars.ARCFORGES_HELLO_RUNTIME,
    "go",
    "Official delivery requires the explicit Go Center runtime.",
  );
  assert.equal(
    config.vars.ARCFORGES_CENTER_MODE,
    "official-hosted",
    "Official delivery requires official-hosted mode.",
  );
  assert.equal(config.workers_dev, false, "Official delivery requires workers.dev disabled.");
  assert.equal(config.preview_urls, false, "Official delivery requires preview URLs disabled.");
}

async function sourceMigrationVersion(): Promise<number> {
  const entries = (await readdir(path.join(root, "center", "internal", "schema", "migrations")))
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/u.test(name))
    .sort();
  assert(entries.length > 0, "The candidate's PostgreSQL migration inventory is empty.");
  for (const [index, name] of entries.entries()) {
    assert.equal(
      Number(name.slice(0, 4)),
      index + 1,
      "The candidate's migration history is not contiguous.",
    );
  }
  return entries.length;
}

export interface DeploymentFixture {
  source: "external-fixture";
  schema: 1;
  github: { dispatch: string; responses: Record<string, unknown> };
  d1: D1Gate;
  postgres: GateRecord;
  databaseRoles: { migration: string; hello: string; database: string };
  worker: { deployments: unknown; versions: Record<string, unknown> };
}

const databaseName = /^[a-z][a-z0-9_]{2,62}$/u;

function producerInput(gate: GateResult): FetchInput {
  return {
    sha: gate.sha,
    tree: gate.tree,
    runId: gate.run.id,
    runNumber: gate.run.number,
    runAttempt: gate.run.attempt,
    candidateAttempt: gate.candidateAttempt,
    artifactId: gate.artifact.id,
    artifactDigest: gate.artifact.digest,
  };
}

export function evaluateFixtureProducer(fixture: DeploymentFixture): FetchInput {
  assert.equal(fixture.schema, 1, "Unsupported deployment fixture schema.");
  assert.equal(
    fixture.source,
    "external-fixture",
    "Only named external fixtures are allowed in preflight.",
  );
  return producerInput(
    evaluateGate((endpoint) => {
      assert(
        Object.hasOwn(fixture.github.responses, endpoint),
        "GitHub fixture response is missing.",
      );
      return fixture.github.responses[endpoint];
    }, fixture.github.dispatch),
  );
}

// A dry run has no runtime database record to fall back to, so it requires a complete fixture rollout inventory.
function requireFixtureRollout(response: unknown): void {
  const versions = (response as { versions?: unknown } | null)?.versions;
  assert(Array.isArray(versions) && versions.length > 0, "Worker fixture deployment is missing.");
  const seen = new Set<string>();
  let percentageTotal = 0;
  for (const raw of versions as unknown[]) {
    assert(raw && typeof raw === "object", "Worker fixture version is invalid.");
    const { version_id: id, percentage } = raw as Record<string, unknown>;
    assert(
      typeof id === "string" &&
        /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(id) &&
        !seen.has(id),
      "Worker fixture version identity is invalid or repeated.",
    );
    assert(
      typeof percentage === "number" &&
        Number.isFinite(percentage) &&
        percentage >= 0 &&
        percentage <= 100,
      "Worker fixture rollout percentage is invalid.",
    );
    seen.add(id);
    percentageTotal += percentage;
  }
  assert(Math.abs(percentageTotal - 100) < 1e-8, "Worker fixture rollout is incomplete.");
}

export async function evaluateFixtureTarget(
  fixture: DeploymentFixture,
  config: WorkerConfig,
  revision: string,
  schemaVersion: number,
) {
  requireFlagshipConfig(config);
  requireGatePassed(fixture.d1, "production", revision);
  const runtimeRole = promotionRuntimeRole(fixture.postgres, "production", revision, schemaVersion);
  const roles = fixture.databaseRoles;
  assert(
    [roles.migration, roles.hello, roles.database].every(
      (name) => typeof name === "string" && databaseName.test(name),
    ),
    "The fixture must name valid database and role identifiers.",
  );
  assert.equal(
    fixture.postgres.database,
    roles.database,
    "The PostgreSQL gate names another database.",
  );
  assert.notEqual(
    runtimeRole,
    roles.migration,
    "The migration and runtime roles must be separate.",
  );

  // Construct inert URIs solely to exercise production's direct/pooled setting and credential compatibility checks.
  const fixtureEnvironment = {
    [directUrlSecret]: `postgresql://${roles.migration}:fixture-only@ep-fixture.invalid.neon.tech/${roles.database}?sslmode=verify-full&channel_binding=require`,
    NEON_DATABASE_URL: `postgresql://${roles.hello}:fixture-only@ep-fixture-pooler.invalid.neon.tech/${roles.database}?sslmode=verify-full&channel_binding=require`,
  };
  centerVariables("production", fixtureEnvironment);
  neonRuntimeSecret(config.vars.ARCFORGES_NEON_HELLO, fixtureEnvironment);
  checkHelloCredential("production", fixtureEnvironment);

  requireFixtureRollout(fixture.worker.deployments);
  const live = await readLiveSlots(async (args) => {
    if (args[0] === "deployments") return JSON.stringify(fixture.worker.deployments);
    const version = args[2];
    assert(
      version && Object.hasOwn(fixture.worker.versions, version),
      "Worker fixture version response is missing.",
    );
    const view = fixture.worker.versions[version] as {
      annotations?: Record<string, unknown>;
    } | null;
    const annotation = view?.annotations?.["workers/message"];
    if (annotation !== undefined) {
      assert(typeof annotation === "string", "Worker fixture version annotation is invalid.");
      const slots = annotation.split(/\s+/u).filter((token) => token.startsWith("runtime-slot="));
      assert(
        slots.length <= 1 && slots.every((slot) => /^runtime-slot=[ab]$/u.test(slot)),
        "Worker fixture runtime slot annotation is ambiguous.",
      );
    }
    return JSON.stringify(view);
  }, []);
  assert(live.unreadable === undefined, "Current Worker slot evidence is unavailable.");
  const protectedSlot = chooseLiveSlot(live).slot;
  assert(protectedSlot, "Current Worker slot evidence names no protected runtime generation.");
  return {
    schemaVersion,
    protectedSlot,
    candidateSlot: protectedSlot === "a" ? "b" : "a",
  } as const;
}

// The preflight accepts only local fixtures, with no effect ports and no access to live credentials or transports.
export async function preflight(directory: string, fixture: DeploymentFixture) {
  const producer = evaluateFixtureProducer(fixture);
  const manifestPath = path.join(directory, "manifest.json");
  const manifestInfo = await lstat(manifestPath);
  assert(
    manifestInfo.isFile() && manifestInfo.size <= 16_384,
    "The candidate manifest is unavailable.",
  );
  const manifest = await readJson<Candidate>(manifestPath);
  assert.equal(typeof manifest.version, "string", "The candidate version is unavailable.");
  const local = /^0\.1\.0-local\.[0-9]+$/u.test(manifest.version);
  const version = local
    ? manifest.version
    : `0.1.0-ci.${producer.runNumber}.${producer.candidateAttempt}`;
  assert.equal(
    manifest.version,
    version,
    "The candidate does not match the exact fixture producer attempt.",
  );
  const environment = proofProcessEnvironment(process.env);
  if (!local)
    Object.assign(environment, {
      GITHUB_ACTIONS: "true",
      GITHUB_SHA: producer.sha,
      GITHUB_REPOSITORY: "ArcForges/Cloud",
      GITHUB_RUN_ID: String(producer.runId),
      GITHUB_RUN_NUMBER: String(producer.runNumber),
      GITHUB_RUN_ATTEMPT: String(producer.candidateAttempt),
    });
  assert.equal(
    await realpath(directory),
    await realpath(candidateDir),
    "Use the candidate in this checkout's stock artifacts/candidate directory.",
  );
  for (const name of await readdir(directory))
    assert(
      (await lstat(path.join(directory, name))).isFile(),
      "Candidate members must be regular files.",
    );
  // Use the unchanged sealed verifier with only the declared producer context in a separate process.
  await runSensitive(
    "candidate",
    process.execPath,
    [path.join(root, "tooling", "project.ts"), "verify"],
    environment,
    "discard",
  );
  const candidate = await readJson<Candidate>(manifestPath);
  assert.deepEqual(candidate, manifest, "The candidate changed during preflight.");
  assert.equal(candidate.dirty, false, "A clean sealed candidate is required.");
  const head = await run("git", ["rev-parse", "HEAD"], true);
  assert.equal(candidate.revision, head, "The candidate belongs to another source revision.");
  if (!local) {
    const tree = await run("git", ["rev-parse", "HEAD^{tree}"], true);
    checkCheckout(head, tree, producer);
  }
  const config = await readJson<WorkerConfig>(path.join(directory, "wrangler.json"));
  const target = await evaluateFixtureTarget(
    fixture,
    config,
    candidate.revision,
    await sourceMigrationVersion(),
  );
  return {
    source: "external-fixture",
    candidate: {
      revision: candidate.revision,
      version: candidate.version,
      imageId: candidate.imageId,
    },
    producer: local ? "local_unpublished" : "fixture_context_matched",
    target,
    archiveCustody: "not_assessed",
    authority: "not_assessed",
    applied: false,
  } as const;
}

interface Deployment {
  revision: string;
  version: string;
  imageId: string;
  imageDigest: string;
  baseUrl: string;
  /**
   * The configured surfaces: those the deployed Worker version forwards and starts the Go center with (ARCFORGES_CENTER_SURFACES),
   * computed from its configuration, not observed. The Container restarts a center left running under another version's start
   * environment before it serves a request (AF-CTR-03), so the center's health (`center.surfaces`) should state the same value;
   * only the local live check and the post-deploy acceptance read the health and compare them.
   */
  center?: { configuredSurfaces: string };
  deployedAt: string;
  verified?: unknown;
}

async function requireCurrentMain(revision: string) {
  assert.equal(process.env.GITHUB_REPOSITORY, "ArcForges/Cloud");
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(process.env.GITHUB_EVENT_NAME, "push");
  const current = await run(
    "gh",
    ["api", "repos/ArcForges/Cloud/git/ref/heads/main", "--jq", ".object.sha"],
    true,
  );
  assert.equal(
    revision,
    current,
    "A newer main commit exists. Only the current main candidate can deploy.",
  );
}

async function deploy() {
  requireSecurityBridgeSuccessor();
  const candidate = await verifyCandidate();
  assert.equal(candidate.dirty, false, "Uncommitted local builds cannot deploy.");
  const config = await readJson<WorkerConfig>(path.join(candidateDir, "wrangler.json"));
  requireFlagshipConfig(config);
  const account = process.env.CLOUDFLARE_ACCOUNT_ID ?? "";
  assert.match(
    account,
    /^[0-9a-f]{32}$/,
    "Set CLOUDFLARE_ACCOUNT_ID in the GitHub cloudflare environment.",
  );
  assert.ok(
    process.env.CLOUDFLARE_API_TOKEN,
    "Set the CLOUDFLARE_API_TOKEN environment secret; see docs/deployment.md.",
  );
  const runtimeSecret = neonRuntimeSecret(config.vars.ARCFORGES_NEON_HELLO, process.env);
  await requireCurrentMain(candidate.revision);
  // CLOUD.70: nothing is pushed or promoted unless the gated D1 migration step passed for this very candidate
  // (a failing or missing step stops promotion; the workflow step before this one writes the record).
  requireGatePassed(readD1Gate("production"), "production", candidate.revision);
  // AF-CTR-02: and the PostgreSQL step migrated the production database for this very candidate.
  const runtimeRole = promotionRuntimeRole(
    await readGate("production"),
    "production",
    candidate.revision,
    await sourceMigrationVersion(),
  );
  await loadCandidateImage(candidate);
  const imageId = candidate.imageId;
  await run(process.execPath, [wrangler, "containers", "push", candidate.image]);
  const registryTag = `registry.cloudflare.com/${account}/${candidate.image}`;
  const digests = JSON.parse(
    await run(
      "docker",
      ["image", "inspect", registryTag, "--format", "{{json .RepoDigests}}"],
      true,
    ),
  ) as string[];
  const prefix = `registry.cloudflare.com/${account}/arcforges-cloud@sha256:`;
  const imageDigest = digests.find((value) => value.startsWith(prefix));
  assert.ok(imageDigest, "Cloudflare registry did not return the pushed image digest.");
  assert.match(imageDigest.slice(prefix.length), /^[0-9a-f]{64}$/);

  config.main = "./candidate/worker.js";
  config.account_id = account;
  config.containers[0].image = imageDigest;
  await writeJson(path.join(root, "artifacts", "deploy.wrangler.json"), config);
  await requireCurrentMain(candidate.revision);
  const deployArguments = [
    wrangler,
    "deploy",
    "--config",
    "artifacts/deploy.wrangler.json",
    "--no-bundle",
    // An explicit empty environment selects the top-level (production) Worker.
    "--env",
    "",
    "--containers-rollout",
    "immediate",
    "--tag",
    candidate.version,
  ];
  // The runtime credential is rotated now, in the process that uploads it with this version; the revision still running keeps its
  // own credential of the other rotation slot until this one replaces it.
  // The live version's message names its runtime slot, which the rotation never touches; the new version is labelled likewise.
  const configArguments = ["--config", "artifacts/deploy.wrangler.json", "--env", ""];
  await withRuntimeCredential(
    "production",
    candidate.image,
    async (runtime, rotation) => {
      await withNeonRuntimeSecret({ ...runtimeSecret, ...runtime }, async (secretArguments) => {
        await run(process.execPath, [
          ...deployArguments,
          "--message",
          slotLabel(String(rotation.slot)),
          ...secretArguments,
        ]);
      });
    },
    {
      runtimeRole,
      liveSlots: () =>
        readLiveSlots((args) => run(process.execPath, [wrangler, ...args], true), configArguments),
    },
  );
  await writeJson(deploymentFile, {
    revision: candidate.revision,
    version: candidate.version,
    imageId,
    imageDigest,
    baseUrl: productionBase,
    center: { configuredSurfaces: centerSurfaces(config.vars.FLAGSHIP_SURFACES) },
    deployedAt: new Date().toISOString(),
  } satisfies Deployment);
}

async function smoke() {
  assert.notEqual(process.env.CI, "true", "Live service tests are local opt-in only.");
  const candidate = await verifyCandidate();
  const deployment = await readJson<Deployment>(deploymentFile);
  const config = await readJson<WorkerConfig>(path.join(candidateDir, "wrangler.json"));
  const runtime = config.vars.ARCFORGES_HELLO_RUNTIME;
  assert(runtime === "go" || runtime === "csharp", "The release must name its deployed runtime.");
  assert.equal(deployment.revision, candidate.revision);
  assert.equal(deployment.imageId, candidate.imageId);
  assert.equal(deployment.baseUrl, productionBase);
  console.log(
    "Waiting for both Worker and Native AOT container identities; no redeploy or application replay.",
  );
  const health = await waitForHealth(
    productionBase,
    candidate.revision,
    true,
    600000,
    expectedIdentity(candidate.version).build,
    runtime,
  );
  verifyHealthIdentity(health, expectedIdentity(candidate.version));
  if (deployment.center)
    assert.equal(
      (health as { center?: { surfaces?: unknown } }).center?.surfaces,
      deployment.center.configuredSurfaces,
      "The running center must serve exactly the surfaces the deployed Worker forwards.",
    );
  const protocol = await runProbe(productionBase, true);
  // The Cloud API route must not replace the already deployed static Web origin.
  const home = await fetch("https://arcforges.com/", {
    redirect: "error",
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(home.status, 200);
  assert.match(home.headers.get("content-type") ?? "", /text\/html/);
  await home.body?.cancel();
  deployment.verified = { at: new Date().toISOString(), health, protocol, webHome: true };
  await writeJson(deploymentFile, deployment);
  console.log("Production Hello gRPC-Web and Web home verified.");
}

async function preflightCLI(directory: string | undefined, evidence: string | undefined) {
  if (!directory || !evidence || process.argv.length !== 5)
    throw new Error("Use preflight <sealed-candidate-directory> <external-fixture.json>.");
  try {
    const fixtureInfo = await lstat(evidence);
    assert(fixtureInfo.isFile() && fixtureInfo.size <= 1_048_576);
    const fixture = JSON.parse(await readFile(evidence, "utf8")) as DeploymentFixture;
    console.log(JSON.stringify(await preflight(directory, fixture), null, 2));
  } catch {
    // Provider fixture contents and assertion diagnostics may contain data that must never appear in receipts.
    throw new Error(
      "Deployment preflight refused the fixture, sealed candidate or target admission.",
    );
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (process.argv[2] === "deploy") await deploy();
  else if (process.argv[2] === "smoke") await smoke();
  else if (process.argv[2] === "preflight") await preflightCLI(process.argv[3], process.argv[4]);
  else throw new Error("Use deploy, smoke or preflight.");
}
