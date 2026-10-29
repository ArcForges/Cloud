// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { copyFile, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { candidateDir, readJson, root, run, sha256, wrangler, writeJson } from "./process.ts";
import { probeProject, runProbe, waitForHealth } from "./protocol.ts";
import { centerSurfaces } from "../worker/ingress/routes.ts";
import {
  notActivatedReplies,
  pageRoutes,
  surfaceRoutes,
} from "../worker/tables/center-tables.generated.ts";
import { sealedToolName } from "./sealed-tool.ts";
import { auditLicences, evaluatedManagedLicences } from "./licence-boundary.ts";
import { auditProvenance } from "./provenance.ts";
import {
  legalBundle,
  stageImageNotices,
  verifyImageProvenance,
  verifyStoredImage,
  verifyReleaseFiles,
} from "./release-provenance.ts";

import {
  expectedIdentity,
  imageBuildVariables,
  verifyIdentity,
  verifyHealthIdentity,
  type Identity,
} from "./build-identity.ts";

/**
 * The publish of the sealed tool (CLOUD.84 S38(2), S41(1)): tools/ArcForges.Cloud.Generation, self-contained for linux-x64 and not
 * single-file. Nothing here may imply the ILLink pack (single-file, trimming or AOT analysis), because the reviewed tool lock does not hold
 * it and the CI restore is locked.
 */
export function toolPublishArguments(output: string): string[] {
  return [
    "publish",
    probeProject,
    "-c",
    "Release",
    "-r",
    "linux-x64",
    "--self-contained",
    "true",
    "-p:PublishSingleFile=false",
    "-p:DebugType=none",
    "-o",
    output,
  ];
}

const payloadFiles = [
  "build-identity.json",
  "docker-image.tar",
  "worker.js",
  "wrangler.json",
  "legal-notices.json",
  "worker-meta.json",
  // CLOUD.84 D1: the isolated proof environment has its own entry, so its bundle is a second sealed member. Its metadata is sealed beside it.
  "proof-worker.js",
  "proof-worker-meta.json",
  "image-provenance.json",
  // CLOUD.84 S33(3)(b), S38(2), S41(1): the self-contained, non-single-file tool archive (tooling/sealed-tool.ts). CI runs its Hello
  // `probe` through runProbe and the deploy jobs its `migrate` command through eng/migrations/shim.ts, each after checking its digest.
  sealedToolName,
] as const;
export interface Candidate {
  schema: 1;
  revision: string;
  dirty: boolean;
  version: string;
  image: string;
  imageId: string;
  files: Record<string, string>;
}
interface ImageInfo {
  Id: string;
  Architecture: string;
  Os: string;
  Config: { User: string; Entrypoint: string[]; Labels: Record<string, string> };
}
export type WorkerConfig = {
  name: string;
  main: string;
  no_bundle?: boolean;
  vars: {
    SOURCE_REVISION: string;
    BUILD_IDENTITY?: string;
    ARCFORGES_NEON_HELLO?: string;
    ARCFORGES_HELLO_RUNTIME?: string;
    FLAGSHIP_SURFACES?: string;
  };
  containers: [
    {
      image: string;
      class_name: string;
      max_instances: number;
      image_vars?: Record<string, string>;
      image_build_context?: string;
    },
  ];
  account_id?: string;
  routes?: unknown[];
  dev?: { ip: string; port: number };
  [key: string]: unknown;
};

async function inspectImage(image: string): Promise<ImageInfo> {
  const info = JSON.parse(await run("docker", ["image", "inspect", image], true)) as ImageInfo[];
  assert.equal(info.length, 1);
  assert.ok(info[0]);
  return info[0];
}

export async function verifyCandidate(): Promise<Candidate> {
  const candidate = await readJson<Candidate>(path.join(candidateDir, "manifest.json"));
  assert.equal(candidate.schema, 1);
  assert.match(candidate.revision, /^[0-9a-f]{40}(-dirty)?$/);
  assert.match(candidate.imageId, /^sha256:[0-9a-f]{64}$/);
  assert.match(candidate.image, /^arcforges-cloud:[a-z0-9.-]+$/);
  assert.match(candidate.version, /^0\.1\.0-(ci\.[0-9]+\.[0-9]+|local\.[0-9]+)$/);
  if (process.env.GITHUB_SHA) {
    assert.equal(candidate.revision, process.env.GITHUB_SHA);
    assert.equal(candidate.dirty, false);
  }
  assert.deepEqual((await readdir(candidateDir)).sort(), [...payloadFiles, "manifest.json"].sort());
  assert.deepEqual(Object.keys(candidate.files).sort(), [...payloadFiles].sort());
  for (const file of payloadFiles) {
    assert.equal(
      await sha256(path.join(candidateDir, file)),
      candidate.files[file],
      `Candidate changed: ${file}`,
    );
  }
  const config = await readJson<WorkerConfig>(path.join(candidateDir, "wrangler.json"));
  assert.equal(config.name, "arcforges-cloud");
  assert.equal(config.main, "./worker.js");
  assert.equal(config.vars.SOURCE_REVISION, candidate.revision);
  assert.equal(config.containers[0]?.image, candidate.image);
  assert.equal(config.containers[0]?.max_instances, 1);
  assert.equal(config.no_bundle, true);
  verifyReleaseFiles(root, candidateDir, candidate.revision, candidate.imageId);
  verifyIdentity(await readJson(path.join(candidateDir, "build-identity.json")), candidate.version);
  assert.equal(
    config.vars.BUILD_IDENTITY,
    JSON.stringify(expectedIdentity(candidate.version).build),
  );
  return candidate;
}

/** The hardening every local container run of the candidate image uses: the production Container's bounds and no privileges. */
const containerHardening = [
  "--read-only",
  "--cap-drop",
  "ALL",
  "--security-opt",
  "no-new-privileges",
  "--memory",
  "256m",
  "--cpus",
  "1",
] as const;

// Local opt-in diagnostic of the sealed candidate image (never CI). It starts the image's C# default entrypoint, then the Go
// center (/app/arcforges-center) from the same image the way the production Container runs it.
export async function testContainer(image: string, revision: string, identity: Identity) {
  assert.notEqual(process.env.CI, "true", "Container runtime tests are local opt-in only.");
  const compiled = JSON.parse(
    await run(
      "docker",
      [
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        image,
        "--build-info",
      ],
      true,
    ),
  ) as unknown;
  assert.deepEqual(compiled, identity, "Actual Native AOT binary identity differs");
  await writeJson(path.join(candidateDir, "build-identity.json"), compiled);
  const imageInfo = await inspectImage(image);
  assert.equal(imageInfo.Os, "linux");
  assert.equal(imageInfo.Architecture, "amd64");
  assert.ok(
    imageInfo.Config.User && !["0", "root"].includes(imageInfo.Config.User),
    "Image must run as non-root.",
  );
  assert.deepEqual(imageInfo.Config.Entrypoint, ["/app/ArcForges.Cloud"]);
  assert.equal(imageInfo.Config.Labels["org.opencontainers.image.revision"], revision);

  // Ephemeral host ports avoid colliding with other repository tasks.
  const id = await run(
    "docker",
    [
      "run",
      "--detach",
      ...containerHardening,
      "--publish",
      "127.0.0.1::8080",
      "--publish",
      "127.0.0.1::8081",
      image,
    ],
    true,
  );
  const binding = async (container: string, port: string) => {
    const output = await run("docker", ["port", container, port], true);
    const match = /^127\.0\.0\.1:(\d+)$/.exec(output);
    assert.ok(match, `Unexpected Docker port: ${output}`);
    return `http://127.0.0.1:${match[1]}`;
  };
  let csharp: { health: unknown; grpcWeb: unknown };
  try {
    const provenance = await verifyImageProvenance(id, revision, imageInfo.Id);
    await writeJson(path.join(candidateDir, "image-provenance.json"), provenance);
    const web = await binding(id, "8080/tcp");
    const health = await waitForHealth(web, revision, false, 60000);
    verifyHealthIdentity(health, identity);
    const grpcWeb = await runProbe(web, false);
    // No native gRPC call to the C# host: its ingress admits binary gRPC-Web only and answers application/grpc with 415
    // (docs/cloud-ingress.md, host admission rule 2). The published native Consumer runs against the Go center below,
    // which admits native gRPC.
    await run("docker", ["restart", id]);
    const restartedWeb = await binding(id, "8080/tcp");
    verifyHealthIdentity(await waitForHealth(restartedWeb, revision, false, 60000), identity);
    await runProbe(restartedWeb, false);
    csharp = { health, grpcWeb };
  } finally {
    await run("docker", ["logs", "--tail", "50", id]);
    await run("docker", ["rm", "--force", id]);
  }

  const center = await testCenterContainer(image, revision, identity, binding);
  await writeJson(path.join(root, "artifacts", "container-evidence.json"), {
    imageId: imageInfo.Id,
    health: csharp.health,
    grpcWeb: csharp.grpcWeb,
    restart: true,
    nonRoot: true,
    center,
  });
  return imageInfo.Id;
}

/**
 * Starts the Go center from the candidate image as the production Container does (worker/foundation/cloud-container.ts):
 * the entrypoint /app/arcforges-center with the mode and public base URL of wrangler.json, under the same hardening. The Neon
 * Hello stays disabled because this local run has no database secret.
 */
async function testCenterContainer(
  image: string,
  revision: string,
  identity: Identity,
  binding: (container: string, port: string) => Promise<string>,
) {
  const entrypoint = "/app/arcforges-center";
  const production = await readJson<{ vars: Record<string, string | undefined> }>(
    path.join(root, "wrangler.json"),
  );
  const mode = production.vars.ARCFORGES_CENTER_MODE;
  const publicBaseUrl = production.vars.ARCFORGES_CENTER_PUBLIC_BASE_URL;
  assert.equal(mode, "official-hosted", "Production must run the center in official-hosted mode.");
  assert.ok(
    publicBaseUrl?.startsWith("https://"),
    "Production must state an https public base URL.",
  );

  const compiled = JSON.parse(
    await run(
      "docker",
      [
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--entrypoint",
        entrypoint,
        image,
        "--build-info",
      ],
      true,
    ),
  ) as { runtime?: unknown; nativeAot?: unknown };
  verifyHealthIdentity(compiled, identity);
  assert.equal(compiled.runtime, "go", "The center's build identity must report the Go runtime.");
  assert.equal(compiled.nativeAot, false);

  const id = await run(
    "docker",
    [
      "run",
      "--detach",
      ...containerHardening,
      "--publish",
      "127.0.0.1::8080",
      "--publish",
      "127.0.0.1::8081",
      "--env",
      `ARCFORGES_CENTER_MODE=${mode}`,
      "--env",
      `ARCFORGES_CENTER_PUBLIC_BASE_URL=${publicBaseUrl}`,
      "--env",
      "ARCFORGES_NEON_HELLO=disabled",
      "--entrypoint",
      entrypoint,
      image,
    ],
    true,
  );
  try {
    const web = await binding(id, "8080/tcp");
    const native = await binding(id, "8081/tcp");
    const health = (await waitForHealth(web, revision, false, 60000, undefined, "go")) as {
      helloBackend?: unknown;
      center?: unknown;
    };
    verifyHealthIdentity(health, identity);
    assert.equal(health.helloBackend, "stateless");
    // No ARCFORGES_CENTER_SURFACES: an official-hosted center serves no surface and says so.
    assert.deepEqual(health.center, {
      binary: "arcforges-center",
      mode,
      publicBaseUrl,
      surfaces: "none",
    });
    const grpcWeb = await runProbe(web, false);
    await run("dotnet", [
      "run",
      "--project",
      "tests/ArcForges.Cloud.Consumer",
      "-c",
      "Release",
      "--no-build",
      "--",
      native,
    ]);
    // SIGTERM, as the Container runtime stops an instance: the center drains and exits 0.
    await run("docker", ["stop", "--time", "20", id]);
    const exitCode = await run("docker", ["inspect", "--format", "{{.State.ExitCode}}", id], true);
    assert.equal(exitCode, "0", "The center must stop cleanly on SIGTERM.");
    return {
      entrypoint,
      mode,
      publicBaseUrl,
      health,
      grpcWeb,
      nativeGrpc: true,
      gracefulStop: true,
    };
  } finally {
    await run("docker", ["logs", "--tail", "50", id]);
    await run("docker", ["rm", "--force", id]);
  }
}

/**
 * AF-CTR-03: with the production configuration (no surface enabled), every surface method of the generated table is answered by the
 * real Worker with the generated STATE/not_activated reply, without a Container call.
 */
async function probeDisabledSurfaces(base: string, flag: string | undefined) {
  assert.equal(
    flag ?? "",
    "",
    "The local Worker test runs the production configuration, which enables no surface.",
  );
  const expected = Buffer.from(notActivatedReplies.identity, "base64");
  for (const route of surfaceRoutes) {
    const response = await fetch(`${base}${route.path}`, {
      method: "POST",
      headers: { "content-type": "application/grpc-web+proto" },
      body: new Uint8Array([0, 0, 0, 0, 0]),
    });
    assert.equal(response.status, 200, route.path);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), expected, route.path);
  }
  // The pages surface is off too: a page route is a path the Worker does not know (404), whatever the method and before anything
  // about the request is read, so the Container is never woken.
  for (const route of pageRoutes) {
    const response = await fetch(`${base}${route.path}`, { method: route.method });
    assert.equal(response.status, 404, `${route.method} ${route.path}`);
    await response.arrayBuffer();
  }
  return { notActivated: surfaceRoutes.length, pagesDisabled: pageRoutes.length };
}

async function testWorker(candidate: Candidate) {
  assert.notEqual(process.env.CI, "true", "Worker runtime tests are local opt-in only.");
  assert.equal(process.platform, "linux", "The real local Containers runtime requires Linux.");
  const testDir = path.join(root, "artifacts", "worker-test");
  await mkdir(testDir, { recursive: true });
  // A FROM-only test wrapper reuses the tested binary/image; it does not restore or compile source.
  await writeFile(path.join(testDir, "Dockerfile"), `FROM ${candidate.image}\n`);
  const config = await readJson<WorkerConfig>(path.join(candidateDir, "wrangler.json"));
  const workerName = `arcforges-cloud-test-${candidate.revision.slice(0, 12)}-${randomUUID().slice(0, 8)}`;
  config.name = workerName;
  config.main = "../candidate/worker.js";
  config.routes = [];
  config.containers[0].image = "./Dockerfile";
  config.dev = { ip: "127.0.0.1", port: 18787 };
  // This opt-in check verifies local transport only; live Neon acceptance is separate.
  config.vars.ARCFORGES_NEON_HELLO = "disabled";
  await writeJson(path.join(testDir, "wrangler.json"), config);
  const child = spawn(
    process.execPath,
    [
      wrangler,
      "dev",
      "--local",
      "--config",
      path.join(testDir, "wrangler.json"),
      "--persist-to",
      path.join(testDir, "state", workerName),
    ],
    {
      cwd: root,
      detached: true,
      stdio: "inherit",
      env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
    },
  );
  try {
    const health = await waitForHealth(
      "http://127.0.0.1:18787/api",
      candidate.revision,
      true,
      180000,
      expectedIdentity(candidate.version).build,
      config.vars.ARCFORGES_HELLO_RUNTIME === "go" ? "go" : "csharp",
    );
    verifyHealthIdentity(health, expectedIdentity(candidate.version));
    // AF-CTR-03: the center was started with the surfaces this Worker forwards.
    if (config.vars.ARCFORGES_HELLO_RUNTIME === "go")
      assert.equal(
        (health as { center?: { surfaces?: unknown } }).center?.surfaces,
        centerSurfaces(config.vars.FLAGSHIP_SURFACES),
        "The center must serve exactly the surfaces the Worker forwards.",
      );
    const result = await runProbe("http://127.0.0.1:18787/api", true);
    const surfaces = await probeDisabledSurfaces(
      "http://127.0.0.1:18787/api",
      config.vars.FLAGSHIP_SURFACES,
    );
    await writeJson(path.join(root, "artifacts", "worker-evidence.json"), {
      workerName,
      revision: candidate.revision,
      health,
      ...result,
      surfaces,
    });
  } finally {
    // Own the process group; Wrangler and its runtime children cannot signal the test runner.
    const stop = (signal: NodeJS.Signals) => {
      if (child.pid && child.exitCode === null && child.signalCode === null) {
        try {
          process.kill(-child.pid, signal);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
        }
      }
    };
    stop("SIGTERM");
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) resolve();
      else {
        child.once("exit", () => resolve());
        const timer = setTimeout(() => {
          stop("SIGKILL");
        }, 10000);
        timer.unref();
      }
    });
    // Miniflare retains Docker containers after exit. Remove only this unique invocation's pair.
    const prefix = `/workerd-${workerName}-CloudContainer-`;
    const ids = (
      await run(
        "docker",
        ["ps", "--all", "--quiet", "--no-trunc", "--filter", `name=${prefix}`],
        true,
      )
    )
      .split(/\s+/u)
      .filter(Boolean);
    for (const id of ids) {
      assert.match(id, /^[a-f0-9]{64}$/u);
      const name = await run("docker", ["inspect", id, "--format", "{{.Name}}"], true);
      assert(name.startsWith(prefix), "Refusing to remove a container outside this test");
      await run("docker", ["rm", "--force", id]);
    }
  }
}

/**
 * The network of the image build's RUN steps (the Dockerfile's locked NuGet restore). Hosted CI uses Docker's default. The host
 * verification (eng/verify_steps.py) selects `host` through ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK, because Docker's default
 * bridge network could not reach NuGet on the workstation's former Linux environment. Only the route of the fetches changes: the restore is locked (each package is checked
 * against the content hash of its packages.lock.json) and both base images are pinned by digest, and the network mode enters neither
 * the image nor the manifest. Refused in CI, so hosted candidates build exactly as before.
 */
export function dockerBuildNetwork(environment: NodeJS.ProcessEnv = process.env): string[] {
  const network = environment.ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK;
  if (!network) return [];
  assert(
    environment.GITHUB_ACTIONS !== "true" && environment.CI !== "true",
    "ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK is for local verification only.",
  );
  assert.equal(network, "host", "ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK accepts only host.");
  return ["--network", "host"];
}

async function buildCandidate() {
  await writeJson(path.join(root, "artifacts/evidence/licence-boundary.json"), auditLicences(root));
  const head = await run("git", ["rev-parse", "HEAD"], true);
  const dirty = (await run("git", ["status", "--porcelain"], true)).length > 0;
  if (process.env.CI === "true") assert.equal(dirty, false, "CI must build a clean checkout.");
  const revision = head + (dirty ? "-dirty" : "");
  const suffix = process.env.GITHUB_RUN_NUMBER
    ? `ci.${process.env.GITHUB_RUN_NUMBER}.${process.env.GITHUB_RUN_ATTEMPT ?? "1"}`
    : `local.${Date.now()}`;
  const version = `0.1.0-${suffix}`;
  const identity = expectedIdentity(version);
  const image = `arcforges-cloud:${suffix}`;
  await mkdir(candidateDir, { recursive: true });
  await writeJson(
    path.join(root, "artifacts/evidence/source-provenance.json"),
    auditProvenance(root),
  );
  stageImageNotices(root, revision);
  await writeJson(path.join(candidateDir, "legal-notices.json"), legalBundle(root, revision));
  const network = dockerBuildNetwork();
  if (network.length > 0)
    console.log("Local verification: the image build fetches over the host network.");
  await run("docker", [
    "build",
    ...network,
    "--platform",
    "linux/amd64",
    "--provenance=false",
    ...Object.entries(imageBuildVariables(identity)).flatMap(([key, value]) => [
      "--build-arg",
      `${key}=${value}`,
    ]),
    "--tag",
    image,
    ".",
  ]);
  const imageInfo = await inspectImage(image);
  assert.equal(imageInfo.Os, "linux");
  assert.equal(imageInfo.Architecture, "amd64");
  assert.ok(imageInfo.Config.User && !["0", "root"].includes(imageInfo.Config.User));
  assert.deepEqual(imageInfo.Config.Entrypoint, ["/app/ArcForges.Cloud"]);
  assert.equal(imageInfo.Config.Labels["org.opencontainers.image.revision"], revision);
  const imageId = imageInfo.Id;
  // Inspect legal contents through a stopped container; never execute the application in CI.
  const provenance = await verifyStoredImage(image, imageId, revision);
  await writeJson(path.join(candidateDir, "image-provenance.json"), provenance);
  await writeJson(path.join(candidateDir, "build-identity.json"), identity);
  await run(process.execPath, [
    wrangler,
    "deploy",
    "--dry-run",
    "--containers-rollout",
    "none",
    "--outdir",
    "artifacts/worker-bundle",
    "--metafile",
    "artifacts/worker-bundle/bundle-meta.json",
  ]);
  await copyFile(
    path.join(root, "artifacts/worker-bundle/bundle-meta.json"),
    path.join(candidateDir, "worker-meta.json"),
  );
  await copyFile(
    path.join(root, "artifacts/worker-bundle/index.js"),
    path.join(candidateDir, "worker.js"),
  );
  // CLOUD.84 D1: the proof bundle is built from its own entry (worker/proof/entry.ts) and sealed with the candidate. The dry-run needs
  // the proof asset directory to exist; its contents are uploaded only at deploy time and are not part of this bundle.
  await mkdir(path.join(root, "artifacts", "proof-assets"), { recursive: true });
  await run(process.execPath, [
    wrangler,
    "deploy",
    "--dry-run",
    "--env",
    "proof",
    "--containers-rollout",
    "none",
    "--outdir",
    "artifacts/worker-bundle-proof",
    "--metafile",
    "artifacts/worker-bundle-proof/bundle-meta.json",
  ]);
  await copyFile(
    path.join(root, "artifacts/worker-bundle-proof/bundle-meta.json"),
    path.join(candidateDir, "proof-worker-meta.json"),
  );
  await copyFile(
    path.join(root, "artifacts/worker-bundle-proof/entry.js"),
    path.join(candidateDir, "proof-worker.js"),
  );
  const config = await readJson<WorkerConfig>(path.join(root, "wrangler.json"));
  delete config.$schema;
  config.main = "./worker.js";
  config.no_bundle = true;
  config.vars.SOURCE_REVISION = revision;
  config.vars.BUILD_IDENTITY = JSON.stringify(identity.build);
  config.containers[0].image = image;
  await writeJson(path.join(candidateDir, "wrangler.json"), config);
  await run("docker", ["save", "--output", "artifacts/candidate/docker-image.tar", image]);
  // CLOUD.84 S33(3)(b), S38(2), S41(1): the tool (its Hello `probe` and its D1 `migrate` command) is published once, self-contained for
  // linux-x64 and NOT single-file. A single-file publish turns on the single-file analyzer, whose implicit Microsoft.NET.ILLink.Tasks
  // reference is not in the reviewed tool lock, so the locked CI restore refuses it (NU1004). The publish output is archived in a fixed
  // order with fixed metadata as one sealed member; the probe runner and the deploy jobs check its SHA-256 against this manifest before they
  // extract and run it, so no .NET build runs in a deploy job. The reviewed tool lock must come out of the publish byte-identical: it is
  // never rewritten or restored here, and a changed lock fails the candidate.
  const toolLockFile = path.join(root, "tools", "ArcForges.Cloud.Generation", "packages.lock.json");
  const reviewedToolLock = await readFile(toolLockFile);
  const toolOutput = path.join(root, "artifacts", "tool-publish");
  await rm(toolOutput, { recursive: true, force: true });
  await run("dotnet", toolPublishArguments(toolOutput));
  assert.ok(
    reviewedToolLock.equals(await readFile(toolLockFile)),
    "The tool publish changed the reviewed tools/ArcForges.Cloud.Generation/packages.lock.json.",
  );
  await run("tar", [
    "--sort=name",
    "--mtime=@0",
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "-cf",
    path.join(candidateDir, sealedToolName),
    "-C",
    toolOutput,
    ".",
  ]);
  const files: Record<string, string> = {};
  for (const file of payloadFiles) files[file] = await sha256(path.join(candidateDir, file));
  await writeJson(path.join(candidateDir, "manifest.json"), {
    schema: 1,
    revision,
    dirty,
    version,
    image,
    imageId,
    files,
  });
  await verifyCandidate();
  console.log(`Verified candidate ${version}: ${imageId}`);
}

export async function verifyToolchain(nodeVersion: string, npmVersion: string) {
  const expectedNode = (await readFile(path.join(root, ".node-version"), "utf8")).trim();
  const manifest = await readJson<{ packageManager: string }>(path.join(root, "package.json"));
  assert.equal(nodeVersion, `v${expectedNode}`, "Select the pinned Node version.");
  assert.equal(`npm@${npmVersion}`, manifest.packageManager, "Select the pinned npm version.");
}

/** The NuGet global packages folder that restore populates (NUGET_PACKAGES overrides the default per-user location). */
function nugetPackagesRoot(): string {
  return process.env.NUGET_PACKAGES || path.join(os.homedir(), ".nuget", "packages");
}

/**
 * WP-05.02: the forbidden-term scan is the canonical scanner and policy of the NuGet package ArcForges.Contracts.Validation named by
 * eng/policy/naming-candidate.json (P2-021 item 4; the npm @arcforges/proto publication is provenance only). The restored package
 * folder must match the pinned archive SHA512, the packaged source commit and both packaged SHA256 values before the scanner runs,
 * and the scanner's report is the source-policy evidence the architecture host binds to the source commit (RP-01, RP-08).
 */
export async function namingScan() {
  const naming = await readJson<{
    package: string;
    version: string;
    sourceCommit: string;
    archiveSha512: string;
    assets: Record<string, string>;
  }>(path.join(root, "eng/policy/naming-candidate.json"));
  const id = naming.package.toLowerCase();
  const namingRoot = path.join(nugetPackagesRoot(), id, naming.version);
  const archive = path.join(namingRoot, `${id}.${naming.version}.nupkg`);
  assert.equal(
    (await readFile(`${archive}.sha512`, "utf8")).trim(),
    naming.archiveSha512,
    "Naming package archive digest differs from the pinned candidate.",
  );
  assert.equal(
    createHash("sha512")
      .update(await readFile(archive))
      .digest("base64"),
    naming.archiveSha512,
    "Naming package archive bytes differ from the pinned candidate.",
  );
  assert.equal(
    (await readJson<{ commit: string }>(path.join(namingRoot, "source.json"))).commit,
    naming.sourceCommit,
  );
  for (const [asset, expected] of Object.entries(naming.assets))
    assert.equal(
      await sha256(path.join(namingRoot, asset)),
      expected,
      `Naming asset changed: ${asset}`,
    );
  await run("python", [
    "-I",
    path.join(namingRoot, "tools/naming/eng/check_naming.py"),
    "--repository",
    `Cloud=${root}`,
    "--report",
    path.join(root, "artifacts/evidence/naming.json"),
  ]);
}

async function main() {
  if (process.argv[2] === "naming") {
    await namingScan();
    return;
  }
  if (process.argv[2] === "toolchain") {
    assert(process.env.npm_execpath, "Run this check through npm run check.");
    await verifyToolchain(
      process.version,
      await run(process.execPath, [process.env.npm_execpath, "--version"], true),
    );
    console.log("Pinned Node/npm toolchain verified.");
    return;
  }
  if (process.argv[2] === "provenance" || process.argv[2] === "provenance-notice") {
    await writeJson(
      path.join(root, "artifacts/evidence/source-provenance.json"),
      auditProvenance(root, { writeNotice: process.argv[2] === "provenance-notice" }),
    );
    return;
  }
  if (process.argv[2] === "licence") {
    await writeJson(
      path.join(root, "artifacts/evidence/licence-boundary.json"),
      auditLicences(root),
    );
    return;
  }
  if (process.argv[2] === "licence-evaluated") {
    await writeJson(
      path.join(root, "artifacts/evidence/licence-evaluated.json"),
      evaluatedManagedLicences(root),
    );
    return;
  }
  switch (process.argv[2]) {
    case "prepare-provenance-test":
      // Generate real inputs outside node:test's child-process context.
      await run(process.execPath, [
        wrangler,
        "deploy",
        "--dry-run",
        "--containers-rollout",
        "none",
        "--outdir",
        "artifacts/provenance-test-worker",
        "--metafile",
        "artifacts/provenance-test-worker/meta.json",
      ]);
      break;
    case "dev": {
      const head = await run("git", ["rev-parse", "HEAD"], true);
      const dirty = (await run("git", ["status", "--porcelain"], true)).length > 0;
      stageImageNotices(root, head + (dirty ? "-dirty" : ""));
      const config = await readJson<WorkerConfig>(path.join(root, "wrangler.json"));
      config.main = path.join(root, "worker/index.ts");
      config.containers[0].image = path.join(root, "Dockerfile");
      config.containers[0].image_build_context = root;
      const identity = expectedIdentity(`0.1.0-local.${Date.now()}`);
      config.containers[0].image_vars = imageBuildVariables(identity);
      config.vars.SOURCE_REVISION = head + (dirty ? "-dirty" : "");
      config.vars.BUILD_IDENTITY = JSON.stringify(identity.build);
      await writeJson(path.join(root, "artifacts/dev.wrangler.json"), config);
      await run(process.execPath, [wrangler, "dev", "--config", "artifacts/dev.wrangler.json"]);
      break;
    }
    case "candidate":
      await buildCandidate();
      break;
    case "verify":
      await verifyCandidate();
      break;
    case "worker":
      await testWorker(await verifyCandidate());
      break;
    case "container": {
      const candidate = await verifyCandidate();
      await testContainer(candidate.image, candidate.revision, expectedIdentity(candidate.version));
      break;
    }
    default:
      throw new Error("Use candidate, verify, worker or container.");
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
