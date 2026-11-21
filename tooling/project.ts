// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstatSync } from "node:fs";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  rmdir,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  candidateDir,
  readJson,
  root,
  run,
  sha256,
  toolArguments,
  wrangler,
  writeJson,
} from "./process.ts";
import { runProbe, waitForHealth } from "./protocol.ts";
import { centerSurfaces } from "../worker/ingress/routes.ts";
import { pageRoutes, surfaceRoutes } from "../worker/tables/center-tables.generated.ts";
import { assertNotActivatedReply } from "./generated-replies.ts";
import { goCandidateFiles } from "./proof-candidate.ts";
import { auditLicences, evaluatedManagedLicences } from "./licence-boundary.ts";
import { auditProvenance, readOwned } from "./provenance.ts";
import {
  legalBundle,
  stageImageNotices,
  verifyBridgeAsset,
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

export interface Candidate {
  schema: 2;
  runtime: "go";
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

export function assertNoD1Binding(config: unknown) {
  assert(
    config && typeof config === "object" && !Array.isArray(config),
    "Missing Worker configuration",
  );
  assert(
    !Object.hasOwn(config, "d1_databases"),
    "The current Go candidate still declares a D1 binding",
  );
}

async function inspectImage(image: string): Promise<ImageInfo> {
  const info = JSON.parse(await run("docker", ["image", "inspect", image], true)) as ImageInfo[];
  assert.equal(info.length, 1);
  assert.ok(info[0]);
  return info[0];
}

const goEntrypoint = "/app/arcforges-center";

function verifyGoImage(image: ImageInfo, revision: string) {
  assert.equal(image.Os, "linux");
  assert.equal(image.Architecture, "amd64");
  assert.ok(
    image.Config.User && !["0", "root"].includes(image.Config.User),
    "Image must run as non-root.",
  );
  assert.deepEqual(image.Config.Entrypoint, [goEntrypoint]);
  assert.equal(image.Config.Labels["org.opencontainers.image.revision"], revision);
}

export async function verifyCandidate(directory = candidateDir): Promise<Candidate> {
  assert((await lstat(directory)).isDirectory(), "Invalid candidate directory");
  const manifest = path.join(directory, "manifest.json");
  assert((await lstat(manifest)).isFile(), "Invalid candidate manifest");
  const candidate = await readJson<Candidate>(manifest);
  assert.deepEqual(Object.keys(candidate).sort(), [
    "dirty",
    "files",
    "image",
    "imageId",
    "revision",
    "runtime",
    "schema",
    "version",
  ]);
  assert.equal(candidate.schema, 2);
  assert.equal(candidate.runtime, "go");
  assert.match(candidate.revision, /^[0-9a-f]{40}(-dirty)?$/);
  assert.match(candidate.imageId, /^sha256:[0-9a-f]{64}$/);
  assert.match(candidate.image, /^arcforges-cloud:[a-z0-9.-]+$/);
  assert.match(candidate.version, /^0\.1\.0-(ci\.[0-9]+\.[0-9]+|local\.[0-9]+)$/);
  if (process.env.GITHUB_SHA) {
    assert.equal(candidate.revision, process.env.GITHUB_SHA);
    assert.equal(candidate.dirty, false);
  }
  assert.deepEqual(
    (await readdir(directory)).sort(),
    [...goCandidateFiles, "manifest.json"].sort(),
  );
  assert.deepEqual(Object.keys(candidate.files).sort(), [...goCandidateFiles].sort());
  for (const file of goCandidateFiles) {
    const member = path.join(directory, file);
    assert((await lstat(member)).isFile(), `Invalid candidate member: ${file}`);
    assert.equal(await sha256(member), candidate.files[file], `Candidate changed: ${file}`);
  }
  const config = await readJson<WorkerConfig & { env?: { proof?: unknown } }>(
    path.join(directory, "wrangler.json"),
  );
  assertNoD1Binding(config);
  assertNoD1Binding(config.env?.proof);
  assert.equal(config.name, "arcforges-cloud");
  assert.equal(config.main, "./worker.js");
  assert.equal(config.vars.SOURCE_REVISION, candidate.revision);
  assert.equal(
    config.vars.ARCFORGES_HELLO_RUNTIME,
    "go",
    "The candidate must select the Go Center.",
  );
  assert.equal(config.containers[0]?.image, candidate.image);
  assert.equal(config.containers[0]?.max_instances, 1);
  assert.equal(config.no_bundle, true);
  verifyReleaseFiles(root, directory, candidate.revision, candidate.imageId);
  verifyIdentity(await readJson(path.join(directory, "build-identity.json")), candidate.version);
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

// Local opt-in diagnostic of the sealed Go candidate image (never CI).
export async function testContainer(image: string, revision: string, identity: Identity) {
  assert.notEqual(process.env.CI, "true", "Container runtime tests are local opt-in only.");
  const imageInfo = await inspectImage(image);
  verifyGoImage(imageInfo, revision);
  const provenance = await verifyStoredImage(image, imageInfo.Id, revision);

  const binding = async (container: string, port: string) => {
    const output = await run("docker", ["port", container, port], true);
    const match = /^127\.0\.0\.1:(\d+)$/.exec(output);
    assert.ok(match, `Unexpected Docker port: ${output}`);
    return `http://127.0.0.1:${match[1]}`;
  };
  const center = await testCenterContainer(image, revision, identity, binding);
  await writeJson(path.join(root, "artifacts", "container-evidence.json"), {
    imageId: imageInfo.Id,
    nonRoot: true,
    provenance,
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
    await run("docker", ["restart", id]);
    const restartedWeb = await binding(id, "8080/tcp");
    verifyHealthIdentity(
      await waitForHealth(restartedWeb, revision, false, 60000, undefined, "go"),
      identity,
    );
    await runProbe(restartedWeb, false);
    // SIGTERM, as the Container runtime stops an instance: the center drains and exits 0.
    await run("docker", ["stop", "--time", "20", id]);
    const exitCode = await run("docker", ["inspect", "--format", "{{.State.ExitCode}}", id], true);
    assert.equal(exitCode, "0", "The center must stop cleanly on SIGTERM.");
    return {
      entrypoint: goEntrypoint,
      mode,
      publicBaseUrl,
      health,
      grpcWeb,
      nativeGrpc: true,
      restart: true,
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
  // Each reply is the surface's generated template with the call's own correlation id in its slot (E4-1), so no two replies are
  // equal; assertNotActivatedReply compares everything but the slot and checks the slot.
  const ids = new Set<string>();
  for (const route of surfaceRoutes) {
    const response = await fetch(`${base}${route.path}`, {
      method: "POST",
      headers: { "content-type": "application/grpc-web+proto" },
      body: new Uint8Array([0, 0, 0, 0, 0]),
    });
    assert.equal(response.status, 200, route.path);
    const id = assertNotActivatedReply(
      route.surface,
      new Uint8Array(await response.arrayBuffer()),
      route.path,
    );
    assert(!ids.has(id), `${route.path}: each call has its own correlation id`);
    ids.add(id);
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
    toolArguments(process.execPath, [
      wrangler,
      "dev",
      "--local",
      "--config",
      path.join(testDir, "wrangler.json"),
      "--persist-to",
      path.join(testDir, "state", workerName),
    ]),
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
      "go",
    );
    verifyHealthIdentity(health, expectedIdentity(candidate.version));
    // AF-CTR-03: the center was started with the surfaces this Worker forwards.
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

export async function stageCandidateDirectory<T>(
  artifacts: string,
  prepare: (directory: string) => Promise<T>,
): Promise<T> {
  assert(
    (await lstat(artifacts)).isDirectory() && (await realpath(artifacts)) === artifacts,
    "Linked candidate staging directory",
  );
  const destination = path.join(artifacts, "candidate");
  const staged = await mkdtemp(path.join(artifacts, "candidate-stage-"));
  let saved: string | undefined;
  try {
    const result = await prepare(staged);
    const existing = lstatSync(destination, { throwIfNoEntry: false });
    if (existing) {
      assert(existing.isDirectory(), "Candidate destination is not a regular directory");
      const archive = await mkdtemp(path.join(artifacts, "candidate-previous-"));
      const previous = path.join(archive, "candidate");
      try {
        await rename(destination, previous);
      } catch (error) {
        await rmdir(archive);
        throw error;
      }
      saved = previous;
      assert(
        (await lstat(saved)).isDirectory(),
        "Candidate destination changed during publication",
      );
    }
    await rename(staged, destination);
    return result;
  } catch (error) {
    try {
      if (saved) {
        assert(
          !lstatSync(destination, { throwIfNoEntry: false }),
          "Candidate destination changed during publication",
        );
        await rename(saved, destination);
        await rmdir(path.dirname(saved));
      }
      await rm(staged, { recursive: true, force: true });
    } catch (restoreError) {
      throw new AggregateError([error, restoreError], "Could not restore candidate staging");
    }
    throw error;
  }
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
  await writeJson(
    path.join(root, "artifacts/evidence/source-provenance.json"),
    auditProvenance(root),
  );
  stageImageNotices(root, revision);
  const network = dockerBuildNetwork();
  if (network.length > 0)
    console.log("Local verification: the image build fetches over the host network.");
  const existingTag = await run("docker", ["image", "ls", "--quiet", image], true);
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
  let imageInfo: ImageInfo | undefined;
  try {
    const builtImage = await inspectImage(image);
    imageInfo = builtImage;
    const candidate = await stageCandidateDirectory(path.dirname(candidateDir), (directory) =>
      prepareCandidate(directory, {
        revision,
        dirty,
        version,
        identity,
        image,
        imageInfo: builtImage,
      }),
    );
    console.log(`Verified candidate ${version}: ${candidate.imageId}`);
  } catch (error) {
    if (!existingTag && imageInfo) {
      try {
        assert.equal(
          (await inspectImage(image)).Id,
          imageInfo.Id,
          "Candidate image tag now names another image",
        );
        await run("docker", ["image", "rm", image]);
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          "Could not remove the failed candidate image",
        );
      }
    }
    throw error;
  }
}

async function prepareCandidate(
  directory: string,
  build: {
    revision: string;
    dirty: boolean;
    version: string;
    identity: Identity;
    image: string;
    imageInfo: ImageInfo;
  },
): Promise<Candidate> {
  const { revision, dirty, version, identity, image, imageInfo } = build;
  verifyGoImage(imageInfo, revision);
  const imageId = imageInfo.Id;
  await writeJson(path.join(directory, "legal-notices.json"), legalBundle(root, revision));
  // Inspect legal contents through a stopped container; never execute the application in CI.
  const provenance = await verifyStoredImage(image, imageId, revision);
  await writeJson(path.join(directory, "image-provenance.json"), provenance);
  await writeJson(path.join(directory, "build-identity.json"), identity);
  const bundles = path.join(directory, "bundles");
  const main = path.join(bundles, "worker");
  const proof = path.join(bundles, "proof");
  await run(process.execPath, [
    wrangler,
    "deploy",
    "--dry-run",
    "--containers-rollout",
    "none",
    "--outdir",
    main,
    "--metafile",
    path.join(main, "bundle-meta.json"),
  ]);
  await copyFile(path.join(main, "bundle-meta.json"), path.join(directory, "worker-meta.json"));
  await copyFile(path.join(main, "index.js"), path.join(directory, "worker.js"));
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
    proof,
    "--metafile",
    path.join(proof, "bundle-meta.json"),
  ]);
  await copyFile(
    path.join(proof, "bundle-meta.json"),
    path.join(directory, "proof-worker-meta.json"),
  );
  await copyFile(path.join(proof, "entry.js"), path.join(directory, "proof-worker.js"));
  await rm(bundles, { recursive: true });
  const config = await readJson<WorkerConfig>(path.join(root, "wrangler.json"));
  delete config.$schema;
  config.main = "./worker.js";
  config.no_bundle = true;
  config.vars.SOURCE_REVISION = revision;
  config.vars.BUILD_IDENTITY = JSON.stringify(identity.build);
  config.containers[0].image = image;
  await writeJson(path.join(directory, "wrangler.json"), config);
  await run("docker", ["save", "--output", path.join(directory, "docker-image.tar"), image]);
  const files: Record<string, string> = {};
  for (const file of goCandidateFiles) files[file] = await sha256(path.join(directory, file));
  await writeJson(path.join(directory, "manifest.json"), {
    schema: 2,
    runtime: "go",
    revision,
    dirty,
    version,
    image,
    imageId,
    files,
  });
  return verifyCandidate(directory);
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
    await run("python", ["eng/check_toolchain.py"]);
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
    case "verify-bridge-asset": {
      const platform = process.argv[3];
      assert(platform === "linux" || platform === "windows", "Unknown bridge platform");
      const name = `arcforges-ctr06-bridge-8e5-${platform}-amd64.zip`;
      const bytes = readOwned(root, `artifacts/ctr06-${platform}/${name}`);
      verifyBridgeAsset(root, platform, bytes);
      break;
    }
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
