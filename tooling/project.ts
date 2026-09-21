// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { copyFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { candidateDir, readJson, root, run, sha256, wrangler, writeJson } from "./process.ts";
import { verifyProtocol, waitForHealth } from "./protocol.ts";
import { verifyKotlin } from "./kotlin.ts";
import { auditLicences, evaluatedManagedLicences } from "./licence-boundary.ts";
import { auditProvenance } from "./provenance.ts";
import {
  legalBundle,
  stageImageNotices,
  verifyImageProvenance,
  verifyReleaseFiles,
} from "./release-provenance.ts";

const payloadFiles = [
  "docker-image.tar",
  "worker.js",
  "wrangler.json",
  "legal-notices.json",
  "worker-meta.json",
  "image-provenance.json",
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
  vars: { SOURCE_REVISION: string };
  containers: [{ image: string; class_name: string; max_instances: number }];
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
  return candidate;
}

export async function testContainer(image: string, revision: string) {
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
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--memory",
      "256m",
      "--cpus",
      "1",
      "--publish",
      "127.0.0.1::8080",
      "--publish",
      "127.0.0.1::8081",
      image,
    ],
    true,
  );
  try {
    const provenance = await verifyImageProvenance(id, revision, imageInfo.Id);
    await writeJson(path.join(candidateDir, "image-provenance.json"), provenance);
    const binding = async (port: string) => {
      const output = await run("docker", ["port", id, port], true);
      const match = /^127\.0\.0\.1:(\d+)$/.exec(output);
      assert.ok(match, `Unexpected Docker port: ${output}`);
      return `http://127.0.0.1:${match[1]}`;
    };
    const web = await binding("8080/tcp");
    const native = await binding("8081/tcp");
    const health = await waitForHealth(web, revision, false, 60000);
    const grpcWeb = await verifyProtocol(web, false);
    const kotlin = await verifyKotlin(web, revision, false, "container");
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
    const restartedWeb = await binding("8080/tcp");
    await waitForHealth(restartedWeb, revision, false, 60000);
    await verifyProtocol(restartedWeb, false);
    const kotlinRestart = await verifyKotlin(restartedWeb, revision, false, "restart");
    await writeJson(path.join(root, "artifacts", "container-evidence.json"), {
      imageId: imageInfo.Id,
      health,
      grpcWeb,
      kotlin,
      kotlinRestart,
      nativeGrpc: true,
      restart: true,
      nonRoot: true,
    });
  } finally {
    await run("docker", ["logs", "--tail", "50", id]);
    await run("docker", ["rm", "--force", id]);
  }
  return imageInfo.Id;
}

async function testWorker(candidate: Candidate) {
  assert.equal(
    process.platform,
    "linux",
    "The real local Containers runtime requires Linux (WSL is supported).",
  );
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
    await waitForHealth("http://127.0.0.1:18787/api", candidate.revision, true, 180000);
    const result = await verifyProtocol("http://127.0.0.1:18787/api", true);
    const kotlin = await verifyKotlin(
      "http://127.0.0.1:18787/api",
      candidate.revision,
      true,
      "worker",
    );
    await writeJson(path.join(root, "artifacts", "worker-evidence.json"), {
      workerName,
      revision: candidate.revision,
      ...result,
      kotlin,
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
  const image = `arcforges-cloud:${suffix}`;
  await mkdir(candidateDir, { recursive: true });
  await writeJson(
    path.join(root, "artifacts/evidence/source-provenance.json"),
    auditProvenance(root),
  );
  stageImageNotices(root, revision);
  await writeJson(path.join(candidateDir, "legal-notices.json"), legalBundle(root, revision));
  await run("docker", [
    "build",
    "--platform",
    "linux/amd64",
    "--provenance=false",
    "--build-arg",
    `SOURCE_REVISION=${revision}`,
    "--tag",
    image,
    ".",
  ]);
  const imageId = await testContainer(image, revision);
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
  const config = await readJson<WorkerConfig>(path.join(root, "wrangler.json"));
  delete config.$schema;
  config.main = "./worker.js";
  config.no_bundle = true;
  config.vars.SOURCE_REVISION = revision;
  config.containers[0].image = image;
  await writeJson(path.join(candidateDir, "wrangler.json"), config);
  await run("docker", ["save", "--output", "artifacts/candidate/docker-image.tar", image]);
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

async function main() {
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
      await run(process.execPath, [wrangler, "dev"]);
      break;
    }
    case "hooks":
      // Worktree-specific settings keep the primary checkout and other tasks untouched.
      await run("git", ["config", "extensions.worktreeConfig", "true"]);
      await run("git", ["config", "--worktree", "core.hooksPath", ".githooks"]);
      break;
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
      await testContainer(candidate.image, candidate.revision);
      break;
    }
    default:
      throw new Error("Use hooks, candidate, verify, worker or container.");
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
