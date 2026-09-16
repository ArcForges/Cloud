// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { copyFile, mkdir, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { candidateDir, readJson, root, run, sha256, wrangler, writeJson } from "./process.ts";
import { verifyProtocol, waitForHealth } from "./protocol.ts";

const payloadFiles = ["docker-image.tar", "worker.js", "wrangler.json"] as const;
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
    await writeJson(path.join(root, "artifacts", "container-evidence.json"), {
      imageId: imageInfo.Id,
      health,
      grpcWeb,
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
      path.join(testDir, "state"),
    ],
    { cwd: root, stdio: "inherit", env: { ...process.env, WRANGLER_SEND_METRICS: "false" } },
  );
  try {
    await waitForHealth("http://127.0.0.1:18787/api", candidate.revision, true, 180000);
    const result = await verifyProtocol("http://127.0.0.1:18787/api", true);
    await writeJson(path.join(root, "artifacts", "worker-evidence.json"), {
      revision: candidate.revision,
      ...result,
    });
  } finally {
    child.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null) resolve();
      else {
        child.once("exit", () => resolve());
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
        }, 10000);
        timer.unref();
      }
    });
  }
}

async function buildCandidate() {
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
  await run("docker", [
    "build",
    "--platform",
    "linux/amd64",
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
  ]);
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

async function main() {
  switch (process.argv[2]) {
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
