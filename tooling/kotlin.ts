// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { readJson, root, run } from "./process.ts";
import { waitForHealth } from "./protocol.ts";

const project = path.join(root, "tests", "kotlin-consumer");
const java = process.env.JAVA_HOME
  ? path.join(process.env.JAVA_HOME, "bin", process.platform === "win32" ? "java.exe" : "java")
  : "java";

export async function buildKotlin() {
  // Invoke the standard wrapper JAR directly so Windows needs no interpolated cmd shell.
  await run(java, [
    "-classpath",
    path.join(project, "gradle", "wrapper", "gradle-wrapper.jar"),
    "org.gradle.wrapper.GradleWrapperMain",
    "--project-dir",
    project,
    "--no-daemon",
    "--console=plain",
    "--dependency-verification=strict",
    "check",
    "installDist",
  ]);
}

export async function verifyKotlin(
  baseUrl: string,
  revision: string,
  worker: boolean,
  label: string,
) {
  assert.match(label, /^[a-z-]+$/);
  const output = path.join(root, "artifacts", `kotlin-${label}-evidence.json`);
  await run(java, [
    "-classpath",
    path.join(project, "build", "install", "cloud-kotlin-consumer", "lib", "*"),
    "io.github.arcforges.cloud.verification.MainKt",
    baseUrl,
    revision,
    worker ? "worker" : "container",
    output,
  ]);
  const evidence = await readJson<{ client: string; revision: string }>(output);
  const packages = await readJson<{ devDependencies: Record<string, string> }>(
    path.join(root, "package.json"),
  );
  assert.equal(
    evidence.client,
    `io.github.arcforges:contracts-connect-client:${packages.devDependencies["@arcforges/api-client"]}`,
  );
  assert.equal(evidence.revision, revision);
  return evidence;
}

async function main() {
  if (process.argv[2] === "build") return buildKotlin();
  if (process.argv[2] === "live") {
    assert.notEqual(process.env.CI, "true", "Live client tests are local opt-in only.");
    const base = "https://arcforges.com/api";
    const response = await fetch(`${base}/healthz`, {
      signal: AbortSignal.timeout(20000),
      redirect: "error",
    });
    assert.equal(response.status, 200);
    const health = (await response.json()) as { revision: string };
    assert.match(health.revision, /^[0-9a-f]{40}$/);
    await waitForHealth(base, health.revision, true, 60000);
    // This command verifies the current deployment, not the unmerged working tree.
    return verifyKotlin(base, health.revision, true, "current-live");
  }
  throw new Error("Use build or live. Build once before running the consumer.");
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) await main();
