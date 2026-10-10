// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { Identity } from "./build-identity.ts";
import { root, run } from "./process.ts";
import { extractSealedTool } from "./sealed-tool.ts";

// The Hello protocol probe is the NuGet Contracts generated client, built and run from tools/ArcForges.Cloud.Generation (CLOUD.84
// S33(3)(b)). The candidate job publishes that tool self-contained for linux-x64, not single-file (S38(2)), and seals it as one archive in
// the candidate manifest (tooling/sealed-tool.ts); the probe is its `probe` command.
export const probeProject = path.join(
  root,
  "tools",
  "ArcForges.Cloud.Generation",
  "ArcForges.Cloud.Generation.csproj",
);
export interface ProbeResult {
  transport: "binary gRPC-Web";
  publishedClient: string;
  greeting: true;
  unicode: true;
  invalidArgument: true;
  resourceExhausted: true;
  workerBoundary: boolean;
}

export async function waitForHealth(
  baseUrl: string,
  revision: string,
  worker: boolean,
  timeoutMs: number,
  expectedWorkerBuild?: Identity["build"],
) {
  const deadline = Date.now() + timeoutMs;
  let last = "no response";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/healthz`, {
        signal: AbortSignal.timeout(20000),
        redirect: "error",
        cache: "no-store",
      });
      last = `HTTP ${response.status}`;
      if (response.ok) {
        const health = (await response.json()) as {
          service: string;
          revision: string;
          nativeAot: boolean;
          workerBuild?: unknown;
        };
        last = JSON.stringify(health);
        if (
          health.service === "arcforges-cloud" &&
          health.revision === revision &&
          health.nativeAot === true &&
          (!worker || response.headers.get("x-arcforges-worker-revision") === revision)
        ) {
          if (expectedWorkerBuild) {
            health.workerBuild = JSON.parse(
              response.headers.get("x-arcforges-worker-build") ?? "null",
            ) as unknown;
            assert.deepEqual(
              health.workerBuild,
              expectedWorkerBuild,
              "Worker build identity differs",
            );
          }
          return health;
        }
      }
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    console.log(`Waiting for the Native AOT container revision ${revision}: ${last}`);
    await delay(5000);
  }
  throw new Error(`Container readiness did not converge within ${timeoutMs / 1000}s: ${last}`);
}

export interface ProbeInvocation {
  command: string;
  args: string[];
  /** The extracted sealed tool, removed after the run; absent for a local dotnet run. */
  directory?: string;
}

/**
 * Runs the Hello protocol assertions against a base URL. CI runs only the sealed tool of the candidate: its digest is checked against the
 * candidate manifest before it is extracted and run, and a missing manifest, a missing archive or a different digest refuses (CLOUD.84
 * S45(3)); nothing is built from source. Local runs build and run the same project with dotnet run. The probe prints one JSON line on
 * success and exits non-zero on any failed assertion.
 */
export function probeInvocation(
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  repositoryRoot: string = root,
): ProbeInvocation {
  if (env.CI === "true" || env.GITHUB_ACTIONS === "true") {
    const sealed = extractSealedTool(repositoryRoot);
    return { command: sealed.executable, args: [...args], directory: sealed.directory };
  }
  return {
    command: "dotnet",
    args: ["run", "--project", probeProject, "-c", "Release", "--", ...args],
  };
}

export async function runProbe(baseUrl: string, worker: boolean): Promise<ProbeResult> {
  const invocation = probeInvocation(["probe", baseUrl, String(worker)]);
  let output: string;
  try {
    output = await run(invocation.command, invocation.args, true);
  } finally {
    if (invocation.directory) await rm(invocation.directory, { recursive: true, force: true });
  }
  const line = output.split(/\r?\n/u).filter(Boolean).at(-1) ?? "";
  const result = JSON.parse(line) as ProbeResult;
  assert.equal(result.workerBoundary, worker, "The probe reports a different Worker boundary");
  return result;
}
