// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { Identity } from "./build-identity.ts";
import { candidateDir, root, run } from "./process.ts";

// The Hello protocol probe is the NuGet Contracts generated client, built and run from tools/ArcForges.Cloud.Generation (CLOUD.84
// S33(3)(b)). The candidate job publishes it self-contained for linux-x64 and seals it in the candidate manifest.
export const probeProject = path.join(
  root,
  "tools",
  "ArcForges.Cloud.Generation",
  "ArcForges.Cloud.Generation.csproj",
);
export const sealedProbeName = "arcforges-probe";

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

/**
 * Runs the Hello protocol assertions against a base URL. CI spawns the sealed binary from the candidate, and local runs build and
 * run the same project with dotnet run. The probe prints one JSON line on success and exits non-zero on any failed assertion.
 */
export function probeInvocation(
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
): { command: string; args: string[] } {
  // A GitHub Actions job runs only the sealed candidate probe (CLOUD.84 S45(3)): a missing binary fails, and nothing is built from source.
  if (env.CI === "true" || env.GITHUB_ACTIONS === "true")
    return { command: path.join(candidateDir, sealedProbeName), args: [...args] };
  return {
    command: "dotnet",
    args: ["run", "--project", probeProject, "-c", "Release", "--", ...args],
  };
}

export async function runProbe(baseUrl: string, worker: boolean): Promise<ProbeResult> {
  const invocation = probeInvocation(["probe", baseUrl, String(worker)]);
  const output = await run(invocation.command, invocation.args, true);
  const line = output.split(/\r?\n/u).filter(Boolean).at(-1) ?? "";
  const result = JSON.parse(line) as ProbeResult;
  assert.equal(result.workerBoundary, worker, "The probe reports a different Worker boundary");
  return result;
}
