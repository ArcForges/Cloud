// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { Identity } from "./build-identity.ts";
import { root, run } from "./process.ts";

// The independent development consumer exercises the published NuGet Hello client against a local Go Center or Worker.
export const probeProject = path.join(
  root,
  "tests",
  "ArcForges.Cloud.Consumer",
  "ArcForges.Cloud.Consumer.csproj",
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
  expectedRuntime: "csharp" | "go" = "csharp",
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
          runtime?: string;
          helloBackend?: string;
          workerBuild?: unknown;
        };
        last = JSON.stringify(health);
        if (
          health.service === "arcforges-cloud" &&
          health.revision === revision &&
          (expectedRuntime === "go"
            ? health.runtime === "go" && health.nativeAot === false
            : health.nativeAot === true) &&
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
    console.log(`Waiting for the container revision ${revision}: ${last}`);
    await delay(5000);
  }
  throw new Error(`Container readiness did not converge within ${timeoutMs / 1000}s: ${last}`);
}

export interface ProbeInvocation {
  command: string;
  args: string[];
}

/**
 * Builds and runs the independent Hello consumer for an explicit development check.
 * Candidate CI uses the Go Center checks. The development consumer reports one JSON line on success.
 */
export function probeInvocation(
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
): ProbeInvocation {
  if (env.CI === "true" || env.GITHUB_ACTIONS === "true") {
    throw new Error("The independent Hello consumer runs locally. CI uses the Go Center checks.");
  }
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
