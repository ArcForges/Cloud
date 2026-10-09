// SPDX-License-Identifier: AGPL-3.0-only
// Shared evidence shape of the HAR.40 local proof drivers. Every proof writes one JSON record under artifacts/harness-proof. The record
// says how real its evidence is: a fixture or a local runtime result is never presented as a Cloudflare provider result, and a live
// measurement that was not run is recorded as not-run, never as passed. The drivers are local opt-in only and refuse to run under CI.
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export type CheckStatus = "passed" | "failed" | "observed";
export type ProofStatus = "passed" | "failed" | "not-run";
/** How real the measured behaviour is. `live` requires a deployed Cloudflare resource; nothing here reads a credential. */
export type Realness = "node-fixture" | "dotnet-local" | "deployed-live" | "not-run";

export interface ProofCheck {
  readonly name: string;
  readonly status: CheckStatus;
  readonly expected: string;
  readonly observed: string;
}

export interface ProofEvidence {
  readonly schemaVersion: 1;
  readonly proof: string;
  readonly task: "HAR.40";
  readonly status: ProofStatus;
  readonly realness: Realness;
  readonly generatedAt: string;
  readonly checks: readonly ProofCheck[];
  /** Measurements that need a deployed resource and were not taken by this run, each with the operator step that takes it. */
  readonly liveNotRun: readonly string[];
  readonly notes: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
}

/** Refuses the run under CI. A proof driver is an explicit local act and never part of a hosted pipeline (P2-017). */
export function assertLocalOptIn(env: NodeJS.ProcessEnv = process.env): void {
  if (env.CI === "true" || env.GITHUB_ACTIONS === "true") {
    throw new Error("The HAR.40 proof drivers are local opt-in only and never run under CI.");
  }
}

/**
 * failed when any check failed; passed when at least one check passed and none failed; otherwise not-run. Observations alone never
 * make a proof passed: a run that only recorded configuration or measurements without a pass/fail criterion is not-run.
 */
export function summarise(checks: readonly ProofCheck[]): ProofStatus {
  if (checks.some((check) => check.status === "failed")) return "failed";
  return checks.some((check) => check.status === "passed") ? "passed" : "not-run";
}

export function evidence(input: {
  readonly proof: string;
  readonly realness: Realness;
  readonly checks: readonly ProofCheck[];
  readonly liveNotRun: readonly string[];
  readonly notes: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
  readonly now?: Date;
}): ProofEvidence {
  return {
    schemaVersion: 1,
    proof: input.proof,
    task: "HAR.40",
    status: summarise(input.checks),
    realness: input.realness,
    generatedAt: (input.now ?? new Date()).toISOString(),
    checks: [...input.checks],
    liveNotRun: [...input.liveNotRun],
    notes: [...input.notes],
    environment: { ...input.environment },
  };
}

export async function writeEvidence(root: string, record: ProofEvidence): Promise<string> {
  const directory = path.join(root, "artifacts", "harness-proof");
  await mkdir(directory, { recursive: true });
  const file = path.join(directory, `${record.proof}.json`);
  await writeFile(file, `${JSON.stringify(record, null, 2)}\n`, "utf8");
  return file;
}

export function check(
  name: string,
  passed: boolean,
  expected: string,
  observed: string,
): ProofCheck {
  return { name, status: passed ? "passed" : "failed", expected, observed };
}

export function percentile(sorted: readonly number[], fraction: number): number {
  if (sorted.length === 0) return Number.NaN;
  const index = Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1);
  return sorted[Math.max(0, index)] as number;
}
