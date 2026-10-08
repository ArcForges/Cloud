// SPDX-License-Identifier: AGPL-3.0-only
// Local opt-in proof 2 of HAR.40 (P2-021 item 5, the executor): runs the offline C# crash-injection and executor suites against the real
// D1 plan oracle (the SQLite oracle with the checked-in plans). It kills the executor before and after every fenced write (claim, reserve,
// dispatch intent, outcome, yield), restarts it as a new process after the lease expires, and asserts that no effect is repeated. It is
// dotnet-local realness: no Cloudflare D1, Durable Object alarm or Container is exercised. Run it through the workstation build slot:
//   python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker <w> --task HAR.40 -- node eng/verification/harness-proof.ts executor-crash
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertLocalOptIn,
  check,
  evidence,
  type ProofCheck,
  type ProofEvidence,
  writeEvidence,
} from "./harness-proof-evidence.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const project = "tests/ArcForges.Cloud.Tests/ArcForges.Cloud.Tests.csproj";
/** The crash matrix and the executor suites; the filter is class-scoped, so no other offline test is selected. */
export const executorFilter =
  "FullyQualifiedName~ArcForges.Cloud.Tests.HarnessFoundation.HarnessCrashTests|FullyQualifiedName~ArcForges.Cloud.Tests.HarnessFoundation.HarnessExecutorTests";

export interface DotnetRun {
  readonly exitCode: number;
  readonly output: string;
}

function runDotnet(args: readonly string[]): Promise<DotnetRun> {
  return new Promise((resolve, reject) => {
    const child = spawn("dotnet", [...args], { cwd: root, windowsHide: true });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ exitCode: code ?? -1, output }));
  });
}

/** Reads the Microsoft.Testing.Platform summary ("total: N", "failed: N", "succeeded: N") from the dotnet output. */
export function parseSummary(
  output: string,
): { total: number; failed: number; succeeded: number } | null {
  const read = (label: string): number | null => {
    const match = new RegExp(`^\\s*${label}:\\s*(\\d+)\\s*$`, "mu").exec(output);
    return match?.[1] === undefined ? null : Number(match[1]);
  };
  const total = read("total");
  const failed = read("failed");
  const succeeded = read("succeeded");
  if (total === null || failed === null || succeeded === null) return null;
  return { total, failed, succeeded };
}

export function executorChecks(run: DotnetRun): ProofCheck[] {
  const summary = parseSummary(run.output);
  return [
    check(
      "dotnet-test-exit-zero",
      run.exitCode === 0,
      "dotnet test exits 0 for the crash and executor suites",
      `exit ${run.exitCode}`,
    ),
    check(
      "summary-reports-tests-and-no-failures",
      summary !== null &&
        summary.total > 0 &&
        summary.failed === 0 &&
        summary.succeeded === summary.total,
      "a parsed summary with at least one test, zero failed and every test succeeded",
      summary === null
        ? "no summary line parsed"
        : `total ${summary.total}, failed ${summary.failed}, succeeded ${summary.succeeded}`,
    ),
  ];
}

export async function runExecutorProof(now = new Date()): Promise<ProofEvidence> {
  const run = await runDotnet([
    "test",
    project,
    "-c",
    "Release",
    "--no-build",
    "--filter",
    executorFilter,
  ]);
  const checks = executorChecks(run);
  return evidence({
    proof: "executor-crash",
    realness: "dotnet-local",
    checks,
    liveNotRun: [
      "Cloudflare D1 fenced writes under a real lease (operator: run the proof environment and kill the Container between a dispatch intent and its outcome).",
      "Durable Object alarm wake after a real process restart (operator: observe the HarnessRunAlarm wake on the proof environment).",
    ],
    notes: [
      "Crash points: claim, reserve, dispatch intent, outcome and yield, each before and after its commit (HarnessCrashTests).",
      "A crashed dispatch intent without an outcome is recorded as an unknown effect and is never dispatched again.",
    ],
    environment: { filter: executorFilter, exitCode: String(run.exitCode) },
    now,
  });
}

export async function main(): Promise<void> {
  assertLocalOptIn();
  const record = await runExecutorProof();
  const file = await writeEvidence(root, record);
  console.log(`executor-crash: ${record.status} (${record.checks.length} checks) -> ${file}`);
  if (record.status !== "passed") process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await main();
}
