// SPDX-License-Identifier: AGPL-3.0-only
// Entry point of the current local opt-in HAR.40 proofs (P2-021 item 5, brief section 4.3). Never CI: each run refuses under CI, reads no
// credential and writes its evidence record under artifacts/harness-proof. Commands:
//   node eng/verification/harness-proof.ts ai-binding        fixture-binding proof of the ai.internal adapter (node-fixture)
//   node eng/verification/harness-proof.ts container-capacity wrangler launch values, plus an optional live probe via HARNESS_CAPACITY_URL
//   node eng/verification/harness-proof.ts all               ai-binding and container-capacity
// The managed executor proof is archived at Cloud 9b8796eac760982d9814f371b820b736ddd945c4.
// Evidence templates and the live steps that remain operator runs are in docs/harness-proofs.md.
import { fileURLToPath } from "node:url";
import path from "node:path";
import { assertLocalOptIn, writeEvidence } from "./harness-proof-evidence.ts";
import { runAiBindingProof } from "./harness-proof-ai.ts";
import { runCapacityProof } from "./harness-proof-capacity.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const names = ["ai-binding", "container-capacity"] as const;
type ProofName = (typeof names)[number];

export function isProofName(value: string | undefined): value is ProofName {
  return value !== undefined && (names as readonly string[]).includes(value);
}

export async function runProof(name: ProofName) {
  switch (name) {
    case "ai-binding":
      return runAiBindingProof();
    case "container-capacity":
      return runCapacityProof();
  }
}

export async function main(argv: readonly string[]): Promise<number> {
  assertLocalOptIn();
  const requested = argv[0];
  const selected: ProofName[] =
    requested === "all" ? [...names] : isProofName(requested) ? [requested] : [];
  if (selected.length === 0) {
    console.error(`Usage: node eng/verification/harness-proof.ts <${names.join("|")}|all>`);
    return 2;
  }
  let exitCode = 0;
  for (const name of selected) {
    const record = await runProof(name);
    const file = await writeEvidence(root, record);
    console.log(
      `${name}: ${record.status} (${record.checks.length} checks, realness ${record.realness}) -> ${file}`,
    );
    if (record.status === "failed") exitCode = 1;
  }
  return exitCode;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exitCode = await main(process.argv.slice(2));
}
