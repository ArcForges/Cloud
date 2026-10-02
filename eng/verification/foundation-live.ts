// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in run of the foundation scenarios against the DEPLOYED proof environment.
// Holding the resource lease RES-cloud-deployment for the duration of this run is the operator's
// obligation (python tools/delivery.py claim RES-cloud-deployment --worker W --task PRF.07, released
// immediately afterwards). Never CI. The evidence file records results, never a secret.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { manifestHash } from "../../worker/storage/plans.generated.ts";
import { runAll } from "./foundation-scenarios.ts";

export async function main() {
  assert.notEqual(process.env.CI, "true", "Live service runs are local opt-in only.");
  const baseUrl = process.env.PROOF_BASE_URL ?? "";
  assert.match(
    baseUrl,
    /^https:\/\/[a-z0-9.-]+$/u,
    "Set PROOF_BASE_URL to the proof Worker origin (https, no path).",
  );
  const operatorToken = process.env.PROOF_OPERATOR_TOKEN ?? "";
  assert(operatorToken.length >= 32, "Set PROOF_OPERATOR_TOKEN.");
  const origin = process.env.PROOF_ALLOWED_ORIGIN ?? "https://account.proof.arcforges.test";

  const startedAt = new Date().toISOString();
  const evidence = await runAll({ baseUrl, operatorToken, origin }, manifestHash, {
    stopContainer: true,
  });
  const file = path.resolve(import.meta.dirname, "../../artifacts/foundation-live-evidence.json");
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(
    file,
    `${JSON.stringify({ startedAt, finishedAt: new Date().toISOString(), host: new URL(baseUrl).host, manifestHash, evidence }, null, 2)}\n`,
  );
  console.log(`Foundation scenarios passed: ${evidence.map((item) => item.scenario).join(", ")}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await main();
