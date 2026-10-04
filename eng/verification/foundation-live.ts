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
import { runScenarios, type Target } from "./foundation-scenarios.ts";
import { loadOperatorKey, signOperatorRequest } from "./proof-operator.ts";

export async function main() {
  assert.notEqual(process.env.CI, "true", "Live service runs are local opt-in only.");
  const baseUrl = process.env.PROOF_BASE_URL ?? "https://proof.arcforges.com";
  assert.match(
    baseUrl,
    /^https:\/\/[a-z0-9.-]+$/u,
    "Set PROOF_BASE_URL to the proof Worker origin (https, no path).",
  );
  // The deployed proof Worker trusts an Ed25519 public key, so the default is a signature made with
  // the operator's local private key file (never printed). A bearer token is only for a target that
  // was configured with one, such as the local harness.
  const operatorToken = process.env.PROOF_OPERATOR_TOKEN ?? "";
  let auth: Pick<Target, "operatorToken" | "authorize">;
  if (operatorToken !== "") {
    assert(operatorToken.length >= 32, "PROOF_OPERATOR_TOKEN must be at least 32 characters.");
    auth = { operatorToken };
  } else {
    const key = loadOperatorKey();
    auth = {
      authorize: (method, host, pathname, body) =>
        signOperatorRequest(key, method, host, pathname, body),
    };
  }
  const origin = process.env.PROOF_ALLOWED_ORIGIN ?? baseUrl;

  const startedAt = new Date().toISOString();
  const evidence = await runScenarios(
    { baseUrl, origin, helloIngress: true, ...auth },
    manifestHash,
    {
      stopContainer: true,
    },
  );
  // The evidence is written before any failure is reported, so a failing scenario never loses the rest.
  const file = path.resolve(import.meta.dirname, "../../artifacts/foundation-live-evidence.json");
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(
    file,
    `${JSON.stringify({ startedAt, finishedAt: new Date().toISOString(), host: new URL(baseUrl).host, manifestHash, evidence }, null, 2)}
`,
  );
  for (const item of evidence)
    console.log(`${item.ok ? "PASS" : "FAIL"} ${item.scenario} ${JSON.stringify(item.detail)}`);
  const failed = evidence.filter((item) => !item.ok);
  assert.equal(
    failed.length,
    0,
    `Failed scenarios: ${failed.map((item) => item.scenario).join(", ")}`,
  );
  console.log(`Foundation scenarios passed: ${evidence.map((item) => item.scenario).join(", ")}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await main();
