// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in deployment of the sealed candidate into the isolated `proof` Wrangler
// environment. It is never run by CI and never touches the production Worker, route or database.
// It needs an interactive operator with Cloudflare account access; nothing here reads a local
// credential store, and secret values come only from named environment variables and never reach
// an argument, a file or the evidence.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const proofWorkerName = "arcforges-cloud-proof";
export const proofDatabaseName = "arcforges-proof-business";

interface ProofEnvironment {
  name?: string;
  containers: { image: string; [key: string]: unknown }[];
  vars: Record<string, string>;
  d1_databases: { database_id?: string; [key: string]: unknown }[];
  [key: string]: unknown;
}
export interface CandidateConfig {
  name: string;
  main: string;
  env: { proof: ProofEnvironment };
  [key: string]: unknown;
}

/** The standalone config to deploy with `--env proof`: only the proof environment is customized. */
export function buildProofConfig(
  candidate: CandidateConfig,
  options: {
    account: string;
    imageDigest: string;
    revision: string;
    databaseId?: string;
    main: string;
  },
): CandidateConfig {
  assert.match(
    options.account,
    /^[0-9a-f]{32}$/u,
    "Set CLOUDFLARE_ACCOUNT_ID to the 32-character account id.",
  );
  assert.match(
    options.imageDigest,
    /^[^\s@]+@sha256:[0-9a-f]{64}$/u,
    "A pinned registry image digest is required.",
  );
  assert(candidate.env?.proof, "The candidate has no proof environment.");
  assert.equal(candidate.env.proof.name, proofWorkerName);
  const config = structuredClone(candidate);
  config.main = options.main;
  (config as Record<string, unknown>).account_id = options.account;
  const proof = config.env.proof;
  assert.equal(proof.containers.length, 1);
  (proof.containers[0] as { image: string }).image = options.imageDigest;
  proof.vars = { ...proof.vars, SOURCE_REVISION: options.revision };
  if (options.databaseId !== undefined) {
    assert.match(
      options.databaseId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
    );
    (proof.d1_databases[0] as { database_id?: string }).database_id = options.databaseId;
  }
  return config;
}

const base64Url = /^[A-Za-z0-9_-]{43}$/u;
/** Deployment secrets by Worker name, read from named environment variables and format-checked. */
export const secretSources = [
  {
    variable: "PROOF_OPERATOR_TOKEN",
    worker: "PROOF_OPERATOR_TOKEN",
    pattern: /^[A-Za-z0-9._~+/=-]{32,256}$/u,
  },
  { variable: "PROOF_HMAC_C2W_SECRET", worker: "HMAC_C2W_SECRET", pattern: base64Url },
  { variable: "PROOF_HMAC_W2C_SECRET", worker: "HMAC_W2C_SECRET", pattern: base64Url },
  { variable: "PROOF_CSRF_SECRET", worker: "CSRF_SECRET", pattern: base64Url },
] as const;

export function collectSecrets(
  environment: Record<string, string | undefined>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const source of secretSources) {
    const value = environment[source.variable];
    // Messages name the variable and never echo a value.
    assert(value !== undefined, `Set ${source.variable} before deploying the proof environment.`);
    assert(source.pattern.test(value), `${source.variable} is not in the required format.`);
    result[source.worker] = value;
  }
  assert.equal(
    new Set(Object.values(result)).size,
    secretSources.length,
    "Proof secrets must be distinct.",
  );
  return result;
}

function wrangler(args: string[], input?: string): Promise<void> {
  const executable = path.resolve(
    import.meta.dirname,
    "../../node_modules/wrangler/bin/wrangler.js",
  );
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [executable, ...args], {
      stdio: [input === undefined ? "ignore" : "pipe", "inherit", "inherit"],
      env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
      windowsHide: true,
    });
    if (input !== undefined) child.stdin?.end(input);
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`wrangler ${args[0]} exited with code ${code}.`)),
    );
  });
}

async function deploy() {
  assert.notEqual(process.env.CI, "true", "The proof deployment is a local opt-in, never CI.");
  const { verifyCandidate } = await import("../../tooling/project.ts");
  const { candidateDir, readJson, root, run, writeJson } = await import("../../tooling/process.ts");
  const secrets = collectSecrets(process.env);
  const account = process.env.CLOUDFLARE_ACCOUNT_ID ?? "";
  assert.ok(process.env.CLOUDFLARE_API_TOKEN, "Set CLOUDFLARE_API_TOKEN for this local session.");
  const candidate = await verifyCandidate();
  assert.equal(candidate.dirty, false, "Uncommitted local builds cannot be deployed.");
  await run("docker", ["load", "--input", "artifacts/candidate/docker-image.tar"]);
  const loaded = await run(
    "docker",
    ["image", "inspect", candidate.image, "--format", "{{.Id}}"],
    true,
  );
  assert.equal(loaded, candidate.imageId, "The loaded image is not the sealed candidate image.");
  await wrangler(["containers", "push", candidate.image]);
  const registryTag = `registry.cloudflare.com/${account}/${candidate.image}`;
  const digests = JSON.parse(
    await run(
      "docker",
      ["image", "inspect", registryTag, "--format", "{{json .RepoDigests}}"],
      true,
    ),
  ) as string[];
  const prefix = `registry.cloudflare.com/${account}/arcforges-cloud@sha256:`;
  const imageDigest = digests.find((value) => value.startsWith(prefix));
  assert.ok(imageDigest, "The registry did not return the pushed image digest.");
  const config = buildProofConfig(
    await readJson<CandidateConfig>(path.join(candidateDir, "wrangler.json")),
    {
      account,
      imageDigest,
      revision: candidate.revision,
      databaseId: process.env.PROOF_D1_DATABASE_ID,
      main: "./candidate/worker.js",
    },
  );
  const file = path.join(root, "artifacts", "proof.wrangler.json");
  await writeJson(file, config);
  const common = ["--config", "artifacts/proof.wrangler.json", "--env", "proof"];
  // Migrations are a separate gated step, never part of Container startup.
  await wrangler(["d1", "migrations", "apply", proofDatabaseName, "--remote", ...common]);
  for (const [name, value] of Object.entries(secrets))
    await wrangler(["secret", "put", name, ...common], value);
  await wrangler([
    "deploy",
    ...common,
    "--no-bundle",
    "--containers-rollout",
    "immediate",
    "--tag",
    `${candidate.version}-proof`,
  ]);
  await writeJson(path.join(root, "artifacts", "proof-deployment.json"), {
    revision: candidate.revision,
    version: candidate.version,
    imageId: candidate.imageId,
    imageDigest,
    worker: proofWorkerName,
    deployedAt: new Date().toISOString(),
  });
  console.log(
    "Proof environment deployed. This is deployment completion, not live acceptance evidence.",
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "deploy") await deploy();
  else throw new Error("Use deploy.");
}
