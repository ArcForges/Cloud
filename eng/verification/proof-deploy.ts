// SPDX-License-Identifier: AGPL-3.0-only
// Pure helpers of the proof-environment deployment: the isolated Wrangler configuration and the
// deployment secrets. The deployment itself runs only in the manually dispatched CI job
// (eng/verification/proof-cloudflare.ts); secrets are generated there at deploy time, handed to
// Wrangler through a runner-local file and never printed, committed or sent anywhere else.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

export const proofWorkerName = "arcforges-cloud-proof";
export const proofDatabaseName = "arcforges-proof-business";
export const proofBucketName = "arcforges-proof-objects";
export const proofQueueNames = ["arcforges-proof-wake", "arcforges-proof-wake-dlq"] as const;
export const proofHostname = "proof.arcforges.com";

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
    /** Relative to the directory of the generated configuration file. */
    migrationsDir?: string;
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
  // workers.dev and preview URLs stay disabled, and the only ingress is the dedicated custom domain;
  // the production route arcforges.com/api/* belongs to the production Worker alone.
  assert.equal(candidate.env.proof.workers_dev, false, "workers.dev must stay disabled.");
  assert.equal(candidate.env.proof.preview_urls, false, "Preview URLs must stay disabled.");
  assert.deepEqual(candidate.env.proof.routes, [{ pattern: proofHostname, custom_domain: true }]);
  const config = structuredClone(candidate);
  config.main = options.main;
  (config as Record<string, unknown>).account_id = options.account;
  const proof = config.env.proof;
  assert.equal(proof.containers.length, 1);
  (proof.containers[0] as { image: string }).image = options.imageDigest;
  // Wrangler validates the top-level container image of the file even for `--env proof`; the
  // production definition is never deployed from this file, so it carries the same registry digest
  // instead of a Dockerfile path.
  const top = (config as Record<string, unknown>).containers as { image: string }[] | undefined;
  if (top?.[0]) top[0].image = options.imageDigest;
  proof.vars = { ...proof.vars, SOURCE_REVISION: options.revision };
  if (options.databaseId !== undefined) {
    assert.match(
      options.databaseId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
    );
    (proof.d1_databases[0] as { database_id?: string }).database_id = options.databaseId;
  }
  if (options.migrationsDir !== undefined)
    (proof.d1_databases[0] as { migrations_dir?: string }).migrations_dir = options.migrationsDir;
  return config;
}

const base64Url = /^[A-Za-z0-9_-]{43}$/u;
/** Deployment secrets by Worker name; the pattern is the shape every consumer expects. */
export const secretSources = [
  { worker: "HMAC_C2W_SECRET", pattern: base64Url },
  { worker: "HMAC_W2C_SECRET", pattern: base64Url },
  { worker: "CSRF_SECRET", pattern: base64Url },
] as const;

/**
 * Fresh random proof secrets (256 bits each, unpadded base64url). The operator credential is not a
 * secret: the Worker trusts an operator public key (see proof-operator.ts), so no operator token exists.
 */
export function generateSecrets(
  random: (bytes: number) => Uint8Array = randomBytes,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const source of secretSources) {
    const value = Buffer.from(random(32)).toString("base64url");
    // Messages name the secret and never echo a value.
    assert(source.pattern.test(value), `${source.worker} was not generated in the required shape.`);
    result[source.worker] = value;
  }
  assert.equal(
    new Set(Object.values(result)).size,
    secretSources.length,
    "Proof secrets must be distinct.",
  );
  return result;
}
