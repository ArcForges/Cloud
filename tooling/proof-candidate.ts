// SPDX-License-Identifier: AGPL-3.0-only
// The protected proof promotion runs each child with only its required credentials and never trusts raw child output.
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  proofProcessEnvironment,
  runSensitive,
  SensitiveProcessError,
} from "./sensitive-process.ts";
import { wrangler } from "./process.ts";

export interface ProofCandidate {
  revision: string;
  dirty: false;
  version: string;
  image: string;
  imageId: string;
}

type SensitiveRunner = typeof runSensitive;
const commitPattern = /^[0-9a-f]{40}$/u;
const imageIdPattern = /^sha256:[0-9a-f]{64}$/u;
const candidateImagePattern = /^arcforges-cloud:[a-z0-9.-]+$/u;
const versionPattern = /^0\.1\.0-(ci\.[0-9]+\.[0-9]+|local\.[0-9]+)$/u;

function verifiedCandidate(value: unknown): ProofCandidate {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("The sealed proof candidate metadata is invalid.");
  const c = value as Record<string, unknown>;
  if (
    typeof c.revision !== "string" ||
    !commitPattern.test(c.revision) ||
    c.dirty !== false ||
    typeof c.image !== "string" ||
    !candidateImagePattern.test(c.image) ||
    typeof c.imageId !== "string" ||
    !imageIdPattern.test(c.imageId) ||
    typeof c.version !== "string" ||
    !versionPattern.test(c.version)
  )
    throw new Error("The sealed proof candidate metadata is invalid.");
  return {
    revision: c.revision,
    dirty: false,
    image: c.image,
    imageId: c.imageId,
    version: c.version,
  };
}

/** Only non-secret context needed by the real verifier to reproduce the gated main-push identity. */
function proofCandidateEnvironment(environment: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const runFields = [
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_RUN_ATTEMPT",
    "ARCFORGES_CANDIDATE_RUN_ID",
    "ARCFORGES_CANDIDATE_RUN_NUMBER",
    "ARCFORGES_CANDIDATE_RUN_ATTEMPT",
  ] as const;
  const child = proofProcessEnvironment(environment, [
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "GITHUB_SHA",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    ...runFields,
  ]);
  if (
    child.GITHUB_ACTIONS !== "true" ||
    child.GITHUB_REPOSITORY !== "ArcForges/Cloud" ||
    child.GITHUB_EVENT_NAME !== "workflow_dispatch" ||
    !child.GITHUB_EVENT_PATH?.trim() ||
    !commitPattern.test(child.GITHUB_SHA ?? "") ||
    runFields.some((field) => !/^[1-9][0-9]{0,15}$/u.test(child[field] ?? ""))
  )
    throw new Error("The proof candidate CI producer context is invalid.");
  return child;
}

/** Verifies the candidate and current main, requires the gate, loads/compares its image, then pushes and validates one digest. */
export async function prepareProofCandidate(
  account: string,
  gate: (revision: string) => Promise<void>,
  options: { environment?: NodeJS.ProcessEnv; run?: SensitiveRunner } = {},
): Promise<{ candidate: ProofCandidate; imageDigest: string }> {
  const env = options.environment ?? process.env;
  const runner = options.run ?? runSensitive;
  const safeRun: SensitiveRunner = async (...parameters) => {
    try {
      return await runner(...parameters);
    } catch {
      throw new SensitiveProcessError(parameters[0], null);
    }
  };
  if (!/^[0-9a-f]{32}$/u.test(account) || !env.GH_TOKEN || !env.CLOUDFLARE_API_TOKEN)
    throw new Error("The protected proof deployment credentials or account are unavailable.");
  const verifyEnv = proofCandidateEnvironment(env);
  const candidate = verifiedCandidate(
    await safeRun(
      "candidate",
      process.execPath,
      [fileURLToPath(import.meta.url), "verify"],
      verifyEnv,
      "json",
    ),
  );
  if (candidate.revision !== verifyEnv.GITHUB_SHA)
    throw new Error("The sealed proof candidate revision does not match the dispatch.");
  const head = await safeRun(
    "head",
    "gh",
    ["api", "repos/ArcForges/Cloud/git/ref/heads/main", "--jq", '{"sha": .object.sha}'],
    proofProcessEnvironment(env, ["GH_TOKEN"]),
    "json",
  );
  if (
    typeof head !== "object" ||
    head === null ||
    Array.isArray(head) ||
    typeof (head as { sha?: unknown }).sha !== "string" ||
    !commitPattern.test((head as { sha: string }).sha) ||
    (head as { sha: string }).sha !== candidate.revision
  )
    throw new Error("The sealed proof candidate is not the current Cloud main revision.");
  try {
    await gate(candidate.revision);
  } catch {
    throw new Error("The acceptance PostgreSQL gate could not be verified.");
  }
  const dockerEnv = proofProcessEnvironment(env);
  await safeRun(
    "image",
    "docker",
    ["load", "--input", "artifacts/candidate/docker-image.tar"],
    dockerEnv,
    "discard",
  );
  const imageId = await safeRun(
    "image",
    "docker",
    ["image", "inspect", candidate.image, "--format", "{{json .Id}}"],
    dockerEnv,
    "json",
  );
  if (typeof imageId !== "string" || !imageIdPattern.test(imageId) || imageId !== candidate.imageId)
    throw new Error("The loaded proof image does not match the sealed candidate.");
  await safeRun(
    "push",
    process.execPath,
    [wrangler, "containers", "push", candidate.image],
    proofProcessEnvironment(env, ["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"]),
    "discard",
  );
  const registryTag = `registry.cloudflare.com/${account}/${candidate.image}`;
  const digests = await safeRun(
    "image",
    "docker",
    ["image", "inspect", registryTag, "--format", "{{json .RepoDigests}}"],
    dockerEnv,
    "json",
  );
  if (!Array.isArray(digests))
    throw new Error("The pushed proof image digest could not be verified.");
  const digestPattern = new RegExp(
    `^registry\\.cloudflare\\.com/${account}/arcforges-cloud@sha256:[0-9a-f]{64}$`,
    "u",
  );
  const matching = [
    ...new Set(
      digests.filter(
        (value): value is string => typeof value === "string" && digestPattern.test(value),
      ),
    ),
  ];
  if (matching.length !== 1)
    throw new Error("The pushed proof image digest could not be verified.");
  return { candidate, imageDigest: matching[0] as string };
}

// Run the existing complete candidate/provenance verification in a child that has no provider or database credentials.
// Its nested git children inherit the same minimal environment; all output and failures are bounded by the caller.
async function verifyInChild(): Promise<void> {
  try {
    const { verifyCandidate } = await import("./project.ts");
    const c = await verifyCandidate();
    process.stdout.write(
      JSON.stringify({
        revision: c.revision,
        dirty: c.dirty,
        image: c.image,
        imageId: c.imageId,
        version: c.version,
      }),
    );
  } catch {
    process.stderr.write("The sealed proof candidate could not be verified.\n");
    process.exitCode = 1;
  }
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) &&
  process.argv[2] === "verify"
)
  await verifyInChild();
