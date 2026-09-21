// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import path from "node:path";
import { candidateDir, readJson, root, run, wrangler, writeJson } from "./process.ts";
import { verifyCandidate, type WorkerConfig } from "./project.ts";
import { verifyProtocol, waitForHealth } from "./protocol.ts";
import { verifyKotlin } from "./kotlin.ts";
import { verifyStoredImage } from "./release-provenance.ts";

import { expectedIdentity, verifyIdentity, verifyHealthIdentity } from "./build-identity.ts";

const productionBase = "https://arcforges.com/api";
const deploymentFile = path.join(root, "artifacts", "deployment.json");

interface Deployment {
  revision: string;
  version: string;
  imageId: string;
  imageDigest: string;
  baseUrl: string;
  deployedAt: string;
  verified?: unknown;
}

async function requireCurrentMain(revision: string) {
  assert.equal(process.env.GITHUB_REPOSITORY, "ArcForges/Cloud");
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(process.env.GITHUB_EVENT_NAME, "push");
  const current = await run(
    "gh",
    ["api", "repos/ArcForges/Cloud/git/ref/heads/main", "--jq", ".object.sha"],
    true,
  );
  assert.equal(
    revision,
    current,
    "A newer main commit exists. Only the current main candidate can deploy.",
  );
}

async function deploy() {
  const candidate = await verifyCandidate();
  assert.equal(candidate.dirty, false, "Uncommitted local builds cannot deploy.");
  const account = process.env.CLOUDFLARE_ACCOUNT_ID ?? "";
  assert.match(
    account,
    /^[0-9a-f]{32}$/,
    "Set CLOUDFLARE_ACCOUNT_ID in the GitHub cloudflare environment.",
  );
  assert.ok(
    process.env.CLOUDFLARE_API_TOKEN,
    "Set the CLOUDFLARE_API_TOKEN environment secret; see docs/deployment.md.",
  );
  await requireCurrentMain(candidate.revision);
  await run("docker", ["load", "--input", "artifacts/candidate/docker-image.tar"]);
  const imageId = await run(
    "docker",
    ["image", "inspect", candidate.image, "--format", "{{.Id}}"],
    true,
  );
  assert.equal(imageId, candidate.imageId, "Loaded image is not the tested image.");
  const actualImageProvenance = await verifyStoredImage(
    candidate.image,
    imageId,
    candidate.revision,
  );
  assert.deepEqual(
    actualImageProvenance,
    await readJson(path.join(candidateDir, "image-provenance.json")),
    "Promoted image provenance changed",
  );
  verifyIdentity(
    JSON.parse(
      await run(
        "docker",
        [
          "run",
          "--rm",
          "--network",
          "none",
          "--read-only",
          "--cap-drop",
          "ALL",
          candidate.image,
          "--build-info",
        ],
        true,
      ),
    ),
    candidate.version,
  );
  await run(process.execPath, [wrangler, "containers", "push", candidate.image]);
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
  assert.ok(imageDigest, "Cloudflare registry did not return the pushed image digest.");
  assert.match(imageDigest.slice(prefix.length), /^[0-9a-f]{64}$/);

  const config = await readJson<WorkerConfig>(path.join(candidateDir, "wrangler.json"));
  config.main = "./candidate/worker.js";
  config.account_id = account;
  config.containers[0].image = imageDigest;
  await writeJson(path.join(root, "artifacts", "deploy.wrangler.json"), config);
  await requireCurrentMain(candidate.revision);
  await run(process.execPath, [
    wrangler,
    "deploy",
    "--config",
    "artifacts/deploy.wrangler.json",
    "--no-bundle",
    "--containers-rollout",
    "immediate",
    "--tag",
    candidate.version,
  ]);
  await writeJson(deploymentFile, {
    revision: candidate.revision,
    version: candidate.version,
    imageId,
    imageDigest,
    baseUrl: productionBase,
    deployedAt: new Date().toISOString(),
  } satisfies Deployment);
}

async function smoke() {
  const candidate = await verifyCandidate();
  const deployment = await readJson<Deployment>(deploymentFile);
  assert.equal(deployment.revision, candidate.revision);
  assert.equal(deployment.imageId, candidate.imageId);
  assert.equal(deployment.baseUrl, productionBase);
  console.log(
    "Waiting for both Worker and Native AOT container identities; no redeploy or application replay.",
  );
  const health = await waitForHealth(
    productionBase,
    candidate.revision,
    true,
    600000,
    expectedIdentity(candidate.version).build,
  );
  verifyHealthIdentity(health, expectedIdentity(candidate.version));
  const protocol = await verifyProtocol(productionBase, true);
  const kotlin = await verifyKotlin(productionBase, candidate.revision, true, "deployed");
  // The Cloud API route must not replace the already deployed static Web origin.
  const home = await fetch("https://arcforges.com/", {
    redirect: "error",
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(home.status, 200);
  assert.match(home.headers.get("content-type") ?? "", /text\/html/);
  await home.body?.cancel();
  deployment.verified = { at: new Date().toISOString(), health, protocol, kotlin, webHome: true };
  await writeJson(deploymentFile, deployment);
  console.log("Production Native AOT gRPC-Web and Web home verified.");
}

if (process.argv[2] === "deploy") await deploy();
else if (process.argv[2] === "smoke") await smoke();
else throw new Error("Use deploy or smoke.");
