// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { root, writeJson } from "../../tooling/process.ts";
import { verifyCandidate } from "../../tooling/project.ts";

async function checkDeployment(target: "production" | "proof") {
  const event = target === "production" ? "push" : "workflow_dispatch";
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.GITHUB_REPOSITORY, "ArcForges/Cloud");
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(process.env.GITHUB_EVENT_NAME, event);

  const candidate = await verifyCandidate();
  assert.equal(candidate.revision, process.env.GITHUB_SHA);
  assert.equal(candidate.dirty, false);
  await writeJson(path.join(root, "artifacts", `migration-gate-${target}.json`), {
    target,
    revision: candidate.revision,
    status: "not-applicable",
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, option, target, ...rest] = process.argv.slice(2);
  assert(command === "deploy" && option === "--target" && rest.length === 0);
  assert(target === "production" || target === "proof");
  await checkDeployment(target);
}
