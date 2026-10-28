// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { dockerBuildNetwork, verifyToolchain } from "../../tooling/project.ts";

test("toolchain pins reject a different Node or npm patch", async () => {
  await verifyToolchain("v24.21.0", "11.19.0");
  await assert.rejects(verifyToolchain("v24.21.1", "11.19.0"), /pinned Node/);
  await assert.rejects(verifyToolchain("v24.21.0", "11.19.1"), /pinned npm/);
});

test("the host build network is a local-only option that hosted CI refuses", () => {
  assert.deepEqual(dockerBuildNetwork({}), []);
  assert.deepEqual(dockerBuildNetwork({ ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK: "host" }), [
    "--network",
    "host",
  ]);
  assert.throws(
    () =>
      dockerBuildNetwork({ ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK: "host", GITHUB_ACTIONS: "true" }),
    /local verification only/,
  );
  assert.throws(
    () => dockerBuildNetwork({ ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK: "host", CI: "true" }),
    /local verification only/,
  );
  assert.throws(
    () => dockerBuildNetwork({ ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK: "bridge" }),
    /only host/,
  );
});

test("every Worker test file runs in npm test or in its own named script", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const path = await import("node:path");
  const root = path.resolve(import.meta.dirname, "../..");
  const scripts = (
    JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    }
  ).scripts;
  const listed = new Set(scripts.test?.split(" ").filter((item) => item.endsWith(".test.ts")));
  for (const file of readdirSync(path.join(root, "tests/worker")).filter((name) =>
    name.endsWith(".test.ts"),
  )) {
    const relative = `tests/worker/${file}`;
    // The release provenance test needs a prepared candidate and runs in test:artifact.
    const own = Object.entries(scripts).some(
      ([name, script]) => name !== "test" && script.includes(relative),
    );
    assert(listed.has(relative) || own, `${relative} is not run by npm test`);
  }
});
