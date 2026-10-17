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
