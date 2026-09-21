// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyToolchain } from "../../tooling/project.ts";

test("toolchain pins reject a different Node or npm patch", async () => {
  await verifyToolchain("v24.21.0", "11.19.0");
  await assert.rejects(verifyToolchain("v24.21.1", "11.19.0"), /pinned Node/);
  await assert.rejects(verifyToolchain("v24.21.0", "11.19.1"), /pinned npm/);
});
