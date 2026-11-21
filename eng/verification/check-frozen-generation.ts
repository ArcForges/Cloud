// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";

// Outputs of the legacy C# generator at Cloud 9b8796eac760982d9814f371b820b736ddd945c4
// (tree 2b35c50007089d6e6c51797f62437334bd2826f3). The old adapter uses a subset
// of the frozen table. The current Go table and the D1 plan audit have their own checks.
const root = new URL("../../", import.meta.url);
const artifacts = {
  "worker/tables/cloud-tables.generated.ts":
    "4da6a0319ca82265883a7d7eacb7eadc29e6027f9d9de34a2c7d0f8bc515811a",
  "eng/generated/contracts-identity.json":
    "98d5cee1f34b9a528c1f686d79c3672506ff1a92e5b6ad710e119e2181c09ec1",
};

for (const [file, expected] of Object.entries(artifacts)) {
  const path = new URL(file, root);
  assert(lstatSync(path).isFile(), `Frozen generated output must be a regular file: ${file}`);
  const content = readFileSync(path, "utf8").replaceAll("\r\n", "\n");
  const actual = createHash("sha256").update(content).digest("hex");
  assert.equal(actual, expected, `Frozen generated output changed: ${file}`);
}

console.log("Frozen generation artifacts match the reviewed Cloud source.");
