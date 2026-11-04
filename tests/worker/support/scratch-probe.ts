// SPDX-License-Identifier: AGPL-3.0-only
// Run only by module-layout.test.ts, in a child process whose TMPDIR is empty: it makes scratch directories and, in the "throw" mode, fails.
import { writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { scratchDirectory } from "./scratch.ts";

const moduleLevel = scratchDirectory("probe-module-");
writeFileSync(path.join(moduleLevel, "file"), "x");

test("a test that removes its directory with its context", (t) => {
  const directory = scratchDirectory("probe-context-", t);
  writeFileSync(path.join(directory, "file"), "x");
  if (process.env.SCRATCH_PROBE_MODE === "throw") throw new Error("the probe fails on purpose");
});

test("a test that relies on the exit hook", () => {
  const directory = scratchDirectory("probe-exit-");
  writeFileSync(path.join(directory, "file"), "x");
  if (process.env.SCRATCH_PROBE_MODE === "throw") throw new Error("the probe fails on purpose");
});
