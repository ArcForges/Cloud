// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { copyStagedBridgeCarrier, withOwnedCleanup } from "../../tooling/ctr06-publisher.ts";
import { scratchDirectory } from "./support/scratch.ts";

test("staged bridge carrier is reused only as a new private file", async (t) => {
  const dir = scratchDirectory("ctr06-carrier-copy-", t);
  const source = path.join(dir, "source");
  const target = path.join(dir, "target");
  assert.equal(await copyStagedBridgeCarrier(source, target), false);
  await writeFile(source, "fixture");
  assert.equal(await copyStagedBridgeCarrier(source, target), true);
  assert.equal(await readFile(target, "utf8"), "fixture");
  await assert.rejects(copyStagedBridgeCarrier(source, target));
  assert.equal(await readFile(target, "utf8"), "fixture");
});

test("promotion and cleanup failures remain independently visible", async () => {
  const primary = new Error("promotion failed");
  const cleanup = new Error("cleanup failed");
  await assert.rejects(
    withOwnedCleanup(
      async () => {
        throw primary;
      },
      async () => {
        throw cleanup;
      },
    ),
    (error: unknown) =>
      error instanceof AggregateError &&
      error.errors.length === 2 &&
      error.errors[0] === primary &&
      error.errors[1] === cleanup,
  );
  await assert.rejects(
    withOwnedCleanup(
      async () => "done",
      async () => {
        throw cleanup;
      },
    ),
    (error: unknown) => error === cleanup,
  );
});
