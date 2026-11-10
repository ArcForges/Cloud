// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mkdtemp, readFile, rmdir, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { copyStagedBridgeCarrier, withOwnedCleanup } from "../../tooling/ctr06-publisher.ts";

test("staged bridge carrier is reused only as a new private file", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "ctr06-carrier-copy-"));
  const source = path.join(dir, "source");
  const target = path.join(dir, "target");
  try {
    assert.equal(await copyStagedBridgeCarrier(source, target), false);
    await writeFile(source, "fixture");
    assert.equal(await copyStagedBridgeCarrier(source, target), true);
    assert.equal(await readFile(target, "utf8"), "fixture");
    await assert.rejects(copyStagedBridgeCarrier(source, target));
    assert.equal(await readFile(target, "utf8"), "fixture");
  } finally {
    await unlink(source).catch(() => undefined);
    await unlink(target).catch(() => undefined);
    await rmdir(dir);
  }
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
