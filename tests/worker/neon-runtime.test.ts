// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { access, readFile, stat } from "node:fs/promises";
import test from "node:test";
import { neonRuntimeSecret, withNeonRuntimeSecret } from "../../tooling/neon-runtime.ts";

const fixture =
  "postgresql://owner:synthetic-only@ep-fixture-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

test("Neon deployment is explicit and missing credentials fail before promotion", () => {
  assert.equal(neonRuntimeSecret(undefined, {}), undefined);
  assert.throws(() => neonRuntimeSecret("enabled", {}), /NEON_DATABASE_URL/u);
  assert.throws(
    () => neonRuntimeSecret("enabled", { NEON_DATABASE_URL: "synthetic-private-value" }),
    (error: Error) => {
      assert.doesNotMatch(error.message, /synthetic-private-value/u);
      return true;
    },
  );
  assert.throws(() =>
    neonRuntimeSecret("enabled", {
      NEON_DATABASE_URL: fixture.replace("sslmode=require", "sslmode=disable"),
    }),
  );
});

test("only the pooled runtime credential is staged and the secret file is removed", async () => {
  const secret = neonRuntimeSecret("enabled", {
    NEON_DATABASE_URL: fixture,
    NEON_DATABASE_URL_DIRECT: "never-forward",
  });
  let secretFile = "";
  await withNeonRuntimeSecret(secret, async (arguments_) => {
    assert.equal(arguments_[0], "--secrets-file");
    const file = arguments_[1];
    assert.ok(file);
    secretFile = file;
    assert.deepEqual(JSON.parse(await readFile(secretFile, "utf8")), {
      NEON_DATABASE_URL: fixture,
    });
    if (process.platform !== "win32") assert.equal((await stat(secretFile)).mode & 0o777, 0o600);
  });
  await assert.rejects(access(secretFile));
});

test("a failed deployment also removes the temporary secret", async () => {
  let secretFile = "";
  await assert.rejects(
    withNeonRuntimeSecret({ NEON_DATABASE_URL: fixture }, async (arguments_) => {
      const file = arguments_[1];
      assert.ok(file);
      secretFile = file;
      throw new Error("synthetic provider failure");
    }),
    /synthetic provider failure/u,
  );
  await assert.rejects(access(secretFile));
});
