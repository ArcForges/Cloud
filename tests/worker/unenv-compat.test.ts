// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { defineEnv } from "../../tooling/unenv-compat.ts";

test("native aliases and removals from the current preset survive environment merging", () => {
  const { env } = defineEnv({
    npmShims: true,
    presets: [
      { alias: { crypto: "node:crypto" }, external: ["node:crypto"], inject: { process: false } },
      { alias: { debug: "debug" }, external: ["node:crypto"] },
    ],
  });
  assert.equal(env.alias.crypto, "node:crypto");
  assert.equal(env.alias.debug, "debug");
  assert.equal(env.external.filter((name) => name === "node:crypto").length, 1);
  assert.equal(Object.hasOwn(env.inject, "process"), false);
  assert.equal(env.polyfill.includes("unenv/polyfill/process"), false);
});

test("unknown environment configuration fails instead of silently changing compatibility", () => {
  assert.throws(() => defineEnv({ presets: [], npmShims: false, unknown: true } as never));
});
