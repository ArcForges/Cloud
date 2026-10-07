// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  validateClassificationEvidence,
  validateSecretClassifications,
} from "./gitleaks-classification.ts";

const root = fileURLToPath(new URL("../", import.meta.url));
const ignore = readFileSync(new URL("../.gitleaksignore", import.meta.url));
const blobs = new Map<string, Buffer>();
for (const fingerprint of ignore.toString().trimEnd().split("\n")) {
  const [commit, path] = fingerprint.split(":");
  const object = `${commit}:${path}`;
  blobs.set(
    object,
    execFileSync("git", ["--no-replace-objects", "show", object], {
      cwd: root,
      timeout: 5000,
      maxBuffer: 262144,
      stdio: ["ignore", "pipe", "ignore"],
    }),
  );
}
function original(object: string): Buffer {
  const bytes = blobs.get(object);
  assert.ok(bytes);
  return bytes;
}

test("classifications verify both complete genuine immutable Git blobs", () => {
  validateSecretClassifications();
  validateClassificationEvidence(ignore, original);
});

test("classification rejects altered or broad fingerprint evidence", () => {
  const text = ignore.toString();
  const lines = text.trimEnd().split("\n");
  const hostile = [
    "",
    text.trimEnd(),
    `${text}\n`,
    `${text}${lines[0]}\n`,
    `${lines[1]}\n${lines[0]}\n`,
    `${lines[0]}\n`,
    text.replace("389039", "489039"),
    text.replace("Composition/", "Foreign/"),
    text.replace("generic-api-key", "other-rule"),
    text.replace(":12\n", ":11\n"),
    text.replace("ApplicationPresenceModule.cs", "*.cs"),
    `${text}another:unknown:generic-api-key:1\n`,
  ];
  for (const value of hostile) {
    assert.throws(
      () => validateClassificationEvidence(Buffer.from(value), original),
      /noncanonical/,
    );
  }
});

test("classification refuses missing original historical objects", () => {
  assert.throws(
    () =>
      validateClassificationEvidence(ignore, () => {
        throw new Error("private subprocess output must not escape");
      }),
    /missing original object/,
  );
});

test("classification refuses any changed complete original blob without disclosing it", () => {
  const changes = [
    (text: string) => text.replace("application.presence.v1", "application.presence.v2"),
    (text: string) => text.replace("const string", "static string"),
    (text: string) =>
      text.replace("    internal", "   internal").replace("    private", "   private"),
    (text: string) => `neighboring credential=private-value\n${text}`,
    (text: string) =>
      text.replace('"application.presence.v1";', '"application.presence.v1"; private-token'),
    (text: string) => `${text}\n`,
  ];
  for (const [target] of blobs) {
    for (const change of changes) {
      const mutated = Buffer.from(change(original(target).toString("utf8")));
      assert.notDeepEqual(mutated, original(target));
      assert.throws(
        () =>
          validateClassificationEvidence(ignore, (object) =>
            object === target ? mutated : original(object),
          ),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.match(error.message, /original blob mismatch/);
          assert.doesNotMatch(error.message, /private-value|private-token|application\.presence/);
          return true;
        },
      );
    }
  }
});
