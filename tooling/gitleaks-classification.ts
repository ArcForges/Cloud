// SPDX-License-Identifier: AGPL-3.0-only
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const commit = "389039026a5daa15503ffdf792ba1ca942e7bc64";
const selector = "application.presence.v1";
const selectorHash = "7cf0693e77f170ec1ffc1bdba110939f674d30a62b35264a8e0a7e87f6643de5";
const rows = [
  {
    path: "src/ArcForges.Cloud/Composition/ApplicationPresenceModule.cs",
    line: 12,
    declaration: `    internal const string CredentialKey = "${selector}";`,
    bytes: 68,
    lineHash: "e21b5c465a2e80280395a1157f9baf6989d6f9c669e5f7a99ab8ea7f4e7df49b",
    blobHash: "b903a616e7450c168a55e40faa1b84f274484321383a5e2aebac5b817fdd2251",
  },
  {
    path: "tests/ArcForges.Cloud.Tests/Presence/KeyedPresenceIngressTests.cs",
    line: 13,
    declaration: `    private const string Key = "${selector}";`,
    bytes: 57,
    lineHash: "6c64ad9767c12a4452be6685253a7e23926c9df85006eb7dac714e92b455da28",
    blobHash: "5d6f7c9de7bdd2d49af1188412adacd0ee2ab420dac8a25c05545da1dfeaa633",
  },
] as const;

function sha(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function validateClassificationEvidence(
  ignore: Uint8Array,
  readOriginal: (object: string) => Uint8Array,
): void {
  if (ignore.length > 4096) throw new Error("secret classification: fingerprint size");
  const canonical = rows
    .map((row) => `${commit}:${row.path}:generic-api-key:${row.line}\n`)
    .join("");
  if (!Buffer.from(ignore).equals(Buffer.from(canonical))) {
    throw new Error("secret classification: noncanonical fingerprints");
  }
  if (Buffer.byteLength(selector) !== 23 || sha(selector) !== selectorHash) {
    throw new Error("secret classification: invalid public selector");
  }
  for (const [index, row] of rows.entries()) {
    let blob: Uint8Array;
    try {
      blob = readOriginal(`${commit}:${row.path}`);
    } catch {
      throw new Error(`secret classification ${index}: missing original object`);
    }
    if (blob.length > 262144 || sha(blob) !== row.blobHash) {
      throw new Error(`secret classification ${index}: original blob mismatch`);
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(blob);
    const line = text.split("\n")[row.line - 1];
    if (
      line !== row.declaration ||
      Buffer.byteLength(line) !== row.bytes ||
      sha(line) !== row.lineHash
    ) {
      throw new Error(`secret classification ${index}: original declaration mismatch`);
    }
  }
}

export function validateSecretClassifications(): void {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const ignorePath = resolve(root, ".gitleaksignore");
  const descriptor = openSync(ignorePath, "r");
  let ignore: Uint8Array;
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > 4096) {
      throw new Error("secret classification: invalid fingerprint file");
    }
    const bounded = Buffer.alloc(4097);
    let count = 0;
    while (count < bounded.length) {
      const read = readSync(descriptor, bounded, count, bounded.length - count, null);
      if (read === 0) break;
      count += read;
    }
    if (count > 4096) throw new Error("secret classification: fingerprint size");
    ignore = bounded.subarray(0, count);
  } finally {
    closeSync(descriptor);
  }
  validateClassificationEvidence(ignore, (object) =>
    execFileSync("git", ["--no-replace-objects", "show", object], {
      cwd: root,
      timeout: 5000,
      maxBuffer: 262144,
      stdio: ["ignore", "pipe", "ignore"],
    }),
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    validateSecretClassifications();
    console.log("Two immutable public-selector classifications verified.");
  } catch {
    console.error("Secret classification validation refused.");
    process.exitCode = 1;
  }
}
