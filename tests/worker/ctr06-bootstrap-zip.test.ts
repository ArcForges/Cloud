// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { inspectBootstrapZip } from "../../tooling/ctr06-bootstrap-zip.ts";
import {
  approval,
  syntheticReceipt,
  syntheticZip,
  target,
  zipFixture,
} from "./support/ctr06-bootstrap-mock.ts";

const sha = (value: Buffer) => createHash("sha256").update(value).digest("hex");
const carrier = Buffer.from("isolated synthetic sealed artifact");
function name(runNumber: string, attempt: string) {
  return `arcforges-ctr06-security-bridge-0.1.0-ci.${runNumber}.${attempt}.tar.gz`;
}
function zipTarget(bytes: Buffer) {
  return { ...target(), artifactApiDigest: sha(bytes) };
}

test("same ZIP object yields the checked receipt and carrier, including deflate and data descriptors", () => {
  const request = target();
  const stored = syntheticZip(request);
  assert.deepEqual(inspectBootstrapZip(stored, request, approval), carrier);
  const compressed = zipFixture(
    [
      ["bootstrap-receipt.json", syntheticReceipt(request)],
      [name(request.runNumber, request.attempt), carrier],
    ],
    true,
    true,
  );
  assert.deepEqual(inspectBootstrapZip(compressed, zipTarget(compressed), approval), carrier);
});

test("rejects unknown, duplicate, linked, overlapping and malformed ZIP members", () => {
  const request = target();
  const receipt = syntheticReceipt(request);
  const badZips: Buffer[] = [];
  badZips.push(
    zipFixture(
      [
        ["bootstrap-receipt.json", receipt],
        [name(request.runNumber, request.attempt), carrier],
      ],
      true,
      true,
      true,
    ),
  );
  badZips.push(
    zipFixture([
      ["bootstrap-receipt.json", receipt],
      ["bootstrap-receipt.json", receipt],
    ]),
  );
  badZips.push(
    zipFixture([
      ["bootstrap-receipt.json", receipt],
      ["../outside", carrier],
    ]),
  );
  const linked = Buffer.from(syntheticZip(request));
  const central = linked.readUInt32LE(linked.length - 6);
  linked.writeUInt32LE((0o120777 << 16) >>> 0, central + 38);
  badZips.push(linked);
  const overlap = Buffer.from(syntheticZip(request));
  const first = overlap.readUInt32LE(overlap.length - 6);
  const second =
    first +
    46 +
    overlap.readUInt16LE(first + 28) +
    overlap.readUInt16LE(first + 30) +
    overlap.readUInt16LE(first + 32);
  overlap.writeUInt32LE(0, second + 42);
  badZips.push(overlap);
  const encrypted = Buffer.from(syntheticZip(request));
  const index = encrypted.readUInt32LE(encrypted.length - 6);
  encrypted.writeUInt16LE(1, index + 8);
  badZips.push(encrypted);
  const corrupted = Buffer.from(syntheticZip(request));
  const content = 30 + corrupted.readUInt16LE(26) + corrupted.readUInt16LE(28);
  corrupted[content] = (corrupted[content] ?? 0) ^ 1;
  badZips.push(corrupted);
  for (const bytes of badZips)
    assert.throws(() => inspectBootstrapZip(bytes, zipTarget(bytes), approval));
  assert.throws(() => inspectBootstrapZip(Buffer.from("truncated"), request, approval));
});

test("receipt, source, producer and carrier contents remain bound even when outer ZIP digest matches", () => {
  const request = target();
  const filename = name(request.runNumber, request.attempt);
  const forged = JSON.parse(syntheticReceipt(request).toString("utf8")) as {
    producer: { commit: string };
  };
  forged.producer.commit = "0".repeat(40);
  const bytes = Buffer.from(JSON.stringify(forged));
  const archive = zipFixture([
    ["bootstrap-receipt.json", bytes],
    [filename, carrier],
  ]);
  assert.throws(() =>
    inspectBootstrapZip(archive, { ...zipTarget(archive), receiptDigest: sha(bytes) }, approval),
  );
  const altered = zipFixture([
    ["bootstrap-receipt.json", syntheticReceipt(request)],
    [filename, Buffer.alloc(carrier.length, 1)],
  ]);
  assert.throws(() => inspectBootstrapZip(altered, zipTarget(altered), approval));
  assert.throws(() =>
    inspectBootstrapZip(
      syntheticZip(request),
      { ...request, receiptDigest: "0".repeat(64) },
      approval,
    ),
  );
});
