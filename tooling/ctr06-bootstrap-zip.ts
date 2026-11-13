// SPDX-License-Identifier: AGPL-3.0-only
// Bounded ZIP32 reader for the two flat files in a same-run bootstrap artifact.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { crc32, inflateRawSync } from "node:zlib";
import type { ApprovedBootstrap, AttemptTarget } from "./ctr06-bootstrap-registry.ts";
import { bridgeSource } from "./ctr06-security-bridge-source.ts";
import { object, parseDocument } from "./provenance.ts";

const maxZip = 512 * 1024 * 1024;
const maxReceipt = 64 * 1024;
const sha = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
type Member = {
  name: string;
  flags: number;
  method: number;
  crc: number;
  compressed: number;
  size: number;
  local: number;
};
function extra(buffer: Buffer) {
  for (let index = 0; index < buffer.length;) {
    assert(index + 4 <= buffer.length, "Truncated ZIP extra field");
    const id = buffer.readUInt16LE(index);
    const length = buffer.readUInt16LE(index + 2);
    index += 4;
    assert(index + length <= buffer.length, "Truncated ZIP extra field value");
    assert(id === 0x5455 || id === 0x7875, "Unsupported or ambiguous ZIP extra field");
    index += length;
  }
}
function range(buffer: Buffer, start: number, length: number, limit = buffer.length): Buffer {
  assert(
    Number.isSafeInteger(start) &&
      Number.isSafeInteger(length) &&
      start >= 0 &&
      length >= 0 &&
      start + length <= limit &&
      limit <= buffer.length,
    "ZIP range outside archive",
  );
  return buffer.subarray(start, start + length);
}

/** Uses one exact archive object: checks ZIP SHA, bounded entries, CRCs, receipt and carrier bytes. */
export function inspectBootstrapZip(
  archive: Buffer,
  target: AttemptTarget,
  approval: ApprovedBootstrap,
): Buffer {
  assert(archive.length >= 22 && archive.length <= maxZip, "ZIP size invalid");
  assert.equal(sha(archive), target.artifactApiDigest, "GitHub artifact ZIP digest differs");
  const end = archive.length - 22;
  assert.equal(archive.readUInt32LE(end), 0x06054b50, "ZIP end record missing");
  assert.equal(archive.readUInt16LE(end + 4), 0);
  assert.equal(archive.readUInt16LE(end + 6), 0);
  assert.equal(archive.readUInt16LE(end + 8), 2);
  assert.equal(archive.readUInt16LE(end + 10), 2);
  assert.equal(archive.readUInt16LE(end + 20), 0, "ZIP comments are unsupported");
  const centralSize = archive.readUInt32LE(end + 12);
  const centralOffset = archive.readUInt32LE(end + 16);
  assert.equal(centralOffset + centralSize, end, "ZIP central directory bounds differ");
  const expectedCarrier = `arcforges-ctr06-security-bridge-0.1.0-ci.${target.runNumber}.${target.attempt}.tar.gz`;
  const expected = new Set(["bootstrap-receipt.json", expectedCarrier]);
  const members: Member[] = [];
  const names = new Set<string>();
  let cursor = centralOffset;
  for (let i = 0; i < 2; i++) {
    range(archive, cursor, 46, end);
    assert.equal(archive.readUInt32LE(cursor), 0x02014b50, "ZIP central member missing");
    const creator = archive.readUInt16LE(cursor + 4);
    const version = archive.readUInt16LE(cursor + 6);
    const flags = archive.readUInt16LE(cursor + 8);
    const method = archive.readUInt16LE(cursor + 10);
    const crc = archive.readUInt32LE(cursor + 16);
    const compressed = archive.readUInt32LE(cursor + 20);
    const size = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    const disk = archive.readUInt16LE(cursor + 34);
    const attrs = archive.readUInt32LE(cursor + 38);
    const local = archive.readUInt32LE(cursor + 42);
    assert(version <= 20 && (flags & ~0x0808) === 0 && (method === 0 || method === 8));
    assert(
      disk === 0 &&
        commentLength === 0 &&
        compressed > 0 &&
        size > 0 &&
        compressed <= maxZip &&
        size <= maxZip,
    );
    assert((attrs & 0x10) === 0, "ZIP directory is unsupported");
    if (creator >>> 8 === 3) {
      const kind = (attrs >>> 16) & 0xf000;
      assert(kind === 0 || kind === 0x8000, "ZIP link or special member");
    }
    const name = range(archive, cursor + 46, nameLength, end).toString("utf8");
    assert(
      expected.has(name) &&
        !names.has(name) &&
        Buffer.from(name).equals(range(archive, cursor + 46, nameLength, end)),
      "Unknown or duplicate ZIP member",
    );
    names.add(name);
    extra(range(archive, cursor + 46 + nameLength, extraLength, end));
    members.push({ name, flags, method, crc, compressed, size, local });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  assert.equal(cursor, end);
  assert.equal(names.size, 2);
  members.sort((a, b) => a.local - b.local);
  let next = 0;
  const contents = new Map<string, Buffer>();
  for (const member of members) {
    assert.equal(member.local, next, "ZIP local members overlap or contain unclassified data");
    const local = member.local;
    range(archive, local, 30, centralOffset);
    assert.equal(archive.readUInt32LE(local), 0x04034b50, "ZIP local member missing");
    assert.equal(archive.readUInt16LE(local + 6), member.flags);
    assert.equal(archive.readUInt16LE(local + 8), member.method);
    const localCrc = archive.readUInt32LE(local + 14);
    const localCompressed = archive.readUInt32LE(local + 18);
    const localSize = archive.readUInt32LE(local + 22);
    const nameLength = archive.readUInt16LE(local + 26);
    const extraLength = archive.readUInt16LE(local + 28);
    assert.equal(
      range(archive, local + 30, nameLength, centralOffset).toString("utf8"),
      member.name,
    );
    extra(range(archive, local + 30 + nameLength, extraLength, centralOffset));
    if ((member.flags & 8) === 0) {
      assert.equal(localCrc, member.crc);
      assert.equal(localCompressed, member.compressed);
      assert.equal(localSize, member.size);
    } else
      assert(
        (localCrc === 0 || localCrc === member.crc) &&
          (localCompressed === 0 || localCompressed === member.compressed) &&
          (localSize === 0 || localSize === member.size),
      );
    const start = local + 30 + nameLength + extraLength;
    const compressed = range(archive, start, member.compressed, centralOffset);
    let value: Buffer;
    if (member.method === 0) value = Buffer.from(compressed);
    else {
      const inflated = inflateRawSync(compressed, {
        maxOutputLength: member.size,
        info: true,
      }) as unknown as { buffer: unknown; engine: { bytesWritten: number } };
      assert(Buffer.isBuffer(inflated.buffer), "Invalid ZIP inflation result");
      assert.equal(
        inflated.engine.bytesWritten,
        compressed.length,
        "ZIP deflate contains trailing data",
      );
      value = inflated.buffer;
    }
    assert.equal(value.length, member.size);
    assert.equal(crc32(value), member.crc, "ZIP member CRC differs");
    next = start + member.compressed;
    if ((member.flags & 8) !== 0) {
      range(archive, next, 12, centralOffset);
      if (archive.readUInt32LE(next) === 0x08074b50) {
        range(archive, next, 16, centralOffset);
        next += 4;
      }
      assert.equal(archive.readUInt32LE(next), member.crc);
      assert.equal(archive.readUInt32LE(next + 4), member.compressed);
      assert.equal(archive.readUInt32LE(next + 8), member.size);
      next += 12;
    }
    contents.set(member.name, value);
  }
  assert.equal(next, centralOffset, "ZIP contains trailing unclassified data");
  const receiptBytes = contents.get("bootstrap-receipt.json");
  const carrier = contents.get(expectedCarrier);
  assert(receiptBytes && receiptBytes.length <= maxReceipt && carrier);
  assert.equal(receiptBytes.length, Number(target.receiptSize), "Bootstrap receipt size differs");
  assert.equal(sha(receiptBytes), target.receiptDigest, "Bootstrap receipt digest differs");
  assert.equal(carrier.length, Number(target.artifactSize));
  assert.equal(sha(carrier), target.artifactDigest, "Carrier digest differs");
  const receipt = object(
    parseDocument(receiptBytes),
    "schema producer source version carrier manifestSha256",
  );
  assert.equal(receipt.schema, "arcforges.ctr06-security-bridge-bootstrap.v1");
  assert.deepEqual(receipt.source, bridgeSource);
  assert.equal(receipt.version, `0.1.0-ci.${target.runNumber}.${target.attempt}`);
  assert.deepEqual(receipt.producer, {
    repository: "ArcForges/Cloud",
    workflowRef: "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main",
    commit: target.producer,
    tree: approval.approvedTree,
    runId: target.run,
    runNumber: target.runNumber,
    runAttempt: Number(target.attempt),
    pipelineRun: `https://github.com/ArcForges/Cloud/actions/runs/${target.run}`,
  });
  const description = object(receipt.carrier, "name sha256 size members");
  assert.equal(description.name, expectedCarrier);
  assert.equal(description.sha256, target.artifactDigest);
  assert.equal(description.size, carrier.length);
  assert(
    typeof description.members === "number" &&
      Number.isSafeInteger(description.members) &&
      description.members > 0,
  );
  assert(
    typeof receipt.manifestSha256 === "string" && /^[a-f0-9]{64}$/u.test(receipt.manifestSha256),
  );
  return carrier;
}
