// SPDX-License-Identifier: AGPL-3.0-only
// Linux private append-only broker journal. A surviving lock is never adopted after interruption.
import assert from "node:assert/strict";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import path from "node:path";
import { object, parseDocument } from "./provenance.ts";

const maxEvents = 10_000;
const maxEventBytes = 16_384;
const emptyHash = "0".repeat(64);
const eventName = /^event-([0-9]{8})\.json$/u;
const fieldName = new Set([
  "repository",
  "exception",
  "purpose",
  "approvedHead",
  "approvedTree",
  "merge",
  "producer",
  "originalRun",
  "eventDigest",
  "run",
  "runNumber",
  "attempt",
  "gateDigest",
  "gateChallenge",
  "artifactId",
  "artifactDigest",
  "artifactApiDigest",
  "receiptDigest",
  "receiptSize",
  "artifactSize",
  "release",
  "targetDigest",
  "issueId",
  "capabilityId",
  "status",
  "observedDigest",
  "associationDigest",
]);
const eventKind = new Set([
  "authorization",
  "attempt",
  "run_association",
  "issue_intent",
  "issue_result",
  "publish_intent",
  "publication",
  "reconciliation",
]);
const publicValue = /^[A-Za-z0-9._:-]{1,256}$/u;
const digest = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");

type PublicFields = Record<string, string>;
export type JournalEvent = { kind: string; fields: PublicFields };
export type JournalEntry = { sequence: number; previous: string; event: JournalEvent };

function checkEvent(value: unknown): JournalEvent {
  const item = object(value, "kind fields");
  assert(typeof item.kind === "string" && eventKind.has(item.kind), "Unknown journal event");
  const fields = object(item.fields);
  const keys = Object.keys(fields);
  assert(keys.length > 0 && keys.length <= fieldName.size, "Invalid public journal fields");
  for (const key of keys) {
    assert(fieldName.has(key), "Non-public or unknown journal field");
    assert(
      typeof fields[key] === "string" && publicValue.test(fields[key]),
      "Invalid public journal value",
    );
  }
  return { kind: item.kind, fields: fields as PublicFields };
}

function sameObject(a: Stats, b: Stats): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

function trustedDirectory(root: string): number {
  assert.equal(process.platform, "linux", "Private broker journal is supported only on Linux");
  assert(
    path.isAbsolute(root) && path.resolve(root) === root,
    "Journal root must be an absolute canonical path",
  );
  const uid = process.getuid?.();
  assert(typeof uid === "number", "Cannot determine journal owner");
  const parts = root.split(path.sep).filter(Boolean);
  let current: string = path.sep;
  for (const part of parts) {
    current = path.join(current, part);
    const state = lstatSync(current);
    assert(state.isDirectory() && !state.isSymbolicLink(), "Untrusted journal ancestor");
    assert(state.uid === 0 || state.uid === uid, "Untrusted journal ancestor owner");
    if (current === root) {
      assert(state.uid === uid && (state.mode & 0o077) === 0, "Journal directory is not private");
    } else if ((state.mode & 0o022) !== 0) {
      assert((state.mode & 0o1000) !== 0, "Shared writable non-sticky journal ancestor");
    }
  }
  const before = lstatSync(root);
  const fd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    assert(opened.isDirectory() && sameObject(before, opened), "Journal directory changed");
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function readRegular(name: string, maximum: number): Buffer {
  const before = lstatSync(name);
  assert(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.nlink === 1 &&
      before.uid === process.getuid?.() &&
      (before.mode & 0o077) === 0,
    "Unsafe journal file",
  );
  const fd = openSync(name, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    assert(
      opened.isFile() && sameObject(before, opened) && opened.size <= maximum,
      "Journal file changed",
    );
    const result = readFileSync(fd);
    assert(
      result.length === opened.size && sameObject(lstatSync(name), fstatSync(fd)),
      "Journal file changed while reading",
    );
    return result;
  } finally {
    closeSync(fd);
  }
}

function exclusiveWrite(file: string, bytes: Buffer): void {
  const fd = openSync(
    file,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** One holder owns a real, atomic filesystem lock; restart never treats that lock as ownership. */
export class BootstrapJournal {
  readonly #root: string;
  readonly #directory: number;
  readonly #lock: string;
  readonly #secret: Buffer;
  #released = false;
  #writeUncertain = false;

  constructor(root: string) {
    this.#directory = trustedDirectory(root);
    this.#root = root;
    this.#lock = path.join(root, ".broker-lock");
    this.#secret = randomBytes(32);
    try {
      mkdirSync(this.#lock, { mode: 0o700 }); // atomic across processes, never recursive
      fsyncSync(this.#directory);
      exclusiveWrite(path.join(this.#lock, "owner"), Buffer.from(`${digest(this.#secret)}\n`));
      const lockFd = openSync(
        this.#lock,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        fsyncSync(lockFd);
      } finally {
        closeSync(lockFd);
      }
      fsyncSync(this.#directory);
      this.#assertOwner();
      this.read(); // an incomplete, unknown or corrupt journal is never adopted
    } catch (error) {
      closeSync(this.#directory);
      // Never remove a lock here: it may have become durable before a later operation failed.
      throw error;
    }
  }

  #assertOwner(): void {
    assert(!this.#released, "Journal holder already closed");
    const root = lstatSync(this.#root);
    assert(
      root.isDirectory() &&
        root.uid === process.getuid?.() &&
        (root.mode & 0o077) === 0 &&
        sameObject(root, fstatSync(this.#directory)),
      "Journal root changed",
    );
    const lock = lstatSync(this.#lock);
    assert(
      lock.isDirectory() &&
        !lock.isSymbolicLink() &&
        lock.uid === process.getuid?.() &&
        (lock.mode & 0o077) === 0,
      "Journal lock changed",
    );
    assert.deepEqual(readdirSync(this.#lock), ["owner"], "Unexpected journal lock content");
    const actual = readRegular(path.join(this.#lock, "owner"), 65);
    const expected = Buffer.from(`${digest(this.#secret)}\n`);
    assert(
      actual.length === expected.length && timingSafeEqual(actual, expected),
      "Journal lock owner differs",
    );
  }

  read(): JournalEntry[] {
    this.#assertOwner();
    const names = readdirSync(this.#root).filter((name) => name !== ".broker-lock");
    assert(
      names.length <= maxEvents && names.every((name) => eventName.test(name)),
      "Unknown journal content",
    );
    names.sort();
    const entries: JournalEntry[] = [];
    let previous = emptyHash;
    for (const [index, name] of names.entries()) {
      assert.equal(
        name,
        `event-${String(index + 1).padStart(8, "0")}.json`,
        "Journal sequence differs",
      );
      const bytes = readRegular(path.join(this.#root, name), maxEventBytes);
      const row = object(parseDocument(bytes), "sequence previous event");
      assert.equal(row.sequence, index + 1);
      assert.equal(row.previous, previous, "Journal hash chain differs");
      entries.push({ sequence: index + 1, previous, event: checkEvent(row.event) });
      previous = digest(bytes);
    }
    this.#assertOwner();
    return entries;
  }

  append(event: JournalEvent): JournalEntry {
    const checked = checkEvent(event);
    const entries = this.read();
    assert(entries.length < maxEvents, "Journal event limit reached");
    const sequence = entries.length + 1;
    const previous =
      sequence === 1
        ? emptyHash
        : digest(
            readRegular(
              path.join(this.#root, `event-${String(sequence - 1).padStart(8, "0")}.json`),
              maxEventBytes,
            ),
          );
    const entry = { sequence, previous, event: checked };
    const bytes = Buffer.from(`${JSON.stringify(entry)}\n`);
    assert(bytes.length <= maxEventBytes, "Journal event too large");
    this.#assertOwner();
    try {
      exclusiveWrite(
        path.join(this.#root, `event-${String(sequence).padStart(8, "0")}.json`),
        bytes,
      );
      fsyncSync(this.#directory);
      this.#assertOwner();
    } catch (error) {
      // A partially written or unsynced event is not a clean outcome. Keep the lock.
      this.#writeUncertain = true;
      throw error;
    }
    return entry;
  }

  close(): void {
    assert(!this.#writeUncertain, "Uncertain journal write cannot release the lock");
    this.#assertOwner();
    unlinkSync(path.join(this.#lock, "owner"));
    const lockFd = openSync(
      this.#lock,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      fsyncSync(lockFd);
    } finally {
      closeSync(lockFd);
    }
    rmdirSync(this.#lock);
    fsyncSync(this.#directory);
    this.#released = true;
    closeSync(this.#directory);
  }
}
