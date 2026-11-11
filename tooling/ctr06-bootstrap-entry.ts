// SPDX-License-Identifier: AGPL-3.0-only
// Phase-one client. No production collector, transport or broker profile has been reviewed.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  constants,
  createReadStream,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  bridgeSource,
  collectBridgeFacts,
  validateBridgeProducer,
  type ProducerFacts,
} from "./ctr06-security-bridge-source.ts";
import { object, parseDocument } from "./provenance.ts";
import { root } from "./process.ts";
import { requireReviewedAuthorityProfile } from "./ctr06-bootstrap-profile.ts";
import { inspectGateProof } from "./ctr06-bootstrap-gate.ts";
import { verifyCollectorIdentity } from "./ctr06-bootstrap-oidc.ts";

type Producer = ReturnType<typeof validateBridgeProducer>;
const hexDigest = /^[a-f0-9]{64}$/u;
const maxCarrier = 512 * 1024 * 1024;

/** Validates the caller's actual protected GitHub event and checkout; this is not authority evidence. */
export function checkedBootstrapProducer(
  env: NodeJS.ProcessEnv,
  event: unknown,
  facts: ProducerFacts,
): Producer {
  return validateBridgeProducer(env, event, facts);
}

function regular(pathname: string, maximum: number): number {
  const before = lstatSync(pathname);
  assert(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.nlink === 1 &&
      before.size > 0 &&
      before.size <= maximum,
    "Unsafe sealed input",
  );
  const fd = openSync(pathname, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    assert(
      opened.isFile() &&
        opened.dev === before.dev &&
        opened.ino === before.ino &&
        opened.size === before.size,
      "Sealed input changed",
    );
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function boundedRead(fd: number, maximum: number): Buffer {
  const before = fstatSync(fd);
  assert(before.isFile() && before.size > 0 && before.size <= maximum);
  const data = Buffer.alloc(before.size);
  let offset = 0;
  while (offset < data.length) {
    const count = readSync(fd, data, offset, data.length - offset, null);
    assert(count > 0, "Sealed input became short");
    offset += count;
  }
  const after = fstatSync(fd);
  assert(
    before.dev === after.dev &&
      before.ino === after.ino &&
      before.size === after.size &&
      before.mtimeMs === after.mtimeMs &&
      before.ctimeMs === after.ctimeMs,
    "Sealed input changed during read",
  );
  return data;
}

/** Checks local receipt and bytes only. A broker must independently fetch and verify the actual same-run artifact. */
export async function inspectLocalSealedCarrier(directory: string, producer: Producer) {
  assert(path.isAbsolute(directory), "Sealed input directory must be absolute");
  const dir = lstatSync(directory);
  assert(dir.isDirectory() && !dir.isSymbolicLink(), "Unsafe sealed input directory");
  const receiptPath = path.join(directory, "bootstrap-receipt.json");
  const receiptFd = regular(receiptPath, 64 * 1024);
  let receiptBytes: Buffer;
  try {
    receiptBytes = boundedRead(receiptFd, 64 * 1024);
  } finally {
    closeSync(receiptFd);
  }
  const receipt = object(
    parseDocument(receiptBytes),
    "schema producer source version carrier manifestSha256",
  );
  assert.equal(receipt.schema, "arcforges.ctr06-security-bridge-bootstrap.v1");
  assert.deepEqual(receipt.producer, producer.producer);
  assert.deepEqual(receipt.source, bridgeSource);
  assert.equal(receipt.version, producer.version);
  assert(typeof receipt.manifestSha256 === "string" && hexDigest.test(receipt.manifestSha256));
  const carrier = object(receipt.carrier, "name sha256 size members");
  assert.equal(carrier.name, `arcforges-ctr06-security-bridge-${producer.version}.tar.gz`);
  assert(typeof carrier.sha256 === "string" && hexDigest.test(carrier.sha256));
  assert(
    typeof carrier.size === "number" &&
      Number.isSafeInteger(carrier.size) &&
      carrier.size > 0 &&
      carrier.size <= maxCarrier,
  );
  assert(
    typeof carrier.members === "number" &&
      Number.isSafeInteger(carrier.members) &&
      carrier.members > 0,
  );
  const name = carrier.name as string;
  const fd = regular(path.join(directory, name), maxCarrier);
  try {
    const before = fstatSync(fd);
    assert.equal(before.size, carrier.size);
    const digest = createHash("sha256");
    let consumed = 0;
    for await (const chunk of createReadStream("", { fd, autoClose: false })) {
      assert(Buffer.isBuffer(chunk));
      consumed += chunk.length;
      assert(consumed <= before.size, "Sealed carrier grew during read");
      digest.update(chunk);
    }
    assert.equal(consumed, before.size);
    const after = fstatSync(fd);
    assert(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        before.mtimeMs === after.mtimeMs &&
        before.ctimeMs === after.ctimeMs,
      "Sealed carrier changed while reading",
    );
    assert.equal(digest.digest("hex"), carrier.sha256, "Sealed carrier digest differs");
    return {
      artifactSha256: carrier.sha256,
      size: carrier.size,
      receiptSha256: createHash("sha256").update(receiptBytes).digest("hex"),
      receiptSize: receiptBytes.length,
    };
  } finally {
    closeSync(fd);
  }
}

function actualProducer(): { producer: Producer; eventDigest: string } {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  assert(eventPath && path.isAbsolute(eventPath), "Missing GitHub event context");
  const fd = regular(eventPath, 1024 * 1024);
  let eventBytes: Buffer;
  try {
    eventBytes = boundedRead(fd, 1024 * 1024);
  } finally {
    closeSync(fd);
  }
  return {
    producer: checkedBootstrapProducer(
      process.env,
      parseDocument(eventBytes),
      collectBridgeFacts(root),
    ),
    eventDigest: createHash("sha256").update(eventBytes).digest("hex"),
  };
}

export async function runBootstrapEntry(mode: string, directory?: string): Promise<void> {
  assert(mode === "authority" || mode === "publication", "Unknown bootstrap operation");
  const { producer, eventDigest } = actualProducer();
  let carrier: Awaited<ReturnType<typeof inspectLocalSealedCarrier>> | undefined;
  if (mode === "publication") {
    assert(directory, "Missing sealed carrier");
    carrier = await inspectLocalSealedCarrier(directory, producer);
  }
  // No hostname, provider/issuer credentials, signed JSON or caller-supplied policy can manufacture
  // a reviewed production trust profile. A future profile must implement actual source coverage,
  // enforced lease and independent broker readback before this refusal can be replaced.
  const profile = requireReviewedAuthorityProfile();
  if (mode === "authority") {
    const approval = await profile.gateApproval(producer, eventDigest);
    assert.equal(approval.merge, producer.producer.commit);
    assert.equal(approval.eventDigest, eventDigest);
    const challenge = randomBytes(32).toString("hex");
    const proof = await profile.collectGate(producer, approval, challenge);
    const at = Math.floor(Date.now() / 1000);
    const context = {
      producer: producer.producer.commit,
      run: producer.producer.runId,
      runNumber: producer.producer.runNumber,
      attempt: String(producer.producer.runAttempt),
      originalRun: approval.originalRun,
      eventDigest,
      challenge,
    };
    const checked = await inspectGateProof(
      context,
      proof,
      at,
      profile.requiredDomains,
      async (item, when) => {
        const identity = await profile.collectorRun(item, context);
        assert.equal(identity.sourceSha, profile.collectorSourceSha);
        await verifyCollectorIdentity(item.payload, item.token, identity, when);
      },
    );
    await profile.verifyGateControls(proof, producer, approval);
    assert(
      typeof checked.lease.end === "number" && Math.floor(Date.now() / 1000) < checked.lease.end,
    );
    const output = process.env.GITHUB_OUTPUT;
    assert(output && path.isAbsolute(output), "Missing GitHub output file");
    appendFileSync(output, `gate-digest=${checked.digest}\ngate-challenge=${challenge}\n`, {
      encoding: "utf8",
    });
    return;
  }
  const artifactId = process.env.ARCFORGES_CTR06_SEALED_ARTIFACT_ID;
  assert(
    artifactId &&
      /^[1-9][0-9]{0,14}$/u.test(artifactId) &&
      Number.isSafeInteger(Number(artifactId)),
  );
  const gateDigest = process.env.ARCFORGES_CTR06_GATE_DIGEST;
  const gateChallenge = process.env.ARCFORGES_CTR06_GATE_CHALLENGE;
  assert(
    gateDigest && gateChallenge && hexDigest.test(gateDigest) && hexDigest.test(gateChallenge),
  );
  assert(carrier);
  return profile.submitPublication(producer, { artifactId, ...carrier, gateDigest, gateChallenge });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    await runBootstrapEntry(process.argv[2] ?? "", process.argv[3]);
  } catch {
    process.stderr.write(
      "Security bridge authority: NOT PROVEN (missing or invalid producer context, or no reviewed live authority/broker profile)\n",
    );
    process.exitCode = 1;
  }
}
