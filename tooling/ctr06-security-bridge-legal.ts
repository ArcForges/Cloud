// SPDX-License-Identifier: AGPL-3.0-only
// The 8e5 legal closure is audited against 8e5, not against the newer producer's push parent.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { bridgeSource, verifyTrackedBridgeSource } from "./ctr06-security-bridge-source.ts";
import { parseDocument, readOwned, validateRecord } from "./provenance.ts";

const sha256 = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");
const bytes = (value: unknown) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);

/** Runs the historical validators unchanged, with their supported explicit source baseline. */
export async function securityBridgeLegal(sourceDirectory: string, producerDirectory: string) {
  verifyTrackedBridgeSource(sourceDirectory);
  const provenance = await import(
    pathToFileURL(path.join(sourceDirectory, "tooling/provenance.ts")).href
  );
  const release = await import(
    pathToFileURL(path.join(sourceDirectory, "tooling/release-provenance.ts")).href
  );
  const licence = await import(
    pathToFileURL(path.join(sourceDirectory, "tooling/licence-boundary.ts")).href
  );
  const licenceAudit = licence.auditLicences(sourceDirectory);
  const audit = provenance.auditProvenance(sourceDirectory, { base: bridgeSource.commit });
  assert.equal(audit.sourceCommit, bridgeSource.commit);
  assert.equal(audit.comparisonCommit, bridgeSource.commit);
  assert.equal(audit.dirty, false);
  const { profile, profilePath, profileHash, artifacts } = release.releaseProfile(sourceDirectory);
  const names = [
    ...new Set<string>([...profile.worker.legalFiles, ...profile.image.legalFiles]),
  ].sort();
  const files: Record<string, string> = {};
  for (const name of names)
    files[name] = new TextDecoder("utf-8", { fatal: true })
      .decode(provenance.readOwned(sourceDirectory, name))
      .replaceAll("\r\n", "\n");
  const records: Record<string, unknown> = {};
  for (const id of audit.activeRecords)
    records[id] = provenance.parseDocument(
      provenance.readOwned(sourceDirectory, `${provenance.store}${id}.json`),
    );
  const bundle = {
    schemaVersion: 1,
    repository: "https://github.com/ArcForges/Cloud",
    revision: bridgeSource.commit,
    source: { commit: audit.sourceCommit, dirty: audit.dirty, noticeSha256: audit.noticeSha256 },
    profile: { path: profilePath, sha256: profileHash },
    artifacts,
    records,
    files,
  };
  // The 8e5 r110 receipt still says Go 1.27.3. Bind a separate current producer
  // record to the actual 1.27.4 standard-library licence without rewriting it.
  const license = readOwned(producerDirectory, "third-party/Go.LICENSE.txt");
  const recordBytes = readOwned(producerDirectory, "eng/provenance/records/go-go-legal-r2.json");
  const record = validateRecord(parseDocument(recordBytes));
  assert.equal(record.id, "go-go-legal-r2");
  assert.equal(record.sourceCommit, "7b2881024c95a11ddb86663a616340aa3a88b67f");
  assert.equal(record.supersedes, "go-go-legal-r1");
  assert.equal(sha256(license), "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad");
  const securityGo = {
    "security-bridge/go-1.27.4/LICENSE": license,
    "security-bridge/go-1.27.4/go-go-legal-r2.json": recordBytes,
  };
  const imageReceipt = {
    schemaVersion: 1,
    revision: bridgeSource.commit,
    source: bundle.source,
    profile: bundle.profile,
    records: bundle.records,
    legal: Object.fromEntries(
      profile.image.legalFiles.map((name: string) => {
        const content = files[name];
        assert(typeof content === "string" && content.trim());
        return [name, sha256(content)];
      }),
    ),
    baseLegal: profile.image.baseLegal,
  };
  return {
    audit,
    licenceAudit,
    profile,
    bundle,
    imageReceipt,
    securityGo,
    verifyWorker: release.verifyWorker as (
      owner: string,
      bundle: Buffer,
      metadata: unknown,
    ) => unknown,
  };
}

function tree(directory: string): string[] {
  const names: string[] = [];
  const visit = (relative: string) => {
    for (const entry of readdirSync(path.join(directory, relative))) {
      const name = path.posix.join(relative, entry);
      const info = lstatSync(path.join(directory, name));
      assert(!info.isSymbolicLink(), "Linked bridge image member");
      if (info.isDirectory()) visit(name);
      else {
        assert(info.isFile(), "Non-regular bridge image member");
        names.push(name);
      }
    }
  };
  visit("");
  return names.sort();
}

function setNewNoticeModes(directory: string): void {
  const walk = (current: string) => {
    const info = lstatSync(current);
    assert(!info.isSymbolicLink());
    if (info.isDirectory()) {
      chmodSync(current, 0o755);
      for (const name of readdirSync(current)) walk(path.join(current, name));
    } else {
      assert(info.isFile());
      chmodSync(current, 0o644);
    }
  };
  walk(directory);
}

function assertReadableTree(directory: string, executables: string[], skipRoot = false): void {
  const walk = (current: string, relative: string) => {
    const info = lstatSync(current);
    assert(!info.isSymbolicLink());
    const mode = info.mode & 0o777;
    if (info.isDirectory()) {
      if (relative || !skipRoot)
        assert.equal(mode, 0o755, `Untraversable image directory: ${relative}`);
      for (const name of readdirSync(current))
        walk(path.join(current, name), path.posix.join(relative, name));
    } else {
      assert(info.isFile());
      assert.equal(
        mode,
        executables.includes(relative) ? 0o755 : 0o644,
        `Unreadable image member: ${relative}`,
      );
    }
  };
  walk(directory, "");
}

/** Write only a new staging directory; it is an input to the image build, not a release. */
export function stageSecurityBridgeNotices(
  sourceDirectory: string,
  legal: Awaited<ReturnType<typeof securityBridgeLegal>>,
) {
  const artifacts = path.join(sourceDirectory, "artifacts");
  mkdirSync(artifacts, { recursive: true });
  assert(lstatSync(artifacts).isDirectory() && !lstatSync(artifacts).isSymbolicLink());
  const directory = path.join(artifacts, "image-notices");
  mkdirSync(directory);
  for (const name of legal.profile.image.legalFiles as string[]) {
    const destination = path.join(directory, name);
    mkdirSync(path.dirname(destination), { recursive: true });
    const contents = legal.bundle.files[name];
    assert(typeof contents === "string");
    writeFileSync(destination, contents, { flag: "wx" });
  }
  writeFileSync(path.join(directory, "provenance.json"), bytes(legal.imageReceipt), { flag: "wx" });
  for (const [name, content] of Object.entries(legal.securityGo)) {
    const destination = path.join(directory, name);
    mkdirSync(path.dirname(destination), { recursive: true });
    writeFileSync(destination, content, { flag: "wx" });
  }
  setNewNoticeModes(directory);
  assertReadableTree(directory, []);
  assert.deepEqual(
    tree(directory),
    [...legal.profile.image.legalFiles, "provenance.json", ...Object.keys(legal.securityGo)].sort(),
  );
}

/** Verify the complete /app tree copied from a stopped image and all legal material. */
export function verifySecurityBridgeImageFiles(
  sourceDirectory: string,
  appDirectory: string,
  legal: Awaited<ReturnType<typeof securityBridgeLegal>>,
) {
  const expected = [
    "ArcForges.Cloud",
    "arcforges-center",
    "LICENSE",
    "notices/provenance.json",
    ...(legal.profile.image.legalFiles as string[]).map((name) => `notices/${name}`),
    ...Object.keys(legal.securityGo).map((name) => `notices/${name}`),
  ].sort();
  assert.deepEqual(tree(appDirectory), expected, "Unclassified or missing bridge image member");
  // Docker copies into an existing private audit directory, whose mode is not the image root.
  assertReadableTree(appDirectory, ["ArcForges.Cloud", "arcforges-center"], true);
  assert(
    readFileSync(path.join(appDirectory, "notices/provenance.json")).equals(
      bytes(legal.imageReceipt),
    ),
  );
  assert.equal(
    readFileSync(path.join(appDirectory, "LICENSE"), "utf8").replaceAll("\r\n", "\n"),
    readFileSync(path.join(sourceDirectory, "LICENSE"), "utf8").replaceAll("\r\n", "\n"),
  );
  const members: Record<string, string> = {};
  for (const name of expected) members[name] = sha256(readFileSync(path.join(appDirectory, name)));
  for (const [name, expectedHash] of Object.entries(legal.imageReceipt.legal))
    assert.equal(members[`notices/${name}`], expectedHash, `Changed bridge legal text: ${name}`);
  for (const [name, content] of Object.entries(legal.securityGo))
    assert.equal(
      members[`notices/${name}`],
      sha256(content),
      `Changed security compiler legal text: ${name}`,
    );
  for (const name of ["ArcForges.Cloud", "arcforges-center"]) {
    assert(
      readFileSync(path.join(appDirectory, name))
        .subarray(0, 4)
        .equals(Buffer.from([127, 69, 76, 70])),
    );
    assert(
      lstatSync(path.join(appDirectory, name)).mode & 0o111,
      `Non-executable image member: ${name}`,
    );
  }
  return {
    revision: bridgeSource.commit,
    profile: legal.bundle.profile,
    members,
    records: Object.keys(legal.bundle.records).sort(),
    baseLegal: legal.imageReceipt.baseLegal,
  };
}
