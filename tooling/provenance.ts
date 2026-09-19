// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { gitEnvironment } from "./process.ts";

type ObjectValue = Record<string, unknown>;
export const store = "eng/provenance/records/";
export const inventoryPath = "eng/provenance/files.json";
export const noticePath = "eng/provenance/NOTICE.txt";
const policyPath = "eng/policy/reuse-policy.json";
const recordKeys =
  "schemaVersion id kind sourceRepository sourceCommit sourcePaths licence attribution targets artifactTargets disposition verification notice lifetime generation review supersedes";
export const decisions = {
  permissive: { AGPL: "audit", Apache: "audit" },
  "agpl-compatible": { AGPL: "exact-review", Apache: "prohibited" },
  "gpl-only": { AGPL: "prohibited", Apache: "prohibited" },
  unclear: { AGPL: "prohibited", Apache: "prohibited" },
  incompatible: { AGPL: "prohibited", Apache: "prohibited" },
};
export const licences: Record<string, keyof typeof decisions> = {
  "Apache-2.0": "permissive",
  MIT: "permissive",
  "BSD-2-Clause": "permissive",
  "BSD-3-Clause": "permissive",
  ISC: "permissive",
  "AGPL-3.0-only": "agpl-compatible",
  "GPL-2.0-only": "gpl-only",
  "GPL-3.0-only": "gpl-only",
  NOASSERTION: "unclear",
  "EPL-1.0": "incompatible",
};
export function object(value: unknown, fields?: string): ObjectValue {
  assert(
    value !== null && typeof value === "object" && !Array.isArray(value),
    "Expected JSON object",
  );
  if (fields)
    assert.deepEqual(
      Object.keys(value).sort(),
      fields.split(" ").sort(),
      "Unknown or missing fields",
    );
  return value as ObjectValue;
}
export function text(value: unknown): string {
  assert(
    typeof value === "string" && value.trim().length > 0 && !value.includes("\0"),
    "Required text is blank or invalid",
  );
  return value;
}
function rows(value: unknown): unknown[] {
  assert(Array.isArray(value), "Expected array");
  return value;
}
export function digest(value: unknown, length = 64): string {
  const result = text(value);
  assert(new RegExp(`^[a-f0-9]{${length}}$`, "u").test(result), "Invalid immutable digest");
  return result;
}
export function relative(value: unknown): string {
  const result = text(value);
  assert(
    !/[\\:*?<>|]/u.test(result) &&
      [...result].every((character) => character.charCodeAt(0) >= 32) &&
      !result.startsWith("/"),
    "Unsafe relative path",
  );
  assert(
    result.split("/").every((part) => part && ![".", ".."].includes(part) && !/[. ]$/u.test(part)),
    "Unsafe relative path",
  );
  return result;
}
function strings(value: unknown, check: (v: unknown) => string = text, nonempty = true): string[] {
  const result = rows(value).map(check);
  assert(!nonempty || result.length > 0, "Required list is empty");
  assert.equal(new Set(result).size, result.length, "Duplicate list entry");
  return result;
}
export function hash(data: Buffer, normalization = "raw"): string {
  assert(["raw", "lf"].includes(normalization), "Unknown byte normalization");
  return createHash("sha256")
    .update(
      normalization === "lf"
        ? Buffer.from(
            new TextDecoder("utf-8", { fatal: true }).decode(data).replaceAll("\r\n", "\n"),
          )
        : data,
    )
    .digest("hex");
}
export function readOwned(root: string, name: string): Buffer {
  root = realpathSync(root);
  const full = path.resolve(root, relative(name));
  assert(
    full.startsWith(root + path.sep) && realpathSync(full).startsWith(root + path.sep),
    "Escaping source path",
  );
  for (let current = full; current !== root; current = path.dirname(current))
    assert(!lstatSync(current).isSymbolicLink(), "Linked source path");
  assert(lstatSync(full).isFile(), "Expected regular source file");
  return readFileSync(full);
}
// Detect ambiguous duplicate keys before JSON.parse can silently discard them.
export function parseDocument(input: Buffer | string): unknown {
  const source =
    typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
  let cursor = 0;
  const space = () => {
    while (/\s/u.test(source[cursor] ?? "") && cursor < source.length) cursor++;
  };
  const quoted = (): string => {
    const start = cursor++;
    while (cursor < source.length) {
      const char = source[cursor++];
      if (char === "\\") cursor++;
      else if (char === '"') return JSON.parse(source.slice(start, cursor)) as string;
    }
    throw new Error("Unterminated JSON string");
  };
  const scan = (depth: number): void => {
    assert(depth < 100, "Excessive JSON depth");
    space();
    const char = source[cursor];
    if (char === '"') {
      quoted();
      return;
    }
    if (char === "{" || char === "[") {
      cursor++;
      space();
      const end = char === "{" ? "}" : "]";
      const keys = new Set<string>();
      if (source[cursor] === end) {
        cursor++;
        return;
      }
      while (cursor < source.length) {
        if (char === "{") {
          assert.equal(source[cursor], '"', "Invalid JSON key");
          const key = quoted();
          assert(!keys.has(key), "Duplicate JSON key");
          keys.add(key);
          space();
          assert.equal(source[cursor++], ":", "Invalid JSON object");
        }
        scan(depth + 1);
        space();
        if (source[cursor] === end) {
          cursor++;
          return;
        }
        assert.equal(source[cursor++], ",", "Invalid JSON separator");
        space();
      }
      throw new Error("Unterminated JSON collection");
    }
    const literal =
      /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(
        source.slice(cursor),
      );
    assert(literal, "Invalid JSON literal");
    cursor += literal[0].length;
  };
  scan(0);
  space();
  assert.equal(cursor, source.length, "Trailing JSON material");
  return JSON.parse(source) as unknown;
}
const document = (root: string, file: string) => object(parseDocument(readOwned(root, file)));
export function git(root: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    env: gitEnvironment(),
  }).trim();
}
function repository(value: unknown) {
  const url = new URL(text(value));
  assert(
    url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      url.pathname !== "/",
    "Invalid canonical repository",
  );
}
function evidence(value: unknown) {
  const entries = rows(value);
  assert(entries.length > 0, "Missing file-level evidence");
  for (const item of entries) {
    const row = object(item, "path sha256 finding");
    relative(row.path);
    digest(row.sha256);
    text(row.finding);
  }
}
function allowed(spdx: unknown, category?: unknown, used = true) {
  const name = text(spdx);
  assert(Object.hasOwn(licences, name), "Unreviewed licence expression");
  const classification = licences[name];
  assert(classification);
  if (category !== undefined)
    assert.equal(category, classification, "Incorrect licence classification");
  if (used)
    assert.notEqual(decisions[classification].AGPL, "prohibited", "Prohibited source licence");
}
function source(value: unknown) {
  const item = object(value, "repository commit paths spdx evidence");
  repository(item.repository);
  digest(item.commit, 40);
  strings(item.paths, relative);
  allowed(item.spdx);
  evidence(item.evidence);
}
export function validateRecord(value: unknown): ObjectValue {
  const r = object(value, recordKeys);
  assert.equal(r.schemaVersion, 1);
  assert(/^[a-z0-9]+(?:-[a-z0-9]+)*-r[1-9][0-9]*$/u.test(text(r.id)), "Invalid record ID");
  assert(["source", "generated", "legal-document"].includes(text(r.kind)), "Unknown material kind");
  repository(r.sourceRepository);
  digest(r.sourceCommit, 40);
  strings(r.sourcePaths, relative);
  const legal = object(r.licence, "spdx category evidence scope copyingPermission");
  allowed(legal.spdx, legal.category, !["Reference Only", "Drop"].includes(text(r.disposition)));
  evidence(legal.evidence);
  text(legal.scope);
  if (r.kind === "legal-document") text(legal.copyingPermission);
  else
    assert.equal(legal.copyingPermission, null, "Source cannot claim the legal-document exemption");
  strings(r.attribution);
  const targets = rows(r.targets);
  if (r.kind === "legal-document")
    assert.equal(
      rows(r.artifactTargets).length,
      0,
      "Legal text cannot bind generated implementation",
    );
  const targetPaths: string[] = [];
  for (const value of targets) {
    const target = object(value, "path sha256 normalization");
    targetPaths.push(relative(target.path));
    digest(target.sha256);
    assert(["raw", "lf"].includes(text(target.normalization)), "Unknown normalization");
    if (r.kind === "legal-document")
      assert(
        /^(?:[a-z0-9_-]+[.])*(?:license|licence|copying|notices?)(?:[.](?:txt|md))?$/iu.test(
          path.basename(text(target.path)),
        ),
        "Legal document target is not legal text",
      );
  }
  assert.equal(targetPaths.length, new Set(targetPaths).size, "Duplicate record target");
  for (const value of rows(r.artifactTargets)) {
    const target = object(value, "project package kind profile sha256");
    relative(target.project);
    text(target.package);
    text(target.kind);
    relative(target.profile);
    digest(target.sha256);
  }
  assert(
    ["Copy", "Rewrite", "Improve", "Replace", "Reference Only", "Drop"].includes(
      text(r.disposition),
    ),
    "Unknown disposition",
  );
  if (["Reference Only", "Drop"].includes(text(r.disposition)))
    assert.equal(
      targets.length + rows(r.artifactTargets).length,
      0,
      "Reference material cannot bind reused targets",
    );
  else assert(targets.length + rows(r.artifactTargets).length > 0, "Used record has no targets");
  const verification = object(r.verification, "kind command expected artifacts");
  text(verification.kind);
  text(verification.command);
  text(verification.expected);
  for (const value of rows(verification.artifacts)) {
    const archive = object(value, "url sha256 members");
    repository(archive.url);
    digest(archive.sha256);
    strings(archive.members, relative);
  }
  const notice = object(r.notice, "required text files distribution reason");
  assert.equal(typeof notice.required, "boolean");
  text(notice.reason);
  text(notice.distribution);
  strings(notice.files, relative, notice.required as boolean);
  if (notice.required) text(notice.text);
  else assert.equal(notice.text, null);
  const lifetime = object(r.lifetime, "status owner removalTrigger");
  text(lifetime.owner);
  assert(["temporary", "permanent"].includes(text(lifetime.status)), "Unknown lifetime");
  if (lifetime.status === "temporary") text(lifetime.removalTrigger);
  else assert.equal(lifetime.removalTrigger, null);
  if (r.kind === "generated") {
    const generation = object(r.generation, "generators inputs command outputSpdx");
    for (const key of ["generators", "inputs"]) {
      const entries = rows(generation[key]);
      assert(entries.length > 0, "Missing generation identity");
      entries.forEach(source);
    }
    text(generation.command);
    assert.equal(generation.outputSpdx, legal.spdx);
  } else assert.equal(r.generation, null, "Only generated records declare generation");
  const review = object(
    r.review,
    "owner reviewer reviewedOn decision rationale baselineCommit reconciliation",
  );
  assert.equal(review.owner, "Licensing and Provenance Owner");
  text(review.reviewer);
  text(review.rationale);
  assert(
    /^\d{4}-\d{2}-\d{2}$/u.test(text(review.reviewedOn)) &&
      !Number.isNaN(Date.parse(text(review.reviewedOn))) &&
      new Date(text(review.reviewedOn)).toISOString().slice(0, 10) === review.reviewedOn,
    "Invalid review date",
  );
  assert.equal(review.decision, "approved", "Unapproved contribution");
  digest(review.baselineCommit, 40);
  assert.equal(typeof review.reconciliation, "boolean");
  if (r.supersedes !== null)
    assert(
      /^[a-z0-9]+(?:-[a-z0-9]+)*-r[1-9][0-9]*$/u.test(text(r.supersedes)) && r.supersedes !== r.id,
      "Invalid superseding record",
    );
  return r;
}
export function comparisonCommit(root: string): string {
  let candidate: string;
  if (process.env.GITHUB_EVENT_NAME) {
    assert(process.env.GITHUB_EVENT_PATH, "Missing trusted event history");
    const event = object(parseDocument(readFileSync(process.env.GITHUB_EVENT_PATH)));
    switch (process.env.GITHUB_EVENT_NAME) {
      case "pull_request":
        candidate = text(object(object(event.pull_request).base).sha);
        break;
      case "push":
        candidate = text(event.before);
        break;
      case "merge_group":
        candidate = text(object(event.merge_group).base_sha);
        break;
      case "workflow_dispatch":
      case "schedule":
        candidate = git(root, "rev-parse", "HEAD");
        break;
      default:
        throw new Error("Unsupported comparison event");
    }
  } else
    candidate =
      git(root, "symbolic-ref", "--short", "HEAD") === "main"
        ? git(root, "rev-parse", "HEAD")
        : git(root, "rev-parse", "origin/main");
  digest(candidate, 40);
  assert(!/^0+$/u.test(candidate), "Missing comparison base");
  git(root, "cat-file", "-e", `${candidate}^{commit}`);
  return candidate;
}
export function renderNotice(records: Map<string, ObjectValue>, active: string[]): Buffer {
  const lines = [
    "Cloud source provenance",
    "",
    "Original material retains its recorded licence and full legal text.",
    "",
  ];
  for (const id of [...active].sort()) {
    const r = records.get(id);
    assert(r);
    const n = object(r.notice);
    lines.push(
      id,
      `${text(r.sourceRepository)} @ ${text(r.sourceCommit)}`,
      text(object(r.licence).spdx),
      n.required ? text(n.text) : text(n.reason),
      "",
    );
  }
  return Buffer.from(lines.join("\n"));
}
export function auditProvenance(
  root: string,
  options: { base?: string; writeNotice?: boolean } = {},
) {
  root = realpathSync(root);
  const head = git(root, "rev-parse", "HEAD");
  const state = git(root, "status", "--porcelain");
  const policy = object(
    document(root, policyPath),
    "schemaVersion repository licenceBoundary authority decisions licences",
  );
  assert.equal(policy.schemaVersion, 1);
  assert.equal(policy.repository, "Cloud");
  assert.equal(policy.licenceBoundary, "AGPL");
  assert.deepEqual(policy.decisions, decisions);
  assert.deepEqual(policy.licences, licences);
  const authority = object(policy.authority, "repository commit path");
  assert.equal(authority.repository, "https://github.com/ArcForges/ArcForges-Design");
  digest(authority.commit, 40);
  assert.equal(authority.path, "docs/assurance/reference-coverage-and-provenance.md");
  const template = object(
    document(root, "eng/provenance/template.json"),
    "schemaVersion instructions example",
  );
  assert.equal(template.schemaVersion, 1);
  text(template.instructions);
  object(template.example, recordKeys);
  const inventory = object(
    document(root, inventoryPath),
    "schemaVersion repository firstParty reused artifacts",
  );
  assert.equal(inventory.schemaVersion, 1);
  assert.equal(inventory.repository, "Cloud");
  const firstParty = strings(inventory.firstParty, relative);
  const reused = object(inventory.reused);
  const artifacts = strings(inventory.artifacts, text, false);
  const classified = [...firstParty, ...Object.keys(reused)];
  classified.forEach(relative);
  assert.equal(classified.length, new Set(classified).size, "Repeated file classification");
  const actual = [
    ...new Set(
      git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        .split("\0")
        .filter(Boolean),
    ),
  ].sort();
  assert.deepEqual(classified.sort(), actual, "Source inventory drift");
  for (const name of actual) readOwned(root, name);
  const records = new Map<string, ObjectValue>();
  for (const file of actual.filter((file) => file.startsWith(store))) {
    assert(
      file.endsWith(".json") && path.posix.dirname(file) === store.slice(0, -1),
      "Unknown record member",
    );
    const record = validateRecord(document(root, file));
    assert.equal(file, `${store}${text(record.id)}.json`);
    assert(!records.has(text(record.id)), "Duplicate record identity");
    records.set(text(record.id), record);
  }
  assert(records.size > 0, "No real provenance record");
  const retired = new Set<string>();
  for (const record of records.values()) {
    let current = record;
    const visited = new Set([text(record.id)]);
    while (current.supersedes !== null) {
      const id = text(current.supersedes);
      assert(!visited.has(id) && records.has(id), "Broken superseding chain");
      visited.add(id);
      current = records.get(id) as ObjectValue;
    }
    if (record.supersedes !== null) {
      const id = text(record.supersedes);
      assert(!retired.has(id), "Forked supersession");
      retired.add(id);
    }
  }
  const active = [...new Set([...Object.values(reused).map(text), ...artifacts])];
  assert(active.length > 0, "No active real record");
  for (const id of active) {
    const record = records.get(id);
    assert(record && !retired.has(id), "Missing or retired active record");
    for (const item of rows(record.targets)) {
      const target = object(item);
      const name = text(target.path);
      assert.equal(reused[name], id, "Missing record target binding");
      assert.equal(
        hash(readOwned(root, name), text(target.normalization)),
        target.sha256,
        "Changed reused bytes",
      );
    }
    for (const item of rows(record.artifactTargets)) {
      const target = object(item);
      assert(artifacts.includes(id), "Unregistered artifact record");
      readOwned(root, text(target.project));
      assert.equal(
        hash(readOwned(root, text(target.profile)), "lf"),
        target.sha256,
        "Changed artifact profile",
      );
    }
    for (const file of strings(object(record.notice).files, relative, false)) readOwned(root, file);
  }
  for (const [name, id] of Object.entries(reused))
    assert(
      rows(records.get(text(id))?.targets).some((t) => object(t).path === name),
      "Unbound reused file",
    );
  for (const id of artifacts)
    assert(rows(records.get(id)?.artifactTargets).length > 0, "Empty artifact binding");
  for (const record of records.values()) {
    const hasMaterial = rows(record.targets).length + rows(record.artifactTargets).length > 0;
    assert(
      !hasMaterial ||
        active.includes(text(record.id)) ||
        retired.has(text(record.id)) ||
        (rows(record.artifactTargets).length === 0 &&
          rows(record.targets).every((target) => !actual.includes(text(object(target).path)))),
      "Used record silently abandoned",
    );
  }
  const base = options.base ?? comparisonCommit(root);
  digest(base, 40);
  git(root, "cat-file", "-e", `${base}^{commit}`);
  const oldFiles = git(root, "ls-tree", "-r", "--name-only", base).split("\n");
  for (const file of oldFiles.filter((file) => file.startsWith(store)))
    assert.equal(
      readOwned(root, file).toString("utf8").replaceAll("\r\n", "\n"),
      execFileSync("git", ["show", `${base}:${file}`], {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
        env: gitEnvironment(),
      }).replaceAll("\r\n", "\n"),
      "Used record changed or removed",
    );
  if (oldFiles.includes(inventoryPath)) {
    const old = object(parseDocument(git(root, "show", `${base}:${inventoryPath}`)));
    for (const [file, oldId] of Object.entries(object(old.reused))) {
      if (!actual.includes(file) || reused[file] === oldId) continue;
      assert(reused[file], "Reused file reclassified as authored");
      let record = records.get(text(reused[file]));
      while (record && record.supersedes !== oldId && record.supersedes !== null)
        record = records.get(text(record.supersedes));
      assert(record?.supersedes === oldId, "Changed reuse lacks supersession");
    }
  }
  const conflicts = actual.filter((name) => name.startsWith("eng/provenance/conflicts/"));
  for (const file of conflicts) {
    const conflict = object(
      document(root, file),
      "schemaVersion id material evidence boundary owner requiredDecision status resolution",
    );
    assert.equal(conflict.schemaVersion, 1);
    for (const key of ["id", "material", "evidence", "boundary", "owner", "requiredDecision"])
      text(conflict[key]);
    assert.equal(conflict.status, "resolved", "Unresolved provenance conflict");
    text(conflict.resolution);
  }
  const notice = renderNotice(records, active);
  if (options.writeNotice) writeFileSync(path.join(root, noticePath), notice);
  else assert.deepEqual(readOwned(root, noticePath), notice, "Provenance NOTICE drift");
  assert.equal(git(root, "rev-parse", "HEAD"), head, "Source changed during audit");
  if (!options.writeNotice)
    assert.equal(git(root, "status", "--porcelain"), state, "Worktree changed during audit");
  return {
    result: "passed",
    repository: "Cloud",
    sourceCommit: head,
    comparisonCommit: base,
    dirty: Boolean(git(root, "status", "--porcelain")),
    files: actual.length,
    reusedFiles: Object.keys(reused).length,
    records: records.size,
    activeRecords: active.sort(),
    noticeSha256: hash(notice),
  };
}
