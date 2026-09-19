// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  auditProvenance,
  comparisonCommit,
  git,
  hash,
  inventoryPath,
  noticePath,
  parseDocument,
  readOwned,
  relative,
  store,
  validateRecord,
} from "../../tooling/provenance.ts";
import { root as owner } from "../../tooling/process.ts";

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "cloud-provenance-"));
  const write = (file: string, value: unknown) => {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(
      path.join(root, file),
      typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`,
    );
  };
  const commit = () => {
    git(root, "add", ".");
    git(
      root,
      "-c",
      "user.name=Provenance Test",
      "-c",
      "user.email=provenance@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--allow-empty",
      "-qm",
      "Fixture",
    );
    return git(root, "rev-parse", "HEAD");
  };
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "core.autocrlf", "false");
  const initial = commit();
  const bytes = "Authored test fixture for the reuse validator.\n";
  const record = {
    schemaVersion: 1,
    id: "fixture-source-r1",
    kind: "source",
    sourceRepository: "https://example.invalid/fixture",
    sourceCommit: "a".repeat(40),
    sourcePaths: ["source.txt"],
    licence: {
      spdx: "MIT",
      category: "permissive",
      evidence: [
        { path: "LICENSE", sha256: "b".repeat(64), finding: "Test-only licence evidence." },
      ],
      scope: "Synthetic validator fixture only.",
      copyingPermission: null as string | null,
    },
    attribution: ["Test author attribution."],
    targets: [{ path: "reused.txt", sha256: hash(Buffer.from(bytes)), normalization: "lf" }],
    artifactTargets: [],
    disposition: "Copy",
    verification: {
      kind: "fixture",
      command: "Run validator tests",
      expected: "Reject the independently chosen invalid states",
      artifacts: [],
    },
    notice: {
      required: true,
      text: "Test author attribution.",
      files: [noticePath],
      distribution: "source",
      reason: "Fixture notice",
    },
    lifetime: { status: "permanent", owner: "Test owner", removalTrigger: null as string | null },
    generation: null,
    review: {
      owner: "Licensing and Provenance Owner",
      reviewer: "Test reviewer",
      reviewedOn: "2026-09-19",
      decision: "approved",
      rationale: "Synthetic test only",
      baselineCommit: initial,
      reconciliation: false,
    },
    supersedes: null as string | null,
  };
  write("reused.txt", bytes);
  write(`${store}${record.id}.json`, record);
  for (const file of ["eng/policy/reuse-policy.json", "eng/provenance/template.json"])
    write(file, readFileSync(path.join(owner, file), "utf8"));
  write(noticePath, "");
  write(inventoryPath, {});
  const inventory = {
    schemaVersion: 1,
    repository: "Cloud",
    firstParty: [
      "eng/policy/reuse-policy.json",
      "eng/provenance/template.json",
      `${store}${record.id}.json`,
      noticePath,
      inventoryPath,
    ],
    reused: { "reused.txt": record.id } as Record<string, string>,
    artifacts: [] as string[],
  };
  write(inventoryPath, inventory);
  auditProvenance(root, { base: initial, writeNotice: true });
  const baseline = commit();
  return {
    root,
    record,
    inventory,
    baseline,
    write,
    commit,
    save: () => {
      write(`${store}${record.id}.json`, record);
      write(inventoryPath, inventory);
    },
    check: () => auditProvenance(root, { base: baseline }),
    cleanup: () => {
      assert.equal(path.dirname(root), os.tmpdir());
      assert(path.basename(root).startsWith("cloud-provenance-"));
      rmSync(root, { recursive: true });
    },
  };
}
type Fixture = ReturnType<typeof fixture>;
function scenario(name: string, run: (f: Fixture) => void) {
  test(name, () => {
    const f = fixture();
    try {
      run(f);
    } finally {
      f.cleanup();
    }
  });
}

scenario("real Git inventory yields a clean, source-bound record and deterministic notice", (f) => {
  const result = f.check();
  assert.equal(result.sourceCommit, f.baseline);
  assert.equal(result.dirty, false);
  assert.equal(result.reusedFiles, 1);
  assert.deepEqual(result.activeRecords, ["fixture-source-r1"]);
  assert.match(readFileSync(path.join(f.root, noticePath), "utf8"), /Test author attribution/u);
});
for (const field of [
  "sourceRepository",
  "sourceCommit",
  "sourcePaths",
  "licence",
  "attribution",
  "targets",
  "disposition",
  "verification",
  "notice",
  "lifetime",
  "review",
  "generation",
])
  scenario(`reject a missing ${field} field`, (f) => {
    const record: Record<string, unknown> = { ...f.record };
    delete record[field];
    assert.throws(() => validateRecord(record), /Unknown or missing fields/u);
  });
scenario("reject blank attribution, oracle, temporary trigger and reviewer", (f) => {
  for (const mutate of [
    (r: typeof f.record) => {
      r.attribution = [" "];
    },
    (r: typeof f.record) => {
      r.verification.command = "";
    },
    (r: typeof f.record) => {
      r.lifetime.status = "temporary";
    },
    (r: typeof f.record) => {
      r.review.reviewer = "";
    },
  ]) {
    const r = structuredClone(f.record);
    mutate(r);
    assert.throws(() => validateRecord(r));
  }
});
scenario("require generated input and generator identities", (f) => {
  const r = {
    ...f.record,
    kind: "generated",
    generation: { generators: [], inputs: [], command: "test", outputSpdx: "MIT" },
  };
  assert.throws(() => validateRecord(r), /Missing generation identity/u);
});
scenario("source code cannot use the legal-document reproduction scope", (f) => {
  f.record.kind = "legal-document";
  f.record.licence.copyingPermission = "Test grant";
  for (const name of ["worker.ts", "LICENSE.js", "NOTICE.dll", "license-helper.cs"])
    assert.throws(
      () => validateRecord({ ...f.record, targets: [{ ...f.record.targets[0], path: name }] }),
      /not legal text/u,
    );
});
scenario("reject prohibited, unknown or misclassified source licences", (f) => {
  for (const [spdx, category] of [
    ["GPL-3.0-only", "gpl-only"],
    ["NOASSERTION", "unclear"],
    ["MadeUp", "permissive"],
    ["MIT", "agpl-compatible"],
  ])
    assert.throws(() =>
      validateRecord({ ...f.record, licence: { ...f.record.licence, spdx, category } }),
    );
});
scenario("GPL reference-only decisions cannot bind implementation", (f) => {
  const record = {
    ...f.record,
    disposition: "Reference Only",
    targets: [],
    licence: { ...f.record.licence, spdx: "GPL-3.0-only", category: "gpl-only" },
  };
  validateRecord(record);
  assert.throws(() => validateRecord({ ...record, targets: f.record.targets }), /cannot bind/u);
});
scenario("reject normalized invalid calendar dates and unapproved decisions", (f) => {
  for (const review of [
    { ...f.record.review, reviewedOn: "2026-02-30" },
    { ...f.record.review, decision: "pending" },
  ])
    assert.throws(() => validateRecord({ ...f.record, review }));
});
scenario("reject an unclassified new file", (f) => {
  f.write("unexpected.txt", "new");
  assert.throws(f.check, /inventory drift/u);
});
scenario("reject removed targets and changed reused bytes", (f) => {
  f.write("reused.txt", "changed");
  assert.throws(f.check, /Changed reused bytes/u);
  rmSync(path.join(f.root, "reused.txt"));
  assert.throws(f.check);
});
scenario("reject a missing referenced record", (f) => {
  rmSync(path.join(f.root, `${store}${f.record.id}.json`));
  git(f.root, "rm", "--cached", `${store}${f.record.id}.json`);
  f.inventory.firstParty = f.inventory.firstParty.filter((name) => !name.startsWith(store));
  f.write(inventoryPath, f.inventory);
  assert.throws(f.check, /No real provenance record/u);
});
scenario("reject used record mutations including terminal whitespace", (f) => {
  const file = `${store}${f.record.id}.json`;
  f.write(file, `${readFileSync(path.join(f.root, file), "utf8")}\n`);
  assert.throws(f.check, /Used record changed/u);
});
scenario("retiring a target preserves its immutable record", (f) => {
  const replacement = {
    ...f.record,
    id: "fixture-source-r2",
    supersedes: f.record.id,
    targets: [{ ...f.record.targets[0], sha256: hash(Buffer.from("changed\n")) }],
  };
  f.write(`${store}${replacement.id}.json`, replacement);
  f.inventory.firstParty.push(`${store}${replacement.id}.json`);
  f.inventory.reused["reused.txt"] = replacement.id;
  f.write("reused.txt", "changed\n");
  f.write(inventoryPath, f.inventory);
  auditProvenance(f.root, { base: f.baseline, writeNotice: true });
  assert.equal(f.check().records, 2);
  rmSync(path.join(f.root, `${store}${f.record.id}.json`));
  f.inventory.firstParty = f.inventory.firstParty.filter(
    (file) => file !== `${store}${f.record.id}.json`,
  );
  f.write(inventoryPath, f.inventory);
  assert.throws(f.check);
});
scenario("reject silent reclassification of reused source", (f) => {
  f.inventory.firstParty.push("reused.txt");
  delete f.inventory.reused["reused.txt"];
  f.save();
  assert.throws(f.check);
});
scenario("reject forked supersession and source identity cycles", (f) => {
  for (const id of ["fixture-source-r2", "fixture-source-r3"]) {
    f.write(`${store}${id}.json`, { ...f.record, id, supersedes: f.record.id });
    f.inventory.firstParty.push(`${store}${id}.json`);
  }
  f.save();
  assert.throws(f.check, /Forked supersession/u);
});
scenario("block unresolved contribution conflicts", (f) => {
  const file = "eng/provenance/conflicts/fixture.json";
  f.write(file, {
    schemaVersion: 1,
    id: "fixture",
    material: "reused.txt",
    evidence: "Unknown source grant",
    boundary: "AGPL",
    owner: "Licensing and Provenance Owner",
    requiredDecision: "Review or remove",
    status: "blocked",
    resolution: null,
  });
  f.inventory.firstParty.push(file);
  f.save();
  assert.throws(f.check, /Unresolved provenance conflict/u);
});
scenario("reject changed policy and lost notice", (f) => {
  const file = "eng/policy/reuse-policy.json";
  const original = readFileSync(path.join(f.root, file), "utf8");
  f.write(file, original.replace('"prohibited"', '"audit"'));
  assert.throws(f.check);
  f.write(file, original);
  f.write(noticePath, "Incomplete notice\n");
  assert.throws(f.check, /NOTICE drift/u);
});
scenario("reject absent trusted comparison history", (f) => {
  assert.throws(() => auditProvenance(f.root, { base: "f".repeat(40) }));
});
scenario("CI must use the event base and fail when it is absent", (f) => {
  const previousName = process.env.GITHUB_EVENT_NAME,
    previousPath = process.env.GITHUB_EVENT_PATH;
  try {
    process.env.GITHUB_EVENT_NAME = "pull_request";
    process.env.GITHUB_EVENT_PATH = path.join(f.root, "event.json");
    f.write("event.json", { pull_request: { base: { sha: f.baseline } } });
    assert.equal(comparisonCommit(f.root), f.baseline);
    f.write("event.json", {});
    assert.throws(() => comparisonCommit(f.root));
    process.env.GITHUB_EVENT_NAME = "push";
    f.write("event.json", { before: "0".repeat(40) });
    assert.throws(() => comparisonCommit(f.root), /Missing comparison base/u);
  } finally {
    for (const [key, value] of [
      ["GITHUB_EVENT_NAME", previousName],
      ["GITHUB_EVENT_PATH", previousPath],
    ]) {
      assert(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
scenario("inherited hook Git selection cannot redirect source or fixture operations", (f) => {
  const saved = new Map(
    ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"].map((key) => [key, process.env[key]]),
  );
  try {
    process.env.GIT_DIR = path.join(f.root, "unrelated.git");
    process.env.GIT_WORK_TREE = path.join(f.root, "unrelated-tree");
    process.env.GIT_INDEX_FILE = path.join(f.root, "unrelated-index");
    assert.equal(f.check().sourceCommit, f.baseline);
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
scenario("reject linked paths escaping a repository", (f) => {
  const outside = mkdtempSync(path.join(os.tmpdir(), "cloud-provenance-outside-"));
  try {
    writeFileSync(path.join(outside, "source.txt"), "outside");
    symlinkSync(
      outside,
      path.join(f.root, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    assert.throws(() => readOwned(f.root, "linked/source.txt"), /Escaping|Linked/u);
  } finally {
    assert.equal(path.dirname(outside), os.tmpdir());
    rmSync(outside, { recursive: true });
  }
});
test("reject ambiguous JSON, unsafe paths and invalid UTF-8 text", () => {
  for (const source of ['{"x":1,"x":2}', '{"a":{"x":1,"x":2}}', '{"x":1} false', "[1,]"])
    assert.throws(() => parseDocument(source));
  assert.deepEqual(parseDocument('{"x":[1,true,null,"escaped\\"value"]}'), {
    x: [1, true, null, 'escaped"value'],
  });
  for (const file of ["../x", "a/../x", "C:/x", "a\\b", "/x", "a/*", "a/./x", "a. /x"])
    assert.throws(() => relative(file));
  assert.throws(() => hash(Buffer.from([255]), "lf"));
  assert.equal(hash(Buffer.from("a\r\nb\n"), "lf"), hash(Buffer.from("a\nb\n")));
});
