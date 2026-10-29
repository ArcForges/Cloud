// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

test("the exact Npgsql licence is admitted while unknown licence claims remain refused", () => {
  const record = JSON.parse(
    readFileSync(
      path.join(owner, "eng/provenance/records/npgsql-postgresql-legal-r1.json"),
      "utf8",
    ),
  );
  assert.equal(validateRecord(record).id, "npgsql-postgresql-legal-r1");
  record.licence.spdx = "Unreviewed-Database-License";
  assert.throws(() => validateRecord(record), /Unreviewed licence/u);
});

type Allowlist = Record<string, string | string[]>;

/**
 * The allowlist blocks of .gitleaks.toml, read for exactly the subset the file uses: one `[extend]` table and `[[allowlists]]`
 * tables of string and string-array values. Anything else (another table, a value of another kind, text between the strings
 * of an array) fails, so the pins below see every row the scanner would.
 */
function gitleaksConfig(text: string): { extend: string[]; allowlists: Allowlist[] } {
  const strings = (body: string) => {
    const values: string[] = [];
    const rest = body.replace(/'''([^']*)'''|"((?:[^"\\]|\\.)*)"/gu, (_, literal, basic) => {
      values.push(literal ?? JSON.parse(`"${basic}"`));
      return "";
    });
    return { values, rest };
  };
  const extend: string[] = [];
  const allowlists: Allowlist[] = [];
  let table: "none" | "extend" | "allowlist" = "none";
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index] ?? "";
    if (line === "" || line.startsWith("#")) continue;
    if (line === "[extend]" || line === "[[allowlists]]") {
      table = line === "[extend]" ? "extend" : "allowlist";
      if (table === "allowlist") allowlists.push({});
      continue;
    }
    const entry = /^([A-Za-z]+) = (.*)$/u.exec(line);
    assert.ok(entry, `unexpected .gitleaks.toml line ${index + 1}`);
    const [, key = "", start = ""] = entry;
    if (table === "extend") {
      extend.push(`${key} = ${start}`);
      continue;
    }
    const current = allowlists.at(-1);
    assert.ok(current && table === "allowlist" && !(key in current), `unexpected key ${key}`);
    let value = start;
    if (value === "[") {
      while (lines[index + 1] !== "]") {
        index++;
        assert.ok(index < lines.length, "unterminated array");
        value += `\n${lines[index]}`;
      }
      index++;
      value += "\n]";
    }
    if (value.startsWith("[")) {
      const { values, rest } = strings(value);
      assert.match(rest, /^\[[\s,]*\]$/u, `unexpected array content in ${key}`);
      current[key] = values;
    } else {
      const { values, rest } = strings(value);
      assert.ok(values.length === 1 && rest === "", `unexpected value of ${key}`);
      current[key] = values[0] ?? "";
    }
  }
  return { extend, allowlists };
}

/**
 * A gitleaks (RE2) pattern as a JavaScript expression. The patterns use only a leading (?s) flag and escaped punctuation, which
 * needs the non-Unicode mode (RE2 accepts `\-` anywhere).
 */
function gitleaksPattern(pattern: string) {
  return pattern.startsWith("(?s)") ? new RegExp(pattern.slice(4), "s") : new RegExp(pattern);
}

test("the secret-scan allowlist holds exactly its reviewed blocks and the exact AF-CTR-03 digest rows", () => {
  const regexText = (value: string) => value.replace(/[-.]/gu, (c) => `\\${c}`);
  const lf = (file: string) =>
    createHash("sha256")
      .update(readFileSync(path.join(owner, file), "utf8").replaceAll("\r\n", "\n"))
      .digest("hex");
  const config = gitleaksConfig(readFileSync(path.join(owner, ".gitleaks.toml"), "utf8"));
  assert.deepEqual(config.extend, ["useDefault = true"]);
  const keys = ["description", "condition", "targetRules", "paths", "regexTarget", "regexes"];
  for (const block of config.allowlists) {
    assert.deepEqual(Object.keys(block), keys);
    assert.equal(block.condition, "AND");
    assert.deepEqual(block.targetRules, ["generic-api-key"]);
  }
  // S31 and S44: 64-hex values of the release profiles and of the Contracts identity copy, unchanged.
  const [s31, s44, ...rows] = config.allowlists;
  assert.ok(s31 && s44);
  assert.match(String(s31.description), /^S31: /u);
  assert.deepEqual(s31.paths, ["^eng/provenance/artifact-profiles/cloud-release-r[0-9]+\\.json$"]);
  assert.match(String(s44.description), /^S44: /u);
  assert.deepEqual(s44.paths, ["^eng/generated/contracts-identity\\.json$"]);
  for (const block of [s31, s44]) {
    assert.equal(block.regexTarget, "secret");
    assert.deepEqual(block.regexes, ["^[0-9a-f]{64}$"]);
  }
  // AF-CTR-03: one block per file (the policy and the receipts af-ctr-03-r1 to af-ctr-03-r8), each row one exact
  // key-and-digest line of an immutable record named in the inputs maps.
  // The digests are computed here from the records, so this file holds no digest literal.
  const records = [
    "eng/provenance/records/go-gowebauthn-legal-r1.json",
    "eng/provenance/records/go-gowebauthnx-legal-r1.json",
  ];
  const files = [
    "eng/policy/dependency-policy.json",
    "eng/policy/dependency-reviews/af-ctr-03-r1.json",
    "eng/policy/dependency-reviews/af-ctr-03-r2.json",
    "eng/policy/dependency-reviews/af-ctr-03-r3.json",
    "eng/policy/dependency-reviews/af-ctr-03-r4.json",
    "eng/policy/dependency-reviews/af-ctr-03-r5.json",
    "eng/policy/dependency-reviews/af-ctr-03-r6.json",
    "eng/policy/dependency-reviews/af-ctr-03-r7.json",
    "eng/policy/dependency-reviews/af-ctr-03-r8.json",
  ];
  assert.equal(rows.length, files.length, "a new allowlist block needs its own reviewed pin");
  const expected = records.map(
    (record) => `(?s)^\\s*"${regexText(record)}":\\s*"${lf(record)}",?\\s*$`,
  );
  files.forEach((file, index) => {
    const block = rows[index];
    assert.ok(block);
    assert.match(String(block.description), /^AF-CTR-03: /u);
    assert.equal(block.regexTarget, "line");
    assert.deepEqual(block.paths, [`^${regexText(file)}$`]);
    assert.deepEqual(block.regexes, expected);
    const exempt = gitleaksPattern(String(block.paths?.[0]));
    assert.ok(exempt.test(file));
    for (const other of [
      `${file}.backup`,
      `x/${file}`,
      ...files.filter((_, other) => other !== index),
      "eng/policy/dependency-reviews/af-ctr-03-r9.json",
    ])
      assert.ok(!exempt.test(other), other);
    // Positive control: the rows match exactly the lines that name the two records, and every row matches one.
    const patterns = expected.map(gitleaksPattern);
    const lines = readFileSync(path.join(owner, file), "utf8").split("\n");
    const naming = lines.filter((line) => records.some((record) => line.includes(`"${record}"`)));
    assert.deepEqual(
      lines.filter((line) => patterns.some((pattern) => pattern.test(line))),
      naming,
    );
    assert.equal(naming.length, index === 0 ? 4 : 2);
    for (const pattern of patterns) assert.ok(lines.some((line) => pattern.test(line)));
    // Negative controls: another digest, an upper-case digest, another key, more on the line.
    records.forEach((record, row) => {
      const pattern = patterns[row] ?? /$^/u;
      const digest = lf(record);
      assert.ok(pattern.test(`    "${record}": "${digest}",`));
      for (const line of [
        `    "${record}": "${"0".repeat(64)}",`,
        `    "${record}": "${digest.toUpperCase()}",`,
        `    "${record.replace("-r1.json", "-r2.json")}": "${digest}",`,
        `    "${record}": "${digest}", "other": "value",`,
        `    "${record}": "${digest}1",`,
      ])
        assert.ok(!pattern.test(line), line);
    });
  });
});
