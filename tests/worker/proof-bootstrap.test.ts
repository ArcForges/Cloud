// SPDX-License-Identifier: AGPL-3.0-only
// The proof bootstrap (AF-CTR-03 A2): the operator script that generates the owner's one-time token, the user-only files it and the
// browser acceptance script use, the dispatch inputs that carry the token's digest to the Worker, and the rule that no checked-in
// configuration carries a bootstrap.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { grants, sid, whoami, windowsMachine } from "./support/windows-machine.ts";
import {
  bootstrapFileName,
  createBootstrapFile,
  digestOfToken,
  generateBootstrap,
  parseBootstrapRecord,
  readBootstrapFile,
  runBootstrap,
} from "../../eng/verification/proof-bootstrap.ts";
import {
  type CandidateConfig,
  buildProofConfig,
  checkProofBootstrap,
  maxBootstrapLeadMs,
  proofBootstrapFromEnvironment,
  sealedProofBundle,
} from "../../eng/verification/proof-deploy.ts";
import {
  type Machine,
  assertUserOnly,
  ensureUserOnlyDirectory,
  parseIcaclsPrincipals,
  parseWhoami,
  readUserOnlyFile,
  realMachine,
  replaceUserOnlyFile,
  windowsGrantArguments,
  writeUserOnlyFile,
} from "../../eng/verification/user-only.ts";

const root = path.resolve(import.meta.dirname, "../..");
const script = path.join(root, "eng/verification/proof-bootstrap.ts");
const wrangler = JSON.parse(
  readFileSync(path.join(root, "wrangler.json"), "utf8"),
) as CandidateConfig;
const ciText = readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
const now = new Date("2026-11-01T10:00:00.789Z");
const zeros = (bytes: number) => new Uint8Array(bytes);

const scratches: string[] = [];
function scratch(): string {
  const directory = mkdtempSync(path.join(os.tmpdir(), "af-bootstrap-"));
  scratches.push(directory);
  return directory;
}
test.after(() => {
  for (const directory of scratches) rmSync(directory, { recursive: true, force: true });
});

// The digest is the SHA-256 of the exact token text, prefix included. The vector is the center's own (session.BootstrapDigest's
// known-answer test): 32 zero bytes are 43 'A' characters.
const knownToken = `afb1.${"A".repeat(43)}`;
const knownDigest = "09e0b22a38f1d38f287867c42c2969cf2063ee0194d43f87cb6f1ec7654df8b8";

test("the token is afb1. and 43 base64url characters and its digest is the center's", () => {
  const fixed = generateBootstrap({ hours: 24, now, random: zeros });
  assert.equal(fixed.token, knownToken);
  assert.equal(fixed.sha256, knownDigest);
  assert.equal(digestOfToken(knownToken), knownDigest);
  // The digest is of the text, not of the decoded bytes.
  assert.notEqual(fixed.sha256, digestOfToken("A".repeat(43)));
  const first = generateBootstrap({ hours: 24, now });
  const second = generateBootstrap({ hours: 24, now });
  assert.match(first.token, /^afb1\.[A-Za-z0-9_-]{43}$/u);
  assert.notEqual(first.token, second.token);
  assert.match(first.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(first.sha256, digestOfToken(first.token));
  assert.throws(() => generateBootstrap({ hours: 24, now, random: () => new Uint8Array(31) }));
});

test("the expiry is to the second, in UTC, within seven days and accepted by the dispatch rule", () => {
  assert.equal(generateBootstrap({ hours: 24, now }).expiresAt, "2026-11-02T10:00:00Z");
  assert.equal(generateBootstrap({ hours: 1, now }).expiresAt, "2026-11-01T11:00:00Z");
  const longest = generateBootstrap({ hours: 168, now });
  assert.equal(longest.expiresAt, "2026-11-08T10:00:00Z");
  // The longest token is accepted at the moment it was made, and its lead only shrinks.
  assert.deepEqual(
    checkProofBootstrap({ sha256: longest.sha256, expiresAt: longest.expiresAt }, now),
    {
      sha256: longest.sha256,
      expiresAt: longest.expiresAt,
    },
  );
  assert.equal(maxBootstrapLeadMs, 7 * 24 * 3_600_000);
  for (const hours of [0, 169, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])
    assert.throws(() => generateBootstrap({ hours, now }), /--hours/u, String(hours));
});

test("the command prints the digest and the expiry and nothing else, and writes the token for its owner alone", () => {
  const directory = path.join(scratch(), "proof-bootstrap");
  const lines: string[] = [];
  runBootstrap(["--dir", directory], { out: (line) => lines.push(line) }, { now, random: zeros });
  assert.deepEqual(lines, [
    `bootstrap_sha256: ${knownDigest}`,
    "bootstrap_expires_at: 2026-11-02T10:00:00Z",
  ]);
  const file = path.join(directory, bootstrapFileName);
  // POSIX modes; on Windows the DACL tests below (a fake machine, and the real one in the other tests) hold the same promise.
  if (process.platform !== "win32") {
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(statSync(directory).mode & 0o777, 0o700);
  }
  const record = readBootstrapFile(file);
  assert.equal(record.token, knownToken);
  assert.equal(record.sha256, knownDigest);
  assert.equal(record.expiresAt, "2026-11-02T10:00:00Z");
  for (const line of lines) assert(!line.includes(knownToken) && !line.includes(file));
  // One-shot: a second run neither replaces the file nor prints anything.
  const again: string[] = [];
  const before = readFileSync(file, "utf8");
  assert.throws(
    () => runBootstrap(["--dir", directory], { out: (line) => again.push(line) }, { now }),
    /one-shot/u,
  );
  assert.deepEqual(again, []);
  assert.equal(readFileSync(file, "utf8"), before);
  // A token that is made but not written is never reported: a failing write prints nothing.
  const refused: string[] = [];
  assert.throws(() =>
    runBootstrap(
      ["--dir", path.join(scratch(), "x")],
      { out: (line) => refused.push(line) },
      {
        machine: {
          platform: "linux",
          run: () => "",
          uid: () => (process.getuid?.() ?? 0) + 1,
        },
      },
    ),
  );
  assert.deepEqual(refused, []);
});

test("the command reads its arguments strictly and falls back to the directory of the environment", () => {
  const base = scratch();
  for (const argv of [
    ["--hours"],
    ["--hours", "x"],
    ["--hours", "0"],
    ["--hours", "169"],
    ["--hours", "1.5"],
    ["--dir"],
    ["--token", "afb1.x"],
    ["24"],
    ["--hours", "24", "extra"],
  ])
    assert.throws(
      () =>
        runBootstrap(argv, { out: () => {} }, { environment: { PROOF_BOOTSTRAP_DIR: base }, now }),
      Error,
      argv.join(" "),
    );
  assert.deepEqual(readdirNames(base), [], "a refused command leaves nothing behind");
  const lines: string[] = [];
  runBootstrap(
    [],
    { out: (line) => lines.push(line) },
    { environment: { PROOF_BOOTSTRAP_DIR: base }, now },
  );
  assert.equal(lines.length, 2);
  assert(existsSync(path.join(base, bootstrapFileName)));
});

function readdirNames(directory: string): string[] {
  return readdirSync(directory).sort();
}

test("run as a program it prints two lines to the standard output and no token anywhere", () => {
  const home = scratch();
  const result = spawnSync(process.execPath, [script, "--hours", "2"], {
    encoding: "utf8",
    env: { ...process.env, HOME: home, USERPROFILE: home, PROOF_BOOTSTRAP_DIR: "" },
  });
  assert.equal(result.status, 0, result.stderr);
  const file = path.join(home, ".arcforges", "proof-bootstrap", bootstrapFileName);
  const record = parseBootstrapRecord(readFileSync(file, "utf8"));
  const lines = result.stdout.trimEnd().split("\n");
  assert.equal(lines.length, 2);
  assert.match(lines[0] ?? "", /^bootstrap_sha256: [0-9a-f]{64}$/u);
  assert.match(lines[1] ?? "", /^bootstrap_expires_at: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u);
  assert(!result.stdout.includes(record.token) && !result.stderr.includes(record.token));
  const second = spawnSync(process.execPath, [script], {
    encoding: "utf8",
    env: { ...process.env, HOME: home, USERPROFILE: home, PROOF_BOOTSTRAP_DIR: "" },
  });
  assert.equal(second.status, 1);
  assert.equal(second.stdout, "");
  assert(!second.stderr.includes(record.token));
  const usage = spawnSync(process.execPath, [script, "--bad"], { encoding: "utf8" });
  assert.equal(usage.status, 1);
  assert.equal(usage.stdout, "");
});

test("a bootstrap file is read back only when it is the file the command writes", () => {
  const good = generateBootstrap({ hours: 24, now, random: zeros });
  const text = JSON.stringify(good);
  assert.deepEqual(parseBootstrapRecord(text), good);
  const damaged: [string, unknown][] = [
    ["not JSON", "{"],
    ["not an object", "[]"],
    ["version", { ...good, version: 2 }],
    ["token shape", { ...good, token: "afb1.short" }],
    ["token prefix", { ...good, token: `afb2.${"A".repeat(43)}` }],
    ["digest of another token", { ...good, sha256: "0".repeat(64) }],
    ["uppercase digest", { ...good, sha256: good.sha256.toUpperCase() }],
    ["expiry shape", { ...good, expiresAt: "2026-11-02T10:00:00+00:00" }],
    ["expiry with fraction", { ...good, expiresAt: "2026-11-02T10:00:00.5Z" }],
  ];
  for (const [name, value] of damaged) {
    const body = typeof value === "string" ? value : JSON.stringify(value);
    assert.throws(
      () => parseBootstrapRecord(body),
      (error: Error) => !error.message.includes("AAAA") && !error.message.includes(good.sha256),
      name,
    );
  }
});

// ---------------------------------------------------------------------------------------------------------------------------
// User-only files

test("a user-only file is created exclusively, replaced whole and read back", () => {
  const directory = path.join(scratch(), "state");
  const file = path.join(directory, "credential.json");
  writeUserOnlyFile(file, "secret one\n");
  assert.equal(readUserOnlyFile(file), "secret one\n");
  assert.throws(() => writeUserOnlyFile(file, "replaced"), /EEXIST/u);
  assert.equal(readUserOnlyFile(file), "secret one\n", "the existing file is not touched");
  replaceUserOnlyFile(file, "secret two\n");
  assert.deepEqual(
    readdirNames(directory),
    ["credential.json"],
    "no temporary file is left behind",
  );
  assert.equal(readUserOnlyFile(file), "secret two\n");
  const created = createBootstrapFile(
    path.join(scratch(), "d"),
    generateBootstrap({ hours: 1, now }),
  );
  assert(existsSync(created));
});

// The POSIX half: modes and owners. On Windows the same promise is the DACL, which the tests with a Windows machine below hold.
test(
  "POSIX: a user-only file is private from its first byte and every read and write checks it",
  { skip: process.platform === "win32" && "POSIX modes" },
  () => {
    const directory = path.join(scratch(), "state");
    const file = path.join(directory, "credential.json");
    writeUserOnlyFile(file, "secret one\n");
    assert.equal(statSync(directory).mode & 0o777, 0o700);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    replaceUserOnlyFile(file, "secret two\n");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    // Anyone else's access is refused before the content is read or written, and the message names the path only.
    for (const mode of [0o640, 0o604, 0o644, 0o660, 0o666, 0o607]) {
      chmodSync(file, mode);
      assert.throws(
        () => readUserOnlyFile(file),
        (error: Error) => error.message.includes(file) && !error.message.includes("secret"),
        mode.toString(8),
      );
      assert.throws(() => replaceUserOnlyFile(file, "no"), /readable by more than its owner/u);
      assert.throws(() => assertUserOnly(file), /readable/u);
    }
    chmodSync(file, 0o600);
    chmodSync(directory, 0o750);
    assert.throws(() => readUserOnlyFile(file), /readable/u, "a group-readable directory");
    ensureUserOnlyDirectory(directory, realMachine(), (name) => name === "credential.json");
    assert.equal(
      statSync(directory).mode & 0o777,
      0o700,
      "a directory of the tool's own files is tightened",
    );
    assert.equal(readUserOnlyFile(file), "secret two\n");
    // A file of another owner is refused even at 0600.
    const foreign: Machine = {
      platform: "linux",
      run: () => "",
      uid: () => (process.getuid?.() ?? 0) + 1,
    };
    assert.throws(() => assertUserOnly(file, foreign), /readable/u);
    const created = createBootstrapFile(
      path.join(scratch(), "d"),
      generateBootstrap({ hours: 1, now }),
    );
    assert.equal(statSync(created).mode & 0o777, 0o600);
  },
);

test("on Windows the directory then the file get one entry for the user and the result is verified", () => {
  const directory = path.join(scratch(), "state");
  const file = path.join(directory, "credential.json");
  const { machine, commands } = windowsMachine();
  writeUserOnlyFile(file, "secret", machine);
  assert.deepEqual(grants(commands), [
    ["icacls", directory, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`],
    ["icacls", file, "/inheritance:r", "/grant:r", `*${sid}:F`],
  ]);
  const order = commands.map((entry) => entry.join(" "));
  assert(
    order.findIndex((entry) => entry.includes(`${directory} /inheritance:r`)) <
      order.findIndex((entry) => entry.includes(`${file} /inheritance:r`)),
    "the directory is private before the file exists",
  );
  assert.deepEqual(windowsGrantArguments("C:\\x", sid, false), [
    "C:\\x",
    "/inheritance:r",
    "/grant:r",
    `*${sid}:F`,
  ]);
  assert.equal(readUserOnlyFile(file, machine), "secret");
});

test("on Windows any other principal in the DACL refuses the file", () => {
  const file = path.join(scratch(), "credential.json");
  writeFileSync(file, "x");
  for (const extra of [
    "NT AUTHORITY\\SYSTEM",
    "BUILTIN\\Administrators",
    "BUILTIN\\Users",
    "Everyone",
    "WORKSTATION-1\\other",
  ]) {
    const { machine } = windowsMachine(
      (target) =>
        `${target} WORKSTATION-1\\tester:(F)\r\n${" ".repeat(target.length + 1)}${extra}:(R)\r\n\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n`,
    );
    assert.throws(
      () => assertUserOnly(file, machine),
      (error: Error) => error.message.includes(file) && !error.message.includes(extra),
      extra,
    );
  }
  // The user may be named by SID, and a listing with no entry at all is no proof of privacy.
  const bySid = windowsMachine((target) => `${target} ${sid}:(F)\r\n`);
  assertUserOnly(file, bySid.machine);
  const empty = windowsMachine(
    () => "Successfully processed 1 files; Failed processing 0 files\r\n",
  );
  assert.throws(() => assertUserOnly(file, empty.machine), /readable/u);
});

test("the Windows parsers read the commands' output and nothing more", () => {
  assert.deepEqual(parseWhoami(whoami), { name: "workstation-1\\tester", sid });
  assert.throws(() => parseWhoami("ERROR: nothing"), /Cannot determine/u);
  assert.throws(() => parseWhoami('"a","not-a-sid"'));
  const target = "C:\\Users\\sam\\.arcforges\\proof";
  const listing = [
    `${target} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)`,
    `${" ".repeat(target.length)} WORKSTATION-1\\tester:(OI)(CI)(F)`,
    "",
    "Successfully processed 1 files; Failed processing 0 files",
  ].join("\r\n");
  assert.deepEqual(parseIcaclsPrincipals(listing, target), [
    "NT AUTHORITY\\SYSTEM",
    "WORKSTATION-1\\tester",
  ]);
  assert.deepEqual(parseIcaclsPrincipals("Successfully processed 1 files", target), []);
  // The listings Windows 11 printed for this procedure's commands (a directory, an inheriting file, a file made private): the path
  // comes back in the file system's case, and a name with a space is one principal.
  const real = "C:\\Users\\tester\\AppData\\Local\\Temp\\af-icacls-c10f394f";
  assert.deepEqual(
    parseIcaclsPrincipals(
      `${real} WORKSTATION\\tester:(OI)(CI)(F)\r\n\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n`,
      real,
    ),
    ["WORKSTATION\\tester"],
  );
  assert.deepEqual(
    parseIcaclsPrincipals(
      `${real.toLowerCase()}\\x.json WORKSTATION\\tester:(F)\r\n`,
      `${real}\\x.json`,
    ),
    ["WORKSTATION\\tester"],
  );
  assert.deepEqual(
    parseIcaclsPrincipals(`${real}\\x.json NT AUTHORITY\\SYSTEM:(I)(F)\r\n`, `${real}\\x.json`),
    ["NT AUTHORITY\\SYSTEM"],
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// The dispatch

const digest = `registry.example/arcforges-cloud@sha256:${"a".repeat(64)}`;
const account = "0".repeat(32);
const later = "2026-11-02T10:00:00Z";
const config = (extra: Partial<Parameters<typeof buildProofConfig>[1]> = {}) =>
  buildProofConfig(wrangler, {
    account,
    imageDigest: digest,
    revision: "b".repeat(40),
    main: sealedProofBundle,
    now,
    ...extra,
  });

test("the dispatch's digest and expiry reach the proof environment alone", () => {
  const withoutBootstrap = config();
  assert.equal(withoutBootstrap.env.proof.vars.ARCFORGES_CENTER_BOOTSTRAP_SHA256, undefined);
  assert.equal(withoutBootstrap.env.proof.vars.ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT, undefined);
  const withBootstrap = config({ bootstrap: { sha256: knownDigest, expiresAt: later } });
  assert.equal(withBootstrap.env.proof.vars.ARCFORGES_CENTER_BOOTSTRAP_SHA256, knownDigest);
  assert.equal(withBootstrap.env.proof.vars.ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT, later);
  // Production's variables and the checked-in file are untouched.
  const top = withBootstrap as unknown as { vars: Record<string, string> };
  assert.equal(top.vars.ARCFORGES_CENTER_BOOTSTRAP_SHA256, undefined);
  assert.equal(top.vars.ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT, undefined);
  assert(
    !JSON.stringify(wrangler).includes("BOOTSTRAP"),
    "the checked-in wrangler.json carries no bootstrap",
  );
  assert.deepEqual(
    Object.keys(withBootstrap.env.proof.vars)
      .filter((key) => key.includes("BOOTSTRAP"))
      .sort(),
    ["ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT", "ARCFORGES_CENTER_BOOTSTRAP_SHA256"],
  );
});

test("a checked-in bootstrap is refused wherever it is, and the checks do not echo the value", () => {
  for (const place of ["top", "proof"] as const) {
    const candidate = structuredClone(wrangler) as CandidateConfig;
    const vars =
      place === "top"
        ? (candidate as unknown as { vars: Record<string, string> }).vars
        : candidate.env.proof.vars;
    vars.ARCFORGES_CENTER_BOOTSTRAP_SHA256 = knownDigest;
    assert.throws(
      () =>
        buildProofConfig(candidate, {
          account,
          imageDigest: digest,
          revision: "b".repeat(40),
          main: sealedProofBundle,
        }),
      (error: Error) =>
        /ARCFORGES_CENTER_BOOTSTRAP_SHA256/u.test(error.message) &&
        !error.message.includes(knownDigest),
      place,
    );
  }
});

test("the digest is 64 lowercase hex characters and the expiry a future instant at most seven days ahead", () => {
  const good = { sha256: knownDigest, expiresAt: later };
  assert.deepEqual(checkProofBootstrap(good, now), good);
  const secret = knownToken;
  for (const [name, bad] of [
    ["the token itself", { ...good, sha256: secret }],
    ["uppercase", { ...good, sha256: knownDigest.toUpperCase() }],
    ["short", { ...good, sha256: knownDigest.slice(1) }],
    ["long", { ...good, sha256: `${knownDigest}0` }],
    ["padded", { ...good, sha256: ` ${knownDigest}` }],
    ["not hex", { ...good, sha256: `g${knownDigest.slice(1)}` }],
    ["empty digest", { ...good, sha256: "" }],
    ["offset", { ...good, expiresAt: "2026-11-02T10:00:00+00:00" }],
    ["fraction", { ...good, expiresAt: "2026-11-02T10:00:00.000Z" }],
    ["no seconds", { ...good, expiresAt: "2026-11-02T10:00Z" }],
    ["local", { ...good, expiresAt: "2026-11-02T10:00:00" }],
    ["lowercase", { ...good, expiresAt: "2026-11-02t10:00:00z" }],
    ["date only", { ...good, expiresAt: "2026-11-02" }],
    ["a day that does not exist", { ...good, expiresAt: "2026-02-30T10:00:00Z" }],
    ["hour 24", { ...good, expiresAt: "2026-11-02T24:00:00Z" }],
    ["past", { ...good, expiresAt: "2026-11-01T09:59:59Z" }],
    ["now", { ...good, expiresAt: "2026-11-01T10:00:00Z" }],
    ["seven days and a second", { ...good, expiresAt: "2026-11-08T10:00:01Z" }],
    ["a year", { ...good, expiresAt: "2027-11-01T10:00:00Z" }],
  ] as const) {
    assert.throws(
      () => checkProofBootstrap(bad, now),
      (error: Error) =>
        !error.message.includes(secret) &&
        !error.message.includes(bad.sha256 || "\u0000") &&
        !error.message.includes(bad.expiresAt),
      name,
    );
    assert.throws(() => config({ bootstrap: bad }), Error, `buildProofConfig: ${name}`);
  }
  // Seven days to the second is the longest; a moment before the expiry is the last moment it is accepted.
  assert.deepEqual(
    checkProofBootstrap({ ...good, expiresAt: "2026-11-08T10:00:00Z" }, now).expiresAt,
    "2026-11-08T10:00:00Z",
  );
  assert.deepEqual(
    checkProofBootstrap({ ...good, expiresAt: "2026-11-01T10:00:01Z" }, now).expiresAt,
    "2026-11-01T10:00:01Z",
  );
});

test("the workflow's two inputs are both given or both empty", () => {
  assert.equal(proofBootstrapFromEnvironment({}, now), undefined);
  assert.equal(
    proofBootstrapFromEnvironment(
      { PROOF_BOOTSTRAP_SHA256: "", PROOF_BOOTSTRAP_EXPIRES_AT: "" },
      now,
    ),
    undefined,
  );
  assert.deepEqual(
    proofBootstrapFromEnvironment(
      { PROOF_BOOTSTRAP_SHA256: knownDigest, PROOF_BOOTSTRAP_EXPIRES_AT: later },
      now,
    ),
    { sha256: knownDigest, expiresAt: later },
  );
  assert.throws(
    () => proofBootstrapFromEnvironment({ PROOF_BOOTSTRAP_SHA256: knownDigest }, now),
    /together/u,
  );
  assert.throws(
    () => proofBootstrapFromEnvironment({ PROOF_BOOTSTRAP_EXPIRES_AT: later }, now),
    /together/u,
  );
  assert.throws(() =>
    proofBootstrapFromEnvironment(
      { PROOF_BOOTSTRAP_SHA256: "x", PROOF_BOOTSTRAP_EXPIRES_AT: later },
      now,
    ),
  );
});

test("the workflow takes the two inputs for the deploy step only, through the environment", () => {
  const dispatch = ciText.slice(
    ciText.indexOf("  workflow_dispatch:"),
    ciText.indexOf("  schedule:"),
  );
  for (const name of ["bootstrap_sha256", "bootstrap_expires_at"]) {
    const block = dispatch.slice(dispatch.indexOf(`      ${name}:`));
    assert.match(
      block.split("\n").slice(0, 12).join("\n"),
      /type: string\n\s+required: false\n\s+default: ""/u,
      name,
    );
    // Every use of an input is `${{ inputs.<name> }}` on an env: line of the deploy step.
    const uses = ciText.split("\n").filter((line) => line.includes(`inputs.${name}`));
    assert.equal(uses.length, 1, name);
    assert.match(
      uses[0] ?? "",
      /^\s+PROOF_BOOTSTRAP_(SHA256|EXPIRES_AT): \$\{\{ inputs\.[a-z0-9_]+ \}\}$/u,
      name,
    );
  }
  const deployStep = ciText.slice(
    ciText.indexOf("      - run: npm run deploy:proof"),
    ciText.indexOf("      - name: Preserve proof deployment evidence"),
  );
  assert.match(deployStep, /PROOF_BOOTSTRAP_SHA256: \$\{\{ inputs\.bootstrap_sha256 \}\}/u);
  assert.match(deployStep, /PROOF_BOOTSTRAP_EXPIRES_AT: \$\{\{ inputs\.bootstrap_expires_at \}\}/u);
  // Neither input is ever interpolated into a script body.
  for (const line of ciText.split("\n"))
    if (/^\s+(run|-\s*run):/u.test(line)) assert(!line.includes("inputs."), line);
});

test("the deployment record carries the dispatch's digest and expiry, never a token", () => {
  const record = readFileSync(path.join(root, "eng/verification/proof-cloudflare.ts"), "utf8");
  assert(
    record.includes(
      "bootstrap: bootstrap ? { sha256: bootstrap.sha256, expiresAt: bootstrap.expiresAt } : null,",
    ),
  );
  assert(record.includes("const bootstrap = proofBootstrapFromEnvironment(process.env);"));
  assert(
    record.includes("    bootstrap,\n  });"),
    "the validated bootstrap reaches buildProofConfig",
  );
  for (const file of [
    "eng/verification/proof-cloudflare.ts",
    "eng/verification/proof-deploy.ts",
    "eng/verification/proof-bootstrap.ts",
  ]) {
    const text = readFileSync(path.join(root, file), "utf8");
    assert(!/console\.(log|error|warn)\([^)]*\btoken\b/u.test(text), `${file} prints a token`);
  }
});

test("nothing in the repository holds a token of the shape afb1. followed by 43 characters", () => {
  const found = spawnSync(
    "git",
    [
      "grep",
      "-nE",
      "afb1\\.[A-Za-z0-9_-]{43}",
      "--",
      ".",
      ":(exclude)tests",
      ":(exclude)center/internal",
    ],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(found.stdout, "", "a bootstrap token was committed");
});

// ---------------------------------------------------------------------------------------------------------------------------
// Which directories the tool may restrict (the Windows grant strips every other entry of a directory and of what it holds)

test("a directory that someone else filled is refused and left alone, whatever the machine", () => {
  const filled = path.join(scratch(), "projects");
  mkdirSync(filled);
  writeFileSync(path.join(filled, "notes.txt"), "mine");
  // Shared with others, as a folder of a checkout or a profile is.
  if (process.platform !== "win32") chmodSync(filled, 0o755);
  const before = readdirSync(filled);
  // The bootstrap command, the user-only helpers and the credential store all refuse it.
  assert.throws(
    () => runBootstrap(["--dir", filled], { out: () => {} }, { now }),
    /holds files that are not this tool's|readable by more than its owner/u,
  );
  assert.throws(() => ensureUserOnlyDirectory(filled), /holds files that are not this tool's/u);
  assert.throws(
    () => ensureUserOnlyDirectory(filled, realMachine(), (name) => name === "credential.json"),
    /holds files that are not this tool's/u,
  );
  assert.deepEqual(readdirSync(filled), before);
  if (process.platform !== "win32")
    assert.equal(statSync(filled).mode & 0o777, 0o755, "its mode is not changed");
  const { machine, commands } = windowsMachine(
    (target) =>
      `${target} WORKSTATION-1\\tester:(OI)(CI)(F)\r\n${" ".repeat(target.length + 1)}BUILTIN\\Users:(OI)(CI)(R)\r\n`,
  );
  assert.throws(
    () => ensureUserOnlyDirectory(filled, machine),
    /holds files that are not this tool's/u,
  );
  assert.throws(
    () => writeUserOnlyFile(path.join(filled, "x.json"), "secret", machine),
    /readable by more than its owner/u,
    "a directory that exists is checked, not changed, by a write",
  );
  assert.deepEqual(
    grants(commands),
    [],
    "no DACL of the directory or of what it holds was changed",
  );
  assert(!existsSync(path.join(filled, "x.json")));
  // A file that is not a directory.
  const file = path.join(scratch(), "a-file");
  writeFileSync(file, "x");
  assert.throws(() => ensureUserOnlyDirectory(file), /is not a directory/u);
});

test("an empty directory, one that holds only the tool's own files, and a new one under new parents are made private", () => {
  const empty = path.join(scratch(), "empty");
  mkdirSync(empty);
  const first = windowsMachine();
  ensureUserOnlyDirectory(empty, first.machine);
  assert.deepEqual(grants(first.commands), [
    ["icacls", empty, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`],
  ]);
  const own = path.join(scratch(), "own");
  mkdirSync(own);
  writeFileSync(path.join(own, "owner-bootstrap.json"), "{}");
  const second = windowsMachine();
  ensureUserOnlyDirectory(own, second.machine, (name) => name === "owner-bootstrap.json");
  assert.equal(grants(second.commands).length, 1);
  const deep = path.join(scratch(), "a", "b", "c");
  const third = windowsMachine();
  ensureUserOnlyDirectory(deep, third.machine);
  assert(existsSync(deep));
  // Only the new directory itself is restricted, not the parents the call had to make.
  assert.deepEqual(grants(third.commands), [
    ["icacls", deep, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`],
  ]);
});

test("the bootstrap's directory, given by hand, is made private when it is empty and refused untouched when it holds anything else", () => {
  const record = generateBootstrap({ hours: 1, now, random: zeros });
  // An empty directory that exists (a folder of the profile or the temporary folder, with inherited entries on Windows) gets the
  // directory's grant before the file is created in it, then the file's.
  const empty = path.join(scratch(), "given");
  mkdirSync(empty);
  const first = windowsMachine();
  const file = createBootstrapFile(empty, record, first.machine);
  assert.deepEqual(grants(first.commands), [
    ["icacls", empty, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`],
    ["icacls", file, "/inheritance:r", "/grant:r", `*${sid}:F`],
  ]);
  if (process.platform !== "win32") {
    const shared = path.join(scratch(), "shared");
    mkdirSync(shared);
    chmodSync(shared, 0o755);
    createBootstrapFile(shared, record);
    assert.equal(statSync(shared).mode & 0o777, 0o700, "a shared empty directory becomes private");
  }
  // A directory someone else filled is refused before anything is written or granted.
  const filled = path.join(scratch(), "filled");
  mkdirSync(filled);
  writeFileSync(path.join(filled, "notes.txt"), "mine");
  const second = windowsMachine();
  assert.throws(
    () => createBootstrapFile(filled, record, second.machine),
    /holds files that are not this tool's/u,
  );
  assert.deepEqual(grants(second.commands), []);
  assert(!existsSync(path.join(filled, bootstrapFileName)));
  assert.deepEqual(readdirSync(filled), ["notes.txt"]);
});

test("on Windows a directory whose DACL still shows another principal after the grant is refused", () => {
  const fresh = path.join(scratch(), "new");
  const { machine } = windowsMachine(
    (target) =>
      `${target} WORKSTATION-1\\tester:(OI)(CI)(F)\r\n${" ".repeat(target.length + 1)}BUILTIN\\Users:(OI)(CI)(R)\r\n`,
  );
  assert.throws(
    () => ensureUserOnlyDirectory(fresh, machine),
    (error: Error) => error.message.includes(fresh) && !error.message.includes("BUILTIN"),
  );
});
