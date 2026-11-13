// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { BootstrapJournal } from "../../tooling/ctr06-bootstrap-journal.ts";
import { scratchDirectory } from "./support/scratch.ts";

const event = {
  kind: "authorization",
  fields: { repository: "1372264358", exception: "AF-CTR-06", purpose: "security-bridge" },
};
const moduleUrl = new URL("../../tooling/ctr06-bootstrap-journal.ts", import.meta.url).href;
function directory(t: TestContext) {
  return scratchDirectory("ctr06-journal-", t);
}
async function holdingProcess(
  root: string,
  t: TestContext,
): Promise<ChildProcessWithoutNullStreams> {
  const source = `import { BootstrapJournal } from ${JSON.stringify(moduleUrl)};
const j = new BootstrapJournal(process.argv[1]);
j.append({kind:'issue_intent',fields:{run:'123',attempt:'1',issueId:'a1'}});
process.stdout.write('READY\\n');
process.stdin.once('data', () => { j.close(); process.exit(0); });`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", source, root], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  const result = await Promise.race([
    once(child.stdout, "data").then(([chunk]) => String(chunk)),
    once(child, "exit").then(([code]) => {
      throw new Error(`Journal helper exited before readiness: ${code}`);
    }),
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("Journal helper timed out")), 5000).unref();
    }),
  ]);
  assert.match(result, /^READY/);
  return child;
}

if (process.platform === "linux") {
  test("durable journal survives close and restart with hash-chain validation", (t) => {
    const root = directory(t);
    const first = new BootstrapJournal(root);
    first.append(event);
    first.append({
      kind: "attempt",
      fields: { run: "123", attempt: "1", artifactDigest: "a".repeat(64) },
    });
    first.close();
    const second = new BootstrapJournal(root);
    assert.deepEqual(
      second.read().map((x) => x.event.kind),
      ["authorization", "attempt"],
    );
    second.close();
    assert.equal(existsSync(path.join(root, ".broker-lock")), false);
  });

  test("real competing process cannot acquire a held journal", async (t) => {
    const root = directory(t);
    const child = await holdingProcess(root, t);
    assert.throws(() => new BootstrapJournal(root), /EEXIST/);
    child.stdin.write("release");
    const [code] = await once(child, "exit");
    assert.equal(code, 0);
    const next = new BootstrapJournal(root);
    assert.equal(next.read()[0]?.event.kind, "issue_intent");
    next.close();
  });

  test("process death leaves durable intent and a lock which is never silently adopted", async (t) => {
    const root = directory(t);
    const child = await holdingProcess(root, t);
    child.kill("SIGKILL");
    const [, signal] = await once(child, "exit");
    assert.equal(signal, "SIGKILL");
    assert.equal(existsSync(path.join(root, ".broker-lock")), true);
    assert.match(readFileSync(path.join(root, "event-00000001.json"), "utf8"), /issue_intent/);
    assert.throws(() => new BootstrapJournal(root), /EEXIST/);
  });

  test("a real filesystem write failure preserves the lock and prevents clean close", (t) => {
    assert.notEqual(
      process.getuid?.(),
      0,
      "This permission check needs the ordinary non-root broker user",
    );
    const root = directory(t);
    const j = new BootstrapJournal(root);
    chmodSync(root, 0o500);
    assert.throws(() => j.append(event), /EACCES/);
    chmodSync(root, 0o700);
    assert.throws(() => j.close(), /Uncertain journal write/);
    assert.equal(existsSync(path.join(root, ".broker-lock")), true);
  });

  test("unknown data, unsafe ancestors and non-public fields fail without adoption", (t) => {
    const root = directory(t);
    const j = new BootstrapJournal(root);
    assert.throws(
      () => j.append({ kind: "issue_result", fields: { token: "secret" } }),
      /Non-public/,
    );
    j.close();
    writeFileSync(path.join(root, "event-00000001.json"), '{"sequence":1,"sequence":2}');
    assert.throws(() => new BootstrapJournal(root));
    assert.equal(existsSync(path.join(root, ".broker-lock")), true);
    const parent = path.join(directory(t), "shared");
    mkdirSync(parent, { mode: 0o777 });
    chmodSync(parent, 0o777);
    const privateRoot = path.join(parent, "private");
    mkdirSync(privateRoot, { mode: 0o700 });
    assert.throws(() => new BootstrapJournal(privateRoot), /non-sticky/);
    assert.equal(existsSync(path.join(privateRoot, ".broker-lock")), false);
  });
} else {
  test("unsupported broker journal platform refuses before creating state", () => {
    assert.throws(() => new BootstrapJournal(path.resolve("ctr06-not-created")), /only on Linux/);
  });
}
