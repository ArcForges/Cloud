// SPDX-License-Identifier: AGPL-3.0-only

// The smoke of eng/center.py must never leave the center it started running (smoke-1): a process that does not exit within the grace
// period of the stop request is killed, within a bounded wait, and one that exits in time is left alone. The harness runs the real
// stop_process against a child that ignores SIGTERM (a Python child with SIGTERM ignored; on Windows terminate() is a kill, so the
// child that outlives it there is a sleeping one the harness cannot signal, and only the prompt-exit case is checked).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const harness = String.raw`
import importlib.util, json, subprocess, sys, time
spec = importlib.util.spec_from_file_location("center_eng", sys.argv[1])
center = importlib.util.module_from_spec(spec)
spec.loader.exec_module(center)
STUBBORN = "import signal, sys, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nprint('ready', flush=True)\ntime.sleep(300)"
POLITE = "import sys, time\nprint('ready', flush=True)\ntime.sleep(300)"
def start(source):
    child = subprocess.Popen([sys.executable, "-c", source], stdout=subprocess.PIPE, text=True)
    child.stdout.readline()
    return child
result = {}
polite = start(POLITE)
started = time.monotonic()
code, killed = center.stop_process(polite, grace=10, kill_wait=5)
result["polite"] = {"killed": killed, "exited": polite.poll() is not None, "seconds": time.monotonic() - started}
if hasattr(__import__("signal"), "SIGKILL") and sys.platform != "win32":
    stubborn = start(STUBBORN)
    started = time.monotonic()
    code, killed = center.stop_process(stubborn, grace=1, kill_wait=5)
    result["stubborn"] = {"killed": killed, "exited": stubborn.poll() is not None, "code": code, "seconds": time.monotonic() - started}
print(json.dumps(result))
`;

test("stop_process lets a child that exits on the stop request go and kills one that does not", () => {
  const run = spawnSync("python", ["-I", "-B", "-c", harness, path.join(root, "eng/center.py")], {
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout.trim().split("\n").at(-1) as string) as Record<
    string,
    { killed: boolean; exited: boolean; seconds: number; code?: number }
  >;
  assert.deepEqual(
    [result.polite?.killed, result.polite?.exited],
    [false, true],
    "a child that exits on the stop request is not killed",
  );
  if (process.platform !== "win32") {
    assert.deepEqual(
      [result.stubborn?.killed, result.stubborn?.exited],
      [true, true],
      "a child that ignores the stop request is killed and gone",
    );
    assert.ok((result.stubborn?.seconds ?? 99) < 10, "the kill is bounded");
  }
});

test("the smoke stops its center through stop_process and fails when it had to kill it", () => {
  const run = spawnSync(
    "python",
    [
      "-I",
      "-c",
      "import sys; src = open(sys.argv[1], encoding='utf-8').read(); i = src.index('def smoke('); j = src.index('def check()'); print(src[i:j])",
      path.join(root, "eng/center.py"),
    ],
    { encoding: "utf8" },
  );
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /code, killed = stop_process\(process\)/u);
  assert.match(run.stdout, /if killed:\s+raise SystemExit/u);
  assert.doesNotMatch(run.stdout, /process\.wait\(timeout=30\)/u);
});
