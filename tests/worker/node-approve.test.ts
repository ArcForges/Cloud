// SPDX-License-Identifier: AGPL-3.0-only
// The node-approve mode of the browser acceptance (AF-CTR-04 E3): its arguments, the begin files of node-probe it accepts, the request
// bound it applies with node-probe on the same edge key, and the elements it touches on the fleet pages (checked against the center's
// own templates, so a renamed element fails here, not in a live run).
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  combinedBusiest,
  defaultReportName,
  main,
  nodeApproveRequestsPerMinute,
  parseArguments,
} from "../../eng/verification/browser/acceptance.ts";
import { CredentialStore } from "../../eng/verification/browser/credentials.ts";
import {
  acceptedChange,
  maxRequestsPerWindow,
  requestBurst,
} from "../../eng/verification/browser/driver.ts";
import { AcceptanceError, type Report } from "../../eng/verification/browser/flow.ts";
import {
  type BeginFile,
  beginSecrets,
  busiestOf,
  parseBegin,
  stepUpsAtMost,
  stepUpsPerTenMinutes,
} from "../../eng/verification/browser/node-flow.ts";
import { fleet } from "../../eng/verification/browser/selectors.ts";
import { realMachine } from "../../eng/verification/user-only.ts";
import { FleetBrowser, FleetCenter, type FleetFakeOptions } from "./support/fleet-fake.ts";

const scratches: string[] = [];
test.after(() => {
  for (const directory of scratches) rmSync(directory, { recursive: true, force: true });
});

const base = "https://proof.arcforges.com/api";
const flow = "3f2a9c4e-1b7d-4e8a-9c3b-5d6e7f8a9b0c";
const good = {
  case: "pkce-1",
  kind: "pkce",
  url: `${base}/connect#flow=${flow}`,
  fingerprint: "0A1B-2C3D-4E5F-6071-8293",
  name: "node-probe-101500",
  os: "Linux",
  arch: "x64",
  version: "0.1.0-dev",
  centerHost: "proof.arcforges.com",
  decision: "approve",
};

test("the node-approve arguments: a watch directory, a bound below the edge's, its own report, one mode", () => {
  const parsed = parseArguments(["--node-approve", "--watch", "/tmp/h"], {}, "linux", "/home/x");
  assert.equal(parsed.nodeApprove, true);
  assert.equal(parsed.requestsPerMinute, nodeApproveRequestsPerMinute);
  assert(nodeApproveRequestsPerMinute < maxRequestsPerWindow);
  assert(parsed.report.endsWith(defaultReportName.nodeApprove));
  assert.equal(parsed.cases, 2);
  for (const argv of [
    ["--node-approve"],
    ["--watch", "/tmp/h"],
    ["--negative"],
    ["--node-approve", "--watch", "/tmp/h", "--operator-grant"],
    ["--node-approve", "--watch", "/tmp/h", "--cases", "0"],
    ["--node-approve", "--watch", "/tmp/h", "--cases", "9"],
    ["--node-approve", "--watch", "/tmp/h", "--base-url", "https://arcforges.com/api"],
  ])
    assert.throws(() => parseArguments(argv, {}, "linux", "/home/x"), JSON.stringify(argv));
});

test("a begin file is accepted only for this center's fleet pages with the exact fragment", () => {
  assert.equal(parseBegin(JSON.stringify(good), base).case, "pkce-1");
  const device = {
    ...good,
    case: "device-1",
    kind: "device",
    url: `${base}/activate#code=BCDF-GHJK`,
    userCode: "BCDF-GHJK",
  };
  assert.equal(parseBegin(JSON.stringify(device), base).userCode, "BCDF-GHJK");
  for (const bad of [
    { ...good, url: `https://evil.example/api/connect#flow=${flow}` },
    { ...good, url: `${base}/connect?flow=${flow}` },
    { ...good, url: `${base}/connect#flow=${flow.toUpperCase()}` },
    { ...good, url: `${base}/activate#code=BCDF-GHJK` },
    { ...good, url: `${base}/account/passkeys#flow=${flow}` },
    { ...device, userCode: "BCDF-GHJL" },
    { ...device, url: `${base}/activate#code=bcdf-ghjk`, userCode: "bcdf-ghjk" },
    { ...good, case: "../x" },
    { ...good, kind: "token" },
    { ...good, decision: "maybe" },
    { ...good, fingerprint: "0a1b-2c3d-4e5f-6071-8293" },
    { ...good, name: "" },
    { ...good, name: "x\ny" },
    { ...good, name: "n".repeat(65) },
  ])
    assert.throws(
      () => parseBegin(JSON.stringify(bad), base),
      AcceptanceError,
      JSON.stringify(bad),
    );
  assert.throws(() => parseBegin("{", base), AcceptanceError);
});

test("the busiest minute of node-probe's requests is a rolling 60 seconds", () => {
  assert.equal(busiestOf([]), 0);
  assert.equal(busiestOf([0, 59_999, 60_000]), 2);
  assert.equal(busiestOf([0, 1, 2, 120_000]), 3);
  assert.equal(busiestOf([5, 1, 3]), 3);
});

test("every element the node-approve flow touches is in the center's fleet templates", () => {
  const templates = [
    "connect",
    "connect-review",
    "connect-done",
    "activate",
    "activate-review",
    "activate-done",
    "fleet-node",
  ]
    .map((name) =>
      readFileSync(
        new URL(`../../center/internal/pages/templates/${name}.gohtml`, import.meta.url),
        "utf8",
      ),
    )
    .join("\n");
  for (const [key, selector] of Object.entries(fleet)) {
    if (typeof selector !== "string") continue;
    if (!selector.startsWith("#")) continue;
    const id = /^#([a-z-]+)/u.exec(selector)?.[1];
    assert(id && templates.includes(`id="${id}"`), `${key}: ${selector}`);
  }
  assert(templates.includes('id="user-code-shown"'));
  assert.match(
    fleet.revokeDevice("node-probe-1"),
    /^tr:has\(th bdi:text-is\("node-probe-1"\)\) form\[action\$="\/account\/devices\/revoke"\] button$/u,
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// A run against the fleet fake (support/fleet-fake.ts)

interface Case {
  case: string;
  kind: "pkce" | "device";
  decision: "approve" | "deny";
}

interface NodeRun {
  center: FleetCenter;
  exitCode: number;
  stderr: string[];
  report: Report;
  everything: string;
  begins: BeginFile[];
}

async function nodeRun(
  cases: readonly Case[],
  options: FleetFakeOptions = {},
  argv: readonly string[] = [],
): Promise<NodeRun> {
  const center = new FleetCenter(base, options);
  const files = new Map<string, string>();
  const begins: BeginFile[] = [];
  cases.forEach((item, index) => {
    const key =
      item.kind === "pkce"
        ? `3f2a9c4e-1b7d-4e8a-9c3b-5d6e7f8a9b${String(index).padStart(2, "0")}`
        : `BCDF-GHJ${"KLMNPQRS"[index]}`;
    const fingerprint = `0A1B-2C3D-4E5F-6071-82${String(index).padStart(2, "0")}`;
    const name = `node-probe-120000-${item.case}`;
    center.add({ kind: item.kind, key, name, fingerprint });
    const begin: BeginFile = {
      case: item.case,
      kind: item.kind,
      url: `${base}${item.kind === "pkce" ? `/connect#flow=${key}` : `/activate#code=${key}`}`,
      ...(item.kind === "device" ? { userCode: key } : {}),
      fingerprint,
      name,
      os: "Linux",
      arch: "x64",
      version: "0.1.0-dev",
      centerHost: "proof.arcforges.com",
      decision: item.decision,
    };
    begins.push(begin);
    files.set(`${item.case}.begin.json`, JSON.stringify(begin));
    files.set(
      `${item.case}.result.json`,
      JSON.stringify({
        case: item.case,
        kind: item.kind,
        passed: true,
        steps: [{ name: "begin", ok: true, outcome: "ok" }],
        requests: [new Date(center.clockMs).toISOString()],
      }),
    );
  });
  const stateDir = mkdtempSync(path.join(os.tmpdir(), "af-node-approve-"));
  scratches.push(stateDir);
  new CredentialStore(stateDir).create(
    {
      baseUrl: base,
      rpId: "proof.arcforges.com",
      displayName: "Proof owner",
      credentials: [
        {
          credentialId: "AQIDBA==",
          isResidentCredential: true,
          rpId: "proof.arcforges.com",
          privateKey: "QUFBQUFBQUE=",
          userHandle: "dXNlcg==",
          signCount: 1,
          transport: "internal",
        },
      ],
    },
    new Date(center.clockMs),
  );
  const browser = new FleetBrowser(center);
  const stdout: string[] = [];
  const stderr: string[] = [];
  const reports: string[] = [];
  const exitCode = await main(
    [
      "--node-approve",
      "--watch",
      "/handshake",
      "--base-url",
      base,
      "--state-dir",
      stateDir,
      "--pace-ms",
      "0",
      "--timeout-ms",
      "1000",
      "--wait-ms",
      "10000",
      "--cases",
      String(cases.length),
      ...argv,
    ],
    {
      environment: {},
      platform: "linux",
      home: "/home/tester",
      packageDirectory: "/cloud/eng/verification/browser",
      launcher: async () => browser,
      machine: realMachine(),
      now: () => new Date(center.clockMs),
      sleep: async (milliseconds) => {
        center.clockMs += milliseconds;
      },
      write: (line) => stdout.push(line),
      writeError: (line) => stderr.push(line),
      exists: () => true,
      read: () => JSON.stringify({ browsers: [{ name: "chromium", revision: "1243" }] }),
      writeReport: (_file, text) => reports.push(text),
      handshake: () => ({
        list: () => [...files.keys()],
        read: (name) => files.get(name) ?? "",
        write: (name, text) => {
          files.set(name, text);
        },
      }),
    },
  );
  const reportText = reports[0] ?? "{}";
  return {
    center,
    exitCode,
    stderr,
    report: JSON.parse(reportText) as Report,
    everything: [...stdout, ...stderr, reportText].join("\n"),
    begins,
  };
}

test("a run decides on both pages, hands a browser sign-in back by the link and by the script, and revokes what it approved", async () => {
  const run = await nodeRun(
    [
      { case: "device-1", kind: "device", decision: "approve" },
      { case: "device-2", kind: "device", decision: "deny" },
      { case: "pkce-1", kind: "pkce", decision: "approve" },
      { case: "pkce-2", kind: "pkce", decision: "approve" },
    ],
    {},
    ["--negative"],
  );
  assert.equal(run.exitCode, 0, run.everything);
  assert.equal(run.report.result, "passed");
  assert.deepEqual(run.center.devices, []);
  assert.equal(run.center.decisions, 4);
  assert.equal(run.center.wrongEntries, 1);
  // Three approvals, the wrong group and three revocations.
  assert.equal(run.center.stepUps, 7);
  assert(run.center.stepUps <= stepUpsAtMost(4, true));
  assert.equal(run.report.facts.devicesRevoked, 3);
  assert.equal(run.report.facts.devicesLeft, 0);
  assert.equal(run.report.facts["pkce-1Via"], "manual link");
  assert.equal(run.report.facts["pkce-2Via"], "script");
  assert(run.report.steps.every((step) => step.ok && step.attempts === 1));
  for (const begin of run.begins)
    for (const secret of beginSecrets(begin)) assert(!run.everything.includes(secret), secret);
});

test("an approval the center committed before a later check failed is still revoked, and the report says how many devices are left", async () => {
  const run = await nodeRun([{ case: "device-1", kind: "device", decision: "approve" }], {
    resultCheckFails: true,
    sessionEndsAfterDecision: true,
  });
  assert.equal(run.exitCode, 1);
  assert.match(run.stderr.join("\n"), /approve with the step-up" failed/u);
  // The clean-up found the tab signed out (the devices page sent it to the sign-in), signed in and revoked the device.
  assert.deepEqual(run.center.devices, []);
  assert.equal(run.center.revocations, 1);
  assert.equal(run.report.facts.devicesRevoked, 1);
  assert.equal(run.report.facts.devicesLeft, 0);
  assert(
    run.report.steps.some((step) => step.name === "clean-up: open the devices page" && step.ok),
  );
});

test("a run without an approval reports no device left, and one whose clean-up cannot look reports them unknown", async () => {
  const denied = await nodeRun([{ case: "pkce-1", kind: "pkce", decision: "deny" }]);
  assert.equal(denied.exitCode, 0, denied.everything);
  assert.equal(denied.report.facts.devicesLeft, 0);
  assert(!denied.report.steps.some((step) => step.name.startsWith("clean-up")));
  const blind = await nodeRun([{ case: "pkce-1", kind: "pkce", decision: "approve" }], {
    gotoRejects: true,
  });
  assert.equal(blind.exitCode, 1);
  assert.equal(blind.report.facts.devicesLeft, "unknown");
});

test("the flow ID and the user code (with and without its hyphen) stay out of the report and stderr when a navigation fails", async () => {
  for (const kind of ["pkce", "device"] as const) {
    const run = await nodeRun([{ case: `${kind}-1`, kind, decision: "approve" }], {
      gotoRejects: true,
    });
    assert.equal(run.exitCode, 1);
    assert.match(run.stderr.join("\n"), /ERR_CONNECTION_RESET/u);
    const [begin] = run.begins;
    assert(begin !== undefined);
    const secrets = beginSecrets(begin);
    assert.equal(secrets.length, kind === "pkce" ? 1 : 2);
    if (kind === "device") assert.equal(secrets[1], "BCDFGHJK");
    for (const secret of secrets) assert(!run.everything.includes(secret), `${kind}: ${secret}`);
    assert.match(run.everything, /\[redacted\]/u);
  }
});

test("a 429 after a wrong fingerprint group's 400 fails the step: no second step-up and no second entry", async () => {
  const run = await nodeRun(
    [{ case: "device-1", kind: "device", decision: "approve" }],
    {
      limitAfterWrongTail: true,
    },
    ["--negative"],
  );
  assert.equal(run.exitCode, 1);
  assert.match(run.stderr.join("\n"), /rate limited \(429\)/u);
  assert.equal(run.center.stepUps, 1);
  assert.equal(run.center.wrongEntries, 1);
  assert.equal(run.center.decisions, 0);
  const negative = run.report.steps.find((step) => step.name.includes("wrong fingerprint tail"));
  assert.equal(negative?.attempts, 1);
});

test("a 429 after a step-up proof fails the decision step: no second step-up", async () => {
  for (const kind of ["pkce", "device"] as const) {
    const run = await nodeRun([{ case: `${kind}-1`, kind, decision: "approve" }], {
      limitAfterStepUp: true,
    });
    assert.equal(run.exitCode, 1, kind);
    assert.match(run.stderr.join("\n"), /rate limited \(429\)/u);
    assert.equal(run.center.stepUps, 1, kind);
    assert.equal(run.center.decisions, 0, kind);
    assert.equal(run.report.facts.devicesLeft, 0, kind);
  }
});

test("every answer of the center to a fleet decision is a change; the edge's 429 and a server error are not", () => {
  for (const pathname of ["/api/connect/decision", "/api/activate/decision"]) {
    for (const status of [200, 303, 400, 403, 409])
      assert.equal(acceptedChange("POST", status, pathname), true);
    for (const status of [429, 500, 502])
      assert.equal(acceptedChange("POST", status, pathname), false);
    assert.equal(acceptedChange("GET", 200, pathname), false);
  }
  assert.equal(acceptedChange("POST", 400, "/api/account/passkeys/remove"), false);
  assert.equal(acceptedChange("POST", 200, "/api/session/v1/web/step-up/complete"), false);
});

test("the edge bound counts node-probe's busiest minute with the browser's, and the browser's rate is 36 after a burst of 4", () => {
  assert.equal(nodeApproveRequestsPerMinute, 36);
  assert.equal(nodeApproveRequestsPerMinute + requestBurst, 40);
  const probe = Array.from({ length: 12 }, (_, index) => index * 1000);
  assert.equal(combinedBusiest(38, probe), 50);
  assert(combinedBusiest(38, probe) <= maxRequestsPerWindow);
  // Without the probe, 44 would pass; with it the run is over the bound.
  assert(44 <= maxRequestsPerWindow);
  assert.equal(combinedBusiest(44, probe), 56);
  assert(combinedBusiest(44, probe) > maxRequestsPerWindow);
});

test("--cases refuses a set that could spend more step-ups than the center allows in 10 minutes", () => {
  assert.equal(stepUpsPerTenMinutes, 10);
  assert.equal(stepUpsAtMost(5, false), 10);
  assert.equal(stepUpsAtMost(4, true), 9);
  const parse = (...extra: string[]) =>
    parseArguments(["--node-approve", "--watch", "/tmp/h", ...extra], {}, "linux", "/home/x");
  assert.equal(parse("--cases", "5").cases, 5);
  assert.equal(parse("--cases", "4", "--negative").cases, 4);
  assert.throws(() => parse("--cases", "6"), /12 step-ups .* 10 per account in 10 minutes/u);
  assert.throws(() => parse("--cases", "5", "--negative"), /11 step-ups/u);
});
