// SPDX-License-Identifier: AGPL-3.0-only
// The node-approve mode of the browser acceptance (AF-CTR-04 E3): its arguments, the begin files of node-probe it accepts, the request
// bound it applies with node-probe on the same edge key, and the elements it touches on the fleet pages (checked against the center's
// own templates, so a renamed element fails here, not in a live run).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  defaultReportName,
  nodeApproveRequestsPerMinute,
  parseArguments,
} from "../../eng/verification/browser/acceptance.ts";
import { maxRequestsPerWindow } from "../../eng/verification/browser/driver.ts";
import { AcceptanceError } from "../../eng/verification/browser/flow.ts";
import { busiestOf, parseBegin } from "../../eng/verification/browser/node-flow.ts";
import { fleet } from "../../eng/verification/browser/selectors.ts";

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
