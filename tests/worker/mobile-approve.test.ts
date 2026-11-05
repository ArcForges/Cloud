// SPDX-License-Identifier: AGPL-3.0-only
// The mobile-approve mode of the browser acceptance (AF-CTR-04 part M, H3): its arguments and step-up budget, the begin files of
// mobile-probe it accepts, the callback link it hands the probe, and the elements it touches on the mobile pages (checked against the
// center's own templates, so a renamed element fails here, not in a live run).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  defaultReportName,
  nodeApproveRequestsPerMinute,
  parseArguments,
} from "../../eng/verification/browser/acceptance.ts";
import {
  callbackSecrets,
  checkCallbackLink,
  mobileBeginSecrets,
  mobileStepUpsAtMost,
  parseMobileBegin,
  probeDeviceIds,
  revokeDeviceSelector,
  reviewFlowSelector,
  reviewWaitMs,
} from "../../eng/verification/browser/mobile-flow.ts";
import { mobile } from "../../eng/verification/browser/selectors.ts";

const base = "https://proof.arcforges.com/api";
const flow = "9b2d6c1e-3f4a-4b5c-8d6e-7f8091a2b3c4";
const begin = {
  case: "approve-1",
  scenario: "approve",
  authorizeUrl: `${base}/mobile/authorize#flow=${flow}`,
  decision: "approve",
  centerHost: "proof.arcforges.com",
  platform: "android-15",
  appVersion: "0.0.0-mobile-probe",
};

test("--mobile-approve needs --watch, paces like --node-approve and refuses a set that could spend more than 10 step-ups", () => {
  const parsed = parseArguments(
    ["--mobile-approve", "--watch", "/tmp/h", "--cases", "4"],
    {},
    "linux",
    "/home/x",
  );
  assert.equal(parsed.mobileApprove, true);
  assert.equal(parsed.requestsPerMinute, nodeApproveRequestsPerMinute);
  assert.equal(path.basename(parsed.report), defaultReportName.mobileApprove);
  assert.equal(mobileStepUpsAtMost(5), 10);
  for (const argv of [
    ["--mobile-approve"],
    ["--mobile-approve", "--watch", "/tmp/h", "--cases", "6"],
    ["--mobile-approve", "--node-approve", "--watch", "/tmp/h"],
    ["--mobile-approve", "--watch", "/tmp/h", "--negative"],
    ["--mobile-approve", "--operator-grant", "--watch", "/tmp/h"],
  ])
    assert.throws(() => parseArguments(argv, {}, "linux", "/home/x"), JSON.stringify(argv));
});

test("a begin file is accepted only for this center's authorization page with its exact fragment and its scenario's decision", () => {
  assert.deepEqual(parseMobileBegin(JSON.stringify(begin), base), begin);
  assert.deepEqual(mobileBeginSecrets(begin as never), [flow]);
  for (const change of [
    { authorizeUrl: `https://evil.example/api/mobile/authorize#flow=${flow}` },
    { authorizeUrl: `${base}/connect#flow=${flow}` },
    { authorizeUrl: `${base}/mobile/authorize#flow=${flow.toUpperCase()}` },
    { authorizeUrl: `${base}/mobile/authorize?flow=${flow}` },
    { scenario: "steal" },
    { decision: "deny" },
    { scenario: "deny", decision: "approve" },
    { case: "Bad Case" },
    { platform: "android+15" },
    { appVersion: "" },
  ])
    assert.throws(
      () => parseMobileBegin(JSON.stringify({ ...begin, ...change }), base),
      JSON.stringify(change),
    );
  assert.throws(() => parseMobileBegin("not json", base));
});

test("the done page's link must be this center's release callback with the issuer, and its code is a secret", () => {
  const state = "s".repeat(32);
  const iss = encodeURIComponent(base);
  const code = `${"A".repeat(42)}E`;
  const link = `https://proof.arcforges.com/app/callback#code=${code}&state=${state}&iss=${iss}`;
  assert.equal(checkCallbackLink(link, base, true), link);
  assert.deepEqual(callbackSecrets(link), [link, code]);
  const denial = `https://proof.arcforges.com/app/callback#error=access_denied&state=${state}&iss=${iss}`;
  assert.equal(checkCallbackLink(denial, base, false), denial);
  for (const [bad, approved] of [
    [null, true],
    [denial, true],
    [link, false],
    [`https://evil.example/app/callback#code=${code}&state=${state}&iss=${iss}`, true],
    [
      `https://proof.arcforges.com/app/callback#code=${code}&state=${state}&iss=${encodeURIComponent("https://evil.example/api")}`,
      true,
    ],
    [`https://proof.arcforges.com/app/callback#code=${code}&state=${state}`, true],
    [
      `https://proof.arcforges.com/app/callback#code=${"A".repeat(42)}B&state=${state}&iss=${iss}`,
      true,
    ],
  ] as const)
    assert.throws(() => checkCallbackLink(bad, base, approved), String(bad));
});

test("every element the flow touches is in the center's mobile templates", () => {
  const root = path.resolve(import.meta.dirname, "../../center/internal/pages/templates");
  const review = readFileSync(path.join(root, "mobile-authorize-review.gohtml"), "utf8");
  const done = readFileSync(path.join(root, "mobile-authorize-done.gohtml"), "utf8");
  for (const id of [mobile.platform, mobile.version, mobile.claimNote])
    assert(review.includes(`id="${id.slice(1)}"`), id);
  assert(review.includes('id="approve"') && review.includes('id="deny"'));
  assert(done.includes(`id="${mobile.appLink.slice(1)}"`));
  assert.equal(mobile.appCallback, "/app/callback");
});

test("the clean-up revokes exactly the devices mobile-probe names, found by the device ID of their revoke form", () => {
  const device = "0f1e2d3c-4b5a-4968-8776-655443322110";
  const result = { case: "approve-1", kind: "mobile", passed: true, steps: [], requests: [] };
  assert.deepEqual(probeDeviceIds({ ...result, deviceIds: [device] }), [device]);
  assert.deepEqual(probeDeviceIds({ ...result, deviceIds: [] }), []);
  assert.deepEqual(probeDeviceIds(result), []);
  for (const deviceIds of [
    [device.toUpperCase()],
    [`${device} `],
    ["Android phone"],
    [device, device],
    device,
    [1],
  ])
    assert.throws(() => probeDeviceIds({ ...result, deviceIds }), String(deviceIds));
  assert.equal(
    revokeDeviceSelector(device),
    `form[action$="/account/devices/revoke"]:has(input[name="device_id"][value="${device}"]) button`,
  );
  assert.throws(() => revokeDeviceSelector('x"] , button'));
  // The devices page's revoke form carries the device ID in exactly the input the selector names.
  const template = readFileSync(
    path.join(import.meta.dirname, "../../center/internal/pages/templates/devices.gohtml"),
    "utf8",
  );
  assert.match(
    template,
    /<form method="post" action="\{\{\$\.Base\}\}\/account\/devices\/revoke"[^>]*>\n<input type="hidden" name="csrf" value="\{\{\$\.CSRF\}\}">\n<input type="hidden" name="command_id" value="\{\{\.RevokeCommand\}\}">\n<input type="hidden" name="device_id" value="\{\{\.ID\}\}">/u,
  );
});

test("the review wait: the real-network budget with a sign-in on the way, --timeout-ms otherwise, never less than --timeout-ms", () => {
  const defaults = parseArguments(
    ["--mobile-approve", "--watch", "/tmp/h"],
    {},
    "linux",
    "/home/x",
  );
  assert.equal(defaults.timeoutMs, 30_000);
  assert.equal(reviewWaitMs(defaults, true), 180_000);
  assert.equal(reviewWaitMs(defaults, false), 30_000);
  const longer = parseArguments(
    [
      "--mobile-approve",
      "--watch",
      "/tmp/h",
      "--timeout-ms",
      "240000",
      "--real-timeout-ms",
      "60000",
    ],
    {},
    "linux",
    "/home/x",
  );
  assert.equal(reviewWaitMs(longer, true), 240_000);
  assert.equal(reviewWaitMs(longer, false), 240_000);
  // The step waits for the review's own element, never for a load event of the review page.
  const source = readFileSync(
    path.join(import.meta.dirname, "../../eng/verification/browser/mobile-flow.ts"),
    "utf8",
  );
  assert.equal(source.includes("waitForPath(pagePathname(world, mobile.review)"), false);
  assert.match(source, /const waitMs = reviewWaitMs\(world, !a\.signedIn\);/u);
});

test("the review found by the wait must be of the begin file's flow: its hidden flow_id input", () => {
  const parsed = parseMobileBegin(JSON.stringify(begin), base);
  assert.equal(reviewFlowSelector(parsed), `input[type="hidden"][name="flow_id"][value="${flow}"]`);
  assert.throws(() =>
    reviewFlowSelector({ ...parsed, authorizeUrl: `${base}/mobile/authorize#flow=x"],input` }),
  );
  // The review template carries the flow in exactly that input (the review and the decision forms).
  const template = readFileSync(
    path.join(
      import.meta.dirname,
      "../../center/internal/pages/templates/mobile-authorize-review.gohtml",
    ),
    "utf8",
  );
  assert(template.includes('<input type="hidden" name="flow_id" value="{{.Mobile.FlowID}}">'));
  // The step checks it right after the wait, before it reads the review.
  const source = readFileSync(
    path.join(import.meta.dirname, "../../eng/verification/browser/mobile-flow.ts"),
    "utf8",
  );
  assert.match(
    source,
    /a\.signedIn = true;\n\s*expect\(\n\s*\(await a\.tab\.count\(reviewFlowSelector\(begin\)\)\) > 0,/u,
  );
});
