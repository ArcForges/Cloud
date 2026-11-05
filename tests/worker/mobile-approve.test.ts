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
