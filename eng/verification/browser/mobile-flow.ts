// SPDX-License-Identifier: AGPL-3.0-only
// The mobile-approve flow (AF-CTR-04 part M, H3): the saved owner credential (MOCKED hardware: Chromium's virtual authenticator in a
// real browser) approves or denies the mobile native authorizations a mobile app stand-in begins, on the center's /mobile/authorize
// page. The app is center/cmd/mobile-probe (MobileProbe, MOCKED: a Go stand-in, not the ArcForges Android app), which writes
// <case>.begin.json into the handshake directory (the URL to open, the scenario and the decision, the claim as the app reports it;
// none of them secret) and later <case>.result.json (each of its steps and the instant of each of its requests). For each begin file
// the flow opens the URL in the browser (the Custom Tab of a real app), signs in when it has to (the sign-in page returns to the
// authorization page with its fragment), checks the review page against the begin file, decides (an approval proves the step-up of
// class identity.authorizeMobile), reads the callback from the done page's "Open the ArcForges app" link and hands it to the probe in
// <case>.link.json (the MOCKED stand-in of a verified App Link handing the fragment to the app: the probe deletes the file as soon as it
// reads it), and then taps the link as a person would: on the proof host the link loads the fixed /app/callback page, whose script
// removes the fragment from the address. It waits for the probe's result, which names the device of each session it was delivered. At
// the end, also after a failed step, it revokes on the devices page exactly the devices the probe's results named (by device ID, so
// no other phone of the account is touched), and the report says how many of them are left. A case whose result never arrived names
// no device: the report counts such cases, and nothing is revoked for them.
//
// The center's own limits a run spends (docs/center-mobile.md "H3 checklist"): step-ups 10 per account in 10 minutes (one per approval
// and one per revoked device, at most one device per approval: acceptance.ts refuses a --cases that could spend more), mobile_approve_account 20 decisions an hour,
// mobile_begin_prefix 30 begins in 10 minutes (one per case, on the probe's address), mobile_token_prefix 30 failed token requests in
// 10 minutes (the wrong-verifier case spends none: its code matches).
import {
  AcceptanceError,
  Actor,
  type World,
  awaitDocument,
  expect,
  expectReply,
  expectSavedCenter,
  mockedLabel,
  pagePathname,
  pageUrl,
  plainLabel,
  step,
  until,
} from "./flow.ts";
import type { Handshake, ProbeResult } from "./node-flow.ts";

/** What mobile-probe writes at the end: node-probe's result and the device ID of each session it was delivered. */
export interface MobileProbeResult extends ProbeResult {
  deviceIds?: unknown;
}
import { mobile, pages, selectors } from "./selectors.ts";

/** What mobile-probe writes when a person can act. */
export interface MobileBeginFile {
  case: string;
  scenario: "approve" | "deny" | "reuse" | "wrong-verifier";
  authorizeUrl: string;
  decision: "approve" | "deny";
  centerHost: string;
  platform: string;
  appVersion: string;
}

export interface MobileApproveOptions {
  handshake: Handshake;
  /** How many begin files the run handles. */
  cases: number;
  /** The longest wait for a begin file, and for a probe's result after the decision. */
  waitMs: number;
  /** Receives the instants (milliseconds) of mobile-probe's requests as its result files name them, also when a later step fails. */
  probeRequests: number[];
}

const casePattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const flowFragment = /^#flow=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const claimText = /^[A-Za-z0-9._:/-]{1,128}$/u;
const scenarios = ["approve", "deny", "reuse", "wrong-verifier"] as const;
const deviceIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** The device IDs a probe result names: canonical lower-case UUIDs, at most one per case's approval (two would be a probe fault). */
export function probeDeviceIds(result: MobileProbeResult): string[] {
  const ids = result.deviceIds ?? [];
  expect(
    Array.isArray(ids) &&
      ids.length <= 1 &&
      ids.every((id) => typeof id === "string" && deviceIdPattern.test(id)),
    "mobile-probe's result names a device ID that is not one canonical UUID.",
  );
  return ids as string[];
}

/** The revoke button of exactly one device, found by the device ID its revoke form carries. */
export function revokeDeviceSelector(deviceId: string): string {
  expect(deviceIdPattern.test(deviceId), "A device ID is not a canonical UUID.");
  return `form[action$="/account/devices/revoke"]:has(input[name="device_id"][value="${deviceId}"]) button`;
}

/** The most step-ups a mobile-approve run of `cases` cases can spend: one per approval and one per device its clean-up revokes. */
export function mobileStepUpsAtMost(cases: number): number {
  return 2 * cases;
}

/**
 * The wait for the review page after the authorization link: with a sign-in on the way (a passkey ceremony, the sign-in page's
 * return and the review's POST), the real-network budget (--real-timeout-ms, 180 s by default), as the acceptance's own sign-ins
 * take; otherwise --timeout-ms. Neither is less than --timeout-ms. The wait is for the review's elements, not for a load event: on
 * proof the review page was in the tab while its load event had not fired after 30 s.
 */
export function reviewWaitMs(
  world: { timeoutMs: number; realTimeoutMs: number },
  signingIn: boolean,
): number {
  return signingIn ? Math.max(world.timeoutMs, world.realTimeoutMs) : world.timeoutMs;
}

/** Reads and checks a begin file: its URL must be this center's /mobile/authorize with the exact fragment. */
export function parseMobileBegin(text: string, baseUrl: string): MobileBeginFile {
  let value: Partial<MobileBeginFile>;
  try {
    value = JSON.parse(text) as Partial<MobileBeginFile>;
  } catch {
    throw new AcceptanceError("A begin file is not JSON.");
  }
  expect(
    typeof value.case === "string" && casePattern.test(value.case),
    "A begin file names no valid case.",
  );
  expect(
    (scenarios as readonly unknown[]).includes(value.scenario),
    "A begin file names no scenario.",
  );
  expect(
    value.decision === (value.scenario === "deny" ? "deny" : "approve"),
    "A begin file's decision is not its scenario's.",
  );
  const prefix = `${baseUrl}${mobile.authorize}`;
  expect(
    typeof value.authorizeUrl === "string" &&
      value.authorizeUrl.startsWith(prefix) &&
      flowFragment.test(value.authorizeUrl.slice(prefix.length)),
    "A begin file's URL is not this center's authorization page with its fragment.",
  );
  expect(
    typeof value.platform === "string" &&
      claimText.test(value.platform) &&
      typeof value.appVersion === "string" &&
      claimText.test(value.appVersion),
    "A begin file's claim is not of the claim's shape.",
  );
  return value as MobileBeginFile;
}

/**
 * The review page's hidden flow_id input of the begin file's flow: the review the wait found must be of this case's flow, not of
 * another case's (every case reports the same platform and version). The flow ID is the fragment parseMobileBegin checked.
 */
export function reviewFlowSelector(begin: MobileBeginFile): string {
  const [flow] = mobileBeginSecrets(begin);
  expect(
    flow !== undefined &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(flow),
    "A begin file's flow ID is not a canonical UUID.",
  );
  return `input[type="hidden"][name="flow_id"][value="${flow}"]`;
}

/** What of a begin file must stay out of every output: the flow ID (the URL's fragment). */
export function mobileBeginSecrets(begin: MobileBeginFile): string[] {
  return [begin.authorizeUrl.slice(begin.authorizeUrl.indexOf("#flow=") + "#flow=".length)];
}

/**
 * Checks the done page's link: the release callback of this center's origin, with a code (or the denial), the state and the issuer.
 * It returns the link, which holds the one-use code: the caller adds it to the redactor before anything else.
 */
export function checkCallbackLink(link: string | null, baseUrl: string, approved: boolean): string {
  const origin = new URL(baseUrl).origin;
  const iss = `&iss=${encodeURIComponent(baseUrl)}`;
  expect(
    typeof link === "string" && link.startsWith(`${origin}/app/callback#`),
    "The done page links no callback of this center.",
  );
  const fragment = link.slice(`${origin}/app/callback#`.length);
  const pattern = approved
    ? /^code=[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]&state=[A-Za-z0-9._~-]{16,128}&iss=/u
    : /^error=access_denied&state=[A-Za-z0-9._~-]{16,128}&iss=/u;
  expect(
    pattern.test(fragment) && fragment.endsWith(iss),
    "The callback is not of the contract's form with this center's issuer.",
  );
  return link;
}

/** The secret parts of a callback link: the link itself and its code. */
export function callbackSecrets(link: string): string[] {
  const code = /code=([A-Za-z0-9_-]{43})/u.exec(link)?.[1];
  return code === undefined ? [link] : [link, code];
}

async function waitForFile(
  world: World,
  handshake: Handshake,
  name: string,
  waitMs: number,
): Promise<string> {
  let text: string | undefined;
  await until(
    world,
    `the file ${name}`,
    async () => {
      if (!handshake.list().includes(name)) return false;
      text = handshake.read(name);
      return true;
    },
    waitMs,
  );
  return text as string;
}

async function nextBegin(
  world: World,
  handshake: Handshake,
  handled: Set<string>,
  waitMs: number,
): Promise<string> {
  let found: string | undefined;
  await until(
    world,
    "a begin file of mobile-probe",
    async () => {
      found = handshake
        .list()
        .filter((name) => name.endsWith(".begin.json") && !handled.has(name))
        .sort()[0];
      return found !== undefined;
    },
    waitMs,
  );
  return found as string;
}

function readResult(text: string, probeRequests: number[]): MobileProbeResult {
  const result = JSON.parse(text) as MobileProbeResult;
  for (const instant of result.requests ?? []) probeRequests.push(new Date(instant).getTime());
  return result;
}

export async function runMobileApprove(world: World, options: MobileApproveOptions): Promise<void> {
  world.report.mode = "mobile-approve";
  world.write(
    `Mobile authorizations on ${world.baseUrl}: the saved owner credential (MOCKED hardware) decides ${options.cases} attempt(s) of mobile-probe (MOCKED app)`,
  );
  expect(world.store.exists(), "There is no saved owner credential; run the acceptance first.");
  expectSavedCenter(world);
  world.store.prepare();
  const handled = new Set<string>();
  let approvals = 0;
  const unreported = new Set<string>();
  const deviceIds: string[] = [];
  let actor: Actor | undefined;
  let failure: unknown;
  try {
    actor = await Actor.open(world, "owner");
    const a = actor;
    for (let index = 0; index < options.cases; index += 1) {
      const file = await nextBegin(world, options.handshake, handled, options.waitMs);
      handled.add(file);
      const begin = parseMobileBegin(options.handshake.read(file), world.baseUrl);
      world.redactor.add(...mobileBeginSecrets(begin));
      world.write(`case ${begin.case}: ${begin.scenario}`);
      await step(world, `${begin.case}: open the authorization link`, mockedLabel, async () => {
        const reply = await a.tab.goto(begin.authorizeUrl);
        expectReply(reply, 200, mobile.authorize);
        if (!a.signedIn) {
          await a.tab.waitForPath(pagePathname(world, pages.signIn), world.timeoutMs);
          expect(
            !a.tab.url().includes("#"),
            "The sign-in page kept the return fragment in its address.",
          );
        }
      });
      await step(
        world,
        `${begin.case}: ${a.signedIn ? "" : "sign in and "}review the app`,
        mockedLabel,
        async () => {
          const waitMs = reviewWaitMs(world, !a.signedIn);
          if (!a.signedIn) {
            await a.enabled(selectors.signIn);
            await a.tab.click(selectors.signIn);
          }
          // The review page's own element, not its load event (see reviewWaitMs).
          const review = pagePathname(world, mobile.review);
          await until(
            world,
            "the review page",
            async () => {
              if (new URL(a.tab.url()).pathname !== review) return false;
              try {
                return (await a.tab.count(mobile.platform)) > 0;
              } catch {
                return false; // the document is still being replaced
              }
            },
            waitMs,
          );
          a.signedIn = true;
          expect(
            (await a.tab.count(reviewFlowSelector(begin))) > 0,
            "The review page is of another flow than the begin file's.",
          );
          await a.tab.waitForSelector(selectors.heading, waitMs);
          expect(
            (await a.tab.text(selectors.heading)) === "Sign in to the ArcForges app?",
            "The review has another heading.",
          );
          expect(
            (await a.tab.text(mobile.platform)) === begin.platform,
            "The review shows another platform.",
          );
          expect(
            (await a.tab.text(mobile.version)) === begin.appVersion,
            "The review shows another app version.",
          );
          expect(
            (await a.tab.count(mobile.claimNote)) === 1,
            "The review does not say the claim is not verified.",
          );
        },
        { restartable: false },
      );
      await step(
        world,
        `${begin.case}: ${begin.decision === "deny" ? "deny" : "approve with the step-up"} and hand the callback to the app`,
        mockedLabel,
        async () => {
          const previous = a.tab.document();
          if (begin.decision === "approve") {
            approvals += 1;
            unreported.add(begin.case);
          }
          await a.tab.click(begin.decision === "deny" ? mobile.deny : mobile.approve);
          const reply = await awaitDocument(
            world,
            a.tab,
            previous,
            "the done page",
            async () => (await a.tab.text(selectors.heading)) === "Open the ArcForges app",
          );
          expectReply(reply, 200, "The decision");
          const [href] = await a.tab.attributes(mobile.appLink, "href");
          const link = checkCallbackLink(href ?? null, world.baseUrl, begin.decision === "approve");
          world.redactor.add(...callbackSecrets(link));
          options.handshake.write(`${begin.case}.link.json`, `${JSON.stringify({ link })}\n`);
          // The person's tap: on the proof host the App Link is not verified for any installed app, so the browser loads the fixed
          // fallback page, whose script removes the fragment (the code) from the address.
          await a.tab.click(mobile.appLink);
          await a.tab.waitForPath(mobile.appCallback, world.timeoutMs);
          await until(
            world,
            "the fallback page without the fragment",
            async () => !a.tab.url().includes("#"),
          );
          expect(
            (await a.tab.text(selectors.heading)) === "Open the ArcForges app",
            "The fallback page has another heading.",
          );
        },
        { restartable: false },
      );
      await step(world, `${begin.case}: mobile-probe finished its checks`, plainLabel, async () => {
        const result = readResult(
          await waitForFile(world, options.handshake, `${begin.case}.result.json`, options.waitMs),
          options.probeRequests,
        );
        deviceIds.push(...probeDeviceIds(result));
        unreported.delete(begin.case);
        const failed = (result.steps ?? []).filter((item) => !item.ok).map((item) => item.name);
        expect(
          result.passed === true,
          `mobile-probe failed: ${failed.join(", ") || "no step passed"}.`,
        );
        world.report.facts[`${begin.case}Steps`] = (result.steps ?? []).length;
      });
    }
  } catch (error) {
    failure = error;
  }
  world.report.facts.approvals = approvals;
  world.report.facts.devicesNamed = deviceIds.length;
  world.report.facts.casesWithoutResult = unreported.size;
  world.report.facts.devicesLeft = deviceIds.length === 0 ? 0 : "unknown";
  if (actor !== undefined && deviceIds.length > 0) {
    try {
      await cleanUp(world, actor, deviceIds);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure !== undefined) throw failure;
}

/**
 * Revokes, on the devices page, exactly the devices the probe's results named (each revocation proves a step-up; at most one device per
 * approval). A device that is no longer listed (revoked already) is skipped; no other device of the account is touched.
 */
async function cleanUp(world: World, a: Actor, deviceIds: string[]): Promise<void> {
  const listed = async () => {
    let count = 0;
    for (const id of deviceIds) count += (await a.tab.count(revokeDeviceSelector(id))) > 0 ? 1 : 0;
    return count;
  };
  await step(world, "clean-up: open the devices page", mockedLabel, async () => {
    const reply = await a.tab.goto(pageUrl(world, pages.devices));
    expectReply(reply, 200, pages.devices);
    if (new URL(a.tab.url()).pathname === pagePathname(world, pages.signIn)) {
      await a.enabled(selectors.signIn);
      await a.tab.click(selectors.signIn);
      await a.tab.waitForPath(pagePathname(world, pages.devices), world.timeoutMs);
      a.signedIn = true;
    }
    await a.tab.waitForSelector(selectors.heading, world.timeoutMs);
    world.report.facts.devicesLeft = await listed();
  });
  await step(
    world,
    "clean-up: revoke the devices of the delivered sessions",
    mockedLabel,
    async () => {
      let revoked = 0;
      for (const id of deviceIds) {
        const button = revokeDeviceSelector(id);
        if ((await a.tab.count(button)) === 0) continue;
        const previous = a.tab.document();
        await a.tab.click(button);
        await awaitDocument(
          world,
          a.tab,
          previous,
          "the devices page after a revocation",
          async () =>
            (await a.tab.text(selectors.heading)) === "Devices" &&
            (await a.tab.count(button)) === 0,
        );
        revoked += 1;
      }
      world.report.facts.devicesRevoked = revoked;
      world.report.facts.devicesLeft = await listed();
    },
    { restartable: false },
  );
}
