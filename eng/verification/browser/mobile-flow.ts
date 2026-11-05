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
// removes the fragment from the address. It waits for the probe's result. At the end, also after a failed step, it revokes on the
// devices page as many "Android phone" devices as the run's approvals may have added (never more than were listed before the run plus
// those approvals), and the report says how many are left.
//
// The center's own limits a run spends (docs/center-mobile.md "H3 checklist"): step-ups 10 per account in 10 minutes (one per approval
// and one per revoked device: acceptance.ts refuses a --cases that could spend more), mobile_approve_account 20 decisions an hour,
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

/** The most step-ups a mobile-approve run of `cases` cases can spend: one per approval and one per device its clean-up revokes. */
export function mobileStepUpsAtMost(cases: number): number {
  return 2 * cases;
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

function readResult(text: string, probeRequests: number[]): ProbeResult {
  const result = JSON.parse(text) as ProbeResult;
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
          if (!a.signedIn) {
            await a.enabled(selectors.signIn);
            await a.tab.click(selectors.signIn);
          }
          await a.tab.waitForPath(pagePathname(world, mobile.review), world.timeoutMs);
          a.signedIn = true;
          await a.tab.waitForSelector(selectors.heading, world.timeoutMs);
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
          if (begin.decision === "approve") approvals += 1;
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
  world.report.facts.devicesLeft = approvals === 0 ? 0 : "unknown";
  if (actor !== undefined && approvals > 0) {
    try {
      await cleanUp(world, actor, approvals);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure !== undefined) throw failure;
}

/**
 * Revokes, on the devices page, the "Android phone" devices the run's approvals may have added: at most one per approval (each
 * revocation proves a step-up). The probe's installations are new each run, so each delivered session made one such device.
 */
async function cleanUp(world: World, a: Actor, approvals: number): Promise<void> {
  const count = async () => a.tab.count(mobile.revokePhone);
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
    world.report.facts.devicesLeft = await count();
  });
  await step(
    world,
    "clean-up: revoke the phones the approvals created",
    mockedLabel,
    async () => {
      let revoked = 0;
      while (revoked < approvals) {
        const before = await count();
        if (before === 0) break;
        const previous = a.tab.document();
        await a.tab.click(mobile.revokePhone);
        await awaitDocument(
          world,
          a.tab,
          previous,
          "the devices page after a revocation",
          async () =>
            (await a.tab.text(selectors.heading)) === "Devices" && (await count()) < before,
        );
        revoked += 1;
      }
      world.report.facts.devicesRevoked = revoked;
      world.report.facts.devicesLeft = await count();
    },
    { restartable: false },
  );
}
