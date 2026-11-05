// SPDX-License-Identifier: AGPL-3.0-only
// The node-approve flow (AF-CTR-04 E3): the saved owner credential (MOCKED hardware: Chromium's virtual authenticator in a real
// browser) approves or denies the sign-ins a node starts, on the center's /connect and /activate pages. The node is whatever writes
// the handshake files: center/cmd/node-probe (MOCKED: a Go stand-in, not the ArcForges node), or the ArcForges node under its own
// end-to-end test (CloudSignInTests: a REAL node); the flow cannot tell them apart and labels neither. It writes <case>.begin.json into the handshake directory
// (the URL to open, the user code, the key's fingerprint and the node's description, none of them secret) and later
// <case>.result.json (each of its steps and the instant of each of its requests). For each begin file the flow opens the URL in the
// browser, signs in when it has to (the sign-in page returns to the fleet page with its fragment), checks the review page against the
// begin file, decides (an approval proves the step-up; on /activate it types the fingerprint's last group the review withholds), and
// for a browser sign-in hands the result back to the probe's loopback receiver, by the page's script or (the first browser sign-in of
// a run, approved or denied) by its manual link. It then waits for the probe's result. At the end, also after a failed step, it revokes on the devices page
// every device the run's approvals may have created. An approval's node name is recorded before its decision is sent. The center
// creates the device only when the node's next poll collects the approval (Enroll), seconds after the decision, so before the clean-up
// reads the devices page it waits (bounded by --wait-ms in all) for the result of every case whose approval was sent and whose result
// it has not read: node-probe writes it after its poll and its checks. The report always says how many such devices are left
// (`devicesLeft`): "unknown" when the clean-up could not look, or when a probe never answered; the run then names the cases to check on
// /account/devices by hand.
//
// 429s (of the edge, or of a center limit): only the steps that open a link (and the clean-up's visit of the devices page) start again
// from their navigation after a 429; every other step starts from the page an earlier step left and fails on a 429 (step()'s
// `restartable: false`), so no review, lookup, step-up proof, wrong fingerprint group, decision or revocation is ever sent twice. What the
// driver counts as a change besides (acceptedChange): every POST the center accepted (below 400) other than a flow's begin, a step-up
// proof and the operator grant's review, and every decision POST on /connect or /activate the center answered below 500 (the wrong
// group's 400 and a step-up refusal included).
// The center's own limits a run spends (center-fleet.md "Post-deploy checklist"): step-ups 10 per account in 10 minutes (one per
// approval and one per revoked device, one more for --negative; acceptance.ts refuses a --cases that could spend more), node_approve_account
// 20 decisions an hour, device_entry_account 5 wrong entries in its window (--negative spends one), node_flow_prefix 10 Begin/Start in 10
// minutes (one per case, on the probe's address).
import {
  AcceptanceError,
  Actor,
  type World,
  awaitDocument,
  expect,
  expectReply,
  expectSavedCenter,
  mockedLabel,
  plainLabel,
  pagePathname,
  pageUrl,
  step,
  until,
} from "./flow.ts";
import { fleet, pages, selectors } from "./selectors.ts";

/** What node-probe writes when a person can act. */
export interface BeginFile {
  case: string;
  kind: "pkce" | "device";
  url: string;
  userCode?: string;
  fingerprint: string;
  name: string;
  os: string;
  arch: string;
  version: string;
  centerHost: string;
  decision: "approve" | "deny";
}

/** What node-probe writes at the end. */
export interface ProbeResult {
  case: string;
  kind: string;
  passed: boolean;
  steps: { name: string; ok: boolean; outcome: string }[];
  requests: string[];
}

/** The handshake directory, as the flow reads and writes it (a test gives it a fake). */
export interface Handshake {
  list(): string[];
  read(name: string): string;
  write(name: string, text: string): void;
}

export interface NodeApproveOptions {
  handshake: Handshake;
  /** How many begin files the run handles. */
  cases: number;
  /** The longest wait for a begin file, and for a probe's result after the decision. */
  waitMs: number;
  /** Also submits a wrong fingerprint tail once on /activate (the local rehearsal: it spends an entry and a step-up). */
  negative: boolean;
  /** Receives the instants (milliseconds) of node-probe's requests as its result files name them, also when a later step fails. */
  probeRequests: number[];
}

const casePattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const fingerprintPattern = /^[0-9A-F]{4}(?:-[0-9A-F]{4}){4}$/u;
const flowFragment = /^#flow=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const codeFragment = /^#code=[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/u;

/** The center's step-up limit: 10 per account in 10 minutes. */
export const stepUpsPerTenMinutes = 10;

/**
 * The most step-ups a node-approve run of `cases` cases can spend: one per approval and one per device its clean-up revokes (every
 * case may be an approval), one more for --negative.
 */
export function stepUpsAtMost(cases: number, negative: boolean): number {
  return 2 * cases + (negative ? 1 : 0);
}

/**
 * What of a begin file must stay out of every output: the flow ID of a browser sign-in (the URL's fragment) and the user code of a
 * device sign-in, also without its hyphen (the form the center normalizes it to).
 */
export function beginSecrets(begin: BeginFile): string[] {
  if (begin.kind === "pkce")
    return [begin.url.slice(begin.url.indexOf("#flow=") + "#flow=".length)];
  const code = begin.userCode ?? "";
  return [code, code.replace("-", "")];
}

/** Reads and checks a begin file: its URL must be this center's /connect or /activate with the exact fragment. */
export function parseBegin(text: string, baseUrl: string): BeginFile {
  let value: Partial<BeginFile>;
  try {
    value = JSON.parse(text) as Partial<BeginFile>;
  } catch {
    throw new AcceptanceError("A begin file is not JSON.");
  }
  const { url, kind } = value;
  expect(
    typeof value.case === "string" && casePattern.test(value.case),
    "A begin file names no valid case.",
  );
  expect(kind === "pkce" || kind === "device", "A begin file names no kind.");
  expect(
    value.decision === "approve" || value.decision === "deny",
    "A begin file names no decision.",
  );
  expect(typeof url === "string", "A begin file names no URL.");
  const page = kind === "pkce" ? fleet.connect : fleet.activate;
  const prefix = `${baseUrl}${page}`;
  expect(
    url.startsWith(prefix) &&
      (kind === "pkce" ? flowFragment : codeFragment).test(url.slice(prefix.length)),
    "A begin file's URL is not this center's consent or activation page with its fragment.",
  );
  if (kind === "device")
    expect(
      url.slice(prefix.length) === `#code=${value.userCode}`,
      "A begin file's user code is not its URL's.",
    );
  expect(
    typeof value.fingerprint === "string" && fingerprintPattern.test(value.fingerprint),
    "A begin file's fingerprint is not of the fingerprint's shape.",
  );
  expect(
    typeof value.name === "string" &&
      value.name.length > 0 &&
      value.name.length <= 64 &&
      !/\p{Cc}/u.test(value.name),
    "A begin file's node name is not of a name's shape.",
  );
  return value as BeginFile;
}

/** The most instants inside any rolling 60 seconds. */
export function busiestOf(times: readonly number[]): number {
  const sorted = [...times].sort((a, b) => a - b);
  let busiest = 0;
  let first = 0;
  for (let last = 0; last < sorted.length; last += 1) {
    while ((sorted[last] ?? 0) - (sorted[first] ?? 0) >= 60_000) first += 1;
    busiest = Math.max(busiest, last - first + 1);
  }
  return busiest;
}

/** Waits for a file of the handshake directory and returns its text. */
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

/** The next begin file the run has not handled. */
async function nextBegin(
  world: World,
  handshake: Handshake,
  handled: Set<string>,
  waitMs: number,
): Promise<string> {
  let found: string | undefined;
  await until(
    world,
    "a begin file of node-probe",
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

export async function runNodeApprove(world: World, options: NodeApproveOptions): Promise<void> {
  world.report.mode = "node-approve";
  world.write(
    `Node approvals on ${world.baseUrl}: the saved owner credential (MOCKED hardware) decides ${options.cases} sign-in(s) of the node that writes the handshake directory (center/cmd/node-probe is a MOCKED node; the ArcForges node's end-to-end test is the real one)`,
  );
  expect(world.store.exists(), "There is no saved owner credential; run the acceptance first.");
  expectSavedCenter(world);
  world.store.prepare();
  const handled = new Set<string>();
  // The node names of the approvals the run has sent or is about to send, recorded BEFORE the decision: the center may commit an
  // approval whose result page the browser never checks.
  const approvedNames: string[] = [];
  // The cases whose approval POST was sent, and those whose node-probe result was read: a device can exist only for the first, and the
  // clean-up must not look before the probe of each of them has answered.
  const approvalsSent: string[] = [];
  const resultsRead = new Set<string>();
  let browserSignIns = 0;
  let actor: Actor | undefined;
  let failure: unknown;
  try {
    actor = await Actor.open(world, "owner");
    const a = actor;
    for (let index = 0; index < options.cases; index += 1) {
      const file = await nextBegin(world, options.handshake, handled, options.waitMs);
      handled.add(file);
      const begin = parseBegin(options.handshake.read(file), world.baseUrl);
      world.redactor.add(...beginSecrets(begin));
      world.write(`case ${begin.case}: ${begin.kind}, ${begin.decision}`);
      const manual = begin.kind === "pkce" && browserSignIns++ === 0;
      if (begin.decision === "approve") approvedNames.push(begin.name);
      const sent = () => approvalsSent.push(begin.case);
      if (begin.kind === "pkce") await connectCase(world, a, begin, manual, sent);
      else await activateCase(world, a, begin, options.negative, sent);
      options.handshake.write(
        `${begin.case}.approved.json`,
        `${JSON.stringify({ case: begin.case, decision: begin.decision, via: manual ? "link" : "script", at: world.now().toISOString() }, null, 2)}\n`,
      );
      await step(world, `${begin.case}: node-probe finished its checks`, plainLabel, async () => {
        const result = readResult(
          await waitForFile(world, options.handshake, `${begin.case}.result.json`, options.waitMs),
          options.probeRequests,
        );
        resultsRead.add(begin.case);
        const failed = (result.steps ?? []).filter((item) => !item.ok).map((item) => item.name);
        expect(
          result.passed === true,
          `node-probe failed: ${failed.join(", ") || "no step passed"}.`,
        );
        world.report.facts[`${begin.case}Steps`] = (result.steps ?? []).length;
      });
    }
  } catch (error) {
    failure = error;
  }
  // The clean-up runs after a failed step too: every device this run's approvals may have created is revoked, and the report says how
  // many are left.
  world.report.facts.devicesLeft = approvedNames.length === 0 ? 0 : "unknown";
  const unanswered = await awaitProbes(
    world,
    options,
    approvalsSent.filter((name) => !resultsRead.has(name)),
  );
  if (actor !== undefined && approvedNames.length > 0) {
    try {
      await cleanUp(world, actor, approvedNames);
    } catch (error) {
      failure ??= error;
    }
  }
  if (unanswered.length > 0) {
    // The probe of such a case may still poll and enroll its device after the clean-up looked.
    world.report.facts.devicesLeft = "unknown";
    world.report.facts.casesToCheckByHand = unanswered.join(",");
    world.write(
      `  devicesLeft unknown: node-probe never answered for ${unanswered.join(", ")}; once the probes have exited, check /account/devices for their node-probe devices and revoke them by hand`,
    );
  }
  if (failure !== undefined) throw failure;
}

/** Reads a probe's result file and adds the instants of its requests to the run's. */
function readResult(text: string, probeRequests: number[]): ProbeResult {
  const result = JSON.parse(text) as ProbeResult;
  for (const instant of result.requests ?? []) probeRequests.push(new Date(instant).getTime());
  return result;
}

/**
 * Waits, within --wait-ms in all, for the result of each case whose approval was sent and whose result was not read (the step that
 * reads it failed or never ran), so that the device its poll may enroll exists before the clean-up looks. Returns the cases whose probe
 * never answered.
 */
async function awaitProbes(
  world: World,
  options: NodeApproveOptions,
  cases: readonly string[],
): Promise<string[]> {
  const unanswered: string[] = [];
  if (cases.length === 0) return unanswered;
  world.write(`  waiting for node-probe's result of ${cases.join(", ")} before the clean-up`);
  const deadline = world.now().getTime() + options.waitMs;
  for (const name of cases) {
    try {
      const left = Math.max(deadline - world.now().getTime(), 0);
      readResult(
        await waitForFile(world, options.handshake, `${name}.result.json`, left),
        options.probeRequests,
      );
    } catch {
      unanswered.push(name);
    }
  }
  return unanswered;
}

/**
 * Opens a fleet URL and checks the page's reply. The consent page's script moves on at once (to the sign-in page without a session,
 * whose own address keeps no fragment, or to the review), so only the activation page's heading is read here.
 */
async function open(world: World, a: Actor, url: string, consent: boolean): Promise<void> {
  const reply = await a.tab.goto(url);
  expectReply(reply, 200, new URL(url).pathname);
  if (!consent) {
    expect(
      (await a.tab.text(selectors.heading)) === "Activate a node",
      "/activate has another heading.",
    );
    return;
  }
  if (!a.signedIn) {
    await a.tab.waitForPath(pagePathname(world, pages.signIn), world.timeoutMs);
    expect(!a.tab.url().includes("#"), "The sign-in page kept the return fragment in its address.");
  }
}

/** Checks a review page against the begin file. */
async function checkReview(
  world: World,
  a: Actor,
  begin: BeginFile,
  heading: string,
  withheld: boolean,
): Promise<void> {
  expect((await a.tab.text(selectors.heading)) === heading, `The review is not "${heading}".`);
  expect((await a.tab.text(fleet.nodeName)) === begin.name, "The review shows another node name.");
  const shown = await a.tab.text(fleet.nodeFingerprint);
  const expected = withheld ? `${begin.fingerprint.slice(0, -4)}????` : begin.fingerprint;
  expect(shown === expected, "The review shows another key fingerprint.");
  expect(
    (await a.tab.count(fleet.nodeNameNote)) === 1,
    "The review does not say the name is not verified.",
  );
  const origin = (await a.tab.text(fleet.nodeOrigin)) ?? "";
  expect(
    origin === "Origin unknown" || origin.startsWith("Request came from "),
    "The review has no origin line.",
  );
  world.report.facts[`${begin.case}Origin`] = origin;
}

async function connectCase(
  world: World,
  a: Actor,
  begin: BeginFile,
  manual: boolean,
  sent: () => void,
): Promise<void> {
  await step(world, `${begin.case}: open the consent link`, mockedLabel, async () => {
    await open(world, a, begin.url, true);
  });
  await step(
    world,
    `${begin.case}: ${a.signedIn ? "" : "sign in and "}review the node`,
    mockedLabel,
    async () => {
      if (!a.signedIn) {
        await a.enabled(selectors.signIn);
        await a.tab.click(selectors.signIn);
      }
      await a.tab.waitForPath(pagePathname(world, fleet.connectReview), world.timeoutMs);
      a.signedIn = true;
      await a.tab.waitForSelector(selectors.heading, world.timeoutMs);
      await checkReview(world, a, begin, "Connect this node?", false);
    },
    { restartable: false },
  );
  const name =
    begin.decision === "deny"
      ? `${begin.case}: deny; ${manual ? "the manual link" : "the page's script"} hands the denial back`
      : `${begin.case}: approve with the step-up; ${manual ? "the manual link" : "the page's script"} hands the code back`;
  await step(
    world,
    name,
    mockedLabel,
    async () => {
      const before = a.tab.loopbackRequests();
      const previous = a.tab.document();
      if (manual) a.tab.holdLoopback();
      if (begin.decision === "approve") sent();
      await a.tab.click(begin.decision === "deny" ? fleet.deny : fleet.approve);
      if (manual) {
        // The page's script tries the link at once; the held navigation leaves the page as it is (its load never completes, so the step
        // waits for the page's text and the held request, not for a load).
        await until(
          world,
          "the result page and its held navigation",
          async () =>
            a.tab.loopbackRequests() > before &&
            (await a.tab.text(selectors.heading)) === "Return to your terminal",
        );
        const reply = a.tab.document();
        expect(reply !== null && reply !== previous, "The decision gave no new document.");
        expectReply(reply, 200, "The decision");
        expect(
          new URL(a.tab.url()).pathname === pagePathname(world, "/connect/decision"),
          "The held navigation left the page.",
        );
        await a.tab.click(fleet.returnLink);
      }
      await until(world, "the browser at the node's loopback receiver", async () =>
        a.tab.url().startsWith("http://127.0.0.1:"),
      );
      world.report.facts[`${begin.case}Via`] = manual ? "manual link" : "script";
    },
    { restartable: false },
  );
}

async function activateCase(
  world: World,
  a: Actor,
  begin: BeginFile,
  negative: boolean,
  sent: () => void,
): Promise<void> {
  await step(
    world,
    `${begin.case}: open the activation link${a.signedIn ? "" : " and go to the sign-in"}`,
    mockedLabel,
    async () => {
      await open(world, a, begin.url, false);
      expect(!a.tab.url().includes("#"), "The activation page kept the code in its address.");
      // A signed-out visitor reaches the sign-in only through Continue (the page waits for it).
      if (!a.signedIn) {
        await a.enabled(fleet.continueButton);
        await a.tab.click(fleet.continueButton);
        await a.tab.waitForPath(pagePathname(world, pages.signIn), world.timeoutMs);
        expect(
          !a.tab.url().includes("#"),
          "The sign-in page kept the return fragment in its address.",
        );
      }
    },
  );
  await step(
    world,
    `${begin.case}: ${a.signedIn ? "" : "sign in, "}look the code up and review the node`,
    mockedLabel,
    async () => {
      if (!a.signedIn) {
        await a.enabled(selectors.signIn);
        await a.tab.click(selectors.signIn);
        await a.tab.waitForPath(pagePathname(world, fleet.activate), world.timeoutMs);
        a.signedIn = true;
      }
      await a.enabled(fleet.continueButton);
      await a.tab.click(fleet.continueButton);
      await a.tab.waitForPath(pagePathname(world, fleet.activateReview), world.timeoutMs);
      await a.tab.waitForSelector(selectors.heading, world.timeoutMs);
      expect(
        (await a.tab.text("#user-code-shown")) === begin.userCode,
        "The review shows another code.",
      );
      await checkReview(world, a, begin, "Activate this node?", true);
    },
    { restartable: false },
  );
  if (negative && begin.decision === "approve") {
    await step(
      world,
      `${begin.case}: a wrong fingerprint tail is refused and the review is shown again`,
      mockedLabel,
      async () => {
        const previous = a.tab.document();
        const tail = begin.fingerprint.slice(-4);
        await a.tab.setValue(fleet.tailField, tail === "0000" ? "FFFF" : "0000");
        a.tab.expectRefusal(400);
        await a.tab.click(fleet.approve);
        const reply = await awaitDocument(
          world,
          a.tab,
          previous,
          "the review shown again",
          async () =>
            ((await a.tab.text(selectors.errorText)) ?? "").includes("not the last 4 characters"),
        );
        expectReply(reply, 400, "The wrong tail");
        expect(
          (await a.tab.text(selectors.heading)) === "Activate this node?",
          "The wrong tail did not show the review again.",
        );
        await until(
          world,
          "the refusal's console report",
          async () => a.tab.refusalsPending() === 0,
        );
      },
      { restartable: false },
    );
  }
  await step(
    world,
    `${begin.case}: ${begin.decision === "deny" ? "deny" : "type the fingerprint's last group and approve with the step-up"}`,
    mockedLabel,
    async () => {
      const previous = a.tab.document();
      if (begin.decision === "approve") {
        await a.tab.setValue(fleet.tailField, begin.fingerprint.slice(-4).toLowerCase());
        sent();
      }
      await a.tab.click(begin.decision === "deny" ? fleet.deny : fleet.approve);
      const reply = await awaitDocument(
        world,
        a.tab,
        previous,
        "the result page",
        async () => (await a.tab.text(selectors.heading)) === "Return to your terminal",
      );
      expectReply(reply, 200, "The decision");
      expect(
        (await a.tab.count(fleet.deny)) === (begin.decision === "approve" ? 1 : 0),
        "The result page does not offer the denial exactly after an approval.",
      );
    },
    { restartable: false },
  );
}

/**
 * Revokes, on the devices page, every device named by an approval of this run (each revocation proves a step-up). The devices page
 * sends a tab without a session to the sign-in, which signs in first (a run whose first step failed after the sign-in, or before it).
 */
async function cleanUp(world: World, a: Actor, names: readonly string[]): Promise<void> {
  const count = async () =>
    (await Promise.all(names.map(async (name) => a.tab.count(fleet.revokeDevice(name))))).reduce(
      (sum, found) => sum + found,
      0,
    );
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
    expect(
      (await a.tab.text(selectors.heading)) === "Devices",
      "The devices page has another heading.",
    );
    world.report.facts.devicesLeft = await count();
  });
  await step(
    world,
    "clean-up: revoke the devices the approvals created",
    mockedLabel,
    async () => {
      let revoked = 0;
      // Each probe device is found by its name; a name two devices share (two probes started in one second without their own
      // names) is revoked once per device, up to the number of approvals.
      for (const name of names) {
        for (let round = 0; round < names.length; round += 1) {
          const before = await a.tab.count(fleet.revokeDevice(name));
          if (before === 0) break;
          const previous = a.tab.document();
          await a.tab.click(fleet.revokeDevice(name));
          await awaitDocument(
            world,
            a.tab,
            previous,
            "the devices page after a revocation",
            async () =>
              (await a.tab.text(selectors.heading)) === "Devices" &&
              (await a.tab.count(fleet.revokeDevice(name))) < before,
          );
          revoked += 1;
          world.report.facts.devicesLeft = await count();
        }
      }
      world.report.facts.devicesRevoked = revoked;
      world.report.facts.devicesLeft = await count();
      expect(world.report.facts.devicesLeft === 0, "A device of the run is still listed.");
    },
    { restartable: false },
  );
}
