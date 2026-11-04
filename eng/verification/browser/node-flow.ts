// SPDX-License-Identifier: AGPL-3.0-only
// The node-approve flow (AF-CTR-04 E3): the saved owner credential (MOCKED hardware: Chromium's virtual authenticator in a real
// browser) approves or denies the sign-ins a node stand-in starts, on the center's /connect and /activate pages. The node is
// center/cmd/node-probe (MOCKED: a Go stand-in, not the ArcForges node), which writes <case>.begin.json into the handshake directory
// (the URL to open, the user code, the key's fingerprint and the node's description, none of them secret) and later
// <case>.result.json (each of its steps and the instant of each of its requests). For each begin file the flow opens the URL in the
// browser, signs in when it has to (the sign-in page returns to the fleet page with its fragment), checks the review page against the
// begin file, decides (an approval proves the step-up; on /activate it types the fingerprint's last group the review withholds), and
// for a browser sign-in hands the result back to the probe's loopback receiver, by the page's script or (the first browser sign-in of
// a run) by its manual link. It then waits for the probe's result. At the end, also after a failed step, it revokes on the devices page
// every device the run's approvals created.
//
// What counts as a change for step() (a 429 before a change starts the step again from its navigation, after one it fails the run): a
// review (it records the reviewer; on /activate it spends one of the code's five lookups and an entry), a decision, a revocation; a
// step-up proof is in the same step as the decision it is for, and a wrong fingerprint tail (the --negative check) in a step of its own.
// The center's own limits a run spends (center-fleet.md "Post-deploy checklist"): step-ups 10 per account in 10 minutes (one per
// approval and one per revoked device, one more for --negative), node_approve_account 20 decisions an hour, device_entry_account 5
// wrong entries in its window (--negative spends one), node_flow_prefix 10 Begin/Start in 10 minutes (one per case, on the probe's
// address).
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
}

/** What the run learned about the probe's requests: the instants (milliseconds), for the run's request bound. */
export interface NodeApproveOutcome {
  probeRequests: number[];
}

const casePattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const fingerprintPattern = /^[0-9A-F]{4}(?:-[0-9A-F]{4}){4}$/u;
const flowFragment = /^#flow=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const codeFragment = /^#code=[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/u;

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

export async function runNodeApprove(
  world: World,
  options: NodeApproveOptions,
): Promise<NodeApproveOutcome> {
  world.report.mode = "node-approve";
  world.write(
    `Node approvals on ${world.baseUrl}: the saved owner credential (MOCKED hardware) decides ${options.cases} sign-in(s) of node-probe (MOCKED node)`,
  );
  expect(world.store.exists(), "There is no saved owner credential; run the acceptance first.");
  expectSavedCenter(world);
  world.store.prepare();
  const outcome: NodeApproveOutcome = { probeRequests: [] };
  const handled = new Set<string>();
  const approvedNames: string[] = [];
  let signedIn = false;
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
      if (begin.userCode) world.redactor.add(begin.userCode);
      world.write(`case ${begin.case}: ${begin.kind}, ${begin.decision}`);
      const manual =
        begin.kind === "pkce" && begin.decision === "approve" && browserSignIns++ === 0;
      if (begin.kind === "pkce") signedIn = await connectCase(world, a, begin, signedIn, manual);
      else signedIn = await activateCase(world, a, begin, signedIn, options.negative);
      if (begin.decision === "approve") approvedNames.push(begin.name);
      options.handshake.write(
        `${begin.case}.approved.json`,
        `${JSON.stringify({ case: begin.case, decision: begin.decision, via: manual ? "link" : "script", at: world.now().toISOString() }, null, 2)}\n`,
      );
      await step(world, `${begin.case}: node-probe finished its checks`, mockedLabel, async () => {
        const result = JSON.parse(
          await waitForFile(world, options.handshake, `${begin.case}.result.json`, options.waitMs),
        ) as ProbeResult;
        for (const instant of result.requests ?? [])
          outcome.probeRequests.push(new Date(instant).getTime());
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
  // The clean-up runs after a failed step too: every device this run's approvals created is revoked.
  if (actor !== undefined && approvedNames.length > 0) {
    try {
      await cleanUp(world, actor, approvedNames, signedIn);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure !== undefined) throw failure;
  return outcome;
}

/**
 * Opens a fleet URL and checks the page's reply. The consent page's script moves on at once (to the sign-in page without a session,
 * whose own address keeps no fragment, or to the review), so only the activation page's heading is read here.
 */
async function open(
  world: World,
  a: Actor,
  url: string,
  consent: boolean,
  signedIn: boolean,
): Promise<void> {
  const reply = await a.tab.goto(url);
  expectReply(reply, 200, new URL(url).pathname);
  if (!consent) {
    expect(
      (await a.tab.text(selectors.heading)) === "Activate a node",
      "/activate has another heading.",
    );
    return;
  }
  if (!signedIn) {
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
  signedIn: boolean,
  manual: boolean,
): Promise<boolean> {
  await step(world, `${begin.case}: open the consent link`, mockedLabel, async () => {
    await open(world, a, begin.url, true, signedIn);
  });
  await step(
    world,
    `${begin.case}: ${signedIn ? "" : "sign in and "}review the node`,
    mockedLabel,
    async () => {
      if (!signedIn) {
        await a.enabled(selectors.signIn);
        await a.tab.click(selectors.signIn);
      }
      await a.tab.waitForPath(pagePathname(world, fleet.connectReview), world.timeoutMs);
      await a.tab.waitForSelector(selectors.heading, world.timeoutMs);
      await checkReview(world, a, begin, "Connect this node?", false);
    },
  );
  const name =
    begin.decision === "deny"
      ? `${begin.case}: deny; the page hands the denial back to the node`
      : `${begin.case}: approve with the step-up; ${manual ? "the manual link" : "the page's script"} hands the code back`;
  await step(world, name, mockedLabel, async () => {
    const before = a.tab.loopbackRequests();
    const previous = a.tab.document();
    if (manual) a.tab.holdLoopback();
    await a.tab.click(begin.decision === "deny" ? fleet.deny : fleet.approve);
    if (manual) {
      const reply = await awaitDocument(
        world,
        a.tab,
        previous,
        "the result page",
        async () => (await a.tab.text(selectors.heading)) === "Return to your terminal",
      );
      expectReply(reply, 200, "The decision");
      await until(
        world,
        "the page's script to try the loopback link",
        async () => a.tab.loopbackRequests() > before,
      );
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
  });
  return true;
}

async function activateCase(
  world: World,
  a: Actor,
  begin: BeginFile,
  signedIn: boolean,
  negative: boolean,
): Promise<boolean> {
  await step(
    world,
    `${begin.case}: open the activation link${signedIn ? "" : " and go to the sign-in"}`,
    mockedLabel,
    async () => {
      await open(world, a, begin.url, false, true);
      expect(!a.tab.url().includes("#"), "The activation page kept the code in its address.");
      if (!signedIn) {
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
    `${begin.case}: ${signedIn ? "" : "sign in, "}look the code up and review the node`,
    mockedLabel,
    async () => {
      if (!signedIn) {
        await a.enabled(selectors.signIn);
        await a.tab.click(selectors.signIn);
        await a.tab.waitForPath(pagePathname(world, fleet.activate), world.timeoutMs);
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
    );
  }
  await step(
    world,
    `${begin.case}: ${begin.decision === "deny" ? "deny" : "type the fingerprint's last group and approve with the step-up"}`,
    mockedLabel,
    async () => {
      const previous = a.tab.document();
      if (begin.decision === "approve")
        await a.tab.setValue(fleet.tailField, begin.fingerprint.slice(-4).toLowerCase());
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
  );
  return true;
}

/** Revokes, on the devices page, every device named by an approval of this run (each revocation proves a step-up). */
async function cleanUp(
  world: World,
  a: Actor,
  names: readonly string[],
  signedIn: boolean,
): Promise<void> {
  await step(world, "clean-up: revoke the devices the approvals created", mockedLabel, async () => {
    expect(signedIn, "The run never signed in, so it cannot revoke anything.");
    await a.visit(pages.devices, "Devices");
    let revoked = 0;
    for (const name of names) {
      if ((await a.tab.count(fleet.revokeDevice(name))) === 0) continue;
      const previous = a.tab.document();
      await a.tab.click(fleet.revokeDevice(name));
      await awaitDocument(
        world,
        a.tab,
        previous,
        "the devices page after a revocation",
        async () =>
          (await a.tab.count(fleet.revokeDevice(name))) === 0 &&
          (await a.tab.text(selectors.heading)) === "Devices",
      );
      revoked += 1;
    }
    world.report.facts.devicesRevoked = revoked;
    world.report.facts.devicesLeft = (
      await Promise.all(names.map(async (name) => a.tab.count(fleet.revokeDevice(name))))
    ).reduce((sum, count) => sum + count, 0);
    expect(world.report.facts.devicesLeft === 0, "A device of the run is still listed.");
  });
}
