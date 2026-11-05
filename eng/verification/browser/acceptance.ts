// SPDX-License-Identifier: AGPL-3.0-only
// Real-browser acceptance of the center's account pages (AF-CTR-03 A2). Run from the repository root on the Windows host, after
// `npm ci` in this directory (the root `npm ci` never installs this package):
//
//   node eng/verification/browser/acceptance.ts [--base-url https://proof.arcforges.com/api]
//   node eng/verification/browser/acceptance.ts --real-authenticator          (AR-23, with the owner at the keyboard)
//   node eng/verification/browser/acceptance.ts --operator-grant              (the operations page, after an acceptance run)
//
// The browser is the Playwright Chromium revision 1243 that playwright-core 1.63.0 names, started by its explicit executable
// path; nothing is downloaded. The authenticator is Chromium's virtual authenticator, which is MOCKED hardware in a real browser;
// only --real-authenticator reaches Windows Hello. The first run uses the bootstrap token file that proof-bootstrap.ts wrote and
// saves the owner's credential in a user-only file; later runs sign in with it. --operator-grant signs in with that credential
// (it registers no passkey) and drives the operations page of the center: review, a refused step-up, the confirmed grant, its
// replay and a refused reuse. Nothing the run prints, reports or throws holds a token, a key, a cookie value, an account
// identifier or a page's request token, and tracing, screenshots and videos are never switched on.
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  bootstrapFileName,
  defaultBootstrapDirectory,
  readBootstrapFile,
} from "../proof-bootstrap.ts";
import { type Machine, realMachine } from "../user-only.ts";
import { CredentialStore, defaultStateDirectory } from "./credentials.ts";
import {
  type Launcher,
  defaultChromiumPath,
  defaultRequestsPerMinute,
  edgeLimitPerMinute,
  launchPlaywright,
  maxRequestsPerWindow,
  preflight,
  requestBurst,
  requiredChromiumRevision,
  requiredPlaywrightCore,
} from "./driver.ts";
import {
  AcceptanceError,
  type Label,
  type Report,
  newWorld,
  runAcceptance,
  runOperatorGrant,
  runRealAuthenticator,
} from "./flow.ts";
import {
  type Handshake,
  busiestOf,
  runNodeApprove,
  stepUpsAtMost,
  stepUpsPerTenMinutes,
} from "./node-flow.ts";
import { mobileStepUpsAtMost, runMobileApprove } from "./mobile-flow.ts";

export const defaultBaseUrl = "https://proof.arcforges.com/api";
/** The only hosts the script drives: the acceptance environment, or a center on this machine. Production is never a target. */
export const allowedHosts = ["proof.arcforges.com", "localhost"] as const;

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export interface Options {
  baseUrl: string;
  chromium: string;
  stateDir: string;
  bootstrapFile: string;
  displayName: string;
  headed: boolean;
  realAuthenticator: boolean;
  operatorGrant: boolean;
  /** The node-approve mode (AF-CTR-04 E3): the handshake directory node-probe writes into, the number of cases, the waits. */
  nodeApprove: boolean;
  /** The mobile-approve mode (AF-CTR-04 part M, H3): the same handshake directory, written by mobile-probe. */
  mobileApprove: boolean;
  watch: string;
  cases: number;
  waitMs: number;
  negative: boolean;
  report: string;
  paceMs: number;
  timeoutMs: number;
  realTimeoutMs: number;
  requestsPerMinute: number;
}

/** Why a base URL is refused (undefined when it is the acceptance environment's, or a local center's). */
export function baseUrlProblem(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "--base-url is not a URL.";
  }
  if (url.username || url.password || url.search || url.hash)
    return "--base-url carries credentials, a query or a fragment.";
  if (!(allowedHosts as readonly string[]).includes(url.hostname))
    return `--base-url must be on ${allowedHosts.join(" or ")}; production is never driven by this script.`;
  if (
    url.hostname === "localhost"
      ? url.protocol !== "http:" && url.protocol !== "https:"
      : url.protocol !== "https:"
  )
    return "--base-url must be https (http only on localhost).";
  if (url.hostname !== "localhost" && url.port !== "") return "--base-url must not name a port.";
  // The URL must already be in the form the parser makes of it (no dot segments, no upper-case host, no doubled slash): the script
  // builds every address from this text.
  if (
    /%|\/\//u.test(url.pathname) ||
    value.replace(/\/+$/u, "") !== `${url.origin}${url.pathname}`.replace(/\/+$/u, "")
  )
    return "--base-url is not in its plain form.";
  return undefined;
}

/** The report a mode writes unless --report names another file: the operator grant must not overwrite the acceptance's. */
export const defaultReportName = {
  acceptance: "browser-acceptance.json",
  operatorGrant: "browser-operator-grant.json",
  nodeApprove: "browser-node-approve.json",
  mobileApprove: "browser-mobile-approve.json",
};

/**
 * The request bound of the node-approve mode against the hosted edge: node-probe runs on the same machine as the browser (its loopback
 * receiver must be the browser's), so its requests count against the same edge limit; the browser keeps to fewer. The budget paces the
 * browser at this rate after a burst of `requestBurst` (4): at most 40 requests in any minute.
 */
export const nodeApproveRequestsPerMinute = 36;

/**
 * The busiest minute of a node-approve run against the edge: the browser's busiest minute plus node-probe's (the two share the
 * machine's edge key, so their sum bounds the busiest minute of both). The run fails when it exceeds maxRequestsPerWindow.
 */
export function combinedBusiest(browserBusiest: number, probeRequests: readonly number[]): number {
  return browserBusiest + busiestOf(probeRequests);
}

const usage = `Usage: node eng/verification/browser/acceptance.ts [--base-url <url>] [--chromium <path>] [--state-dir <dir>]
  [--bootstrap-file <file>] [--display-name <text>] [--headed] [--real-authenticator | --operator-grant] [--report <file>]
  [--pace-ms <n>] [--timeout-ms <n>] [--real-timeout-ms <n>] [--requests-per-minute <n>] [--help]
  node-approve: [--node-approve] --watch <dir> [--cases <n>] [--wait-ms <n>] [--negative]
  mobile-approve: --mobile-approve --watch <dir> [--cases <n>] [--wait-ms <n>]
Without --real-authenticator or --operator-grant the run enrolls the owner (the first run, with the bootstrap file) or signs in
with the saved credential (every later run).
--operator-grant needs the saved owner credential. It signs in with the MOCKED authenticator, then on the operations page reviews
  and confirms a grant of remote.view for 1 day to the owner's own account, and checks the replay and the refusals. Its report
  defaults to artifacts/${defaultReportName.operatorGrant}.
Edge limit: the hosted edge counts the requests of a client over 60 seconds. Leave at least 90 seconds between two runs against
  the hosted environment, and run --operator-grant only after the returning acceptance has passed.
Step-up limit: apart from the edge, the center allows 10 step-ups per account in 10 minutes. --operator-grant spends 2 step-ups,
  a returning run 3, and a restarted step one more: wait ten minutes between repeated attempts, or a 429 of the center looks like
  the edge's.
--node-approve (node-approve.ts) needs the saved owner credential. It decides the sign-ins that center/cmd/node-probe (MOCKED node)
  starts and announces in the --watch directory, --cases of them (default 2), on /connect and /activate, then revokes the devices
  its approvals created. node-probe runs on the same machine (its loopback receiver must be the browser's), and its requests count
  against the same edge limit: the browser paces itself at ${nodeApproveRequestsPerMinute} requests a minute after a burst of
  ${requestBurst} (at most ${nodeApproveRequestsPerMinute + requestBurst} in any minute), and the run fails when the browser's busiest
  minute and the probe's together exceed ${maxRequestsPerWindow}. Each case may spend 2 step-ups (its approval and its device's
  revocation), so --cases refuses a set that could spend more than the center's ${stepUpsPerTenMinutes} in 10 minutes. --negative also
  submits one wrong fingerprint tail (one more step-up and one entry of the account's budget): for the local rehearsal. Its report
  defaults to artifacts/${defaultReportName.nodeApprove}.
--mobile-approve (mobile-approve.ts, AF-CTR-04 part M) needs the saved owner credential. It decides the attempts that
  center/cmd/mobile-probe (MobileProbe, MOCKED app) begins and announces in the --watch directory, --cases of them, on
  /mobile/authorize; it hands each callback to the probe through the directory, taps the done page's link (the fallback page loads),
  then revokes the phones its approvals created. The probe's requests count against the same edge limit, with the same pacing and
  bound as --node-approve. Each case may spend 2 step-ups, so --cases refuses a set that could spend more than
  ${stepUpsPerTenMinutes}. Its report defaults to artifacts/${defaultReportName.mobileApprove}.
Exit codes: 0 passed, 1 failed, 2 not started (usage, missing browser, credential or bootstrap file).`;

function whole(value: string | undefined, flag: string, min: number, max: number): number {
  if (value === undefined || !/^\d+$/u.test(value) || Number(value) < min || Number(value) > max)
    throw new UsageError(`${flag} is a whole number from ${min} to ${max}.`);
  return Number(value);
}

export function parseArguments(
  argv: readonly string[],
  environment: Record<string, string | undefined>,
  platform: NodeJS.Platform,
  home: string,
): Options {
  const options: Options = {
    baseUrl: environment.PROOF_BASE_URL || defaultBaseUrl,
    chromium: defaultChromiumPath(environment, platform, home),
    stateDir: defaultStateDirectory(environment, home),
    bootstrapFile: path.join(defaultBootstrapDirectory(environment), bootstrapFileName),
    displayName: "Proof owner",
    headed: false,
    realAuthenticator: false,
    operatorGrant: false,
    nodeApprove: false,
    mobileApprove: false,
    watch: "",
    cases: 2,
    waitMs: 600_000,
    negative: false,
    report: path.resolve("artifacts", defaultReportName.acceptance),
    paceMs: 750,
    timeoutMs: 30_000,
    realTimeoutMs: 180_000,
    requestsPerMinute: defaultRequestsPerMinute,
  };
  let headless = false;
  let reportNamed = false;
  let rateNamed = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    const text = (): string => {
      index += 1;
      if (value === undefined || value === "" || value.startsWith("--"))
        throw new UsageError(`${flag} needs a value.\n${usage}`);
      return value;
    };
    switch (flag) {
      case "--base-url":
        options.baseUrl = text();
        break;
      case "--chromium":
        options.chromium = text();
        break;
      case "--state-dir":
        options.stateDir = text();
        break;
      case "--bootstrap-file":
        options.bootstrapFile = text();
        break;
      case "--display-name":
        options.displayName = text();
        break;
      case "--report":
        options.report = path.resolve(text());
        reportNamed = true;
        break;
      case "--headed":
        options.headed = true;
        break;
      case "--headless":
        headless = true;
        break;
      case "--real-authenticator":
        options.realAuthenticator = true;
        break;
      case "--operator-grant":
        options.operatorGrant = true;
        break;
      case "--node-approve":
        options.nodeApprove = true;
        break;
      case "--mobile-approve":
        options.mobileApprove = true;
        break;
      case "--watch":
        options.watch = path.resolve(text());
        break;
      case "--cases":
        options.cases = whole(value, flag, 1, 8);
        index += 1;
        break;
      case "--wait-ms":
        options.waitMs = whole(value, flag, 10_000, 900_000);
        index += 1;
        break;
      case "--negative":
        options.negative = true;
        break;
      case "--pace-ms":
        options.paceMs = whole(value, flag, 0, 60_000);
        index += 1;
        break;
      case "--timeout-ms":
        options.timeoutMs = whole(value, flag, 1_000, 300_000);
        index += 1;
        break;
      case "--real-timeout-ms":
        options.realTimeoutMs = whole(value, flag, 10_000, 900_000);
        index += 1;
        break;
      case "--requests-per-minute":
        options.requestsPerMinute = whole(value, flag, 0, 600);
        rateNamed = true;
        index += 1;
        break;
      default:
        throw new UsageError(`Unknown argument.\n${usage}`);
    }
  }
  if (
    [
      options.realAuthenticator,
      options.operatorGrant,
      options.nodeApprove,
      options.mobileApprove,
    ].filter(Boolean).length > 1
  )
    throw new UsageError(
      "--real-authenticator, --operator-grant, --node-approve and --mobile-approve are separate runs; name one.",
    );
  if (options.operatorGrant && !reportNamed)
    options.report = path.resolve("artifacts", defaultReportName.operatorGrant);
  if (options.nodeApprove && !reportNamed)
    options.report = path.resolve("artifacts", defaultReportName.nodeApprove);
  if (options.mobileApprove && !reportNamed)
    options.report = path.resolve("artifacts", defaultReportName.mobileApprove);
  if (options.nodeApprove && options.watch === "")
    throw new UsageError("--node-approve needs --watch <dir>.");
  if (options.mobileApprove && options.watch === "")
    throw new UsageError("--mobile-approve needs --watch <dir>.");
  if (options.mobileApprove && options.negative)
    throw new UsageError("--negative belongs to --node-approve.");
  if (!options.nodeApprove && !options.mobileApprove && (options.watch !== "" || options.negative))
    throw new UsageError("--watch and --negative belong to --node-approve.");
  if ((options.nodeApprove || options.mobileApprove) && !rateNamed)
    options.requestsPerMinute = nodeApproveRequestsPerMinute;
  if (options.mobileApprove && mobileStepUpsAtMost(options.cases) > stepUpsPerTenMinutes)
    throw new UsageError(
      `--cases ${options.cases} could spend ${mobileStepUpsAtMost(options.cases)} step-ups (one per approval and one per revoked phone), more than the ${stepUpsPerTenMinutes} per account in 10 minutes the center allows.`,
    );
  if (options.nodeApprove && stepUpsAtMost(options.cases, options.negative) > stepUpsPerTenMinutes)
    throw new UsageError(
      `--cases ${options.cases}${options.negative ? " with --negative" : ""} could spend ${stepUpsAtMost(options.cases, options.negative)} step-ups (one per approval and one per revoked device${options.negative ? ", one for --negative" : ""}), more than the ${stepUpsPerTenMinutes} per account in 10 minutes the center allows.`,
    );
  if (options.realAuthenticator) {
    // Windows Hello needs a window the owner can see and answer.
    if (headless)
      throw new UsageError("--real-authenticator needs a visible browser; it cannot be headless.");
    options.headed = true;
  }
  if (options.displayName.length > 128 || options.displayName.trim() === "")
    throw new UsageError("--display-name is 1 to 128 characters.");
  const problem = baseUrlProblem(options.baseUrl);
  if (problem) throw new UsageError(problem);
  // The hosted Worker counts every request of a page load against an edge limit; only a center on this machine may be sent more.
  // (The bound is the browser's, all its tabs together.)
  if (options.requestsPerMinute === 0 && new URL(options.baseUrl).hostname !== "localhost")
    throw new UsageError("--requests-per-minute 0 (no bound) is for a center on localhost only.");
  if (
    options.requestsPerMinute > defaultRequestsPerMinute &&
    new URL(options.baseUrl).hostname !== "localhost"
  )
    throw new UsageError(
      `--requests-per-minute above ${defaultRequestsPerMinute} is for a center on localhost only.`,
    );
  options.baseUrl = options.baseUrl.replace(/\/+$/u, "");
  return options;
}

export interface Dependencies {
  environment: Record<string, string | undefined>;
  platform: NodeJS.Platform;
  home: string;
  packageDirectory: string;
  launcher: Launcher;
  machine: Machine;
  now(): Date;
  sleep(milliseconds: number): Promise<void>;
  write(line: string): void;
  writeError(line: string): void;
  exists(file: string): boolean;
  read(file: string): string;
  writeReport(file: string, text: string): void;
  /** The handshake directory of the node-approve mode (absent: the file system). */
  handshake?: (directory: string) => Handshake;
}

/** The handshake directory on the file system: node-probe's files are read as they are, the flow's are written whole (rename). */
export function fileHandshake(directory: string): Handshake {
  return {
    list: () => (existsSync(directory) ? readdirSync(directory) : []),
    read: (name) => readFileSync(path.join(directory, name), "utf8"),
    write: (name, text) => {
      const temporary = path.join(directory, `.${name}.tmp`);
      writeFileSync(temporary, text, { mode: 0o600 });
      renameSync(temporary, path.join(directory, name));
    },
  };
}

export function realDependencies(): Dependencies {
  return {
    environment: process.env,
    platform: process.platform,
    home: homedir(),
    packageDirectory: import.meta.dirname,
    launcher: launchPlaywright,
    machine: realMachine(),
    now: () => new Date(),
    sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    write: (line) => console.log(line),
    writeError: (line) => console.error(line),
    exists: existsSync,
    read: (file) => readFileSync(file, "utf8"),
    writeReport: (file, text) => {
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, text);
    },
  };
}

/** The labels of a finished report: what was MOCKED and what was REAL. */
export function summary(report: Report): string[] {
  const counts = new Map<Label, number>();
  for (const step of report.steps)
    if (step.ok) counts.set(step.label, (counts.get(step.label) ?? 0) + 1);
  return [...counts.entries()].map(([label, count]) => `${count} step(s): ${label}`);
}

/** Runs the command; the result is the process exit code (0 passed, 1 failed, 2 not started). */
export async function main(argv: readonly string[], deps: Dependencies): Promise<number> {
  if (argv.includes("--help")) {
    deps.write(usage);
    return 0;
  }
  let options: Options;
  try {
    options = parseArguments(argv, deps.environment, deps.platform, deps.home);
  } catch (error) {
    deps.writeError(error instanceof Error ? error.message : usage);
    return 2;
  }
  // Playwright's debug logging prints the values it types; it is never allowed alongside a token.
  if (/\bpw:/u.test(deps.environment.DEBUG ?? "")) {
    deps.writeError("DEBUG names pw:*, which logs typed values. Unset DEBUG and run again.");
    return 2;
  }
  const problems = preflight(options.chromium, deps.packageDirectory, deps.exists, deps.read);
  if (problems.length > 0) {
    for (const problem of problems) deps.writeError(problem);
    return 2;
  }
  const store = new CredentialStore(options.stateDir, deps.machine);
  let bootstrap: ReturnType<typeof readBootstrapFile> | undefined;
  try {
    const needsSaved =
      options.realAuthenticator ||
      options.operatorGrant ||
      options.nodeApprove ||
      options.mobileApprove;
    if (needsSaved && !store.exists()) {
      deps.writeError(
        `${options.realAuthenticator ? "--real-authenticator" : options.operatorGrant ? "--operator-grant" : options.mobileApprove ? "--mobile-approve" : "--node-approve"} needs the saved owner credential; run the acceptance once first.`,
      );
      return 2;
    }
    if (!needsSaved && !store.exists()) {
      bootstrap = readBootstrapFile(options.bootstrapFile, deps.machine);
      if (new Date(bootstrap.expiresAt).getTime() <= deps.now().getTime()) {
        deps.writeError(
          "The bootstrap token has expired; generate a new one with proof-bootstrap.ts and dispatch again.",
        );
        return 2;
      }
    }
  } catch (error) {
    deps.writeError(error instanceof Error ? error.message : "The saved state cannot be read.");
    return 2;
  }
  const browser = await deps.launcher({
    executablePath: options.chromium,
    headless: !options.headed,
    timeoutMs: options.timeoutMs,
    requestsPerMinute: options.requestsPerMinute,
  });
  const world = newWorld({
    browser,
    store,
    baseUrl: options.baseUrl,
    displayName: options.displayName,
    bootstrap,
    now: deps.now,
    sleep: deps.sleep,
    write: deps.write,
    timeoutMs: options.timeoutMs,
    paceMs: options.paceMs,
    realTimeoutMs: options.realTimeoutMs,
    mode: options.realAuthenticator
      ? "real-authenticator"
      : options.operatorGrant
        ? "operator-grant"
        : options.nodeApprove
          ? "node-approve"
          : options.mobileApprove
            ? "mobile-approve"
            : bootstrap
              ? "enroll"
              : "returning",
  });
  world.write(
    `playwright-core ${requiredPlaywrightCore}, Chromium ${world.report.browserVersion} (revision ${requiredChromiumRevision}), ${options.headed ? "headed" : "headless"}`,
  );
  let exitCode = 0;
  const probeRequests: number[] = [];
  try {
    if (options.realAuthenticator) await runRealAuthenticator(world);
    else if (options.operatorGrant) await runOperatorGrant(world);
    else if (options.nodeApprove)
      await runNodeApprove(world, {
        handshake: (deps.handshake ?? fileHandshake)(options.watch),
        cases: options.cases,
        waitMs: options.waitMs,
        negative: options.negative,
        probeRequests,
      });
    else if (options.mobileApprove)
      await runMobileApprove(world, {
        handshake: (deps.handshake ?? fileHandshake)(options.watch),
        cases: options.cases,
        waitMs: options.waitMs,
        probeRequests,
      });
    else await runAcceptance(world);
    world.report.result = "passed";
  } catch (error) {
    world.report.result = "failed";
    exitCode = 1;
    const message =
      error instanceof AcceptanceError
        ? error.message
        : error instanceof Error
          ? `The run stopped: ${error.message}`
          : "The run stopped.";
    deps.writeError(world.redactor.redact(message.split("\n")[0] ?? "The run stopped."));
  } finally {
    world.report.finishedAt = deps.now().toISOString();
    for (const tab of world.tabs) await tab.close().catch(() => undefined);
    await browser.close().catch(() => undefined);
  }
  // What the browser really sent to the origin, redirect hops included: a run that kept to a bound meant for the hosted edge limit
  // and was still seen to send more than the margin allows would be answered with 429 there, so it does not pass.
  const sent = browser.requests();
  world.report.facts.requestsSent = sent.total;
  world.report.facts.requestsBusiest60s = sent.busiest;
  const bounded =
    options.requestsPerMinute >= 1 && options.requestsPerMinute <= defaultRequestsPerMinute;
  // node-probe's requests share the browser's edge key: the two busiest minutes together bound the busiest minute of both.
  const probed = options.nodeApprove || options.mobileApprove;
  if (probed) {
    world.report.facts.probeRequests = probeRequests.length;
    world.report.facts.probeBusiest60s = busiestOf(probeRequests);
    world.report.facts.requestsBusiest60sBound = combinedBusiest(sent.busiest, probeRequests);
  }
  const busiest = probed ? combinedBusiest(sent.busiest, probeRequests) : sent.busiest;
  if (exitCode === 0 && bounded && busiest > maxRequestsPerWindow) {
    world.report.result = "failed";
    exitCode = 1;
    deps.writeError(
      `The browser${options.nodeApprove ? " and node-probe" : options.mobileApprove ? " and mobile-probe" : ""} sent up to ${busiest} requests inside one minute, more than the ${maxRequestsPerWindow} a run may send (the edge limit of the proof environment is ${edgeLimitPerMinute} per minute): it would be answered with 429. The run is failed.`,
    );
  }
  // The report holds steps, counts and flags; if anything secret is in it, it is not written.
  const text = `${JSON.stringify(world.report, null, 2)}\n`;
  if (world.redactor.redact(text) !== text) {
    deps.writeError("The report would hold a secret; it is not written.");
    return 1;
  }
  deps.writeReport(options.report, text);
  for (const line of summary(world.report)) deps.write(line);
  deps.write(world.report.result === "passed" ? "PASSED" : "FAILED");
  return exitCode;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = await main(process.argv.slice(2), realDependencies());
