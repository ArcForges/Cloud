// SPDX-License-Identifier: AGPL-3.0-only
// Real-browser acceptance of the center's account pages (AF-CTR-03 A2). Run from the repository root on the Windows host, after
// `npm ci` in this directory (the root `npm ci` never installs this package):
//
//   node eng/verification/browser/acceptance.ts [--base-url https://proof.arcforges.com/api]
//   node eng/verification/browser/acceptance.ts --real-authenticator          (AR-23, with the owner at the keyboard)
//
// The browser is the Playwright Chromium revision 1243 that playwright-core 1.63.0 names, started by its explicit executable
// path; nothing is downloaded. The authenticator is Chromium's virtual authenticator, which is MOCKED hardware in a real browser;
// only --real-authenticator reaches Windows Hello. The first run uses the bootstrap token file that proof-bootstrap.ts wrote and
// saves the owner's credential in a user-only file; later runs sign in with it. Nothing the run prints, reports or throws holds a
// token, a key or a cookie value, and tracing, screenshots and videos are never switched on.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
  requiredChromiumRevision,
  requiredPlaywrightCore,
} from "./driver.ts";
import {
  AcceptanceError,
  type Label,
  type Report,
  newWorld,
  runAcceptance,
  runRealAuthenticator,
} from "./flow.ts";

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

const usage = `Usage: node eng/verification/browser/acceptance.ts [--base-url <url>] [--chromium <path>] [--state-dir <dir>]
  [--bootstrap-file <file>] [--display-name <text>] [--headed] [--real-authenticator] [--report <file>]
  [--pace-ms <n>] [--timeout-ms <n>] [--real-timeout-ms <n>] [--requests-per-minute <n>]`;

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
    report: path.resolve("artifacts", "browser-acceptance.json"),
    paceMs: 750,
    timeoutMs: 30_000,
    realTimeoutMs: 180_000,
    requestsPerMinute: defaultRequestsPerMinute,
  };
  let headless = false;
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
        index += 1;
        break;
      default:
        throw new UsageError(`Unknown argument.\n${usage}`);
    }
  }
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
    if (options.realAuthenticator && !store.exists()) {
      deps.writeError(
        "--real-authenticator needs the saved owner credential; run the acceptance once first.",
      );
      return 2;
    }
    if (!options.realAuthenticator && !store.exists()) {
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
    mode: options.realAuthenticator ? "real-authenticator" : bootstrap ? "enroll" : "returning",
  });
  world.write(
    `playwright-core ${requiredPlaywrightCore}, Chromium ${world.report.browserVersion} (revision ${requiredChromiumRevision}), ${options.headed ? "headed" : "headless"}`,
  );
  let exitCode = 0;
  try {
    if (options.realAuthenticator) await runRealAuthenticator(world);
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
  if (exitCode === 0 && bounded && sent.busiest > maxRequestsPerWindow) {
    world.report.result = "failed";
    exitCode = 1;
    deps.writeError(
      `The browser sent ${sent.busiest} requests inside one minute, more than the ${maxRequestsPerWindow} a run may send (the edge limit of the proof environment is ${edgeLimitPerMinute} per minute): it would be answered with 429. The run is failed.`,
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
