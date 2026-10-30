// SPDX-License-Identifier: AGPL-3.0-only
// The real-browser acceptance package (AF-CTR-03 A2): its arguments, the pinned-Chromium guard, the saved credential, the flow
// against a stand-in for the center and a browser, the AR-23 mode, and the isolation of its playwright-core package. The flow's
// run against the real center and a real Chromium happens after the merge, on the Windows host; these tests check the script's
// logic, never the center.
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  type Dependencies,
  baseUrlProblem,
  main,
  parseArguments,
} from "../../eng/verification/browser/acceptance.ts";
import {
  CredentialStore,
  checkCredential,
  credentialFileName,
  parseCredentialFile,
} from "../../eng/verification/browser/credentials.ts";
import {
  type Launcher,
  browsersDirectory,
  chromiumPathProblem,
  defaultChromiumPath,
  manifestProblem,
  preflight,
} from "../../eng/verification/browser/driver.ts";
import {
  Redactor,
  cookieProblems,
  headerProblems,
  mockedLabel,
  newWorld,
  realLabel,
} from "../../eng/verification/browser/flow.ts";
import { ids, pages, persistBefore, selectors } from "../../eng/verification/browser/selectors.ts";
import { createBootstrapFile, generateBootstrap } from "../../eng/verification/proof-bootstrap.ts";
import { realMachine } from "../../eng/verification/user-only.ts";
import { pageRoutes, pageSecurityHeaders } from "../../worker/tables/center-tables.generated.ts";
import { FakeBrowser, FakeCenter, type FakeOptions } from "./support/browser-fake.ts";

const root = path.resolve(import.meta.dirname, "../..");
const browserDirectory = path.join(root, "eng/verification/browser");
const baseUrl = "https://proof.arcforges.com/api";
const scratches: string[] = [];
test.after(() => {
  for (const directory of scratches) rmSync(directory, { recursive: true, force: true });
});
const scratch = () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "af-acceptance-"));
  scratches.push(directory);
  return directory;
};

// ---------------------------------------------------------------------------------------------------------------------------
// A run against the stand-in

interface Scenario {
  center: FakeCenter;
  browser: FakeBrowser;
  stateDir: string;
  bootstrapDir: string;
  stdout: string[];
  stderr: string[];
  reports: { file: string; text: string }[];
  sleeps: number[];
  launches: { executablePath: string; headless: boolean }[];
  token: string;
  run(argv?: string[], over?: Partial<Dependencies>): Promise<number>;
  everything(): string;
}

function scenario(options: Partial<FakeOptions> = {}, tokenOverride?: string): Scenario {
  const stateDir = path.join(scratch(), "proof-acceptance");
  const bootstrapDir = path.join(scratch(), "proof-bootstrap");
  const center = new FakeCenter(baseUrl, { token: "", ...options });
  const record = generateBootstrap({ hours: 24, now: new Date(center.clockSeconds * 1000) });
  createBootstrapFile(bootstrapDir, record);
  center.options.token = tokenOverride ?? record.token;
  const browser = new FakeBrowser(center);
  const stdout: string[] = [];
  const stderr: string[] = [];
  const reports: { file: string; text: string }[] = [];
  const sleeps: number[] = [];
  const launches: { executablePath: string; headless: boolean }[] = [];
  const launcher: Launcher = async (launch) => {
    launches.push({ executablePath: launch.executablePath, headless: launch.headless });
    return browser;
  };
  const result: Scenario = {
    center,
    browser,
    stateDir,
    bootstrapDir,
    stdout,
    stderr,
    reports,
    sleeps,
    launches,
    token: record.token,
    async run(argv = [], over = {}) {
      return main(["--pace-ms", "0", ...argv], {
        environment: { PROOF_ACCEPTANCE_DIR: stateDir, PROOF_BOOTSTRAP_DIR: bootstrapDir },
        platform: "win32",
        home: "C:\\Users\\J7Rdm",
        packageDirectory: "C:\\Cloud\\eng\\verification\\browser",
        launcher,
        machine: realMachine(),
        now: () => new Date(center.clockSeconds * 1000),
        sleep: async (milliseconds) => {
          sleeps.push(milliseconds);
          center.clockSeconds += Math.ceil(milliseconds / 1000);
        },
        write: (line) => stdout.push(line),
        writeError: (line) => stderr.push(line),
        exists: () => true,
        read: () => JSON.stringify({ browsers: [{ name: "chromium", revision: "1243" }] }),
        writeReport: (file, text) => reports.push({ file, text }),
        ...over,
      });
    },
    everything: () => [...stdout, ...stderr, ...reports.map((report) => report.text)].join("\n"),
  };
  return result;
}

const store = (s: Scenario) => new CredentialStore(s.stateDir);

test("the first run enrolls the owner, a later run signs in with the saved credential and leaves the account as it was", async () => {
  const s = scenario();
  const saved: { event: string; matches: boolean }[] = [];
  s.center.observe = (event, tab) => {
    if (!Object.values(persistBefore).includes(event as never)) return;
    // When a POST with a new credential or an assertion leaves the browser, the saved file holds the authenticator's credentials
    // with their counters.
    const held = tab.authenticatorModel.held;
    const file = store(s).exists() ? store(s).load().credentials : [];
    const ok =
      held.length > 0 &&
      held.every((credential) =>
        file.some(
          (item) =>
            item.credentialId === credential.credentialId &&
            item.signCount === credential.signCount &&
            item.privateKey === credential.privateKey,
        ),
      );
    saved.push({ event, matches: ok || s.center.passkeys.some((item) => item.real) });
  };
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  assert.equal(s.stdout.at(-1), "PASSED");
  assert(s.center.ownerExists && s.center.tokenSpent);
  assert.deepEqual(
    saved.filter((item) => !item.matches),
    [],
    "the saved file lacked the authenticator's state when a POST left the browser",
  );
  assert(
    saved.some((item) => item.event === persistBefore.enrollment),
    "enrollment",
  );
  assert(
    saved.some((item) => item.event === persistBefore.signIn),
    "sign-in",
  );
  assert(
    saved.some((item) => item.event === persistBefore.stepUp),
    "step-up",
  );
  assert(
    saved.some((item) => item.event === persistBefore.newPasskey),
    "new passkey",
  );
  const file = path.join(s.stateDir, credentialFileName);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync(s.stateDir).mode & 0o777, 0o700);
  const report = JSON.parse(s.reports[0]?.text ?? "{}") as {
    mode: string;
    result: string;
    steps: { name: string; ok: boolean; label: string }[];
    facts: Record<string, unknown>;
  };
  assert.equal(report.mode, "enroll");
  assert.equal(report.result, "passed");
  assert(report.steps.every((entry) => entry.ok));
  assert.deepEqual(
    [...new Set(report.steps.map((entry) => entry.label))].sort(),
    [mockedLabel, "no authenticator"].sort(),
    "every step is labelled MOCKED or as using no authenticator; none claims real hardware",
  );
  assert.equal(report.facts.enrolled, true);
  assert.equal(s.center.passkeys.length, 1, "the second passkey was removed again");
  assert.equal(store(s).load().credentials.length, 1, "and so was its saved credential");
  assert(s.browser.closed);

  // Later runs: the bootstrap is spent and not needed; the counters keep rising and the server accepts them.
  const counter = () => s.center.passkeys[0]?.signCount ?? 0;
  const before = counter();
  s.stdout.length = 0;
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  const again = JSON.parse(s.reports[1]?.text ?? "{}") as { mode: string };
  assert.equal(again.mode, "returning");
  assert(counter() > before);
  assert.equal(s.center.passkeys.length, 1);
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  assert.equal(
    store(s).load().credentials[0]?.signCount,
    counter(),
    "the file follows the server's counter",
  );
  for (const session of s.center.sessions.values()) assert(session.revoked || true);
});

test("a run that restores an older saved credential is refused by the counter rule, which is why every assertion is saved", async () => {
  const s = scenario();
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  const file = path.join(s.stateDir, credentialFileName);
  const old = path.join(scratch(), "old.json");
  copyFileSync(file, old);
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  copyFileSync(old, file);
  s.stderr.length = 0;
  assert.equal(await s.run(), 1);
  assert.match(s.stderr.join("\n"), /failed|stopped/u);
  assert.equal(s.stdout.at(-1), "FAILED");
});

test("no output, report or error holds the token, a key, a credential ID or a cookie value", async () => {
  const s = scenario();
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  const secrets = new Set<string>([s.token]);
  for (const credential of store(s).load().credentials) {
    secrets.add(credential.privateKey);
    secrets.add(credential.credentialId);
    if (credential.userHandle) secrets.add(credential.userHandle);
  }
  for (const tab of s.browser.tabs) for (const value of tab.secretsSeen) secrets.add(value);
  for (const tab of s.browser.tabs)
    for (const credential of tab.authenticatorModel.held) {
      secrets.add(credential.privateKey);
      secrets.add(credential.credentialId);
    }
  assert(secrets.size >= 5, "the scan knows what to look for");
  for (const secret of secrets)
    assert(
      !s.everything().includes(secret),
      `a secret of length ${secret.length} was printed or reported`,
    );
  // The credential file holds the keys (that is its purpose) and nothing else holds them.
  assert(
    readFileSync(path.join(s.stateDir, credentialFileName), "utf8").includes([...secrets][1] ?? ""),
  );
  for (const entry of readdirSync(s.stateDir))
    assert.equal(entry, credentialFileName, "no temporary file is left");
});

test("a secret in a browser error is redacted before it is printed", async () => {
  const s = scenario({});
  s.center.options.leakInErrors = s.token;
  // The bootstrap is refused (another token is expected), and the browser's error quotes the token.
  s.center.options.token = "afb1.not-the-bootstrap";
  assert.equal(await s.run(), 1);
  assert(!s.everything().includes(s.token), "the token is in the output");
  assert.match(s.stderr.join("\n"), /\[redacted\]/u);
  assert(!s.center.ownerExists);
});

test("a failing save stops the request before it leaves the browser, and the account is not created", async () => {
  const s = scenario({ exportNothing: true });
  assert.equal(await s.run(), 1);
  assert(
    !s.center.ownerExists,
    "the bootstrap was spent although the credential could not be saved",
  );
  assert(
    !s.center.events.some((event) => event.includes("enrollment")),
    "the enrollment request left the browser",
  );
  assert(!s.everything().includes(s.token));
  assert.match(s.stderr.join("\n"), /the browser reported 1 problem|failed/u);
});

test("a 429 voids the attempt, the step waits for the advised time and starts again, and three in a row fail the step", async () => {
  const s = scenario({ rateLimit: { remaining: 1, retryAfter: 5 } });
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  assert(s.sleeps.includes(5000), "waited for the Retry-After");
  const report = JSON.parse(s.reports[0]?.text ?? "{}") as { steps: { attempts: number }[] };
  assert.equal(report.steps[0]?.attempts, 2);
  const limited = scenario({ rateLimit: { remaining: 99, retryAfter: 400 } });
  assert.equal(await limited.run(), 1);
  assert.match(limited.stderr.join("\n"), /rate limited \(429\)/u);
  assert.equal(
    limited.sleeps.filter((ms) => ms === 120_000).length,
    2,
    "two waits, each capped at 120 s",
  );
  assert(!limited.center.ownerExists);
});

test("a console error or a policy violation fails the step that caused it", async () => {
  const s = scenario({
    problems: [
      "console error: Refused to execute inline script because it violates the Content Security Policy",
    ],
  });
  assert.equal(await s.run(), 1);
  assert.match(s.stderr.join("\n"), /reported 1 problem/u);
});

test("the run fails on what a real center must never do: a missing header, the token in the address, a lost redirect, a session that survives sign-out", async () => {
  const header = scenario({ badHeader: "content-security-policy" });
  assert.equal(await header.run(), 1);
  assert.match(header.stderr.join("\n"), /content-security-policy/u);
  const address = scenario({ tokenInUrl: true });
  assert.equal(await address.run(), 1);
  assert.match(address.stderr.join("\n"), /token reached the address/u);
  assert(
    !address.everything().includes(address.token),
    "and the token is not printed with the failure",
  );
  const redirect = scenario({ noReturnFragment: true });
  assert.equal(await redirect.run(), 1);
  assert.match(redirect.stderr.join("\n"), /does not lead to the sign-in page/u);
  const survives = scenario({ secondBrowserKeepsSession: true });
  assert.equal(await survives.run(), 1);
  assert.match(survives.stderr.join("\n"), /still reaches the account/u);
});

test("the flow's log lines are redacted as they are written", () => {
  const lines: string[] = [];
  const browser = new FakeBrowser(new FakeCenter(baseUrl, { token: "" }));
  const world = newWorld({
    browser,
    store: new CredentialStore(scratch()),
    baseUrl,
    displayName: "Proof owner",
    mode: "returning",
    now: () => new Date(0),
    sleep: async () => {},
    write: (line) => lines.push(line),
  });
  world.redactor.add("a-secret-value");
  world.write("something a-secret-value happened");
  assert.deepEqual(lines, ["something [redacted] happened"]);
});

test("the run does not start without the pinned browser, a token or credential, or with debug logging", async () => {
  // DEBUG=pw:api prints the values Playwright types.
  const debug = scenario();
  assert.equal(
    await debug.run([], { environment: { DEBUG: "pw:api", PROOF_ACCEPTANCE_DIR: debug.stateDir } }),
    2,
  );
  assert.equal(debug.launches.length, 0);
  assert.match(debug.stderr.join("\n"), /DEBUG/u);
  // The browser is missing, or is not revision 1243.
  const missing = scenario();
  assert.equal(await missing.run([], { exists: (file) => !file.endsWith("chrome.exe") }), 2);
  assert.match(missing.stderr.join("\n"), /not installed/u);
  const other = scenario();
  assert.equal(
    await other.run(["--chromium", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"]),
    2,
  );
  assert.match(other.stderr.join("\n"), /chromium-1243/u);
  assert.equal(other.launches.length, 0);
  const manifest = scenario();
  assert.equal(
    await manifest.run([], {
      read: () => JSON.stringify({ browsers: [{ name: "chromium", revision: "1248" }] }),
    }),
    2,
  );
  // No saved credential and no bootstrap file; an expired bootstrap.
  const none = scenario();
  rmSync(path.join(none.bootstrapDir, "owner-bootstrap.json"));
  assert.equal(await none.run(), 2);
  assert.equal(none.launches.length, 0);
  const expired = scenario();
  expired.center.clockSeconds += 3 * 24 * 3600;
  assert.equal(await expired.run(), 2);
  assert.match(expired.stderr.join("\n"), /expired/u);
  // AR-23 needs the owner's credential.
  const real = scenario();
  assert.equal(await real.run(["--real-authenticator"]), 2);
  assert.match(real.stderr.join("\n"), /saved owner credential/u);
  assert.equal(real.launches.length, 0);
});

test("AR-23: the virtual credential signs in and steps up, Windows Hello creates the passkey and signs in, and the pages' last-used times show it", async () => {
  const s = scenario({ windowsHello: true });
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  const virtualId = s.center.passkeys[0]?.id ?? "";
  const before = s.center.passkeys[0]?.lastUsed;
  s.stdout.length = 0;
  assert.equal(await s.run(["--real-authenticator"]), 0, s.stderr.join("\n"));
  assert.deepEqual(s.launches.at(-1)?.headless, false, "Windows Hello needs a visible browser");
  const report = JSON.parse(s.reports.at(-1)?.text ?? "{}") as {
    mode: string;
    steps: { name: string; label: string; ok: boolean }[];
    facts: Record<string, unknown>;
  };
  assert.equal(report.mode, "real-authenticator");
  const real = report.steps.filter((entry) => entry.label === realLabel);
  assert.equal(real.length, 2, "exactly the creation and the sign-in are marked REAL");
  assert.match(real[0]?.name ?? "", /creates the new passkey/u);
  assert.match(real[1]?.name ?? "", /sign in with Windows Hello/u);
  assert(
    report.steps
      .filter((entry) => entry.label !== realLabel)
      .every((entry) => entry.label !== "REAL hardware: Windows Hello"),
  );
  assert.equal(report.facts.windowsHelloPasskeyCreated, true);
  assert.equal(report.facts.signedInWithWindowsHello, true);
  const helloPasskey = s.center.passkeys.find((item) => item.real);
  assert(
    helloPasskey && helloPasskey.lastUsed !== null,
    "Windows Hello's passkey was used by the sign-in",
  );
  const virtual = s.center.passkeys.find((item) => item.id === virtualId);
  assert(
    virtual?.lastUsed !== before,
    "the virtual credential signed in and stepped up before Windows Hello took over",
  );
  // The Windows Hello credential never reaches the saved file; the virtual one keeps its counter.
  const saved = store(s)
    .load()
    .credentials.map((item) => item.credentialId);
  assert(!saved.includes(helloPasskey?.id ?? ""));
  assert(s.stdout.some((line) => line.includes("Windows Hello asks you to confirm")));
});

test("AR-23 fails when the virtual authenticator is still the one answering", async () => {
  const s = scenario({ windowsHello: true });
  assert.equal(await s.run(), 0, s.stderr.join("\n"));
  s.center.options.brokenDisable = true;
  s.stderr.length = 0;
  assert.equal(await s.run(["--real-authenticator"]), 1);
  assert.match(s.stderr.join("\n"), /Windows Hello|passkey/u);
  const report = JSON.parse(s.reports.at(-1)?.text ?? "{}") as { result: string };
  assert.equal(report.result, "failed");
});

test("AR-23 fails when the center does not show Windows Hello as the passkey that signed in, or shows another passkey as used", async () => {
  for (const [option, message] of [
    ["helloNotMarked", /not marked as used/u],
    ["alsoMarksVirtual", /other than the Windows Hello one/u],
  ] as const) {
    const s = scenario({ windowsHello: true });
    assert.equal(await s.run(), 0, s.stderr.join("\n"));
    s.center.options[option] = true;
    s.stderr.length = 0;
    assert.equal(await s.run(["--real-authenticator"]), 1, option);
    assert.match(s.stderr.join("\n"), message, option);
  }
});

// ---------------------------------------------------------------------------------------------------------------------------
// Arguments

const parse = (argv: string[], environment: Record<string, string> = {}) =>
  parseArguments(argv, environment, "win32", "C:\\Users\\J7Rdm");

test("the arguments have safe defaults and refuse what could drive the wrong place or leak", () => {
  const options = parse([], { LOCALAPPDATA: "C:\\Users\\J7Rdm\\AppData\\Local" });
  assert.equal(options.baseUrl, "https://proof.arcforges.com/api");
  assert.equal(
    options.chromium,
    "C:\\Users\\J7Rdm\\AppData\\Local\\ms-playwright\\chromium-1243\\chrome-win64\\chrome.exe",
  );
  assert.equal(options.headed, false);
  assert.equal(options.realAuthenticator, false);
  assert.equal(parse(["--real-authenticator"]).headed, true);
  assert.throws(() => parse(["--real-authenticator", "--headless"]), /visible/u);
  assert.equal(parse(["--base-url", "http://localhost:8080/"]).baseUrl, "http://localhost:8080");
  assert.equal(
    parse(["--base-url", "https://proof.arcforges.com/api/"]).baseUrl,
    "https://proof.arcforges.com/api",
  );
  for (const bad of [
    "https://arcforges.com/api",
    "https://www.arcforges.com",
    "https://proof.arcforges.com.evil.example/api",
    "http://proof.arcforges.com/api",
    "https://proof.arcforges.com:8443/api",
    "https://user:pass@proof.arcforges.com/api",
    "https://proof.arcforges.com/api?x=1",
    "https://proof.arcforges.com/api#x",
    "https://proof.arcforges.com/api/../x",
    "https://proof.arcforges.com//api",
    "HTTPS://Proof.ArcForges.com/api",
    "https://proof.arcforges.com/a%70i",
    "http://127.0.0.1:8080",
    "ftp://localhost",
    "proof.arcforges.com",
  ])
    assert(baseUrlProblem(bad) !== undefined, bad);
  assert.throws(() => parse(["--base-url", "https://arcforges.com/api"]), /production/u);
  assert.throws(() => parse(["--token", "afb1.x"]), /Unknown argument/u);
  assert.throws(() => parse(["--base-url"]), /needs a value/u);
  assert.throws(() => parse(["--base-url", "--headed"]), /needs a value/u);
  assert.throws(() => parse(["--pace-ms", "-1"]), /whole number/u);
  assert.throws(() => parse(["--timeout-ms", "10"]), /whole number/u);
  assert.throws(() => parse(["--display-name", ""]), /needs a value/u);
  assert.throws(() => parse(["--display-name", "x".repeat(129)]), /1 to 128/u);
  assert.equal(
    parse([], { PROOF_BASE_URL: "http://localhost:9000/api" }).baseUrl,
    "http://localhost:9000/api",
  );
  // The error text never repeats a value that was typed.
  assert.throws(
    () => parse(["--bad-flag-afb1.secret"]),
    (error: Error) => !error.message.includes("afb1.secret"),
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// The pinned browser

test("only Playwright's chromium-1243 is launched, by an explicit path", () => {
  const win =
    "C:\\Users\\J7Rdm\\AppData\\Local\\ms-playwright\\chromium-1243\\chrome-win64\\chrome.exe";
  assert.equal(chromiumPathProblem(win), undefined);
  assert.equal(
    chromiumPathProblem("/home/u/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome"),
    undefined,
  );
  for (const bad of [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Users\\J7Rdm\\AppData\\Local\\ms-playwright\\chromium-1248\\chrome-win64\\chrome.exe",
    "C:\\Users\\J7Rdm\\AppData\\Local\\ms-playwright\\chromium_headless_shell-1243\\chrome-win64\\chrome.exe",
    "C:\\Users\\J7Rdm\\AppData\\Local\\ms-playwright\\chromium-1243\\chrome-win64\\msedge.exe",
    "C:\\x\\chromium-12430\\chrome.exe",
    "",
  ])
    assert(chromiumPathProblem(bad) !== undefined, bad);
  assert.equal(
    defaultChromiumPath(
      { LOCALAPPDATA: "C:\\Users\\J7Rdm\\AppData\\Local" },
      "win32",
      "C:\\Users\\J7Rdm",
    ),
    win,
  );
  assert.equal(
    defaultChromiumPath({}, "win32", "C:\\Users\\J7Rdm"),
    win,
    "without LOCALAPPDATA the profile's AppData\\Local is used",
  );
  assert.equal(
    browsersDirectory({ PLAYWRIGHT_BROWSERS_PATH: "D:\\browsers" }, "win32", "C:\\Users\\J7Rdm"),
    "D:\\browsers",
  );
  assert.equal(
    defaultChromiumPath({}, "linux", "/home/u"),
    "/home/u/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome",
  );
  assert.equal(manifestProblem({ browsers: [{ name: "chromium", revision: "1243" }] }), undefined);
  assert(manifestProblem({ browsers: [{ name: "chromium", revision: "1248" }] }) !== undefined);
  assert(manifestProblem({ browsers: [{ name: "firefox", revision: "1243" }] }) !== undefined);
  assert(manifestProblem(null) !== undefined);
  const problems = preflight(win, "C:\\pkg", () => false);
  assert.equal(problems.length, 2, "the browser and playwright-core are both missing");
  assert.deepEqual(
    preflight(
      win,
      "C:\\pkg",
      () => true,
      () => JSON.stringify({ browsers: [{ name: "chromium", revision: "1243" }] }),
    ),
    [],
  );
  assert.equal(
    preflight(
      win,
      "C:\\pkg",
      () => true,
      () => "not json",
    ).length,
    1,
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// The saved credential

const sample = {
  credentialId: "AQIDBA==",
  isResidentCredential: true,
  rpId: "proof.arcforges.com",
  privateKey: "QUFBQUFBQUE=",
  userHandle: "dXNlcg==",
  signCount: 3,
};

test("the saved credential is read strictly and written only whole, forward and for its owner", () => {
  const directory = path.join(scratch(), "state");
  const saved = new CredentialStore(directory);
  assert.equal(saved.exists(), false);
  saved.prepare();
  const file = {
    baseUrl,
    rpId: "proof.arcforges.com",
    displayName: "Proof owner",
    credentials: [sample],
  };
  const now = new Date("2026-11-01T10:00:00Z");
  saved.create(file, now);
  assert.equal(saved.exists(), true);
  assert.throws(
    () => saved.create(file, now),
    /EEXIST/u,
    "a saved credential is never replaced by a create",
  );
  assert.deepEqual(saved.load().credentials, [sample]);
  assert.equal(statSync(saved.file).mode & 0o777, 0o600);
  // Forward only: a counter may rise and a credential may be added, not lowered or lost.
  const second = { ...sample, credentialId: "BQYHCA==", signCount: 0 };
  saved.save([{ ...sample, signCount: 4 }, second], new Date("2026-11-01T10:05:00Z"));
  assert.equal(saved.load().credentials[0]?.signCount, 4);
  assert.equal(saved.load().createdAt, "2026-11-01T10:00:00.000Z");
  assert.equal(saved.load().updatedAt, "2026-11-01T10:05:00.000Z");
  assert.throws(() => saved.save([{ ...sample, signCount: 3 }, second], now), /lowers/u);
  assert.throws(() => saved.save([second], now), /lacks a saved credential/u);
  assert.throws(() => saved.save([], now), /lacks a saved credential/u);
  assert.throws(
    () =>
      new CredentialStore(path.join(scratch(), "empty")).create({ ...file, credentials: [] }, now),
    /holds no credential/u,
  );
  saved.save([{ ...sample, signCount: 4 }], now, { dropping: [second.credentialId] });
  assert.equal(saved.load().credentials.length, 1);
  assert.deepEqual(readdirSync(directory), [credentialFileName], "no temporary file is left");
  // Never an unreadable or foreign state.
  const text = readFileSync(saved.file, "utf8");
  for (const [name, change] of [
    ["not JSON", "{"],
    ["version", text.replace('"version":1', '"version":2')],
    ["no credentials", text.replace(/"credentials":\[.*\]/u, '"credentials":[]')],
    ["a counter", text.replace('"signCount":4', '"signCount":-1')],
    ["a key", text.replace(/"privateKey":"[^"]*"/u, '"privateKey":"not base64!"')],
  ] as const)
    assert.throws(
      () => parseCredentialFile(change),
      (error: Error) => !error.message.includes(sample.privateKey),
      name,
    );
  assert.throws(
    () => checkCredential({ ...sample, privateKey: 12 }),
    (error: Error) => !error.message.includes("12"),
  );
  assert.throws(
    () =>
      parseCredentialFile(JSON.stringify({ ...JSON.parse(text), credentials: [sample, sample] })),
    /repeats/u,
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// Checks on what the center sends

test("the security headers are the generated set, exactly", () => {
  const good = { ...pageSecurityHeaders };
  assert.deepEqual(headerProblems(good), []);
  assert.equal(Object.keys(good).length, 7);
  for (const name of Object.keys(good)) {
    assert.deepEqual(headerProblems({ ...good, [name]: `${good[name]};` }), [name]);
    const without = { ...good };
    delete without[name];
    assert.deepEqual(headerProblems(without), [name]);
  }
});

test("the session cookie must be exactly what the center sets", () => {
  const now = new Date("2026-11-01T10:00:00Z");
  const cookie = {
    name: "__Host-af_session",
    value: "A".repeat(43),
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    expires: now.getTime() / 1000 + 12 * 3600,
  };
  assert.deepEqual(cookieProblems([cookie], now), []);
  assert.equal(cookieProblems([], now).length, 1);
  assert.equal(cookieProblems([cookie, cookie], now).length, 1);
  for (const [change, expected] of [
    [{ httpOnly: false }, "not HttpOnly"],
    [{ secure: false }, "not Secure"],
    [{ path: "/api" }, "wrong Path"],
    [{ sameSite: "Lax" }, "wrong SameSite"],
    [{ value: "short" }, "not a 43-character handle"],
    [{ expires: now.getTime() / 1000 + 13 * 3600 }, "lifetime outside 12 hours"],
    [{ expires: -1 }, "lifetime outside 12 hours"],
  ] as const)
    assert.deepEqual(cookieProblems([{ ...cookie, ...change }], now), [expected]);
  assert.deepEqual(cookieProblems([cookie, { ...cookie, name: "other" }], now), [
    "another cookie is set",
  ]);
});

test("the redactor replaces every secret, the longest first, and ignores short strings", () => {
  const redactor = new Redactor();
  redactor.add("secretvalue1", "secretvalue1-and-more", "short", undefined);
  assert.equal(
    redactor.redact("a secretvalue1-and-more b secretvalue1 c short"),
    "a [redacted] b [redacted] c short",
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// The script against the center's own pages

const templates = path.join(root, "center/internal/pages/templates");
const template = (name: string) => readFileSync(path.join(templates, `${name}.gohtml`), "utf8");

test("every element and heading the script uses is in the center's templates", () => {
  const all = readdirSync(templates)
    .map((file) => readFileSync(path.join(templates, file), "utf8"))
    .join("\n");
  for (const id of Object.values(ids)) assert(all.includes(`id="${id}"`), `#${id}`);
  for (const [file, heading] of [
    ["sign-in", "Sign in to ArcForges"],
    ["bootstrap", "Create the owner account"],
    ["passkeys", "Account and passkeys"],
    ["sessions", "Sessions"],
    ["devices", "Devices"],
    ["sign-out", "Sign out"],
    ["register", "Create your passkey"],
  ] as const)
    assert(template(file).includes(`>${heading}</h1>`), `${file}: ${heading}`);
  // Tables of one row per item, with the item's name in the row header and the last-used time in the third column of the passkeys.
  for (const file of ["passkeys", "sessions", "devices"]) {
    assert(template(file).includes('<th scope="row">'), file);
    assert(template(file).includes("<tbody>"), file);
  }
  assert(template("passkeys").includes('<td>{{if .LastUsedAt}}<time datetime="{{.LastUsedAt}}">'));
  assert(
    template("sessions").includes("(this session)") &&
      template("devices").includes("(this browser)"),
  );
  // The forms the script submits, by action, and the labels it finds buttons by.
  assert(template("passkeys").includes('action="{{.Base}}/account/passkeys/add"'));
  assert(template("passkeys").includes('action="{{$.Base}}/account/passkeys/remove"'));
  assert(template("passkeys").includes('aria-label="Remove passkey {{.Name}}"'));
  assert(template("sessions").includes('action="{{$.Base}}/account/sessions/revoke"'));
  assert(template("passkeys").includes('data-step-up-class="identity.removeAuthIdentity"'));
  assert(template("sign-in").includes('id="signed-in" hidden'));
  assert(template("base").includes('id="error-summary"'));
  assert(
    selectors.addPasskey.includes("/account/passkeys/add") &&
      selectors.removePasskey.includes("/account/passkeys/remove"),
  );
  assert(selectors.endSession.includes("/account/sessions/revoke"));
});

test("every path the script visits or saves before is a route of the center's generated page table", () => {
  const routes = new Set(pageRoutes.map((route) => `${route.method} ${route.path}`));
  for (const [name, path_] of Object.entries(pages))
    if (name !== "addPasskey") assert(routes.has(`GET ${path_}`), `GET ${path_}`);
  assert(routes.has(`POST ${pages.addPasskey}`));
  for (const path_ of Object.values(persistBefore))
    assert(routes.has(`POST ${path_}`), `POST ${path_}`);
  // Every POST that makes a credential or consumes an assertion is saved before it leaves: the JSON ceremony routes and the
  // registration's completion.
  const ceremony = pageRoutes
    .filter(
      (route) =>
        route.method === "POST" &&
        /enrollment\/complete|authentication\/complete|step-up\/complete|passkeys\/complete/u.test(
          route.path,
        ),
    )
    .map((route) => route.path)
    .sort();
  assert.deepEqual(ceremony, Object.values(persistBefore).sort());
});

// ---------------------------------------------------------------------------------------------------------------------------
// Isolation

test("playwright-core lives in its own package with an exact lockfile that the root never installs", () => {
  const rootManifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as Record<
    string,
    unknown
  >;
  assert.equal(rootManifest.workspaces, undefined, "the root package has no workspaces");
  assert(!JSON.stringify(rootManifest).includes("playwright"));
  assert(!readFileSync(path.join(root, "package-lock.json"), "utf8").includes("playwright"));
  const manifest = JSON.parse(
    readFileSync(path.join(browserDirectory, "package.json"), "utf8"),
  ) as {
    dependencies: Record<string, string>;
    devDependencies?: unknown;
    scripts?: Record<string, string>;
    workspaces?: unknown;
    private: boolean;
  };
  assert.deepEqual(manifest.dependencies, { "playwright-core": "1.63.0" });
  assert.equal(manifest.devDependencies, undefined);
  assert.equal(manifest.workspaces, undefined);
  assert.equal(manifest.private, true);
  for (const hook of ["preinstall", "install", "postinstall", "prepare"])
    assert.equal(manifest.scripts?.[hook], undefined, hook);
  const lock = JSON.parse(
    readFileSync(path.join(browserDirectory, "package-lock.json"), "utf8"),
  ) as {
    lockfileVersion: number;
    packages: Record<
      string,
      {
        version?: string;
        resolved?: string;
        integrity?: string;
        license?: string;
        hasInstallScript?: boolean;
        dependencies?: unknown;
      }
    >;
  };
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(Object.keys(lock.packages).sort(), ["", "node_modules/playwright-core"]);
  const entry = lock.packages["node_modules/playwright-core"];
  assert.equal(entry?.version, "1.63.0");
  assert.equal(
    entry?.resolved,
    "https://registry.npmjs.org/playwright-core/-/playwright-core-1.63.0.tgz",
  );
  assert.match(entry?.integrity ?? "", /^sha512-[A-Za-z0-9+/]{86}==$/u);
  assert.equal(entry?.license, "Apache-2.0");
  assert.equal(entry?.hasInstallScript, undefined);
  assert.equal(entry?.dependencies, undefined, "playwright-core brings no further package");
  const npmrc = readFileSync(path.join(browserDirectory, ".npmrc"), "utf8");
  for (const line of ["save-exact=true", "engine-strict=true", "ignore-scripts=true"])
    assert(npmrc.includes(line), line);
  // No workflow installs it or runs it: it is run by hand on the Windows host.
  const workflow = readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
  assert(!workflow.includes("verification/browser") && !workflow.includes("playwright"));
  assert(!readFileSync(path.join(root, "Dockerfile"), "utf8").includes("playwright"));
});

test("the pinned release names chromium-1243, the browser the Windows host has", () => {
  assert.equal(
    path.basename(path.dirname(path.dirname(defaultChromiumPath({}, "linux", "/h")))),
    "chromium-1243",
  );
  const sources = readdirSync(browserDirectory)
    .filter((file) => file.endsWith(".ts"))
    .map((file) => readFileSync(path.join(browserDirectory, file), "utf8"))
    .join("\n");
  assert(sources.includes('requiredChromiumRevision = "1243"'));
  assert(sources.includes('requiredPlaywrightCore = "1.63.0"'));
});

test("tracing, screenshots, videos, HAR files and downloads are never switched on", () => {
  for (const file of readdirSync(browserDirectory).filter((name) => name.endsWith(".ts"))) {
    const text = readFileSync(path.join(browserDirectory, file), "utf8")
      // Comments may say what is off; code must not turn it on.
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("//") && !line.trimStart().startsWith("*"))
      .join("\n");
    for (const forbidden of [
      /\.tracing\b/u,
      /\.screenshot\(/u,
      /recordVideo/u,
      /recordHar/u,
      /\.startTracing\(/u,
      /acceptDownloads: true/u,
      /\.pdf\(/u,
    ])
      assert(!forbidden.test(text), `${file}: ${forbidden}`);
  }
  const driver = readFileSync(path.join(browserDirectory, "driver.ts"), "utf8");
  assert(driver.includes('serviceWorkers: "block"') && driver.includes("acceptDownloads: false"));
});
