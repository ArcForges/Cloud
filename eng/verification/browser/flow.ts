// SPDX-License-Identifier: AGPL-3.0-only
// The acceptance flow of the center's account pages (AF-CTR-03 A2), written against the small browser interface of driver.ts.
//
// Two modes:
//   - runAcceptance: Chromium's virtual authenticator (MOCKED hardware in a real browser). The first run enrolls the proof owner
//     through the bootstrap and saves the credential; every later run signs in with the saved credential. Each run signs in, steps
//     up, registers a second passkey, lists sessions and devices, ends a session from a second browser, removes the second passkey
//     and signs out.
//   - runRealAuthenticator (AR-23): signs in with the saved virtual credential, removes the virtual authenticator, lets the
//     owner's Windows Hello create a new passkey, signs out and signs in with Windows Hello, and shows from the pages' own
//     "last used" times that Windows Hello (not the virtual credential) made the second sign-in.
//
// The saved credential is written before every POST that carries a new credential or an assertion leaves the browser, so a failed
// run never loses the owner's key; nothing in a log, a report or an error message is a token, a key or a cookie value.
import { pageSecurityHeaders } from "../../../worker/tables/center-tables.generated.ts";
import type { BootstrapRecord } from "../proof-bootstrap.ts";
import {
  type CredentialStore,
  type SavedCredential,
  type Transport,
  type VirtualCredential,
  credentialSecrets,
  nextTransport,
  withoutTransport,
} from "./credentials.ts";
import type { Authenticator, Browser, CookieView, Navigation, Tab } from "./driver.ts";
import { ids, pages, persistBefore, selectors, sessionCookie } from "./selectors.ts";

export const mockedLabel = "MOCKED hardware: Chromium virtual authenticator in a real browser";
export const realLabel = "REAL hardware: Windows Hello";
export const plainLabel = "no authenticator";
export type Label = typeof mockedLabel | typeof realLabel | typeof plainLabel;

/** A failed expectation. Its message is fixed text that names the step or the page, never a value from the browser's session. */
export class AcceptanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AcceptanceError";
  }
}

/** Replaces every secret it was told about, wherever it occurs in a text. */
export class Redactor {
  private readonly secrets = new Set<string>();

  add(...values: (string | undefined)[]): void {
    for (const value of values)
      if (value !== undefined && value.length >= 8) this.secrets.add(value);
  }

  redact(text: string): string {
    let result = text;
    // The longest first, so that a secret that contains another is replaced whole.
    for (const secret of [...this.secrets].sort((a, b) => b.length - a.length))
      result = result.split(secret).join("[redacted]");
    return result;
  }
}

export interface StepRecord {
  name: string;
  label: Label;
  ok: boolean;
  attempts: number;
  milliseconds: number;
  /** Fixed text about the outcome (counts, paths, flags); never a secret. */
  note?: string;
}

export interface Report {
  mode: "enroll" | "returning" | "real-authenticator";
  baseUrl: string;
  startedAt: string;
  finishedAt?: string;
  browserVersion: string;
  steps: StepRecord[];
  /** Facts the run established, by name. */
  facts: Record<string, string | number | boolean>;
  result: "passed" | "failed" | "running";
}

export interface World {
  browser: Browser;
  store: CredentialStore;
  /** The center's public base URL without a trailing slash, such as https://proof.arcforges.com/api. */
  baseUrl: string;
  displayName: string;
  /** The bootstrap of the first run (absent after the owner exists). */
  bootstrap?: BootstrapRecord;
  redactor: Redactor;
  report: Report;
  now(): Date;
  sleep(milliseconds: number): Promise<void>;
  /** Writes one line (already redacted here before it is passed on). */
  write(line: string): void;
  timeoutMs: number;
  /** The wait after each step, which keeps the run under the edge limit. */
  paceMs: number;
  /** The longest wait for the owner to confirm with Windows Hello. */
  realTimeoutMs: number;
  /** Tabs opened so far and how many of their problems were reported. */
  tabs: Tab[];
  problemsSeen: Map<Tab, number>;
  /** Credential IDs removed from the account (they leave the saved file with the next write). */
  dropped: Set<string>;
  /** Whether this run wrote the credential file (the first run does, before the enrollment request leaves the browser). */
  createdCredentialFile: boolean;
}

export function newWorld(
  input: Pick<World, "browser" | "store" | "baseUrl" | "displayName" | "now" | "sleep" | "write"> &
    Partial<Pick<World, "bootstrap" | "timeoutMs" | "paceMs" | "realTimeoutMs">> & {
      mode: Report["mode"];
    },
): World {
  const redactor = new Redactor();
  if (input.bootstrap) redactor.add(input.bootstrap.token);
  return {
    browser: input.browser,
    store: input.store,
    baseUrl: input.baseUrl,
    displayName: input.displayName,
    bootstrap: input.bootstrap,
    redactor,
    report: {
      mode: input.mode,
      baseUrl: input.baseUrl,
      startedAt: input.now().toISOString(),
      browserVersion: input.browser.version(),
      steps: [],
      facts: {},
      result: "running",
    },
    now: input.now,
    sleep: input.sleep,
    write: (line) => input.write(redactor.redact(line)),
    timeoutMs: input.timeoutMs ?? 30_000,
    paceMs: input.paceMs ?? 750,
    realTimeoutMs: input.realTimeoutMs ?? 180_000,
    tabs: [],
    problemsSeen: new Map(),
    dropped: new Set(),
    createdCredentialFile: false,
  };
}

// ---------------------------------------------------------------------------------------------------------------------------
// Checks

function expect(condition: boolean, message: string): asserts condition {
  if (!condition) throw new AcceptanceError(message);
}

/** The security headers (generated from the center's own table) a page reply lacks or has with another value. */
export function headerProblems(headers: Record<string, string>): string[] {
  const problems: string[] = [];
  for (const [name, value] of Object.entries(pageSecurityHeaders))
    if (headers[name.toLowerCase()] !== value) problems.push(name);
  return problems;
}

/** What is wrong with the session cookie the browser holds (nothing, when it is exactly what the center sets). */
export function cookieProblems(cookies: readonly CookieView[], now: Date): string[] {
  const found = cookies.filter((cookie) => cookie.name === sessionCookie.name);
  if (found.length !== 1) return [`${found.length} session cookies`];
  const [cookie] = found;
  if (cookie === undefined) return ["no session cookie"];
  const problems: string[] = [];
  if (!cookie.httpOnly) problems.push("not HttpOnly");
  if (!cookie.secure) problems.push("not Secure");
  if (cookie.path !== sessionCookie.path) problems.push("wrong Path");
  if (cookie.sameSite !== sessionCookie.sameSite) problems.push("wrong SameSite");
  if (!/^[A-Za-z0-9_-]{43}$/u.test(cookie.value)) problems.push("not a 43-character handle");
  const lifetime = cookie.expires - now.getTime() / 1000;
  if (!(lifetime > 0 && lifetime <= 12 * 3600 + 60)) problems.push("lifetime outside 12 hours");
  if (cookies.some((item) => item.name !== sessionCookie.name))
    problems.push("another cookie is set");
  return problems;
}

// ---------------------------------------------------------------------------------------------------------------------------
// Steps

const maxAttempts = 3;
const maxRateLimitWaitSeconds = 120;

function basePath(world: World): string {
  return new URL(world.baseUrl).pathname.replace(/\/$/u, "");
}
const pageUrl = (world: World, pagePath: string) => `${world.baseUrl}${pagePath}`;
const pagePathname = (world: World, pagePath: string) => `${basePath(world)}${pagePath}`;

function newProblems(world: World): string[] {
  const fresh: string[] = [];
  for (const tab of world.tabs) {
    const all = tab.problems();
    fresh.push(...all.slice(world.problemsSeen.get(tab) ?? 0));
    world.problemsSeen.set(tab, all.length);
  }
  return fresh;
}

/**
 * Runs one step. A 429 seen anywhere during an attempt (the edge limiter answers before the center sees the request) makes the
 * attempt void: the step waits for the advised time and starts again, at most three attempts; a step therefore starts from a
 * navigation. Any console error, page error or policy violation fails the step.
 */
async function step<T>(
  world: World,
  name: string,
  label: Label,
  run: () => Promise<T>,
): Promise<T> {
  const started = world.now().getTime();
  const record: StepRecord = { name, label, ok: false, attempts: 0, milliseconds: 0 };
  world.report.steps.push(record);
  world.write(`  ${name} [${label}]`);
  for (;;) {
    record.attempts += 1;
    const changesBefore = totalChanges(world);
    let outcome: { value: T } | { error: unknown };
    try {
      outcome = { value: await run() };
    } catch (error) {
      outcome = { error };
    }
    const limited = world.tabs
      .map((tab) => tab.rateLimited())
      .filter((seconds): seconds is number => seconds !== undefined);
    if (limited.length > 0) {
      newProblems(world);
      // The edge limiter answers before the center sees a request, so a step may start again from its navigation, unless an
      // earlier request of the attempt already changed something: a step that removes a passkey cannot find it a second time.
      if (totalChanges(world) > changesBefore) {
        record.note = "rate limited (429) after a change was made";
        record.milliseconds = world.now().getTime() - started;
        // What the step said about its own failure comes with it: "the account may exist; do not delete the credential file" must
        // not be lost behind the 429.
        const cause =
          "error" in outcome && outcome.error instanceof Error ? ` ${outcome.error.message}` : "";
        throw new AcceptanceError(
          `Step "${name}" was rate limited (429) after a request of it had changed something; it is not repeated.${cause}`,
        );
      }
      if (record.attempts >= maxAttempts) {
        record.note = "rate limited (429) on every attempt";
        record.milliseconds = world.now().getTime() - started;
        throw new AcceptanceError(`Step "${name}" was rate limited (429) on every attempt.`);
      }
      const wait = Math.min(Math.max(...limited), maxRateLimitWaitSeconds);
      world.write(`    rate limited (429): waiting ${wait} s, then the step starts again`);
      await world.sleep(wait * 1000);
      continue;
    }
    const problems = newProblems(world);
    record.milliseconds = world.now().getTime() - started;
    if (problems.length === 0 && "value" in outcome) {
      record.ok = true;
      await world.sleep(world.paceMs);
      return outcome.value;
    }
    let reason = "the step failed";
    if (problems.length > 0)
      reason = `the browser reported ${problems.length} problem(s): ${problems.join("; ")}`;
    else if ("error" in outcome && outcome.error instanceof Error) reason = outcome.error.message;
    // What the pages say about the failure (fixed texts of the center's refusals) is worth more than a timeout.
    reason += await pageReason(world);
    record.note = world.redactor.redact(reason);
    throw new AcceptanceError(`Step "${name}" failed: ${record.note}`);
  }
}

function totalChanges(world: World): number {
  return world.tabs.reduce((sum, tab) => sum + tab.changes(), 0);
}

/** The path and the error summary of each tab that shows one: fixed texts of the pages, never a secret. */
async function pageReason(world: World): Promise<string> {
  const notes: string[] = [];
  for (const tab of world.tabs) {
    try {
      const summary = (await tab.attributes(`#${ids.errorSummary}`, "hidden"))[0];
      if (summary !== null) continue;
      const text = await tab.text(selectors.errorText);
      if (text) notes.push(`${new URL(tab.url()).pathname} says "${text.slice(0, 200)}"`);
    } catch {
      // A tab that cannot be read adds nothing.
    }
  }
  return notes.length > 0 ? ` (page: ${notes.join("; ")})` : "";
}

/** Polls until the check holds; the wait is counted in polls so that a fake clock needs no support. */
async function until(
  world: World,
  what: string,
  check: () => Promise<boolean>,
  timeoutMs: number = world.timeoutMs,
): Promise<void> {
  const interval = 250;
  for (let poll = 0; poll <= timeoutMs / interval; poll += 1) {
    if (await check()) return;
    await world.sleep(interval);
  }
  throw new AcceptanceError(`Timed out waiting for ${what}.`);
}

// ---------------------------------------------------------------------------------------------------------------------------
// One browser tab with its virtual authenticator

/** A virtual authenticator of the tab, the transport it was added with and the transport its credential is saved under. */
interface Slot {
  authenticator: Authenticator;
  saveAs: Transport;
}

/**
 * One browser tab and its virtual authenticators: ONE PER CREDENTIAL. Chromium keeps one discoverable credential per relying party
 * and user handle on an authenticator (a second replaces the first, and addCredential refuses it), and the account's passkeys all
 * share one user handle. The first credential lives on the single `internal` authenticator, every further one on its own with
 * another transport, which the saved file records.
 */
class Actor {
  readonly world: World;
  readonly tab: Tab;
  slots: Slot[] = [];
  /** Credentials taken off the tab for the registration ceremony (nothing the page excludes may be held then). */
  parked: SavedCredential[] = [];
  /**
   * Saved credentials this tab never put on an authenticator: those of passkeys that earlier runs left behind. A key whose passkey
   * the center never accepted would answer a sign-in and fail it, so only the owner's own credential is attached for the sign-in.
   * They stay in the saved file, until the cleanup of the run forgets them.
   */
  deferred: SavedCredential[] = [];
  /** The virtual environment is gone (AR-23): the saved file is no longer this tab's to write. */
  virtualGone = false;

  constructor(world: World, tab: Tab) {
    this.world = world;
    this.tab = tab;
  }

  /**
   * Opens a tab in a new browser context. It gets one virtual authenticator for each saved credential (with `owner`: for the
   * owner's own credential, the one on the `internal` transport, and no other), or, with none saved, one empty `internal`
   * authenticator for the enrollment.
   */
  static async open(world: World, attach: "all" | "owner" = "all"): Promise<Actor> {
    const tab = await world.browser.newTab();
    world.tabs.push(tab);
    const actor = new Actor(world, tab);
    if (world.store.exists()) {
      const saved = world.store.load();
      world.redactor.add(...credentialSecrets(saved.credentials));
      const owners = saved.credentials.filter((credential) => credential.transport === "internal");
      expect(
        attach === "all" || owners.length === 1,
        "The saved file holds no credential of the owner's own.",
      );
      for (const credential of saved.credentials) {
        if (attach === "all" || credential.transport === "internal") await actor.attach(credential);
        else actor.deferred.push(credential);
      }
    } else await actor.attachEmpty();
    // Before a POST that carries a new credential or an assertion leaves the browser, the credentials of the authenticators (with
    // their counters) are saved. If saving fails, the request is stopped.
    await tab.beforePost(
      Object.values(persistBefore).map((path) => `${basePath(world)}${path}`),
      () => actor.persist(),
    );
    return actor;
  }

  /** Adds the credential on an authenticator of its own. */
  async attach(credential: SavedCredential): Promise<void> {
    const authenticator = await this.tab.addAuthenticator(credential.transport);
    await authenticator.addCredential(withoutTransport(credential));
    this.slots.push({ authenticator, saveAs: credential.transport });
  }

  /** Adds an empty authenticator that will hold a credential saved under `saveAs`. */
  async attachEmpty(
    saveAs: Transport = "internal",
    transport: Transport = "internal",
  ): Promise<Slot> {
    const slot = { authenticator: await this.tab.addAuthenticator(transport), saveAs };
    this.slots.push(slot);
    return slot;
  }

  /** Removes every authenticator of the tab. */
  async removeAll(): Promise<void> {
    for (const slot of this.slots) await slot.authenticator.remove();
    this.slots = [];
  }

  /** The credentials the authenticators hold, with the counters they have now. */
  async held(): Promise<SavedCredential[]> {
    const held: SavedCredential[] = [];
    for (const slot of this.slots)
      for (const credential of await slot.authenticator.credentials())
        held.push({ ...credential, transport: slot.saveAs });
    return held;
  }

  /** Every credential this tab knows: the held ones and those parked for a ceremony. */
  async known(): Promise<SavedCredential[]> {
    const held = await this.held();
    return [
      ...held,
      ...[...this.parked, ...this.deferred].filter(
        (p) => !held.some((credential) => credential.credentialId === p.credentialId),
      ),
    ];
  }

  /** Writes the credentials of this tab to the saved file: the union over its authenticators. */
  async persist(): Promise<void> {
    const { world } = this;
    if (this.virtualGone) return;
    const exported = (await this.known()).filter(
      (credential) => !world.dropped.has(credential.credentialId),
    );
    world.redactor.add(...credentialSecrets(exported));
    if (world.store.exists())
      world.store.save(exported, world.now(), { dropping: [...world.dropped] });
    else {
      world.store.create(
        {
          baseUrl: world.baseUrl,
          rpId: new URL(world.baseUrl).hostname,
          displayName: world.displayName,
          credentials: exported,
        },
        world.now(),
      );
      world.createdCredentialFile = true;
    }
    const persisted = world.report.facts.credentialWrites;
    world.report.facts.credentialWrites = (typeof persisted === "number" ? persisted : 0) + 1;
  }

  /**
   * Runs the page's passkey creation on a fresh authenticator. The page sends every passkey of the account in excludeCredentials, so
   * a held credential would refuse the ceremony (InvalidStateError), and a held credential of the same user handle would be replaced.
   * Every authenticator is therefore taken off (their credentials parked, counters read first), the ceremony runs on one empty
   * authenticator, and afterwards each credential, the new one included, goes back on an authenticator of its own.
   */
  async registerFresh(
    ceremony: () => Promise<void>,
    strays: readonly string[] = [],
  ): Promise<SavedCredential> {
    this.parked = await this.held();
    const saveAs = nextTransport(this.parked);
    expect(saveAs !== undefined, noFreeTransport(strays));
    await this.removeAll();
    const fresh = await this.attachEmpty(saveAs, "internal");
    let created: SavedCredential | undefined;
    let failure: unknown;
    let failed = false;
    try {
      await ceremony();
    } catch (error) {
      failure = error;
      failed = true;
    }
    try {
      // Whatever the ceremony did, the authenticator holds what it made, and the saved file may hold it already (it is written
      // before the request that carries it leaves): the credential goes back with the others, so that the tab and the file agree.
      let made: VirtualCredential[] = [];
      try {
        made = await fresh.authenticator.credentials();
      } catch (error) {
        if (!failed) throw error;
      }
      if (made.length === 1) created = { ...(made[0] as VirtualCredential), transport: saveAs };
      if (!failed)
        expect(made.length === 1, "The authenticator did not make exactly one new credential.");
    } finally {
      await this.removeAll();
      const parked = this.parked;
      this.parked = [];
      for (const credential of [...parked, ...(created ? [created] : [])])
        await this.attach(credential);
    }
    if (failed) throw failure;
    return created as SavedCredential;
  }

  /**
   * Forgets the credentials this tab left deferred, that is every credential but the owner's own: each was made by a run of this
   * script for a passkey named `acceptance-*`, and is of no use once that passkey is off the account (or when the center never
   * accepted it). The saved file is written without them.
   */
  async forgetDeferred(): Promise<number> {
    // `persist` leaves out every credential `world.dropped` names, so this is all the forgetting there is.
    for (const credential of this.deferred) this.world.dropped.add(credential.credentialId);
    await this.persist();
    return this.deferred.length;
  }

  /** Takes the virtual environment away (AR-23): the browser then reaches the real authenticators. */
  async goReal(): Promise<void> {
    await this.removeAll();
    await this.tab.disableVirtual();
    this.virtualGone = true;
  }

  /** Opens a page, expects the center's headers and the page's heading. */
  async visit(pagePath: string, heading: string, landedOn: string = pagePath): Promise<Navigation> {
    const { tab, world } = this;
    const navigation = await tab.goto(pageUrl(world, pagePath));
    expect(navigation.status === 200, `GET ${pagePath} answered ${navigation.status}.`);
    const missing = headerProblems(navigation.headers);
    expect(
      missing.length === 0,
      `GET ${pagePath} lacks or changes security headers: ${missing.join(", ")}.`,
    );
    expect(
      navigation.headers["content-type"]?.startsWith("text/html") === true,
      `GET ${pagePath} is not HTML.`,
    );
    expect(
      new URL(tab.url()).pathname === pagePathname(world, landedOn),
      `GET ${pagePath} landed on ${new URL(tab.url()).pathname}.`,
    );
    expect((await tab.text(selectors.heading)) === heading, `${pagePath} has another heading.`);
    return navigation;
  }

  async rows(): Promise<number> {
    return this.tab.count(selectors.rows);
  }

  async hidden(selector: string): Promise<boolean> {
    return (await this.tab.attributes(selector, "hidden"))[0] !== null;
  }

  /** Waits for the page's script to enable a button (it does so once the page's first call returned). */
  async enabled(selector: string): Promise<void> {
    await this.tab.waitForSelector(`${selector}:not([disabled])`, this.world.timeoutMs);
  }

  async signOutHere(): Promise<void> {
    const { tab, world } = this;
    await this.visit(pages.signOut, "Sign out");
    await this.enabled(selectors.signOut);
    await tab.click(selectors.signOut);
    await tab.waitForPath(pagePathname(world, pages.signIn), world.timeoutMs);
  }

  /** Signs in on the sign-in page with the authenticator (the page's script asserts, then goes to the passkeys). */
  async signInHere(timeoutMs: number = this.world.timeoutMs): Promise<void> {
    const { tab, world } = this;
    await this.enabled(selectors.signIn);
    await tab.click(selectors.signIn);
    await tab.waitForPath(pagePathname(world, pages.passkeys), timeoutMs);
  }

  async cookieChecks(): Promise<string[]> {
    const cookies = await this.tab.cookies();
    this.world.redactor.add(...cookies.map((cookie) => cookie.value));
    return cookieProblems(cookies, this.world.now());
  }
}

// ---------------------------------------------------------------------------------------------------------------------------
// The virtual-authenticator acceptance

/** The name every passkey this script registers starts with (the owner's own passkeys, AR-23's included, never do). */
const strayPrefix = "acceptance-";

/** The unique name of the passkey this run registers and removes again. */
function passkeyName(world: World): string {
  return `${strayPrefix}${world.now().toISOString().replace(/[-:T]/gu, "").slice(0, 14)}`;
}

/** What a registration says when the saved file has no transport left, with the passkeys of earlier runs that may be the cause. */
export function noFreeTransport(strays: readonly string[]): string {
  return `The saved file holds as many credentials as there are transports. Passkeys of earlier runs that may still be on the account: ${strays.length > 0 ? strays.join(", ") : "none listed"}. See the runbook, "A run that stopped".`;
}

/** The saved credential must be the one of this center: a file made for another center would only fail at the sign-in. */
function expectSavedCenter(world: World): void {
  const saved = world.store.load();
  expect(
    saved.baseUrl === world.baseUrl && saved.rpId === new URL(world.baseUrl).hostname,
    `The saved credential was made for ${saved.baseUrl} (relying party ${saved.rpId}), not for ${world.baseUrl}; name another directory for this center with --state-dir (or PROOF_ACCEPTANCE_DIR).`,
  );
}

export async function runAcceptance(world: World): Promise<void> {
  const returning = world.store.exists();
  world.report.mode = returning ? "returning" : "enroll";
  world.write(
    `Acceptance of ${world.baseUrl} (${returning ? "the saved owner credential" : "the bootstrap"})`,
  );
  if (!returning)
    expect(world.bootstrap !== undefined, "There is no saved credential and no bootstrap file.");
  else expectSavedCenter(world);
  world.store.prepare();

  const a = await step(
    world,
    "open a browser with a virtual authenticator",
    mockedLabel,
    async () => {
      // A returning run signs in with the owner's own credential; what earlier runs left in the file waits until it is forgotten.
      const actor = await Actor.open(world, "owner");
      const signIn = await actor.visit(pages.signIn, "Sign in to ArcForges");
      world.report.facts.securityHeaders = Object.keys(pageSecurityHeaders).length;
      expect(signIn.status === 200, "The sign-in page is not served.");
      expect((await actor.tab.cookies()).length === 0, "A new browser holds a cookie.");
      return actor;
    },
  );

  if (!returning) {
    await step(world, "enroll the owner with the bootstrap token", mockedLabel, async () => {
      const bootstrap = world.bootstrap;
      expect(bootstrap !== undefined, "There is no bootstrap.");
      // A start from nothing: an attempt that was refused has left a credential on the authenticator and, maybe, in the file.
      await a.removeAll();
      await a.attachEmpty();
      await a.visit(pages.bootstrap, "Create the owner account");
      await a.enabled(selectors.create);
      // The token is typed into the page's field from this process; it is in no URL, no log and no report.
      await a.tab.setValue(selectors.token, bootstrap.token);
      await a.tab.setValue(selectors.displayName, world.displayName);
      const acceptedBefore = a.tab.changes();
      const unsettledBefore = a.tab.unsettled();
      try {
        await a.tab.click(selectors.create);
        await a.tab.waitForPath(pagePathname(world, pages.passkeys), world.timeoutMs);
      } catch (error) {
        if (a.tab.changes() > acceptedBefore || a.tab.unsettled() > unsettledBefore) {
          // The center accepted the enrollment (the account is created, the token is spent), or may have: its reply was lost or was
          // a server error. The tab did not arrive, and the file holds the only copy of the owner's key, so it stays unless every
          // reply to the enrollment request was a definite refusal.
          const reason = error instanceof Error ? error.message : "the step failed";
          throw new AcceptanceError(
            `The account may exist; do not delete the credential file. Cause: ${reason}`,
          );
        }
        // Nothing was accepted: the credential saved for the enrollment belongs to nothing, and a file left behind would make the
        // next run "returning" and never use the bootstrap token.
        if (world.createdCredentialFile) {
          world.store.discard();
          world.createdCredentialFile = false;
        }
        throw error;
      }
      expect(
        !a.tab.url().includes("token") && !a.tab.url().includes(bootstrap.token),
        "The token reached the address.",
      );
      expect((await a.rows()) === 1, "The new account does not show exactly one passkey.");
      expect(world.store.exists(), "The credential was not saved before the account was created.");
      const problems = await a.cookieChecks();
      expect(problems.length === 0, `The session cookie: ${problems.join(", ")}.`);
      world.report.facts.enrolled = true;
    });
  }

  await step(
    world,
    "sign out, find the protected page closed, sign in with the passkey",
    mockedLabel,
    async () => {
      if (!returning) await a.signOutHere();
      else await a.visit(pages.signIn, "Sign in to ArcForges");
      // A protected page without a session sends the visitor to the sign-in page and remembers where to go back to.
      await a.tab.goto(pageUrl(world, pages.passkeys));
      expect(
        new URL(a.tab.url()).pathname === pagePathname(world, pages.signIn) &&
          a.tab.url().includes(`#return=`),
        "A protected page without a session does not lead to the sign-in page.",
      );
      expect(
        await a.hidden(`#${ids.signedIn}`),
        "The sign-in page claims a session that does not exist.",
      );
      await a.signInHere();
      const problems = await a.cookieChecks();
      expect(problems.length === 0, `The session cookie: ${problems.join(", ")}.`);
    },
  );

  // A run that stopped after it had registered its passkey leaves that passkey on the account and its key in the saved file; the
  // owner's file would run out of transports after three such runs. The returning run removes what an earlier run left.
  if (returning && a.deferred.length > 0) {
    await step(world, "remove the passkeys an earlier run left behind", mockedLabel, async () => {
      await a.visit(pages.passkeys, "Account and passkeys");
      const strays = (await a.tab.texts(selectors.rowHeaders)).filter((text) =>
        text.startsWith(strayPrefix),
      );
      for (const stray of strays) {
        const rows = await a.rows();
        await a.tab.click(`${selectors.removePasskey}[aria-label="Remove passkey ${stray}"]`);
        await until(
          world,
          "the stray passkey to leave the list",
          async () => (await a.rows()) === rows - 1,
        );
      }
      const left = (await a.tab.texts(selectors.rowHeaders)).filter((text) =>
        text.startsWith(strayPrefix),
      );
      expect(left.length === 0, "A passkey of an earlier run is still on the account.");
      await a.forgetDeferred();
      world.report.facts.strayPasskeysRemoved = strays.length;
    });
  }

  const name = passkeyName(world);
  let before = 0;
  let extraId = "";
  await step(
    world,
    "step up with the passkey and register a second passkey",
    mockedLabel,
    async () => {
      await a.visit(pages.passkeys, "Account and passkeys");
      before = await a.rows();
      const strays = (await a.tab.texts(selectors.rowHeaders)).filter((text) =>
        text.startsWith(strayPrefix),
      );
      await a.tab.setValue(selectors.newPasskeyName, name);
      await a.tab.click(selectors.addPasskey);
      await a.tab.waitForSelector(selectors.createPasskey, world.timeoutMs);
      expect(
        (await a.tab.text(selectors.heading)) === "Create your passkey",
        "No registration page after the step-up.",
      );
      const created = await a.registerFresh(async () => {
        await a.tab.click(selectors.createPasskey);
        await a.tab.waitForPath(pagePathname(world, pages.passkeys), world.timeoutMs);
      }, strays);
      // Every credential is back on an authenticator of its own: what the tab holds is what the saved file holds.
      const held = (await a.held()).map((credential) => credential.credentialId).sort();
      const saved = world.store
        .load()
        .credentials.map((credential) => credential.credentialId)
        .sort();
      expect(
        held.length === saved.length && held.every((id, index) => id === saved[index]),
        "After the registration the tab does not hold the credentials of the saved file.",
      );
      await until(
        world,
        "the new passkey in the list",
        async () => (await a.rows()) === before + 1,
      );
      expect(
        (await a.tab.texts(selectors.rowHeaders)).includes(name),
        "The new passkey is not listed by its name.",
      );
      extraId = created.credentialId;
      world.redactor.add(extraId);
      world.report.facts.passkeysAfterAdd = before + 1;
    },
  );

  await step(world, "list the sessions and the devices", plainLabel, async () => {
    await a.visit(pages.sessions, "Sessions");
    const rows = await a.rows();
    expect(rows >= 1, "No session is listed.");
    expect(
      (await a.tab.texts(selectors.rowHeaders)).filter((text) => text.includes("(this session)"))
        .length === 1,
      "This browser's session is not the one marked.",
    );
    world.report.facts.sessionsListed = rows;
    await a.visit(pages.devices, "Devices");
    const devices = await a.rows();
    expect(devices >= 1, "No device is listed.");
    const here = (await a.tab.texts(selectors.rowHeaders)).filter((text) =>
      text.includes("(this browser)"),
    );
    expect(here.length === 1, "This browser's device is not the one marked.");
    world.report.facts.devicesListed = devices;
  });

  const b = await step(
    world,
    "sign in from a second browser and end a session",
    mockedLabel,
    async () => {
      const actor = await Actor.open(world);
      await actor.visit(pages.signIn, "Sign in to ArcForges");
      await actor.signInHere();
      await actor.visit(pages.sessions, "Sessions");
      const sessions = await actor.rows();
      expect(sessions >= 2, "The second browser does not see the first session.");
      await actor.tab.click(selectors.endSession);
      await until(
        world,
        "the ended session to leave the list",
        async () => (await actor.rows()) === sessions - 1,
      );
      world.report.facts.sessionsAfterRevoke = sessions - 1;
      return actor;
    },
  );

  await step(
    world,
    "the first browser keeps or loses its session as the revocation says",
    plainLabel,
    async () => {
      await a.tab.goto(pageUrl(world, pages.sessions));
      const ended = new URL(a.tab.url()).pathname === pagePathname(world, pages.signIn);
      world.report.facts.firstSessionEnded = ended;
      if (!ended) await a.signOutHere();
    },
  );

  await step(world, "remove the second passkey and sign out", mockedLabel, async () => {
    await b.visit(pages.passkeys, "Account and passkeys");
    const rows = await b.rows();
    await b.tab.click(`${selectors.removePasskey}[aria-label="Remove passkey ${name}"]`);
    await until(
      world,
      "the removed passkey to leave the list",
      async () => (await b.rows()) === rows - 1,
    );
    expect(
      !(await b.tab.texts(selectors.rowHeaders)).includes(name),
      "The removed passkey is still listed.",
    );
    world.dropped.add(extraId);
    await b.persist();
    expect(
      (await b.rows()) === before,
      "The account does not return to its passkeys from before the run.",
    );
    await b.signOutHere();
    await b.tab.goto(pageUrl(world, pages.passkeys));
    expect(
      new URL(b.tab.url()).pathname === pagePathname(world, pages.signIn),
      "A signed-out browser still reaches the account.",
    );
  });
  world.report.facts.passkeysAtEnd = before;
}

// ---------------------------------------------------------------------------------------------------------------------------
// AR-23: Windows Hello

/** The "last used" instants of the passkeys table by passkey name (null where a passkey was never used). */
async function lastUsed(actor: Actor): Promise<Map<string, string | null>> {
  const names = await actor.tab.texts(selectors.rowHeaders);
  const cells = await actor.tab.texts(selectors.passkeyLastUsed);
  expect(names.length === cells.length, "The passkeys table is not one row per passkey.");
  const instants = await actor.tab.attributes(`${selectors.passkeyLastUsed} time`, "datetime");
  // A "Never" cell has no <time>; the instants of the other cells follow in order.
  let next = 0;
  const result = new Map<string, string | null>();
  names.forEach((name, index) => {
    const used = cells[index] !== "Never";
    result.set(name, used ? (instants[next++] ?? null) : null);
  });
  return result;
}

export async function runRealAuthenticator(world: World): Promise<void> {
  world.report.mode = "real-authenticator";
  world.write(
    `AR-23 on ${world.baseUrl}: the saved virtual credential signs in, Windows Hello creates the new passkey`,
  );
  expect(world.store.exists(), "There is no saved owner credential; run the acceptance first.");
  expectSavedCenter(world);
  const name = `Windows Hello AR-23 ${world.now().toISOString().slice(0, 10)}`;
  let virtualUsed: string | null = null;

  const actor = await step(
    world,
    "sign in with the saved virtual credential",
    mockedLabel,
    async () => {
      const opened = await Actor.open(world, "owner");
      await opened.visit(pages.signIn, "Sign in to ArcForges");
      await opened.signInHere();
      return opened;
    },
  );

  await step(
    world,
    "step up with the virtual credential and reach the passkey creation",
    mockedLabel,
    async () => {
      await actor.visit(pages.passkeys, "Account and passkeys");
      await actor.tab.setValue(selectors.newPasskeyName, name);
      await actor.tab.click(selectors.addPasskey);
      await actor.tab.waitForSelector(selectors.createPasskey, world.timeoutMs);
      expect(
        (await actor.tab.text(selectors.heading)) === "Create your passkey",
        "No registration page after the step-up.",
      );
    },
  );

  await step(
    world,
    "Windows Hello creates the new passkey (confirm when Windows asks)",
    realLabel,
    async () => {
      // From here on the browser reaches the real authenticators: the virtual one is removed and the virtual environment is off.
      expect(actor.slots.length > 0, "There is no virtual authenticator to remove.");
      await actor.goReal();
      world.write(
        "    >>> Windows Hello asks you to confirm now (PIN, fingerprint or face). The script waits.",
      );
      await actor.tab.click(selectors.createPasskey);
      await actor.tab.waitForPath(pagePathname(world, pages.passkeys), world.realTimeoutMs);
      await actor.visit(pages.passkeys, "Account and passkeys");
      expect(
        (await actor.tab.texts(selectors.rowHeaders)).includes(name),
        "The Windows Hello passkey is not listed.",
      );
      const used = await lastUsed(actor);
      expect(used.get(name) === null, "The new passkey is already marked used.");
      virtualUsed = [...used.entries()]
        .filter(([key]) => key !== name)
        .map(([, value]) => value ?? "never")
        .sort()
        .join(",");
      world.report.facts.windowsHelloPasskeyCreated = true;
    },
  );

  await step(world, "sign out", plainLabel, async () => {
    await actor.signOutHere();
  });

  await step(
    world,
    "sign in with Windows Hello (confirm when Windows asks)",
    realLabel,
    async () => {
      await actor.visit(pages.signIn, "Sign in to ArcForges");
      world.write(
        "    >>> Windows Hello asks you to choose the passkey and confirm. The script waits.",
      );
      await actor.signInHere(world.realTimeoutMs);
      await actor.visit(pages.passkeys, "Account and passkeys");
      const used = await lastUsed(actor);
      expect(
        used.get(name) !== null && used.get(name) !== undefined,
        "The Windows Hello passkey is not marked as used by the sign-in.",
      );
      const virtualNow = [...used.entries()]
        .filter(([key]) => key !== name)
        .map(([, value]) => value ?? "never")
        .sort()
        .join(",");
      expect(
        virtualNow === virtualUsed,
        "A passkey other than the Windows Hello one was used for the sign-in.",
      );
      world.report.facts.signedInWithWindowsHello = true;
      const problems = await actor.cookieChecks();
      expect(problems.length === 0, `The session cookie: ${problems.join(", ")}.`);
    },
  );

  await step(world, "sign out", plainLabel, async () => {
    await actor.signOutHere();
  });
}
