// SPDX-License-Identifier: AGPL-3.0-only
// A stand-in for the center's account pages and a browser, for the tests of the acceptance flow (AF-CTR-03 A2). It is deliberately
// strict about what matters to the flow: the bootstrap token works once, an assertion's counter must exceed the stored one (the
// F14 counter rule), every session is its own cookie, a step-up is needed before the changes that need one, and the saved
// credential must exist before the request that carries a new credential or an assertion reaches the "server".
//
// The virtual authenticators follow Chromium's rules, which the real pinned Chromium 153 showed (the first design of the script
// ignored them and passed these tests while failing in the real browser):
//   - the page excludes every passkey of the account in the creation options, and a creation refuses (InvalidStateError, which the
//     page shows as "That passkey is already registered.") when ANY authenticator of the tab holds an excluded credential;
//   - a discoverable credential of the same relying party and user handle REPLACES the one an authenticator holds (all passkeys of
//     an account share one user handle), and WebAuthn.addCredential of such a second credential is refused;
//   - a tab has at most one `internal` authenticator; the other transports may repeat.
// It is no evidence about the real center or a real browser; it checks the script's logic.
import { pageSecurityHeaders } from "../../../worker/tables/center-tables.generated.ts";
import type {
  Transport,
  VirtualCredential,
} from "../../../eng/verification/browser/credentials.ts";
import {
  type Authenticator,
  type Browser,
  type CookieView,
  type Navigation,
  type RequestCounts,
  type Tab,
  acceptedChange,
} from "../../../eng/verification/browser/driver.ts";
import { pages, persistBefore, selectors } from "../../../eng/verification/browser/selectors.ts";

let counter = 0;
const next = (prefix: string) => {
  counter += 1;
  return `${prefix}${counter.toString(36).padStart(8, "0")}`;
};
const b64 = (text: string) => Buffer.from(text).toString("base64");

interface ServerPasskey {
  id: string;
  name: string;
  signCount: number;
  lastUsed: string | null;
  real: boolean;
}

export interface FakeOptions {
  token: string;
  /** Ask the fake to answer 429 (with this Retry-After) to the next N navigations. */
  rateLimit?: { remaining: number; retryAfter: number };
  /** Console problems a page reports at its next load. */
  problems?: string[];
  /** The text an error from the browser carries (a secret in it must be redacted by the script). */
  leakInErrors?: string;
  /** The center does not record a Windows Hello sign-in as the passkey's use. */
  helloNotMarked?: boolean;
  /** A Windows Hello sign-in also marks the other passkeys as used. */
  alsoMarksVirtual?: boolean;
  /** The name of a security header the pages leave out. */
  badHeader?: string;
  /** The pages put the bootstrap token into the address after the enrollment. */
  tokenInUrl?: boolean;
  /** A protected page without a session redirects to the sign-in page without the return fragment. */
  noReturnFragment?: boolean;
  /** Signing out of the second browser leaves its session alive. */
  secondBrowserKeepsSession?: boolean;
  /** The authenticator's export gives nothing (a save that must fail before the request leaves). */
  exportNothing?: boolean;
  /** Whether Windows Hello is present and confirms. */
  windowsHello?: boolean;
  /** Make the "real" create/get use the virtual authenticator even after it is removed (a broken disable). */
  brokenDisable?: boolean;
  /** The center refuses the enrollment request itself (a lost or refused POST). */
  refuseEnrollment?: boolean;
  /** The edge limiter answers the first enrollment POST with a 429 (the center never sees it). */
  limitEnrollmentOnce?: boolean;
  /** The edge limiter answers 429 to the first navigation after a passkey was removed. */
  limitAfterRemoval?: boolean;
  /** The page's creation fails whatever the authenticators hold (the page shows its "already registered" text). */
  pageRefusesCreation?: boolean;
  /** The center accepts the enrollment (the account exists) but the tab never reaches the passkeys page. */
  enrollmentStays?: boolean;
  /** The center accepts the enrollment (the account exists) and its reply is lost: the browser sees no answer at all. */
  enrollmentReplyLost?: boolean;
  /** The center accepts the enrollment and the Worker answers 504: a server error, not a refusal. */
  enrollmentServerError?: boolean;
  /** The center accepts the enrollment and the edge limiter answers the page that follows it with a 429. */
  limitAfterEnrollment?: boolean;
  /** The edge limiter answers 429 to the page the next N sign-ins lead to (after the center accepted the sign-in). */
  limitAfterSignIn?: number;
  /** The devices page cannot be reached (a connection reset): any failure after the second passkey was registered. */
  devicesPageFails?: boolean;
  /** The center refuses the request that completes a new passkey (the key was made and saved, the passkey never existed). */
  refuseNewPasskey?: boolean;
  /** The edge limiter answers the first request that completes a new passkey with a 429 (the center never sees it). */
  limitNewPasskeyOnce?: boolean;
}

export class FakeCenter {
  readonly basePath: string;
  readonly host: string;
  readonly events: string[] = [];
  readonly passkeys: ServerPasskey[] = [];
  readonly sessions = new Map<string, { revoked: boolean; stepUps: number }>();
  tokenSpent = false;
  ownerExists = false;
  /** Every passkey of an account has this user handle (the pages register them so). */
  userHandle = b64("owner-user-handle");
  enrollmentLimited = false;
  newPasskeyLimited = false;
  clockSeconds = 1_800_000_000;
  readonly options: FakeOptions;
  /** The next navigation is answered 429 (set by a change when limitAfterRemoval is on). */
  limitNext = false;
  /** Called when a POST leaves the browser (after the script's hook ran), before the "server" acts on it. */
  observe: (event: string, tab: FakeTab) => void = () => {};

  constructor(baseUrl: string, options: FakeOptions) {
    const url = new URL(baseUrl);
    this.basePath = url.pathname.replace(/\/$/u, "");
    this.host = url.host;
    this.options = options;
  }

  instant(): string {
    return new Date(this.clockSeconds * 1000).toISOString();
  }

  /** The server's check of an assertion: the credential is known and its counter exceeds the stored one. */
  assertion(credentialId: string, signCount: number): ServerPasskey {
    const passkey = this.passkeys.find((item) => item.id === credentialId);
    if (!passkey) throw new Error("unknown credential");
    if (signCount <= passkey.signCount) throw new Error("the counter did not advance");
    passkey.signCount = signCount;
    this.clockSeconds += 7;
    passkey.lastUsed = this.instant();
    return passkey;
  }
}

export class FakeAuthenticator implements Authenticator {
  readonly held: VirtualCredential[] = [];
  readonly transport: Transport;
  private readonly tab: FakeTab | undefined;
  exportNothing = false;

  constructor(transport: Transport, tab?: FakeTab) {
    this.transport = transport;
    this.tab = tab;
  }

  async credentials(): Promise<VirtualCredential[]> {
    if (this.exportNothing) return [];
    return this.held.map((credential) => ({ ...credential }));
  }
  async addCredential(credential: VirtualCredential): Promise<void> {
    const stray = Object.keys(credential).filter(
      (key) =>
        ![
          "credentialId",
          "isResidentCredential",
          "rpId",
          "privateKey",
          "userHandle",
          "signCount",
          "largeBlob",
        ].includes(key),
    );
    if (stray.length > 0) throw new Error(`Invalid parameters: ${stray.join(", ")}`);
    if (
      this.held.some(
        (item) => item.rpId === credential.rpId && item.userHandle === credential.userHandle,
      )
    )
      throw new Error("An error occurred trying to create the credential");
    this.held.push({ ...credential });
  }
  async remove(): Promise<void> {
    this.tab?.dropAuthenticator(this);
  }
  /** A creation: refused when this authenticator holds an excluded credential; a credential of the same user handle is replaced. */
  create(rpId: string, userHandle: string, excluded: readonly string[]): VirtualCredential {
    if (this.held.some((item) => excluded.includes(item.credentialId))) {
      const error = new Error(
        "The user attempted to register an authenticator that contains one of the credentials already registered with the relying party.",
      );
      error.name = "InvalidStateError";
      throw error;
    }
    for (let index = this.held.length - 1; index >= 0; index -= 1)
      if (this.held[index]?.rpId === rpId && this.held[index]?.userHandle === userHandle)
        this.held.splice(index, 1);
    const credential: VirtualCredential = {
      credentialId: b64(next("cred-")),
      isResidentCredential: true,
      rpId,
      privateKey: b64(next("private-key-")),
      userHandle,
      signCount: 0,
    };
    this.held.push(credential);
    return credential;
  }
  assert(): VirtualCredential | undefined {
    const credential = this.held[0];
    if (credential) credential.signCount += 1;
    return credential;
  }
}

type Page =
  | { kind: "none" }
  | {
      kind: "sign-in" | "bootstrap" | "passkeys" | "sessions" | "devices" | "sign-out" | "register";
    };

export class FakeTab implements Tab {
  readonly center: FakeCenter;
  index = 0;
  /** The virtual authenticators of the tab now (Chromium's WebAuthn environment of the page). */
  authenticators: FakeAuthenticator[] = [];
  /** Windows Hello: its own credentials, not exported. */
  readonly hello = new FakeAuthenticator("internal");
  /** The virtual environment is enabled (an authenticator was added) and not yet switched off. */
  private virtualEnabled = false;
  private errorText = "";
  private changeCount = 0;
  private unsettledCount = 0;
  private handle: string | undefined;
  private currentUrl = "about:blank";
  private page: Page = { kind: "none" };
  private readonly values = new Map<string, string>();
  private readonly hooks = new Map<string, (pathname: string) => Promise<void>>();
  private pendingName = "";
  private readonly seenProblems: string[] = [];
  private retryAfter: number | undefined;
  readonly secretsSeen: string[] = [];

  constructor(center: FakeCenter) {
    this.center = center;
  }

  private path(suffix: string): string {
    return `${this.center.basePath}${suffix}`;
  }

  private session(): { revoked: boolean; stepUps: number } | undefined {
    const record = this.handle ? this.center.sessions.get(this.handle) : undefined;
    return record && !record.revoked ? record : undefined;
  }

  dropAuthenticator(authenticator: FakeAuthenticator): void {
    // A broken disable leaves the virtual authenticators answering after the script removed them.
    if (this.center.options.brokenDisable === true) return;
    this.authenticators = this.authenticators.filter((item) => item !== authenticator);
  }

  /** The credential an assertion uses: the first virtual authenticator that holds one, else Windows Hello when it is the only way. */
  private assertWith(): { credential: VirtualCredential; real: boolean } {
    for (const authenticator of this.authenticators) {
      const credential = authenticator.assert();
      if (credential) return { credential, real: false };
    }
    if (
      this.authenticators.length === 0 &&
      !this.virtualEnabled &&
      this.center.options.windowsHello === true
    ) {
      const credential = this.hello.assert();
      if (credential) return { credential, real: true };
    }
    throw new Error("no credential");
  }

  async goto(url: string): Promise<Navigation> {
    const target = new URL(url);
    const options = this.center.options;
    if (options.devicesPageFails && target.pathname === this.path(pages.devices))
      throw new Error("net::ERR_CONNECTION_RESET");
    if (this.center.limitNext) {
      this.center.limitNext = false;
      this.retryAfter = 5;
      return { status: 429, headers: {} };
    }
    if (options.rateLimit && options.rateLimit.remaining > 0) {
      options.rateLimit.remaining -= 1;
      this.retryAfter = options.rateLimit.retryAfter;
      return { status: 429, headers: {} };
    }
    const suffix = target.pathname.slice(this.center.basePath.length);
    const kinds: Record<string, Page["kind"]> = {
      [pages.signIn]: "sign-in",
      [pages.bootstrap]: "bootstrap",
      [pages.passkeys]: "passkeys",
      [pages.sessions]: "sessions",
      [pages.devices]: "devices",
      [pages.signOut]: "sign-out",
    };
    const kind = kinds[suffix];
    if (kind === undefined) return { status: 404, headers: {} };
    const protectedPage = kind === "passkeys" || kind === "sessions" || kind === "devices";
    if (protectedPage && !this.session()) {
      this.currentUrl = `${target.origin}${this.path(pages.signIn)}${
        options.noReturnFragment ? "" : `#return=${encodeURIComponent(target.pathname)}`
      }`;
      this.page = { kind: "sign-in" };
    } else {
      this.currentUrl = url;
      this.page = { kind };
    }
    if (options.problems?.length) this.seenProblems.push(...options.problems.splice(0));
    const headers: Record<string, string> = { ...pageSecurityHeaders };
    if (options.badHeader) delete headers[options.badHeader];
    return { status: 200, headers: { ...headers, "content-type": "text/html; charset=utf-8" } };
  }

  url(): string {
    return this.currentUrl;
  }

  /** A POST the center accepted: counted by the rule the driver counts by, so that a rule changed there changes the stand-in too. */
  private accepted(suffix: string): void {
    if (acceptedChange("POST", 200, this.path(suffix))) this.changeCount += 1;
  }

  private async post(suffix: string): Promise<void> {
    const pathname = this.path(suffix);
    const hook = this.hooks.get(pathname);
    if (hook) await hook(pathname);
    this.center.observe(suffix, this);
    this.center.events.push(`post ${suffix}`);
  }

  private navigate(suffix: string, kind: Page["kind"]): void {
    this.currentUrl = `https://${this.center.host}${this.path(suffix)}`;
    this.page = { kind };
  }

  private async stepUp(): Promise<void> {
    const record = this.session();
    if (!record) throw new Error("no session for a step-up");
    const { credential } = this.assertWith();
    await this.post(persistBefore.stepUp);
    this.center.assertion(credential.credentialId, credential.signCount);
    record.stepUps += 1;
    this.accepted(persistBefore.stepUp);
  }

  async click(selector: string): Promise<void> {
    const leak = this.center.options.leakInErrors;
    try {
      await this.act(selector);
    } catch (error) {
      if (leak !== undefined) throw new Error(`${(error as Error).message} (${leak})`);
      throw error;
    }
  }

  private async act(selector: string): Promise<void> {
    const center = this.center;
    const host = center.host;
    if (selector === selectors.create && this.page.kind === "bootstrap") {
      const token = this.values.get(selectors.token);
      const authenticator = this.authenticators[0];
      if (!authenticator) throw new Error("no authenticator");
      // Every enrollment ceremony gets a user handle of its own from the center; the account keeps the one of its creation.
      const userHandle = b64(next("enrolled-user-"));
      const credential = authenticator.create(host.split(":")[0] ?? host, userHandle, []);
      await this.post(persistBefore.enrollment);
      if (center.options.limitEnrollmentOnce && !center.enrollmentLimited) {
        center.enrollmentLimited = true;
        this.retryAfter = 5;
        return;
      }
      if (
        token !== center.options.token ||
        center.tokenSpent ||
        center.ownerExists ||
        center.options.refuseEnrollment === true
      )
        throw new Error("the bootstrap was refused");
      const lost =
        center.options.enrollmentReplyLost === true ||
        center.options.enrollmentServerError === true;
      // A reply that is lost or a server error is no answer the browser counts as accepted, though the center acted on the request.
      if (lost) this.unsettledCount += 1;
      else this.accepted(persistBefore.enrollment);
      center.userHandle = userHandle;
      center.tokenSpent = true;
      center.ownerExists = true;
      center.passkeys.push({
        id: credential.credentialId,
        name: "Passkey",
        signCount: 0,
        lastUsed: null,
        real: false,
      });
      this.handle = next("session-");
      center.sessions.set(this.handle, { revoked: false, stepUps: 0 });
      if (center.options.enrollmentStays === true || lost) return;
      if (center.options.limitAfterEnrollment === true) {
        // The enrollment is accepted; the redirect GET that follows it meets the edge limiter.
        this.retryAfter = 5;
        return;
      }
      this.navigate(pages.passkeys, "passkeys");
      if (center.options.tokenInUrl) this.currentUrl += `#token=${token}`;
      return;
    }
    if (selector === selectors.signIn && this.page.kind === "sign-in") {
      const { credential, real } = this.assertWith();
      await this.post(persistBefore.signIn);
      const used = center.assertion(credential.credentialId, credential.signCount);
      this.accepted(persistBefore.signIn);
      if ((center.options.limitAfterSignIn ?? 0) > 0) {
        // The sign-in is accepted; the redirect GET that follows it meets the edge limiter.
        center.options.limitAfterSignIn = (center.options.limitAfterSignIn ?? 0) - 1;
        this.retryAfter = 5;
      }
      if (real && center.options.helloNotMarked) used.lastUsed = null;
      if (real && center.options.alsoMarksVirtual)
        for (const other of center.passkeys) if (!other.real) other.lastUsed = center.instant();
      this.handle = next("session-");
      center.sessions.set(this.handle, { revoked: false, stepUps: 0 });
      const back = /#return=(.*)$/u.exec(this.currentUrl)?.[1];
      this.currentUrl = `https://${host}${back ? decodeURIComponent(back) : this.path(pages.passkeys)}`;
      this.page = { kind: "passkeys" };
      return;
    }
    if (selector === selectors.signOut && this.page.kind === "sign-out") {
      const keep = center.options.secondBrowserKeepsSession === true && this.index > 0;
      const record = this.session();
      if (record && !keep) record.revoked = true;
      if (!keep) this.handle = undefined;
      this.accepted("/session/v1/web/logout");
      this.navigate(pages.signIn, "sign-in");
      return;
    }
    if (selector === selectors.addPasskey && this.page.kind === "passkeys") {
      this.pendingName = this.values.get(selectors.newPasskeyName) ?? "";
      await this.stepUp();
      this.navigate(`${pages.passkeys}/add`, "register");
      return;
    }
    if (selector === selectors.createPasskey && this.page.kind === "register") {
      const real =
        this.authenticators.length === 0 &&
        !this.virtualEnabled &&
        center.options.windowsHello === true;
      const target = real ? this.hello : this.authenticators[0];
      if (!target) throw new Error("no authenticator");
      if (center.options.pageRefusesCreation) {
        this.errorText = "That passkey is already registered.";
        return;
      }
      const excluded = center.passkeys.map((item) => item.id);
      // The page asks for every passkey of the account to be excluded; an authenticator that holds one refuses the whole creation.
      if (
        !real &&
        this.authenticators.some((a) => a.held.some((item) => excluded.includes(item.credentialId)))
      ) {
        this.errorText = "That passkey is already registered.";
        return;
      }
      const credential = target.create(host.split(":")[0] ?? host, center.userHandle, excluded);
      await this.post(persistBefore.newPasskey);
      if (center.options.refuseNewPasskey === true) {
        this.errorText = "The passkey could not be saved.";
        return;
      }
      if (center.options.limitNewPasskeyOnce === true && !center.newPasskeyLimited) {
        center.newPasskeyLimited = true;
        this.retryAfter = 5;
        return;
      }
      this.accepted(persistBefore.newPasskey);
      this.errorText = "";
      center.passkeys.push({
        id: credential.credentialId,
        name: this.pendingName,
        signCount: 0,
        lastUsed: null,
        real,
      });
      this.navigate(pages.passkeys, "passkeys");
      return;
    }
    if (selector === selectors.endSession && this.page.kind === "sessions") {
      await this.stepUp();
      const mine = this.handle;
      const other = [...center.sessions.entries()].find(
        ([key, value]) => key !== mine && !value.revoked,
      );
      if (!other) throw new Error("no other session");
      other[1].revoked = true;
      this.accepted("/account/sessions/revoke");
      return;
    }
    const removal =
      /^form\[action\$="\/account\/passkeys\/remove"\] button\[aria-label="Remove passkey (.+)"\]$/u.exec(
        selector,
      );
    if (removal && this.page.kind === "passkeys") {
      await this.stepUp();
      const index = center.passkeys.findIndex((item) => item.name === removal[1]);
      if (index < 0 || center.passkeys.length < 2) throw new Error("cannot remove");
      center.passkeys.splice(index, 1);
      this.accepted("/account/passkeys/remove");
      if (center.options.limitAfterRemoval) center.limitNext = true;
      return;
    }
    throw new Error(`nothing to click for ${selector} on ${this.page.kind}`);
  }

  async setValue(selector: string, value: string): Promise<void> {
    this.values.set(selector, value);
  }

  private rowTexts(): string[] {
    const center = this.center;
    switch (this.page.kind) {
      case "passkeys":
        return center.passkeys.map((item) => item.name);
      case "sessions":
        return [...center.sessions.entries()]
          .filter(([, value]) => !value.revoked)
          .map(([key]) => `Chrome on Windows${key === this.handle ? " (this session)" : ""}`);
      case "devices":
        return [...center.sessions.entries()]
          .filter(([, value]) => !value.revoked)
          .map(([key]) => `Chrome on Windows${key === this.handle ? " (this browser)" : ""}`);
      default:
        return [];
    }
  }

  async text(selector: string): Promise<string | null> {
    if (selector === selectors.errorText) return this.errorText;
    if (selector !== selectors.heading) return null;
    const headings: Record<string, string> = {
      "sign-in": "Sign in to ArcForges",
      bootstrap: "Create the owner account",
      passkeys: "Account and passkeys",
      sessions: "Sessions",
      devices: "Devices",
      "sign-out": "Sign out",
      register: "Create your passkey",
    };
    return headings[this.page.kind] ?? null;
  }

  async texts(selector: string): Promise<string[]> {
    if (selector === selectors.rowHeaders) return this.rowTexts();
    if (selector === selectors.passkeyLastUsed)
      return this.center.passkeys.map((item) =>
        item.lastUsed ? item.lastUsed.slice(0, 10) : "Never",
      );
    return [];
  }

  async attributes(selector: string, name: string): Promise<(string | null)[]> {
    if (selector === "#signed-in" && name === "hidden") return this.session() ? [null] : [""];
    if (selector === selectors.errorSummary && name === "hidden")
      return [this.errorText ? null : ""];
    if (selector === `${selectors.passkeyLastUsed} time` && name === "datetime")
      return this.center.passkeys.flatMap((item) => (item.lastUsed ? [item.lastUsed] : []));
    return [];
  }

  async count(selector: string): Promise<number> {
    if (selector === selectors.rows) return this.rowTexts().length;
    if (selector === selectors.createPasskey) return this.page.kind === "register" ? 1 : 0;
    return 0;
  }

  async waitForPath(pathname: string): Promise<void> {
    if (new URL(this.currentUrl).pathname !== pathname)
      throw new Error(`Timeout waiting for ${pathname}`);
  }

  async waitForSelector(selector: string): Promise<void> {
    const known: Record<string, Page["kind"]> = {
      [`${selectors.create}:not([disabled])`]: "bootstrap",
      [`${selectors.signIn}:not([disabled])`]: "sign-in",
      [`${selectors.signOut}:not([disabled])`]: "sign-out",
      [selectors.createPasskey]: "register",
    };
    if (known[selector] !== this.page.kind) throw new Error(`Timeout waiting for ${selector}`);
  }

  async beforePost(
    paths: readonly string[],
    hook: (pathname: string) => Promise<void>,
  ): Promise<void> {
    for (const pathname of paths) this.hooks.set(pathname, hook);
  }

  problems(): string[] {
    return [...this.seenProblems];
  }

  rateLimited(): number | undefined {
    const seconds = this.retryAfter;
    this.retryAfter = undefined;
    return seconds;
  }

  async addAuthenticator(transport: Transport): Promise<Authenticator> {
    if (
      transport === "internal" &&
      this.authenticators.some((item) => item.transport === "internal")
    )
      throw new Error("Chrome only supports one internal authenticator per environment");
    const authenticator = new FakeAuthenticator(transport, this);
    authenticator.exportNothing = this.center.options.exportNothing === true;
    this.authenticators.push(authenticator);
    this.virtualEnabled = true;
    return authenticator;
  }

  async disableVirtual(): Promise<void> {
    if (this.center.options.brokenDisable === true) return;
    this.authenticators = [];
    this.virtualEnabled = false;
  }

  changes(): number {
    return this.changeCount;
  }

  unsettled(): number {
    return this.unsettledCount;
  }

  async cookies(): Promise<CookieView[]> {
    const record = this.session();
    if (!record || !this.handle) return [];
    const value = Buffer.from(this.handle.padEnd(32, "x"))
      .toString("base64url")
      .slice(0, 43)
      .padEnd(43, "A");
    this.secretsSeen.push(value);
    return [
      {
        name: "__Host-af_session",
        value,
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        expires: this.center.clockSeconds + 12 * 3600,
      },
    ];
  }

  async close(): Promise<void> {}
}

export class FakeBrowser implements Browser {
  readonly tabs: FakeTab[] = [];
  closed = false;
  readonly center: FakeCenter;
  /** What the browser says it sent (a test sets it to see how the run treats a busy minute). */
  requestCounts: RequestCounts = { total: 0, busiest: 0 };

  constructor(center: FakeCenter) {
    this.center = center;
  }

  version(): string {
    return "153.0.8010.12";
  }

  async newTab(): Promise<Tab> {
    const tab = new FakeTab(this.center);
    tab.index = this.tabs.length;
    this.tabs.push(tab);
    return tab;
  }

  requests(): RequestCounts {
    return { ...this.requestCounts };
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}
