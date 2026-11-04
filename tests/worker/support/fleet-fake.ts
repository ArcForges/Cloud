// SPDX-License-Identifier: AGPL-3.0-only
// A stand-in for the center's fleet pages (AF-CTR-04 E3) and a browser tab on them, for the node-approve flow of the browser
// acceptance: /connect and /activate with their reviews and decisions, the sign-in page they send a signed-out visitor to, the
// devices page the clean-up revokes on, the node's loopback receiver, and the edge's 429. It keeps what a run spent (step-ups,
// wrong entries, decisions, devices) so that a test can say what a step must never send twice. It checks the script's logic, never
// the center: the center's own pages are tested in center/internal/pages.
import { pageSecurityHeaders } from "../../../worker/tables/center-tables.generated.ts";
import type {
  Transport,
  VirtualCredential,
} from "../../../eng/verification/browser/credentials.ts";
import type {
  Authenticator,
  Browser,
  CookieView,
  Navigation,
  RequestCounts,
  Tab,
} from "../../../eng/verification/browser/driver.ts";
import { fleet, pages, selectors } from "../../../eng/verification/browser/selectors.ts";

export interface FleetNode {
  kind: "pkce" | "device";
  /** The flow ID (pkce) or the display user code (device). */
  key: string;
  name: string;
  fingerprint: string;
}

export interface FleetFakeOptions {
  /** The result page of an approval has another heading: the center committed the approval, the script's check of it fails. */
  resultCheckFails?: boolean;
  /** The session ends with the first decision (the clean-up's devices page then sends the tab to the sign-in). */
  sessionEndsAfterDecision?: boolean;
  /** The edge answers 429 to the stylesheet of the page a wrong fingerprint group's 400 shows (the center saw the decision). */
  limitAfterWrongTail?: boolean;
  /** The edge answers 429 to the decision POST that follows a step-up proof (the center never sees it). */
  limitAfterStepUp?: boolean;
  /** Navigations reject, with the address in the error's message (as Playwright's do). */
  gotoRejects?: boolean;
}

type Page =
  | "blank"
  | "sign-in"
  | "connect-review"
  | "connect-done"
  | "activate"
  | "activate-review"
  | "activate-done"
  | "devices";

const loopback = "http://127.0.0.1:53111/callback";

export class FleetCenter {
  readonly baseUrl: string;
  readonly options: FleetFakeOptions;
  readonly nodes = new Map<string, FleetNode>();
  /** The names of the devices the approvals created and no revocation removed. */
  devices: string[] = [];
  session = false;
  stepUps = 0;
  wrongEntries = 0;
  decisions = 0;
  revocations = 0;
  clockMs = Date.parse("2026-11-04T12:00:00Z");

  constructor(baseUrl: string, options: FleetFakeOptions = {}) {
    this.baseUrl = baseUrl;
    this.options = options;
  }

  add(node: FleetNode): void {
    this.nodes.set(node.key, node);
  }
}

class StubAuthenticator implements Authenticator {
  readonly transport: Transport;
  private readonly held: VirtualCredential[] = [];
  constructor(transport: Transport) {
    this.transport = transport;
  }
  async credentials(): Promise<VirtualCredential[]> {
    return this.held;
  }
  async addCredential(credential: VirtualCredential): Promise<void> {
    this.held.push(credential);
  }
  async remove(): Promise<void> {}
}

export class FleetTab implements Tab {
  readonly center: FleetCenter;
  page: Page = "blank";
  private address = "about:blank";
  private latest: Navigation | null = null;
  private node: FleetNode | undefined;
  private returnTo: Page | "connect" = "blank";
  private approved = false;
  private tail = "";
  private errorText = "";
  private limited: number | undefined;
  private changeCount = 0;
  private refusals = 0;
  private hold = false;
  private loopbacks = 0;
  readonly sent: number[] = [];

  constructor(center: FleetCenter) {
    this.center = center;
  }

  private path(page: string): string {
    return `${this.center.baseUrl}${page}`;
  }

  /** Requests that left the browser; the fake paces them as the request budget would (36 a minute). */
  private request(count = 1): void {
    for (let index = 0; index < count; index += 1) {
      this.sent.push(this.center.clockMs);
      this.center.clockMs += 1700;
    }
  }

  /** A new document of the center's pages (a page load: the document, its stylesheet and its script). */
  private show(page: Page, address: string, status = 200): void {
    this.page = page;
    this.address = address;
    this.latest = {
      status,
      headers: { ...pageSecurityHeaders, "content-type": "text/html; charset=utf-8" },
    };
    this.request(3);
  }

  private signInPage(returnTo: Page | "connect"): void {
    this.returnTo = returnTo;
    this.show("sign-in", this.path(pages.signIn));
  }

  /** The consent page's script with a session: it posts the review (a change: the center records the reviewer). */
  private connectReview(): void {
    this.changeCount += 1;
    this.show("connect-review", this.path(fleet.connectReview));
  }

  async goto(url: string): Promise<Navigation> {
    if (this.center.options.gotoRejects) {
      // Playwright's error names the address; the fake also names the code as the center normalizes it.
      const code = /#code=(.+)$/u.exec(url)?.[1];
      throw new Error(
        `page.goto: net::ERR_CONNECTION_RESET at ${url}${code ? ` (code ${code.replace("-", "")})` : ""}`,
      );
    }
    const parsed = new URL(url);
    const pathname = parsed.pathname.slice(new URL(this.center.baseUrl).pathname.length);
    if (pathname === fleet.connect) {
      this.node = this.center.nodes.get(parsed.hash.replace(/^#flow=/u, ""));
      if (this.center.session) this.connectReview();
      else this.signInPage("connect");
    } else if (pathname === fleet.activate) {
      this.node = this.center.nodes.get(parsed.hash.replace(/^#code=/u, ""));
      // The page drops the code from its address at once.
      this.show("activate", this.path(fleet.activate));
    } else if (pathname === pages.devices) {
      if (this.center.session) this.show("devices", this.path(pages.devices));
      else this.signInPage("devices");
    } else throw new Error(`The fleet fake serves no ${pathname}.`);
    return this.latest as Navigation;
  }

  url(): string {
    return this.address;
  }

  /** A decision the center accepted: the result page, and on /connect the page's script (or held navigation) to the receiver. */
  private decided(approve: boolean): void {
    this.center.decisions += 1;
    this.changeCount += 1;
    this.approved = approve;
    if (approve && this.node) this.center.devices.push(this.node.name);
    if (this.center.options.sessionEndsAfterDecision) this.center.session = false;
    if (this.node?.kind === "pkce") {
      this.show("connect-done", this.path("/connect/decision"));
      this.loopbacks += 1;
      if (this.hold) this.hold = false;
      else this.address = loopback;
    } else this.show("activate-done", this.path("/activate/decision"));
  }

  /** A step-up proof (harmless for the driver's count), then the decision POST, which the edge may refuse. */
  private provedThenLimited(): boolean {
    this.center.stepUps += 1;
    this.request(2);
    if (!this.center.options.limitAfterStepUp) return false;
    this.limited = 30;
    this.latest = { status: 429, headers: { "retry-after": "30" } };
    this.request();
    return true;
  }

  async click(selector: string): Promise<void> {
    const { center } = this;
    if (this.page === "sign-in" && selector === selectors.signIn) {
      center.session = true;
      this.changeCount += 1;
      this.request(2);
      if (this.returnTo === "connect") this.connectReview();
      else if (this.returnTo === "activate") this.show("activate", this.path(fleet.activate));
      else if (this.returnTo === "devices") this.show("devices", this.path(pages.devices));
      return;
    }
    if (this.page === "activate" && selector === fleet.continueButton) {
      // A signed-out visitor goes to the sign-in only now; with a session the lookup is a review (a change).
      if (!center.session) return this.signInPage("activate");
      this.changeCount += 1;
      this.show("activate-review", this.path(fleet.activateReview));
      return;
    }
    if (this.page === "connect-review" && selector === fleet.approve) {
      if (this.provedThenLimited()) return;
      return this.decided(true);
    }
    if (
      (this.page === "connect-review" || this.page === "activate-review") &&
      selector === fleet.deny
    )
      return this.decided(false);
    if (this.page === "activate-review" && selector === fleet.approve) {
      if (this.provedThenLimited()) return;
      if (this.tail.toUpperCase() !== this.node?.fingerprint.slice(-4)) {
        // The center refuses the wrong group before the evidence is consumed: one entry of the account's budget, a 400 page.
        center.wrongEntries += 1;
        this.changeCount += 1;
        this.errorText = "That is not the last 4 characters of the node's key fingerprint.";
        this.show("activate-review", this.path("/activate/decision"), 400);
        if (this.refusals > 0) this.refusals -= 1;
        if (center.options.limitAfterWrongTail) this.limited = 30;
        return;
      }
      this.errorText = "";
      return this.decided(true);
    }
    if (this.page === "connect-done" && selector === fleet.returnLink) {
      this.address = loopback;
      return;
    }
    if (this.page === "devices") {
      const name = center.devices.find((device) => selector === fleet.revokeDevice(device));
      if (name !== undefined) {
        center.stepUps += 1;
        center.revocations += 1;
        center.devices.splice(center.devices.indexOf(name), 1);
        this.changeCount += 1;
        this.request(2);
        this.show("devices", this.path(pages.devices));
        return;
      }
    }
    throw new Error(`Nothing to click at ${selector} on ${this.page}.`);
  }

  async setValue(selector: string, value: string): Promise<void> {
    if (selector === fleet.tailField) this.tail = value;
  }

  private heading(): string | null {
    switch (this.page) {
      case "sign-in":
        return "Sign in";
      case "connect-review":
        return "Connect this node?";
      case "activate":
        return "Activate a node";
      case "activate-review":
        return "Activate this node?";
      case "connect-done":
      case "activate-done":
        return this.approved && this.center.options.resultCheckFails
          ? "Something went wrong"
          : "Return to your terminal";
      case "devices":
        return "Devices";
      default:
        return null;
    }
  }

  private reviewing(): boolean {
    return this.page === "connect-review" || this.page === "activate-review";
  }

  async text(selector: string): Promise<string | null> {
    const node = this.node;
    if (selector === selectors.heading) return this.heading();
    if (selector === selectors.errorText) return this.errorText;
    if (!this.reviewing() || node === undefined) return null;
    if (selector === fleet.nodeName) return node.name;
    if (selector === fleet.nodeFingerprint)
      return node.kind === "device" ? `${node.fingerprint.slice(0, -4)}????` : node.fingerprint;
    if (selector === fleet.nodeOrigin) return "Request came from Germany (DE), network AS64496";
    if (selector === "#user-code-shown") return node.key;
    return null;
  }

  async texts(): Promise<string[]> {
    return [];
  }

  async attributes(): Promise<(string | null)[]> {
    return [];
  }

  async count(selector: string): Promise<number> {
    if (selector === fleet.nodeNameNote) return this.reviewing() ? 1 : 0;
    if (selector === fleet.deny) return this.page === "activate-done" && this.approved ? 1 : 0;
    if (this.page === "devices")
      return this.center.devices.filter((name) => selector === fleet.revokeDevice(name)).length;
    return 0;
  }

  async waitForPath(pathname: string): Promise<void> {
    if (new URL(this.address).pathname !== pathname)
      throw new Error(`Timed out waiting for ${pathname}.`);
  }

  async waitForSelector(): Promise<void> {}

  async beforePost(): Promise<void> {}

  async fetchJson(): Promise<{ status: number; body: unknown }> {
    throw new Error("The fleet fake serves no JSON route.");
  }

  async submitForm(): Promise<void> {
    throw new Error("The fleet fake takes no forms.");
  }

  document(): Navigation | null {
    return this.latest;
  }

  expectRefusal(): void {
    this.refusals = 1;
  }

  refusalsPending(): number {
    return this.refusals;
  }

  problems(): string[] {
    return [];
  }

  rateLimited(): number | undefined {
    const seconds = this.limited;
    this.limited = undefined;
    return seconds;
  }

  changes(): number {
    return this.changeCount;
  }

  unsettled(): number {
    return 0;
  }

  holdLoopback(): void {
    this.hold = true;
  }

  loopbackRequests(): number {
    return this.loopbacks;
  }

  async addAuthenticator(transport: Transport): Promise<Authenticator> {
    return new StubAuthenticator(transport);
  }

  async disableVirtual(): Promise<void> {}

  async cookies(): Promise<CookieView[]> {
    return [];
  }

  async close(): Promise<void> {}
}

export class FleetBrowser implements Browser {
  readonly center: FleetCenter;
  readonly tabs: FleetTab[] = [];

  constructor(center: FleetCenter) {
    this.center = center;
  }

  version(): string {
    return "153.0.8010.12";
  }

  async newTab(): Promise<Tab> {
    const tab = new FleetTab(this.center);
    this.tabs.push(tab);
    return tab;
  }

  requests(): RequestCounts {
    const sent = this.tabs.flatMap((tab) => tab.sent).sort((a, b) => a - b);
    let busiest = 0;
    let first = 0;
    for (let last = 0; last < sent.length; last += 1) {
      while ((sent[last] ?? 0) - (sent[first] ?? 0) >= 60_000) first += 1;
      busiest = Math.max(busiest, last - first + 1);
    }
    return { total: sent.length, busiest };
  }

  async close(): Promise<void> {}
}
