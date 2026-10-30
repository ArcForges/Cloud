// SPDX-License-Identifier: AGPL-3.0-only
// The browser the acceptance flow drives (AF-CTR-03 A2): a small interface the flow is written against, the guard that only the
// Playwright Chromium revision 1243 is launched (always by an explicit executablePath; browsers are never downloaded), and the
// adapter to playwright-core. playwright-core is imported by name at run time from this package's own node_modules, so the root
// project (which never installs it) does not need its types; the adapter's shapes are the subset below, and the flow is tested
// against fakes of this interface.
//
// Nothing here turns on tracing, screenshots, videos or HAR files, and the token the flow types into the bootstrap page is set with
// a script call that no log line quotes.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { type Transport, type VirtualCredential, withoutTransport } from "./credentials.ts";

/** The Playwright release's browser revision the proof environment's Windows host has installed (playwright-core 1.63.0). */
export const requiredChromiumRevision = "1243";
export const requiredChromiumVersion = "153.0.8010.12";
export const requiredPlaywrightCore = "1.63.0";

export interface Navigation {
  status: number;
  /** Header names in lower case. */
  headers: Record<string, string>;
}

export interface CookieView {
  name: string;
  /** The value is in the view only so that it can be redacted from every output; it is never printed. */
  value: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
  /** Seconds since the epoch, or -1 for a session cookie. */
  expires: number;
}

/**
 * A virtual authenticator of one tab (Chromium's DevTools WebAuthn domain). It holds at most one credential of a relying party and
 * user handle: a second discoverable credential of the same pair replaces the first when it is created, and addCredential refuses it.
 */
export interface Authenticator {
  readonly transport: Transport;
  credentials(): Promise<VirtualCredential[]>;
  addCredential(credential: VirtualCredential): Promise<void>;
  /** Removes this virtual authenticator, and the credentials it holds, from the tab. */
  remove(): Promise<void>;
}

/** One tab in its own browser context (its own cookies and storage). */
export interface Tab {
  goto(url: string): Promise<Navigation>;
  url(): string;
  click(selector: string): Promise<void>;
  /** Sets an input's value inside the page; the value is not part of any log line. */
  setValue(selector: string, value: string): Promise<void>;
  text(selector: string): Promise<string | null>;
  texts(selector: string): Promise<string[]>;
  /** The attribute of every element the selector matches (null where an element has none). */
  attributes(selector: string, name: string): Promise<(string | null)[]>;
  count(selector: string): Promise<number>;
  waitForPath(pathname: string, timeoutMs: number): Promise<void>;
  waitForSelector(selector: string, timeoutMs: number): Promise<void>;
  /** Runs `hook` before a POST to each of these paths leaves the browser; if the hook throws, the request is aborted. */
  beforePost(paths: readonly string[], hook: (pathname: string) => Promise<void>): Promise<void>;
  /** Console errors, page errors and policy violations seen so far (text only). */
  problems(): string[];
  /** The Retry-After seconds of a 429 seen since the last call (cleared by it), or undefined. */
  rateLimited(): number | undefined;
  /** How many POST requests the tab has seen answered without an error (a change the center accepted). */
  changes(): number;
  /** Adds a virtual authenticator; Chromium allows one `internal` authenticator per tab and several of the other transports. */
  addAuthenticator(transport: Transport): Promise<Authenticator>;
  /** Switches the virtual environment off (every virtual authenticator goes), so that the browser reaches real authenticators. */
  disableVirtual(): Promise<void>;
  cookies(): Promise<CookieView[]>;
  close(): Promise<void>;
}

export interface Browser {
  version(): string;
  newTab(): Promise<Tab>;
  close(): Promise<void>;
}

export interface LaunchOptions {
  executablePath: string;
  headless: boolean;
  timeoutMs: number;
  /** The most requests per minute the tab sends (0: no bound, for a center on this machine). See RequestBudget. */
  requestsPerMinute: number;
}

export const defaultRequestsPerMinute = 45;
/**
 * The problem a console message is, if it is one: an error, or a policy violation. The browser asks for /favicon.ico on its own,
 * outside the page's requests, and reports a 404 of it as a console error; that one is not the page's.
 */
export function consoleProblem(
  type: string,
  text: string,
  locationUrl: string,
): string | undefined {
  if (type === "error" && locationUrl.endsWith("/favicon.ico")) return undefined;
  if (type === "error" || /content security policy|trusted type/iu.test(text))
    return `console ${type}: ${text.slice(0, 300)}`;
  return undefined;
}

/** Whether a response is a change the center accepted: a POST that succeeded and that a step could not repeat harmlessly. */
export function acceptedChange(method: string, status: number, pathname: string): boolean {
  return method === "POST" && status < 400 && !harmless.test(pathname);
}

/** The POSTs that a step may repeat after a 429: they start a flow, prove something or add a session; nothing is changed that a repeat would trip over. */
const harmless = /\/(?:authentication\/(?:begin|complete)|step-up\/(?:begin|complete))$/u;
const requestBurst = 8;

/**
 * A bound on the requests the browser sends (every request of the origin, assets included), because the hosted Worker counts them
 * all against an edge limit of 60 per minute and one page load is three requests. It is a generic cell rate: `requestBurst`
 * requests may go at once, then one every 60 / perMinute seconds, so that in any minute at most burst + perMinute (53) requests
 * leave. A request waits for its slot (the wait is short, about 1.3 s at most, so no wait of the flow times out on it).
 */
export class RequestBudget {
  private readonly interval: number;
  private readonly tolerance: number;
  private next = 0;
  private readonly clock: () => number;
  private readonly pause: (milliseconds: number) => Promise<void>;

  constructor(
    perMinute: number,
    clock: () => number = Date.now,
    pause: (milliseconds: number) => Promise<void> = (milliseconds) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds)),
  ) {
    if (!Number.isInteger(perMinute) || perMinute < 1)
      throw new Error("A request budget is a whole number per minute.");
    this.interval = 60_000 / perMinute;
    this.tolerance = (requestBurst - 1) * this.interval;
    this.clock = clock;
    this.pause = pause;
  }

  /** Reserves the next slot and waits for it. */
  async take(): Promise<void> {
    const now = this.clock();
    const slot = Math.max(this.next, now);
    this.next = slot + this.interval;
    const wait = slot - this.tolerance - now;
    // Less than half a millisecond is the rounding of the interval, not a wait.
    if (wait > 0.5) await this.pause(Math.ceil(wait));
  }
}

export type Launcher = (options: LaunchOptions) => Promise<Browser>;

// ---------------------------------------------------------------------------------------------------------------------------
// The browser path

/** Where Playwright keeps its browsers on this machine, unless PLAYWRIGHT_BROWSERS_PATH names another place. */
export function browsersDirectory(
  environment: Record<string, string | undefined>,
  platform: NodeJS.Platform,
  home: string,
): string {
  const configured = environment.PLAYWRIGHT_BROWSERS_PATH;
  if (configured && configured !== "0") return configured;
  if (platform === "win32")
    return path.win32.join(
      environment.LOCALAPPDATA || path.win32.join(home, "AppData", "Local"),
      "ms-playwright",
    );
  if (platform === "darwin") return path.posix.join(home, "Library", "Caches", "ms-playwright");
  return path.posix.join(
    environment.XDG_CACHE_HOME || path.posix.join(home, ".cache"),
    "ms-playwright",
  );
}

/** The default executable of Chromium revision 1243 in that directory. */
export function defaultChromiumPath(
  environment: Record<string, string | undefined>,
  platform: NodeJS.Platform,
  home: string,
): string {
  const root = browsersDirectory(environment, platform, home);
  if (platform === "win32")
    return path.win32.join(
      root,
      `chromium-${requiredChromiumRevision}`,
      "chrome-win64",
      "chrome.exe",
    );
  if (platform === "darwin")
    return path.posix.join(
      root,
      `chromium-${requiredChromiumRevision}`,
      "chrome-mac-arm64",
      "Google Chrome for Testing.app",
      "Contents",
      "MacOS",
      "Google Chrome for Testing",
    );
  return path.posix.join(root, `chromium-${requiredChromiumRevision}`, "chrome-linux64", "chrome");
}

/** Why a path is not the pinned Chromium (undefined when it is). Only the pinned revision is launched, never a system browser. */
export function chromiumPathProblem(executablePath: string): string | undefined {
  const parts = executablePath.split(/[\\/]/u);
  if (!parts.includes(`chromium-${requiredChromiumRevision}`))
    return `The browser must be the Playwright chromium-${requiredChromiumRevision} that playwright-core ${requiredPlaywrightCore} names.`;
  if (!/^(?:chrome(?:\.exe)?|Google Chrome for Testing)$/u.test(parts.at(-1) ?? ""))
    return "The browser path does not end in the Chromium executable.";
  return undefined;
}

/** Whether a playwright-core browser manifest names chromium revision 1243 (undefined when it does). */
export function manifestProblem(manifest: unknown): string | undefined {
  const browsers = (manifest as { browsers?: unknown } | null)?.browsers;
  if (!Array.isArray(browsers)) return "The Playwright browser manifest is unreadable.";
  const entry = browsers.find(
    (item): item is { name: string; revision: string; browserVersion?: string } =>
      typeof item === "object" && item !== null && (item as { name?: unknown }).name === "chromium",
  );
  if (entry?.revision !== requiredChromiumRevision)
    return `The installed playwright-core does not name chromium-${requiredChromiumRevision}; install the exact lockfile of this package (npm ci).`;
  return undefined;
}

/** The checks before a launch: the pinned browser exists, and the installed playwright-core's manifest names it. */
export function preflight(
  executablePath: string,
  packageDirectory: string,
  exists: (file: string) => boolean = existsSync,
  read: (file: string) => string = (file) => readFileSync(file, "utf8"),
): string[] {
  const problems: string[] = [];
  const pathProblem = chromiumPathProblem(executablePath);
  if (pathProblem) problems.push(pathProblem);
  else if (!exists(executablePath))
    problems.push("The pinned Chromium is not installed at that path.");
  const manifestFile = path.join(
    packageDirectory,
    "node_modules",
    "playwright-core",
    "browsers.json",
  );
  if (!exists(manifestFile))
    problems.push("playwright-core is not installed; run `npm ci` in this package's directory.");
  else {
    try {
      const problem = manifestProblem(JSON.parse(read(manifestFile)));
      if (problem) problems.push(problem);
    } catch {
      problems.push("The Playwright browser manifest is unreadable.");
    }
  }
  return problems;
}

// ---------------------------------------------------------------------------------------------------------------------------
// The playwright-core adapter. The shapes are the subset of playwright-core 1.63.0 this file uses.

export interface PwResponse {
  status(): number;
  headers(): Record<string, string>;
  request(): PwRequest;
}
export interface PwRequest {
  method(): string;
  url(): string;
}
export interface PwRoute {
  request(): PwRequest;
  continue(): Promise<void>;
  abort(errorCode?: string): Promise<void>;
}
export interface PwLocator {
  click(): Promise<void>;
  first(): PwLocator;
  textContent(): Promise<string | null>;
  allTextContents(): Promise<string[]>;
  evaluateAll<Result>(
    fn: (elements: Element[], name: string) => Result,
    name: string,
  ): Promise<Result>;
  count(): Promise<number>;
  waitFor(options: { state: "attached" | "visible"; timeout: number }): Promise<void>;
}
export interface PwConsoleMessage {
  type(): string;
  text(): string;
  location(): { url: string };
}
export interface PwPage {
  goto(url: string, options: { waitUntil: "load" }): Promise<PwResponse | null>;
  url(): string;
  locator(selector: string): PwLocator;
  evaluate<Arg>(fn: (arg: Arg) => void, arg: Arg): Promise<void>;
  waitForURL(predicate: (url: URL) => boolean, options: { timeout: number }): Promise<void>;
  route(url: string, handler: (route: PwRoute) => Promise<void>): Promise<unknown>;
  on(event: "console", handler: (message: PwConsoleMessage) => void): void;
  on(event: "pageerror", handler: (error: Error) => void): void;
  on(event: "response", handler: (response: PwResponse) => void): void;
  setDefaultTimeout(timeout: number): void;
}
export interface PwCdpSession {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>;
}
export interface PwContext {
  newPage(): Promise<PwPage>;
  // playwright-core types the page parameter as its full Page; `never` accepts that (the argument is cast at the one call).
  newCDPSession: (page: never) => Promise<PwCdpSession>;
  cookies(): Promise<CookieView[]>;
  close(): Promise<void>;
}
interface PwBrowser {
  version(): string;
  newContext(options: Record<string, unknown>): Promise<PwContext>;
  close(): Promise<void>;
}
export interface PwModule {
  chromium: {
    launch(options: {
      executablePath: string;
      headless: boolean;
      args: string[];
      timeout: number;
    }): Promise<PwBrowser>;
  };
}

/** The options of a virtual authenticator: CTAP2 with discoverable credentials and user verification (the transport is added). */
export const virtualAuthenticatorOptions = {
  protocol: "ctap2",
  ctap2Version: "ctap2_1",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
} as const;

// playwright-core is imported by its name where it is needed, and a missing install gives a clear message here instead of a
// resolution error at load time. The root project never installs the package, so playwright-core.d.ts declares the module without
// types for the root type check; the adapter's own shapes are the subset above, which adapter-check/ proves against the package.
export async function launchPlaywright(options: LaunchOptions): Promise<Browser> {
  let playwright: PwModule;
  try {
    playwright = (await import("playwright-core")) as PwModule;
  } catch {
    throw new Error("playwright-core is not installed; run `npm ci` in this package's directory.");
  }
  const browser = await playwright.chromium.launch({
    executablePath: options.executablePath,
    headless: options.headless,
    args: [],
    timeout: options.timeoutMs,
  });
  return {
    version: () => browser.version(),
    close: () => browser.close(),
    async newTab(): Promise<Tab> {
      // No service worker, download, video, HAR, trace or screenshot: nothing that could keep a copy of a page or a token.
      const context = await browser.newContext({
        serviceWorkers: "block",
        acceptDownloads: false,
        locale: "en-US",
        ignoreHTTPSErrors: false,
      });
      const page = await context.newPage();
      page.setDefaultTimeout(options.timeoutMs);
      const budget =
        options.requestsPerMinute > 0 ? new RequestBudget(options.requestsPerMinute) : undefined;
      return playwrightTab(context, page, budget);
    },
  };
}

/** The tab over a playwright-core page: exported for the tests, which give it a stand-in page and context. */
export function playwrightTab(
  context: PwContext,
  page: PwPage,
  budget: RequestBudget | undefined,
): Tab {
  const problems: string[] = [];
  let retryAfter: number | undefined;
  let changes = 0;
  const hooks = new Map<string, (pathname: string) => Promise<void>>();
  let routing: Promise<unknown> | undefined;
  // One DevTools session per tab: the WebAuthn environment (and its single internal authenticator) belongs to it.
  let session: PwCdpSession | undefined;
  let enabled = false;
  const webauthn = async (): Promise<PwCdpSession> => {
    session ??= await context.newCDPSession(page as never);
    if (!enabled) {
      await session.send("WebAuthn.enable", { enableUI: false });
      enabled = true;
    }
    return session;
  };
  page.on("console", (message) => {
    const problem = consoleProblem(message.type(), message.text(), message.location().url);
    if (problem !== undefined) problems.push(problem);
  });
  page.on("pageerror", (error) => problems.push(`page error: ${error.message.slice(0, 300)}`));
  page.on("response", (response) => {
    const status = response.status();
    if (status === 429) {
      const seconds = Number(response.headers()["retry-after"] ?? "60");
      retryAfter = Math.max(
        retryAfter ?? 0,
        Number.isFinite(seconds) && seconds > 0 ? seconds : 60,
      );
    } else {
      // The begin steps, the proofs and the sign-in only start flows or add a session: a step that started again from its
      // navigation would repeat them harmlessly, which it cannot do with a removal or a registration.
      const request = response.request();
      if (acceptedChange(request.method(), status, new URL(request.url()).pathname)) changes += 1;
    }
  });
  // Every request of the tab goes through one route: the request budget first, then the hook of a POST that carries a credential.
  const route = (): Promise<unknown> => {
    routing ??= page.route("**/*", async (intercepted) => {
      const outgoing = intercepted.request();
      await budget?.take();
      const hooked =
        outgoing.method() === "POST" ? hooks.get(new URL(outgoing.url()).pathname) : undefined;
      if (hooked) {
        try {
          await hooked(new URL(outgoing.url()).pathname);
        } catch (error) {
          problems.push(
            `a request was stopped before it left the browser: ${error instanceof Error ? error.message.slice(0, 200) : "the hook failed"}`,
          );
          await intercepted.abort("failed");
          return;
        }
      }
      await intercepted.continue();
    });
    return routing;
  };
  return {
    async goto(url) {
      await route();
      const response = await page.goto(url, { waitUntil: "load" });
      if (response === null) throw new Error("The navigation gave no response.");
      return { status: response.status(), headers: response.headers() };
    },
    url: () => page.url(),
    click: (selector) => page.locator(selector).first().click(),
    setValue: (selector, value) =>
      page.evaluate(
        ({ target, text }) => {
          const element = document.querySelector(target) as HTMLInputElement | null;
          if (element === null) throw new Error("No such field.");
          element.value = text;
          element.dispatchEvent(new Event("input", { bubbles: true }));
        },
        { target: selector, text: value },
      ),
    text: async (selector) => {
      const locator = page.locator(selector);
      return (await locator.count()) === 0
        ? null
        : ((await locator.first().textContent()) ?? "").trim();
    },
    texts: async (selector) =>
      (await page.locator(selector).allTextContents()).map((text) => text.trim()),
    attributes: (selector, name) =>
      page
        .locator(selector)
        .evaluateAll(
          (elements, attribute) => elements.map((item) => item.getAttribute(attribute)),
          name,
        ),
    count: (selector) => page.locator(selector).count(),
    waitForPath: (pathname, timeout) =>
      page.waitForURL((url) => url.pathname === pathname, { timeout }),
    waitForSelector: (selector, timeout) =>
      page.locator(selector).first().waitFor({ state: "visible", timeout }),
    async beforePost(paths, hook) {
      for (const pathname of paths) hooks.set(pathname, hook);
      await route();
    },
    problems: () => [...problems],
    rateLimited() {
      const seconds = retryAfter;
      retryAfter = undefined;
      return seconds;
    },
    changes: () => changes,
    async addAuthenticator(transport) {
      const cdp = await webauthn();
      const added = (await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: { ...virtualAuthenticatorOptions, transport },
      })) as { authenticatorId: string };
      const authenticatorId = added.authenticatorId;
      return {
        transport,
        async credentials() {
          const reply = (await cdp.send("WebAuthn.getCredentials", { authenticatorId })) as {
            credentials: VirtualCredential[];
          };
          return reply.credentials;
        },
        async addCredential(credential) {
          // Only the fields of the DevTools credential: the transport of a saved credential is ours.
          await cdp.send("WebAuthn.addCredential", {
            authenticatorId,
            credential: withoutTransport(credential),
          });
        },
        async remove() {
          await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
        },
      };
    },
    async disableVirtual() {
      if (session === undefined || !enabled) return;
      await session.send("WebAuthn.disable");
      enabled = false;
    },
    cookies: () => context.cookies(),
    close: () => context.close(),
  };
}
