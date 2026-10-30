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
import type { VirtualCredential } from "./credentials.ts";

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

/** A virtual authenticator of one tab (Chromium's DevTools WebAuthn domain). */
export interface Authenticator {
  credentials(): Promise<VirtualCredential[]>;
  addCredential(credential: VirtualCredential): Promise<void>;
  /** Removes the virtual authenticator and switches the virtual environment off, so that the browser reaches real authenticators. */
  disable(): Promise<void>;
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
  addAuthenticator(): Promise<Authenticator>;
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
  if (platform === "darwin") return path.join(home, "Library", "Caches", "ms-playwright");
  return path.join(environment.XDG_CACHE_HOME || path.join(home, ".cache"), "ms-playwright");
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
    return path.join(
      root,
      `chromium-${requiredChromiumRevision}`,
      "chrome-mac-arm64",
      "Google Chrome for Testing.app",
      "Contents",
      "MacOS",
      "Google Chrome for Testing",
    );
  return path.join(root, `chromium-${requiredChromiumRevision}`, "chrome-linux64", "chrome");
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

interface PwResponse {
  status(): number;
  headers(): Record<string, string>;
}
interface PwRequest {
  method(): string;
  url(): string;
}
interface PwRoute {
  request(): PwRequest;
  continue(): Promise<void>;
  abort(errorCode?: string): Promise<void>;
}
interface PwLocator {
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
interface PwConsoleMessage {
  type(): string;
  text(): string;
}
interface PwPage {
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
interface PwCdpSession {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>;
}
interface PwContext {
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

/** The options of the virtual authenticator: a CTAP2 internal (platform-like) authenticator with discoverable credentials and UV. */
export const virtualAuthenticatorOptions = {
  protocol: "ctap2",
  ctap2Version: "ctap2_1",
  transport: "internal",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
} as const;

// The module is imported by a name held in a variable so that the root project's type check does not look for a package it never
// installs, and so that a missing install gives a clear message here instead of a resolution error at load time.
const playwrightSpecifier = "playwright-core";

export async function launchPlaywright(options: LaunchOptions): Promise<Browser> {
  let playwright: PwModule;
  try {
    playwright = (await import(playwrightSpecifier)) as PwModule;
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
      return playwrightTab(context, page);
    },
  };
}

function playwrightTab(context: PwContext, page: PwPage): Tab {
  const problems: string[] = [];
  let retryAfter: number | undefined;
  const hooks = new Map<string, (pathname: string) => Promise<void>>();
  let routing = false;
  page.on("console", (message) => {
    const type = message.type();
    if (type === "error" || /content security policy|trusted type/iu.test(message.text()))
      problems.push(`console ${type}: ${message.text().slice(0, 300)}`);
  });
  page.on("pageerror", (error) => problems.push(`page error: ${error.message.slice(0, 300)}`));
  page.on("response", (response) => {
    if (response.status() === 429) {
      const seconds = Number(response.headers()["retry-after"] ?? "60");
      retryAfter = Math.max(
        retryAfter ?? 0,
        Number.isFinite(seconds) && seconds > 0 ? seconds : 60,
      );
    }
  });
  return {
    async goto(url) {
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
      if (routing) return;
      routing = true;
      await page.route("**/*", async (route) => {
        const request = route.request();
        const hooked =
          request.method() === "POST" ? hooks.get(new URL(request.url()).pathname) : undefined;
        if (hooked) {
          try {
            await hooked(new URL(request.url()).pathname);
          } catch (error) {
            problems.push(
              `a request was stopped before it left the browser: ${error instanceof Error ? error.message.slice(0, 200) : "the hook failed"}`,
            );
            await route.abort("failed");
            return;
          }
        }
        await route.continue();
      });
    },
    problems: () => [...problems],
    rateLimited() {
      const seconds = retryAfter;
      retryAfter = undefined;
      return seconds;
    },
    async addAuthenticator() {
      const session = await context.newCDPSession(page as never);
      await session.send("WebAuthn.enable", { enableUI: false });
      const added = (await session.send("WebAuthn.addVirtualAuthenticator", {
        options: virtualAuthenticatorOptions,
      })) as { authenticatorId: string };
      const authenticatorId = added.authenticatorId;
      return {
        async credentials() {
          const reply = (await session.send("WebAuthn.getCredentials", { authenticatorId })) as {
            credentials: VirtualCredential[];
          };
          return reply.credentials;
        },
        async addCredential(credential) {
          await session.send("WebAuthn.addCredential", { authenticatorId, credential });
        },
        async disable() {
          await session.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
          await session.send("WebAuthn.disable");
        },
      };
    },
    cookies: () => context.cookies(),
    close: () => context.close(),
  };
}
