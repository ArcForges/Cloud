// SPDX-License-Identifier: AGPL-3.0-only
// The tab the acceptance script drives over playwright-core (AF-CTR-03 A2), tested against a stand-in page, context and DevTools
// session: the route every request of the tab goes through (the request budget first, then the hook of a POST that carries a
// credential), the 429 and change counters, the console filter, and the WebAuthn commands the authenticators send. The flow's own
// tests use a stand-in for the whole tab; this file is where the glue between the two is held.
import assert from "node:assert/strict";
import test from "node:test";
import {
  type PwConsoleMessage,
  type PwContext,
  type PwPage,
  type PwResponse,
  type PwRoute,
  RequestBudget,
  playwrightTab,
} from "../../eng/verification/browser/driver.ts";

interface Sent {
  method: string;
  params: Record<string, unknown> | undefined;
}

/** A page that plays requests through the route handler it was given and then reports the response the test chose. */
function standIn() {
  const events: string[] = [];
  const sent: Sent[] = [];
  const handlers: {
    console?: (m: PwConsoleMessage) => void;
    pageerror?: (e: Error) => void;
    response?: (r: PwResponse) => void;
  } = {};
  let routeHandler: ((route: PwRoute) => Promise<void>) | undefined;
  let routed = 0;
  const response = (
    method: string,
    url: string,
    status: number,
    headers: Record<string, string> = {},
  ): PwResponse => ({
    status: () => status,
    headers: () => headers,
    request: () => ({ method: () => method, url: () => url }),
  });
  const page: PwPage = {
    async goto(url) {
      events.push(`goto ${url}`);
      if (routeHandler === undefined) events.push("no route");
      return response("GET", url, 200);
    },
    url: () => "about:blank",
    locator: () =>
      ({
        first: () => ({
          waitFor: async (options: { state: string }) => {
            events.push(`wait ${options.state}`);
          },
        }),
      }) as never,
    evaluate: async () => {},
    waitForURL: async () => {},
    waitForLoadState: async (state) => {
      events.push(`wait ${state}`);
    },
    async route(_pattern, handler) {
      events.push("route");
      routeHandler = handler;
      routed += 1;
    },
    on(event: string, handler: never) {
      (handlers as Record<string, unknown>)[event] = handler;
    },
    setDefaultTimeout: () => {},
  };
  const context: PwContext = {
    newPage: async () => page,
    newCDPSession: async () => ({
      async send(method, params) {
        sent.push({ method, params });
        if (method === "WebAuthn.addVirtualAuthenticator")
          return { authenticatorId: `auth-${sent.length}` };
        if (method === "WebAuthn.getCredentials") return { credentials: [] };
        return {};
      },
    }),
    cookies: async () => [],
    close: async () => {},
  };
  /** A request the page makes: it passes the route, and the test sees whether it was continued or aborted. */
  const request = async (method: string, url: string): Promise<"continued" | "aborted"> => {
    let outcome: "continued" | "aborted" = "continued";
    const route: PwRoute = {
      request: () => ({ method: () => method, url: () => url }),
      continue: async () => {
        events.push(`continue ${method} ${new URL(url).pathname}`);
      },
      abort: async () => {
        outcome = "aborted";
        events.push(`abort ${method} ${new URL(url).pathname}`);
      },
    };
    if (routeHandler === undefined) throw new Error("the page has no route");
    await routeHandler(route);
    return outcome;
  };
  return {
    page,
    context,
    events,
    sent,
    request,
    routed: () => routed,
    respond: (method: string, url: string, status: number, headers?: Record<string, string>) =>
      handlers.response?.(response(method, url, status, headers)),
    console: (type: string, text: string, url = "") =>
      handlers.console?.({ type: () => type, text: () => text, location: () => ({ url }) }),
    pageError: (message: string) => handlers.pageerror?.(new Error(message)),
  };
}

const origin = "https://proof.arcforges.com";

test("every request of the tab goes through one route, installed before the first navigation, and takes its slot first", async () => {
  const world = standIn();
  const slots: string[] = [];
  const budget = new RequestBudget(
    45,
    () => 0,
    async () => {},
  );
  const counted = Object.create(budget) as RequestBudget;
  counted.take = async () => {
    world.events.push("take");
    slots.push("take");
  };
  const tab = playwrightTab(world.context, world.page, counted);
  await tab.goto(`${origin}/api/account/sign-in`);
  assert.deepEqual(world.events.slice(0, 2), ["route", `goto ${origin}/api/account/sign-in`]);
  await tab.beforePost(["/api/x"], async () => {});
  assert.equal(world.routed(), 1, "one route for the tab, however many hooks");
  world.events.length = 0;
  await world.request("GET", `${origin}/api/account/account.js`);
  await world.request("POST", `${origin}/api/other`);
  assert.deepEqual(world.events, [
    "take",
    "continue GET /api/account/account.js",
    "take",
    "continue POST /api/other",
  ]);
  assert.equal(slots.length, 2, "every request, assets included, takes a slot");
});

test("a hook runs before its POST leaves the browser, and a hook that fails stops the request", async () => {
  const world = standIn();
  const tab = playwrightTab(world.context, world.page, undefined);
  const ran: string[] = [];
  let fail = false;
  await tab.beforePost(["/api/session/v1/web/enrollment/complete"], async (pathname) => {
    ran.push(pathname);
    world.events.push("hook");
    if (fail) throw new Error("the save failed");
  });
  world.events.length = 0;
  assert.equal(
    await world.request("POST", `${origin}/api/session/v1/web/enrollment/complete`),
    "continued",
  );
  assert.deepEqual(world.events, ["hook", "continue POST /api/session/v1/web/enrollment/complete"]);
  // Another method or another path is not hooked.
  assert.equal(
    await world.request("GET", `${origin}/api/session/v1/web/enrollment/complete`),
    "continued",
  );
  assert.equal(
    await world.request("POST", `${origin}/api/session/v1/web/enrollment/complete/x`),
    "continued",
  );
  assert.deepEqual(ran, ["/api/session/v1/web/enrollment/complete"]);
  fail = true;
  assert.equal(
    await world.request("POST", `${origin}/api/session/v1/web/enrollment/complete`),
    "aborted",
  );
  assert.match(
    tab.problems().join("\n"),
    /a request was stopped before it left the browser: the save failed/u,
  );
});

test("a 429 is remembered with its Retry-After until it is read, and only a change the center accepted is counted", async () => {
  const world = standIn();
  const tab = playwrightTab(world.context, world.page, undefined);
  assert.equal(tab.rateLimited(), undefined);
  world.respond("GET", `${origin}/api/account/sign-in`, 429, { "retry-after": "17" });
  world.respond("GET", `${origin}/api/account/account.css`, 429, {});
  assert.equal(tab.rateLimited(), 60, "the largest advice, 60 s where the reply gives none");
  assert.equal(tab.rateLimited(), undefined, "reading clears it");
  world.respond("GET", `${origin}/x`, 429, { "retry-after": "abc" });
  assert.equal(tab.rateLimited(), 60);
  assert.equal(tab.changes(), 0);
  for (const [method, pathname, status, counted] of [
    ["POST", "/api/session/v1/web/authentication/begin", 200, false],
    ["POST", "/api/session/v1/web/step-up/complete", 200, false],
    ["POST", "/api/session/v1/web/authentication/complete", 200, false],
    ["POST", "/api/account/passkeys/remove", 303, true],
    ["POST", "/api/session/v1/web/logout", 200, true],
    ["POST", "/api/account/passkeys/remove", 403, false],
    ["GET", "/api/account/passkeys", 200, false],
  ] as const) {
    const before = tab.changes();
    world.respond(method, `${origin}${pathname}`, status);
    assert.equal(tab.changes() - before, counted ? 1 : 0, `${method} ${pathname} ${status}`);
  }
});

test("a console error is a problem unless it is the browser's own favicon request, a policy violation always is", () => {
  const world = standIn();
  const tab = playwrightTab(world.context, world.page, undefined);
  world.console(
    "error",
    "Failed to load resource: the server responded with a status of 404 ()",
    `${origin}/favicon.ico`,
  );
  assert.deepEqual(tab.problems(), []);
  world.console("error", "Failed to load resource", `${origin}/api/account/account.js`);
  world.console("warning", "Refused by the Content Security Policy");
  world.console("log", "hello");
  world.pageError("boom");
  assert.deepEqual(tab.problems(), [
    "console error: Failed to load resource",
    "console warning: Refused by the Content Security Policy",
    "page error: boom",
  ]);
});

test("the authenticators of a tab share one WebAuthn session, carry their transport, and take only the DevTools fields", async () => {
  const world = standIn();
  const tab = playwrightTab(world.context, world.page, undefined);
  const internal = await tab.addAuthenticator("internal");
  const usb = await tab.addAuthenticator("usb");
  assert.deepEqual(
    world.sent.map((entry) => entry.method),
    ["WebAuthn.enable", "WebAuthn.addVirtualAuthenticator", "WebAuthn.addVirtualAuthenticator"],
    "the environment is enabled once",
  );
  assert.deepEqual(world.sent[0]?.params, { enableUI: false });
  const options = (index: number) =>
    (world.sent[index]?.params?.options ?? {}) as Record<string, unknown>;
  assert.equal(options(1).transport, "internal");
  assert.equal(options(2).transport, "usb");
  for (const index of [1, 2]) {
    assert.equal(options(index).protocol, "ctap2");
    assert.equal(options(index).hasResidentKey, true);
    assert.equal(options(index).hasUserVerification, true);
    assert.equal(options(index).isUserVerified, true);
    assert.equal(options(index).automaticPresenceSimulation, true);
  }
  assert.equal(internal.transport, "internal");
  assert.equal(usb.transport, "usb");
  await usb.addCredential({
    credentialId: "AQID",
    isResidentCredential: true,
    rpId: "localhost",
    privateKey: "QUFBQUFBQUE=",
    userHandle: "dXNlcg==",
    signCount: 3,
    transport: "usb",
  } as never);
  const added = world.sent.at(-1);
  assert.equal(added?.method, "WebAuthn.addCredential");
  assert.deepEqual(Object.keys((added?.params?.credential ?? {}) as object).sort(), [
    "credentialId",
    "isResidentCredential",
    "privateKey",
    "rpId",
    "signCount",
    "userHandle",
  ]);
  assert.notEqual(added?.params?.authenticatorId, undefined);
  await usb.credentials();
  assert.equal(world.sent.at(-1)?.method, "WebAuthn.getCredentials");
  await internal.remove();
  assert.equal(world.sent.at(-1)?.method, "WebAuthn.removeVirtualAuthenticator");
  // Switching the environment off is one command, once; the next authenticator enables it again.
  await tab.disableVirtual();
  await tab.disableVirtual();
  assert.equal(world.sent.filter((entry) => entry.method === "WebAuthn.disable").length, 1);
  await tab.addAuthenticator("internal");
  assert.equal(world.sent.filter((entry) => entry.method === "WebAuthn.enable").length, 2);
});

test("a tab that never had an authenticator can be switched back to the real ones without a command", async () => {
  const world = standIn();
  const tab = playwrightTab(world.context, world.page, undefined);
  await tab.disableVirtual();
  assert.deepEqual(world.sent, []);
});

test("an element is awaited until it is visible and the page has loaded, so its script has run", async () => {
  const world = standIn();
  const tab = playwrightTab(world.context, world.page, undefined);
  await tab.waitForSelector("#create-passkey", 1000);
  assert.deepEqual(world.events, ["wait visible", "wait load"]);
});
