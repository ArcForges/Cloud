// SPDX-License-Identifier: AGPL-3.0-only
// The account pages' script (AF-CTR-03 A2; center/internal/pages/static/account.js), run without a browser: the open-redirect rule for
// the return path (DC-13), the base64url and WebAuthn conversions, the installation claim, the transport, the sign-in, enrollment,
// step-up and sign-out flows, and the pages' wiring against a minimal document (SEC-09: the one-time token leaves the address at
// once). The script is an ES module that starts itself only in a document; here its functions are called with fakes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test, { mock } from "node:test";

import * as script from "../../center/internal/pages/static/account.js";
import type {
  Api,
  ApiResponse as FakeResponse,
} from "../../center/internal/pages/static/account.js";

const location = "../../center/internal/pages/static/account.js";
const origin = "https://proof.example.test";

test("a return path is followed only when it is a path of this origin (DC-13, the open-redirect rule)", () => {
  for (const good of [
    "/connect",
    "/activate?code=1234",
    "/api/account/sessions",
    "/api/account/passkeys",
    "/a/b/c?x=1&y=2",
    "/%2fevil.example",
    "/a%20b",
  ])
    assert.equal(script.safeReturnPath(good, origin), good, good);
  assert.equal(
    script.safeReturnPath("/a/../b", origin),
    "/b",
    "the parser normalises dot segments",
  );
  assert.equal(script.safeReturnPath("/path#frag", origin), "/path", "a fragment is not followed");
  for (const hostile of [
    "",
    "https://evil.example/",
    "http://proof.example.test/",
    "//evil.example",
    "//evil.example/path",
    "/\\evil.example",
    "\\\\evil.example",
    "\\/evil.example",
    "/ /evil.example",
    "/\t/evil.example",
    "/\n/evil.example",
    "/path with space",
    "/a\\b",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,x",
    "vbscript:x",
    "evil.example",
    "relative/path",
    "?query",
    "#fragment",
    "/\u0000",
    "/\u007f",
    "///evil.example",
    "/.//evil.example",
    "/a/..//evil.example",
    "/%2e//evil.example",
    `/${"a".repeat(512)}`,
    "@evil.example",
    ":evil",
    null,
    undefined,
    42,
    {},
    ["/ok"],
  ])
    assert.equal(script.safeReturnPath(hostile, origin), null, JSON.stringify(hostile));
  // The origin is the page's own, whatever the path says.
  assert.equal(script.safeReturnPath("/ok", "http://localhost:8080"), "/ok");
  // A path longer than the bound is refused; one at the bound is not.
  assert.equal(script.safeReturnPath(`/${"a".repeat(511)}`, origin)?.length, 512);
});

test("the fragment's values are read once, percent-decoded, and nothing else is trusted", () => {
  assert.deepEqual(script.parseFragment("#return=%2Fapi%2Faccount%2Fsessions"), {
    return: "/api/account/sessions",
  });
  assert.deepEqual(script.parseFragment("#token=afb1.abc&return=%2Fx"), {
    token: "afb1.abc",
    return: "/x",
  });
  assert.deepEqual(script.parseFragment("#a=%E0%A4%A&b=ok&=x&c"), { b: "ok" });
  assert.deepEqual(script.parseFragment(""), {});
  assert.deepEqual(script.parseFragment("return=x"), {});
  // The return value the sign-in page uses is the validated one of the fragment.
  const value = script.parseFragment("#return=%2F%2Fevil.example").return;
  assert.equal(script.safeReturnPath(value, origin), null);
});

test("base64url is the unpadded RFC 4648 alphabet, both ways", () => {
  for (let length = 0; length < 70; length++) {
    const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + length * 11) % 256);
    const text = Buffer.from(bytes).toString("base64url");
    assert.equal(script.encodeBase64Url(bytes), text, `encode ${length}`);
    assert.equal(script.encodeBase64Url(bytes.buffer), text, "an ArrayBuffer encodes alike");
    assert.deepEqual([...script.decodeBase64Url(text)], [...bytes], `decode ${length}`);
  }
  for (const invalid of ["A", "AAAAA", "A+/=", "AB==", "é", "AA AA", 5 as unknown as string])
    assert.throws(() => script.decodeBase64Url(invalid), TypeError, String(invalid));
});

test("the WebAuthn options are the center's: ES256, a resident key, user verification, no attestation", () => {
  const challenge = {
    flowId: "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5",
    challenge: script.encodeBase64Url(new Uint8Array(32).fill(7)),
    rpId: "proof.example.test",
    options: {
      rpId: "proof.example.test",
      userHandle: script.encodeBase64Url(new Uint8Array(32).fill(9)),
      allowedCredentials: [script.encodeBase64Url(new Uint8Array([1, 2, 3]))],
      excludedCredentials: [script.encodeBase64Url(new Uint8Array([4, 5]))],
      userVerification: "required",
      algorithms: [-7],
    },
  };
  const request = script.requestOptions(challenge);
  assert.equal(request.rpId, "proof.example.test");
  assert.equal(request.userVerification, "required");
  assert.deepEqual([...(request.challenge as Uint8Array)], new Array(32).fill(7));
  assert.deepEqual(
    (request.allowCredentials as { type: string; id: Uint8Array }[]).map((item) => [
      item.type,
      [...item.id],
    ]),
    [["public-key", [1, 2, 3]]],
  );
  const open = script.requestOptions({
    ...challenge,
    options: { ...challenge.options, allowedCredentials: [] },
  });
  assert.equal("allowCredentials" in open, false, "a discoverable sign-in names no credential");
  const creation = script.creationOptions(challenge, "Owner");
  assert.deepEqual(creation.rp, { id: "proof.example.test", name: "ArcForges" });
  assert.deepEqual(creation.pubKeyCredParams, [{ type: "public-key", alg: -7 }]);
  assert.deepEqual(creation.authenticatorSelection, {
    residentKey: "required",
    requireResidentKey: true,
    userVerification: "required",
  });
  assert.equal(creation.attestation, "none");
  const user = creation.user as { id: Uint8Array; name: string; displayName: string };
  assert.deepEqual([...user.id], new Array(32).fill(9));
  assert.equal(user.name, "Owner");
  assert.equal(user.displayName, "Owner");
  assert.deepEqual(
    (creation.excludeCredentials as { type: string; id: Uint8Array }[]).map((item) => [...item.id]),
    [[4, 5]],
  );
});

function bytes(...values: number[]): ArrayBuffer {
  return Uint8Array.from(values).buffer;
}

test("a credential becomes the document's assertion and creation, unpadded base64url throughout", () => {
  const assertion = script.assertionBody({
    rawId: bytes(1, 2, 3),
    response: {
      clientDataJSON: bytes(4, 5),
      authenticatorData: bytes(6),
      signature: bytes(7, 8, 9, 10),
      userHandle: bytes(11, 12),
    },
  });
  assert.deepEqual(assertion, {
    credentialId: "AQID",
    clientDataJson: "BAU",
    authenticatorData: "Bg",
    signature: "BwgJCg",
    userHandle: "Cww",
  });
  const noHandle = script.assertionBody({
    rawId: bytes(1),
    response: {
      clientDataJSON: bytes(1),
      authenticatorData: bytes(1),
      signature: bytes(1),
      userHandle: null,
    },
  });
  assert.equal("userHandle" in noHandle, false);
  const emptyHandle = script.assertionBody({
    rawId: bytes(1),
    response: {
      clientDataJSON: bytes(1),
      authenticatorData: bytes(1),
      signature: bytes(1),
      userHandle: new Uint8Array(0),
    },
  });
  assert.equal("userHandle" in emptyHandle, false, "an empty user handle is not sent");
  const creation = script.creationBody({
    rawId: bytes(1, 2, 3),
    response: {
      clientDataJSON: bytes(4, 5),
      attestationObject: bytes(6),
      getTransports: () => ["internal", "hybrid", "bad transport", "x".repeat(200)],
    },
  });
  assert.deepEqual(creation, {
    credentialId: "AQID",
    clientDataJson: "BAU",
    attestationObject: "Bg",
    transports: ["internal", "hybrid"],
  });
  const many = script.creationBody({
    rawId: bytes(1),
    response: {
      clientDataJSON: bytes(1),
      attestationObject: bytes(1),
      getTransports: () => Array.from({ length: 12 }, (_, index) => `t${index}`),
    },
  });
  assert.equal((many.transports as string[]).length, 8);
  const none = script.creationBody({
    rawId: bytes(1),
    response: { clientDataJSON: bytes(1), attestationObject: bytes(1) },
  });
  assert.deepEqual(none.transports, []);
});

test("the browser's installation claim is one UUID it keeps, and a broken storage does not stop a sign-in", () => {
  const stored = new Map<string, string>();
  const storage = {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: (key: string, value: string) => void stored.set(key, value),
  };
  let drawn = 0;
  const random = { randomUUID: () => `6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e${drawn++}` };
  const first = script.installationClaim(storage, random);
  assert.deepEqual(first, {
    installationId: "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e0",
    product: "arcforges-web",
    platform: "web",
    appVersion: "pages-1",
  });
  assert.equal(script.installationClaim(storage, random).installationId, first.installationId);
  assert.equal(drawn, 1, "the stored claim is reused");
  for (const bad of [
    "",
    "not a uuid",
    "00000000-0000-0000-0000-000000000000",
    "6C1D7F0E-3A52-4B9C-8E47-90A1B2C3D4E5",
  ]) {
    stored.set("af.installation", bad);
    assert.notEqual(script.installationClaim(storage, random).installationId, bad, bad);
  }
  const broken = {
    getItem: () => {
      throw new Error("blocked");
    },
    setItem: () => {
      throw new Error("blocked");
    },
  };
  assert.match(script.installationClaim(broken, random).installationId, /^[0-9a-f-]{36}$/u);
  assert.match(script.installationClaim(undefined, random).installationId, /^[0-9a-f-]{36}$/u);
});

test("a failure is shown as the fixed text of its code, never as text the center sent", () => {
  const { ApiError, errorText } = script;
  assert.match(errorText(new ApiError(403, "step_up_required")), /passkey check first/u);
  assert.match(errorText(new ApiError(429, "rate_limited")), /Too many attempts/u);
  assert.match(errorText(new ApiError(503, "")), /could not be completed/u);
  assert.match(
    errorText(new ApiError(400, "<img src=x onerror=alert(1)>")),
    /could not be completed/u,
  );
  assert.match(
    errorText(Object.assign(new Error("x"), { name: "NotAllowedError" })),
    /prompt was closed/u,
  );
  assert.match(
    errorText(Object.assign(new Error("x"), { name: "AbortError" })),
    /prompt was closed/u,
  );
  assert.match(
    errorText(Object.assign(new Error("x"), { name: "NotSupportedError" })),
    /cannot use passkeys/u,
  );
  assert.match(
    errorText(Object.assign(new Error("x"), { name: "SecurityError" })),
    /cannot use passkeys/u,
  );
  // "Already registered" is true only of a create() that an authenticator refused (js-8): the same error name from get() is not it.
  assert.match(errorText(new script.AlreadyRegisteredError()), /already registered/u);
  assert.match(
    errorText(Object.assign(new Error("x"), { name: "InvalidStateError" })),
    /could not be completed/u,
  );
  assert.match(errorText(new TypeError("Failed to fetch")), /could not be reached/u);
  // The script's own failure to read what it was handed is neither the network nor a refusal.
  assert.match(errorText(new script.PageDataError("bad")), /could not be completed/u);
  // A code is a text only when the table names it (js-8): the names an object inherits are no codes.
  for (const inherited of [
    "constructor",
    "toString",
    "valueOf",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "__proto__",
    "__defineGetter__",
  ])
    assert.match(errorText(new ApiError(400, inherited)), /could not be completed/u, inherited);
  assert.match(errorText(new ApiError(400, 5 as unknown as string)), /could not be completed/u);
  assert.match(errorText("nothing"), /could not be completed/u);
  assert.match(errorText(undefined), /could not be completed/u);
});

function reply(status: number, body: unknown): FakeResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => {
      if (body === undefined) throw new SyntaxError("no JSON");
      return body;
    },
  };
}

test("the transport sends the CSRF token, JSON and cookies of this origin only, and maps refusals", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const api = script.createApi("/api", async (url, init) => {
    seen.push({ url, init });
    if (url.endsWith("/bootstrap"))
      return reply(200, { csrfToken: "T".repeat(43), authenticated: false });
    if (url.endsWith("/fail")) return reply(403, { error: { code: "permission_denied" } });
    if (url.endsWith("/html")) return reply(503, undefined);
    if (url.endsWith("/network")) throw new TypeError("Failed to fetch");
    return reply(200, { ok: true });
  });
  assert.deepEqual(await api.bootstrap(), { csrfToken: "T".repeat(43), authenticated: false });
  assert.equal(seen[0]?.url, "/api/session/v1/web/bootstrap");
  assert.equal(seen[0]?.init.method, "GET");
  assert.equal(seen[0]?.init.credentials, "same-origin");
  assert.equal(seen[0]?.init.cache, "no-store");
  assert.equal(seen[0]?.init.redirect, "error");
  assert.equal(seen[0]?.init.referrerPolicy, "same-origin");
  assert.equal(seen[0]?.init.body, undefined);
  await api.post("/step-up/begin", { a: 1 });
  const post = seen[1];
  assert.equal(post?.url, "/api/session/v1/web/step-up/begin");
  assert.equal(post?.init.method, "POST");
  assert.deepEqual(post?.init.headers, {
    Accept: "application/json",
    "X-AF-CSRF": "T".repeat(43),
    "Content-Type": "application/json",
  });
  assert.equal(post?.init.body, '{"a":1}');
  await api.post("/logout");
  assert.equal(seen[2]?.init.body, undefined, "a sign-out sends no body");
  const signOutHeaders = (seen[2]?.init.headers ?? {}) as Record<string, string>;
  assert.equal(signOutHeaders["Content-Type"], undefined);
  await assert.rejects(
    api.post("/fail", {}),
    (error: { status: number; code: string }) =>
      error.status === 403 && error.code === "permission_denied",
  );
  await assert.rejects(
    api.post("/html", {}),
    (error: { status: number; code: string }) => error.status === 503 && error.code === "",
  );
  await assert.rejects(api.post("/network", {}), TypeError);
  api.useToken("U".repeat(43));
  await api.post("/x", {});
  const lastHeaders = (seen.at(-1)?.init.headers ?? {}) as Record<string, string>;
  assert.equal(lastHeaders["X-AF-CSRF"], "U".repeat(43));
});

/** A recording transport and credential store: what a flow sends, in order, and what the browser would answer. */
function fakes() {
  const calls: { path: string; body: unknown }[] = [];
  const gets: unknown[] = [];
  const creates: unknown[] = [];
  const challenge = (flowId: string, purpose: string, extra: Record<string, unknown> = {}) => ({
    flowId,
    method: "passkey",
    challenge: script.encodeBase64Url(new Uint8Array(32).fill(1)),
    rpId: "proof.example.test",
    options: {
      rpId: "proof.example.test",
      userHandle: script.encodeBase64Url(new Uint8Array(32).fill(2)),
      userVerification: "required",
      algorithms: [-7],
      ...extra,
    },
    purpose,
    expiresAt: "2026-10-29T12:05:00Z",
  });
  const api: Api = {
    bootstrap: async () => ({ csrfToken: "T".repeat(43), authenticated: false }),
    useToken: () => {},
    post: async (path, body) => {
      calls.push({ path, body });
      if (path === "/authentication/begin")
        return challenge(
          "11111111-1111-4111-8111-111111111111",
          (body as { purpose: string }).purpose,
        );
      if (path === "/step-up/begin")
        return challenge("22222222-2222-4222-8222-222222222222", "stepUp");
      return { ok: true, path };
    },
  };
  const credentials = {
    get: async (options: unknown) => {
      gets.push(options);
      return {
        rawId: bytes(1, 2, 3),
        response: {
          clientDataJSON: bytes(4),
          authenticatorData: bytes(5),
          signature: bytes(6),
          userHandle: bytes(7),
        },
      };
    },
    create: async (options: unknown) => {
      creates.push(options);
      return {
        rawId: bytes(1, 2, 3),
        response: {
          clientDataJSON: bytes(4),
          attestationObject: bytes(5),
          getTransports: () => ["internal"],
        },
      };
    },
  };
  return { api, credentials, calls, gets, creates };
}

const claim = {
  installationId: "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5",
  product: "arcforges-web",
  platform: "web",
  appVersion: "pages-1",
};

test("signing in is begin, the browser's get(), complete", async () => {
  const { api, credentials, calls, gets } = fakes();
  await script.signIn({ api, credentials, claim });
  assert.deepEqual(calls, [
    {
      path: "/authentication/begin",
      body: { method: "passkey", purpose: "authenticate", installation: claim },
    },
    {
      path: "/authentication/complete",
      body: {
        flowId: "11111111-1111-4111-8111-111111111111",
        proof: {
          passkey: {
            credentialId: "AQID",
            clientDataJson: "BA",
            authenticatorData: "BQ",
            signature: "Bg",
            userHandle: "Bw",
          },
        },
      },
    },
  ]);
  const options = (gets[0] as { publicKey: Record<string, unknown> }).publicKey;
  assert.equal(options.rpId, "proof.example.test");
  assert.equal(options.userVerification, "required");
  // A prompt the person closes ends the flow without a second call.
  const cancelled = fakes();
  cancelled.credentials.get = async () => {
    throw Object.assign(new Error("closed"), { name: "NotAllowedError" });
  };
  await assert.rejects(
    script.signIn({ api: cancelled.api, credentials: cancelled.credentials, claim }),
    { name: "NotAllowedError" },
  );
  assert.equal(cancelled.calls.length, 1);
  const empty = fakes();
  empty.credentials.get = async () => null as never;
  await assert.rejects(script.signIn({ api: empty.api, credentials: empty.credentials, claim }), {
    name: "NotAllowedError",
  });
});

test("enrolling the owner is begin(enroll), the browser's create(), complete with the one-time token", async () => {
  const { api, credentials, calls, creates } = fakes();
  await script.enroll({ api, credentials, claim, token: "afb1.token", displayName: "Owner" });
  assert.deepEqual(calls, [
    {
      path: "/authentication/begin",
      body: { method: "passkey", purpose: "enroll", installation: claim },
    },
    {
      path: "/enrollment/complete",
      body: {
        flowId: "11111111-1111-4111-8111-111111111111",
        proof: { localCode: "afb1.token" },
        credential: {
          passkey: {
            credentialId: "AQID",
            clientDataJson: "BA",
            attestationObject: "BQ",
            transports: ["internal"],
          },
        },
        profile: { displayName: "Owner" },
      },
    },
  ]);
  const options = (creates[0] as { publicKey: { user: { name: string }; attestation: string } })
    .publicKey;
  assert.equal(options.user.name, "Owner");
  assert.equal(options.attestation, "none");
  // The token travels in the request body of the one call that needs it and is not in the option or in any other call.
  assert.equal(JSON.stringify([calls[0], creates]).includes("afb1.token"), false);
});

test("a step-up names its class and target and is proved with the account's passkey", async () => {
  const { api, credentials, calls } = fakes();
  await script.stepUp({
    api,
    credentials,
    operationClass: "identity.revokeSession",
    targetHash: "a".repeat(64),
  });
  assert.deepEqual(calls[0], {
    path: "/step-up/begin",
    body: {
      operationClass: "identity.revokeSession",
      method: "passkey",
      targetHash: "a".repeat(64),
    },
  });
  assert.equal(calls[1]?.path, "/step-up/complete");
  const completion = (calls[1]?.body ?? {}) as { flowId?: string };
  assert.equal(completion.flowId, "22222222-2222-4222-8222-222222222222");
  await script.signOut({ api });
  assert.deepEqual(calls[2], { path: "/logout", body: undefined });
});

// ---------------------------------------------------------------------------------------------------------------------------
// The pages against a minimal document

type Listener = (event: { key?: string; preventDefault(): void }) => void;

class Element {
  dataset: Record<string, string> = {};
  hidden = false;
  disabled = false;
  textContent = "";
  value = "";
  focused = false;
  removed = false;
  submitted = false;
  attributes: Record<string, string> = {};
  elements: Record<string, Element> = {};
  children: Element[] = [];
  listeners: Record<string, Listener[]> = {};
  addEventListener(type: string, listener: Listener) {
    this.listeners[type] = [...(this.listeners[type] ?? []), listener];
  }
  focus() {
    this.focused = true;
  }
  remove() {
    this.removed = true;
  }
  setAttribute(name: string, value: string) {
    this.attributes[name] = value;
  }
  getAttribute(name: string) {
    return this.attributes[name] ?? null;
  }
  querySelector(selector: string) {
    return selector === "a" ? (this.children[0] ?? null) : null;
  }
  querySelectorAll() {
    return [] as Element[];
  }
  submit() {
    this.submitted = true;
  }
  fire(type: string, event: { key?: string } = {}) {
    const state = { prevented: false };
    const preventDefault = () => {
      state.prevented = true;
    };
    for (const listener of this.listeners[type] ?? []) listener({ ...event, preventDefault });
    return state.prevented;
  }
}

function page(
  name: string,
  ids: string[],
  options: {
    hash?: string;
    forms?: Element[];
    fetchImpl?: (url: string, init: RequestInit) => Promise<FakeResponse>;
    /** "throws": reading window.localStorage itself throws, as a browser that blocks all site data does. */
    storage?: "throws";
  } = {},
) {
  const elements = new Map<string, Element>(ids.map((id) => [id, new Element()]));
  // The server renders the error summary hidden unless the page is an error page.
  const summary = elements.get("error-summary");
  if (summary) summary.hidden = true;
  const body = new Element();
  body.dataset.page = name;
  body.dataset.base = "/api";
  const replaced: unknown[][] = [];
  const assigned: string[] = [];
  const stored = new Map<string, string>();
  // Everything the script does to the outside, in order: the address, the storage and every request.
  const events: string[] = [];
  const fakeFetch = async (url: string, init: RequestInit): Promise<FakeResponse> => {
    events.push(`fetch ${init.method ?? "GET"} ${url}`);
    if (options.fetchImpl) return options.fetchImpl(url, init);
    if (url.endsWith("/bootstrap"))
      return reply(200, { csrfToken: "T".repeat(43), authenticated: false });
    return reply(200, {});
  };
  const fakes_ = fakes();
  const window = {
    document: {
      body,
      getElementById: (id: string) => elements.get(id) ?? null,
      querySelectorAll: () => options.forms ?? [],
    },
    location: {
      origin,
      pathname: "/api/account/bootstrap",
      search: "",
      hash: options.hash ?? "",
      assign: (path: string) => void assigned.push(path),
    },
    history: {
      replaceState: (...args: unknown[]) => {
        events.push("replaceState");
        replaced.push(args);
      },
    },
    localStorage: {
      getItem: (key: string) => stored.get(key) ?? null,
      setItem: (key: string, value: string) => {
        events.push(`storage set ${key}`);
        stored.set(key, value);
      },
    },
    crypto: { randomUUID: () => "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5" },
    navigator: { credentials: fakes_.credentials },
    PublicKeyCredential: function PublicKeyCredential() {},
    fetch: fakeFetch,
  };
  if (options.storage === "throws")
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new DOMException("The operation is insecure.", "SecurityError");
      },
    });
  return { window, elements, replaced, assigned, events, fakes: fakes_ };
}

test("the bootstrap page reads the token from the fragment and removes it from the address at once (SEC-09)", async () => {
  const bootstrapped = page(
    "bootstrap",
    ["heading", "error-summary", "error-text", "status", "token", "display-name", "create"],
    {
      hash: "#token=afb1.one-time-token&return=%2Fx",
    },
  );
  await script.start(bootstrapped.window);
  const token = bootstrapped.elements.get("token");
  assert.equal(token?.value, "afb1.one-time-token");
  assert.deepEqual(
    bootstrapped.replaced,
    [[null, "", "/api/account/bootstrap"]],
    "the address is replaced before anything else",
  );
  assert.equal(bootstrapped.elements.get("create")?.disabled, false);
  assert.equal(bootstrapped.elements.get("heading")?.focused, true, "focus starts on the heading");
  // Without the fragment nothing is replaced and the field stays for the operator to fill.
  const plain = page("bootstrap", [
    "heading",
    "error-summary",
    "error-text",
    "status",
    "token",
    "display-name",
    "create",
  ]);
  await script.start(plain.window);
  assert.deepEqual(plain.replaced, []);
  // Creating the account with an empty field is refused before any call, with the error summary focused.
  const create = bootstrapped.elements.get("create");
  assert(create);
  const nameField = bootstrapped.elements.get("display-name");
  assert(nameField);
  nameField.value = "";
  create.fire("click");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(bootstrapped.elements.get("error-summary")?.hidden, false);
  assert.equal(bootstrapped.elements.get("error-summary")?.focused, true);
  assert.match(bootstrapped.elements.get("error-text")?.textContent ?? "", /not accepted/u);
  assert.equal(create.disabled, false, "the button is usable again");
});

test("the bootstrap page enrolls with the one-time token, clears the field and goes to the passkeys", async () => {
  const seen: { url: string; body: unknown }[] = [];
  const bootstrapped = page(
    "bootstrap",
    ["heading", "error-summary", "error-text", "status", "token", "display-name", "create"],
    {
      hash: "#token=afb1.one-time-token",
      fetchImpl: async (url, init) => {
        seen.push({
          url,
          body: init.body === undefined ? undefined : JSON.parse(String(init.body)),
        });
        if (url.endsWith("/bootstrap"))
          return reply(200, { csrfToken: "T".repeat(43), authenticated: false });
        if (url.endsWith("/authentication/begin"))
          return reply(200, {
            flowId: "11111111-1111-4111-8111-111111111111",
            method: "passkey",
            challenge: script.encodeBase64Url(new Uint8Array(32)),
            rpId: "proof.example.test",
            options: {
              rpId: "proof.example.test",
              userHandle: script.encodeBase64Url(new Uint8Array(32).fill(2)),
              userVerification: "required",
              algorithms: [-7],
            },
            purpose: "enroll",
          });
        return reply(200, {});
      },
    },
  );
  await script.start(bootstrapped.window);
  const nameField = bootstrapped.elements.get("display-name");
  assert(nameField);
  nameField.value = "  Owner  ";
  bootstrapped.elements.get("create")?.fire("click");
  await new Promise((resolve) => setTimeout(resolve, 10));
  const completion = seen.find((call) => call.url.endsWith("/enrollment/complete"));
  assert(completion);
  const sent = completion.body as { proof: unknown; profile: unknown };
  assert.deepEqual(sent.proof, { localCode: "afb1.one-time-token" });
  assert.deepEqual(sent.profile, { displayName: "Owner" });
  assert.equal(bootstrapped.elements.get("token")?.value, "", "the one-time token leaves the page");
  assert.deepEqual(bootstrapped.assigned, ["/api/account/passkeys"]);
});

test("the sign-in page follows a return path of its own origin and no other", async () => {
  for (const [hash, expected] of [
    ["#return=%2Fconnect", "/connect"],
    ["#return=%2F%2Fevil.example", "/api/account/passkeys"],
    ["#return=https%3A%2F%2Fevil.example%2F", "/api/account/passkeys"],
    ["#return=javascript%3Aalert(1)", "/api/account/passkeys"],
    ["", "/api/account/passkeys"],
  ] as const) {
    const signIn = page(
      "sign-in",
      ["heading", "error-summary", "error-text", "status", "sign-in", "signed-in"],
      {
        hash,
        fetchImpl: async (url) => {
          if (url.endsWith("/bootstrap"))
            return reply(200, { csrfToken: "T".repeat(43), authenticated: false });
          if (url.endsWith("/authentication/begin"))
            return reply(200, {
              flowId: "11111111-1111-4111-8111-111111111111",
              method: "passkey",
              challenge: script.encodeBase64Url(new Uint8Array(32)),
              rpId: "proof.example.test",
              options: {
                rpId: "proof.example.test",
                userVerification: "required",
                algorithms: [-7],
              },
              purpose: "authenticate",
            });
          return reply(200, {});
        },
      },
    );
    await script.start(signIn.window);
    const button = signIn.elements.get("sign-in");
    assert.equal(button?.disabled, false);
    button?.fire("click");
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.deepEqual(signIn.assigned, [expected], hash);
  }
});

test("a form that needs a step-up proves it first and is then submitted as it is", async () => {
  const form = new Element();
  form.dataset.stepUpClass = "identity.revokeAllSessions";
  form.dataset.stepUpTarget = "a".repeat(64);
  const csrf = new Element();
  csrf.value = "C".repeat(43);
  form.elements.csrf = csrf;
  const button = new Element();
  form.querySelectorAll = () => [button];
  const seen: string[] = [];
  const sessions = page("sessions", ["heading", "error-summary", "error-text", "status"], {
    forms: [form],
    fetchImpl: async (url, init) => {
      seen.push(
        `${init.method} ${url} ${(init.headers as Record<string, string>)["X-AF-CSRF"] ?? ""}`,
      );
      if (url.endsWith("/step-up/begin"))
        return reply(200, {
          flowId: "22222222-2222-4222-8222-222222222222",
          method: "passkey",
          challenge: script.encodeBase64Url(new Uint8Array(32)),
          rpId: "proof.example.test",
          options: { rpId: "proof.example.test", userVerification: "required", algorithms: [-7] },
          purpose: "stepUp",
        });
      return reply(200, {
        operationClass: "identity.revokeAllSessions",
        expiresAt: "2026-10-29T12:05:00Z",
      });
    },
  });
  // The page wires its forms.
  sessions.window.document.querySelectorAll = (() => [form]) as never;
  await script.start(sessions.window);
  assert.equal(form.fire("submit"), true, "the first submit is held back");
  assert.equal(button.disabled, true);
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(seen, [
    `POST /api/session/v1/web/step-up/begin ${"C".repeat(43)}`,
    `POST /api/session/v1/web/step-up/complete ${"C".repeat(43)}`,
  ]);
  assert.equal(form.submitted, true, "the form is submitted once the step-up is proved");
  assert.equal(form.fire("submit"), false, "the submit that follows is let through");
  // A refusal shows its text, enables the button again and does not submit.
  const refused = new Element();
  refused.dataset.stepUpClass = "identity.revokeAllSessions";
  refused.dataset.stepUpTarget = "a".repeat(64);
  refused.elements.csrf = csrf;
  const other = new Element();
  refused.querySelectorAll = () => [other];
  const failing = page("sessions", ["heading", "error-summary", "error-text", "status"], {
    forms: [refused],
    fetchImpl: async () => reply(403, { error: { code: "rate_limited" } }),
  });
  await script.start(failing.window);
  refused.fire("submit");
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(refused.submitted, false);
  assert.equal(other.disabled, false);
  assert.match(failing.elements.get("error-text")?.textContent ?? "", /Too many attempts/u);
});

test("the creation page fills its hidden fields from the browser's credential and submits", async () => {
  const form = new Element();
  Object.assign(form.dataset, {
    flowId: "11111111-1111-4111-8111-111111111111",
    challenge: script.encodeBase64Url(new Uint8Array(32).fill(3)),
    rpId: "proof.example.test",
    userHandle: script.encodeBase64Url(new Uint8Array(32).fill(4)),
    excluded: `${script.encodeBase64Url(new Uint8Array([1]))},${script.encodeBase64Url(new Uint8Array([2]))}`,
    accountName: "Owner",
  });
  for (const name of ["credential_id", "client_data_json", "attestation_object", "transports"])
    form.elements[name] = new Element();
  const registered = page("register", [
    "heading",
    "error-summary",
    "error-text",
    "status",
    "register",
    "create-passkey",
  ]);
  registered.elements.set("register", form);
  // The page renders the button disabled; the script makes it usable once it has wired it.
  const createButton = registered.elements.get("create-passkey");
  assert(createButton);
  createButton.disabled = true;
  await script.start(registered.window);
  assert.equal(createButton.disabled, false, "the script enables the creation button");
  registered.elements.get("create-passkey")?.fire("click");
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(form.elements.credential_id?.value, "AQID");
  assert.equal(form.elements.client_data_json?.value, "BA");
  assert.equal(form.elements.attestation_object?.value, "BQ");
  assert.equal(form.elements.transports?.value, "internal");
  assert.equal(form.submitted, true);
  const options = (
    registered.fakes.creates[0] as {
      publicKey: { excludeCredentials: unknown[]; user: { name: string } };
    }
  ).publicKey;
  assert.equal(options.excludeCredentials.length, 2);
  assert.equal(options.user.name, "Owner");
});

test("the script writes text only with textContent and loads nothing", () => {
  const source = readFileSync(new URL(location, import.meta.url), "utf8");
  for (const sink of [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function",
    "srcdoc",
    "importScripts",
    "createElement",
    "appendChild",
  ])
    assert.equal(source.includes(sink), false, sink);
  assert.equal(/https?:\/\//u.test(source), false, "no absolute URL");
  assert.equal(/\bimport\s*\(|\bimport\s+.*from/u.test(source), false, "no import");
  assert.match(source, /textContent/u);
});

// ---------------------------------------------------------------------------------------------------------------------------
// The fix round (js-1 to js-8): a blocked storage, the script-needed line, the order of the address and the requests, the
// return path of a signed-in visitor, the guards of every ceremony, the wording of every code, and the create path's error.

const never = () => new Promise<never>(() => {});
const settle = (ms = 10) => new Promise((resolve) => setTimeout(resolve, ms));
const common = ["heading", "error-summary", "error-text", "status"];
const signedOut = () => reply(200, { csrfToken: "T".repeat(43), authenticated: false });

function challengeBody(purpose: string, extra: Record<string, unknown> = {}) {
  return {
    flowId: "11111111-1111-4111-8111-111111111111",
    method: "passkey",
    challenge: script.encodeBase64Url(new Uint8Array(32)),
    rpId: "proof.example.test",
    options: {
      rpId: "proof.example.test",
      userHandle: script.encodeBase64Url(new Uint8Array(32).fill(2)),
      userVerification: "required",
      algorithms: [-7],
      ...extra,
    },
    purpose,
  };
}

/** A creation page: the form whose data attributes carry the options, and its hidden fields. */
function creationForm(): Element {
  const form = new Element();
  Object.assign(form.dataset, {
    flowId: "11111111-1111-4111-8111-111111111111",
    challenge: script.encodeBase64Url(new Uint8Array(32).fill(3)),
    rpId: "proof.example.test",
    userHandle: script.encodeBase64Url(new Uint8Array(32).fill(4)),
    excluded: "",
    accountName: "Owner",
  });
  for (const name of ["credential_id", "client_data_json", "attestation_object", "transports"])
    form.elements[name] = new Element();
  return form;
}

test("a browser that blocks its storage does not stop the sign-in or the bootstrap page (js-1)", async () => {
  for (const [name, ids] of [
    ["sign-in", [...common, "sign-in", "signed-in"]],
    ["bootstrap", [...common, "token", "display-name", "create"]],
  ] as const) {
    let begun: unknown;
    const blocked = page(name, [...ids], {
      storage: "throws",
      fetchImpl: async (url, init) => {
        if (url.endsWith("/authentication/begin")) begun = JSON.parse(String(init.body));
        return url.endsWith("/bootstrap") ? signedOut() : never();
      },
    });
    await script.start(blocked.window);
    const button = blocked.elements.get(name === "sign-in" ? "sign-in" : "create");
    assert.equal(button?.disabled, false, `${name}: the button is usable`);
    assert.equal(button?.listeners.click?.length, 1, `${name}: the click is wired`);
    // A claim is produced for the page load though nothing can be kept.
    if (name === "bootstrap") {
      for (const [id, value] of [
        ["display-name", "Owner"],
        ["token", "afb1.t"],
      ] as const) {
        const field = blocked.elements.get(id);
        if (field) field.value = value;
      }
    }
    button?.fire("click");
    await settle();
    const installation = (begun as { installation?: { installationId?: string } })?.installation;
    assert.match(
      installation?.installationId ?? "",
      /^[0-9a-f-]{36}$/u,
      `${name}: a claim is sent`,
    );
  }
});

test("a page that cannot work without its script says so until the script runs (js-3)", async () => {
  for (const [name, ids] of [
    ["sign-in", [...common, "sign-in", "signed-in"]],
    ["bootstrap", [...common, "token", "display-name", "create"]],
    ["sign-out", [...common, "sign-out"]],
    ["register", [...common, "register", "create-passkey"]],
    ["passkeys", common],
    ["operations-review", common],
  ] as const) {
    const shown = page(name, [...ids, "needs-script"]);
    if (name === "register") shown.elements.set("register", creationForm());
    const line = shown.elements.get("needs-script");
    assert.equal(line?.removed, false, `${name}: the line is there until the script runs`);
    await script.start(shown.window);
    assert.equal(line?.removed, true, `${name}: the script removed the line`);
  }
});

test("the script reads the address first and writes only the installation claim, no log and no token anywhere (SEC-09)", async () => {
  const logged: string[] = [];
  const names = ["log", "info", "warn", "error", "debug", "trace", "dir", "table"] as const;
  const spies = names.map((name) => mock.method(console, name, () => void logged.push(name)));
  try {
    const token = "afb1.one-time-token";
    const ids = [...common, "token", "display-name", "create"];
    const base = { hash: `#token=${token}&return=%2Fx` };
    // The address is replaced before anything else, whatever fails after it: no passkeys, or a bootstrap read that fails.
    const unsupported = page("bootstrap", ids, base);
    delete (unsupported.window as { PublicKeyCredential?: unknown }).PublicKeyCredential;
    await script.start(unsupported.window);
    assert.equal(unsupported.events[0], "replaceState", "without passkeys");
    assert.equal(unsupported.elements.get("token")?.value, token);
    const failing = page("bootstrap", ids, {
      ...base,
      fetchImpl: async () => {
        throw new TypeError("Failed to fetch");
      },
    });
    await script.start(failing.window);
    assert.equal(failing.events[0], "replaceState", "with a bootstrap read that fails");
    assert.match(failing.elements.get("error-text")?.textContent ?? "", /could not be reached/u);

    // A whole enrollment: the claim is the one write to the storage, and the token is in no address and in no request's address.
    const working = page("bootstrap", ids, {
      ...base,
      fetchImpl: async (url) =>
        url.endsWith("/authentication/begin")
          ? reply(200, challengeBody("enroll"))
          : url.endsWith("/bootstrap")
            ? signedOut()
            : reply(200, {}),
    });
    await script.start(working.window);
    const name = working.elements.get("display-name");
    if (name) name.value = "Owner";
    working.elements.get("create")?.fire("click");
    await settle();
    assert.equal(working.events[0], "replaceState");
    assert.equal(working.assigned.length, 1);
    assert.deepEqual(
      working.events.filter((event) => event.startsWith("storage")),
      ["storage set af.installation"],
    );
    for (const event of [...working.events, ...working.assigned, ...working.replaced.map(String)])
      assert.equal(event.includes(token), false, `the token is in: ${event}`);
    assert.deepEqual(logged, [], "the script writes no log");
  } finally {
    for (const spy of spies) spy.mock.restore();
  }
});

test("a signed-in visitor of the sign-in page is offered only a validated return path (js-6)", async () => {
  for (const [hash, expected] of [
    ["#return=%2Fconnect", "/connect"],
    ["#return=%2Fapi%2Faccount%2Fsessions", "/api/account/sessions"],
    ["#return=%2F%2Fevil.example", "/api/account/passkeys"],
    ["#return=https%3A%2F%2Fevil.example%2F", "/api/account/passkeys"],
    ["#return=javascript%3Aalert(1)", "/api/account/passkeys"],
    ["#return=%2F%5Cevil.example", "/api/account/passkeys"],
    ["#return=%2F%0A%2Fevil.example", "/api/account/passkeys"],
    ["#return=data%3Atext%2Fhtml%2Cx", "/api/account/passkeys"],
    ["#return=%2F%2F%2Fevil.example", "/api/account/passkeys"],
    ["#return", "/api/account/passkeys"],
    ["", "/api/account/passkeys"],
  ] as const) {
    const signIn = page("sign-in", [...common, "sign-in", "signed-in"], {
      hash,
      fetchImpl: async () => reply(200, { csrfToken: "T".repeat(43), authenticated: true }),
    });
    const link = new Element();
    const line = signIn.elements.get("signed-in");
    assert(line);
    line.hidden = true;
    line.children = [link];
    await script.start(signIn.window);
    assert.equal(line.hidden, false, hash);
    assert.equal(link.attributes.href, expected, hash);
  }
});

test("every ceremony disables its button while it runs, and a second click starts no second one (js-7)", async () => {
  // The button of each page is disabled while the first call of its flow is unanswered.
  const held = async (url: string) => (url.endsWith("/bootstrap") ? signedOut() : never());
  const signIn = page("sign-in", [...common, "sign-in", "signed-in"], { fetchImpl: held });
  await script.start(signIn.window);
  const signInButton = signIn.elements.get("sign-in");
  assert.equal(signInButton?.disabled, false);
  signInButton?.fire("click");
  await settle();
  assert.equal(signInButton?.disabled, true, "sign-in");

  const boot = page("bootstrap", [...common, "token", "display-name", "create"], {
    hash: "#token=afb1.t",
    fetchImpl: held,
  });
  await script.start(boot.window);
  const nameField = boot.elements.get("display-name");
  if (nameField) nameField.value = "Owner";
  boot.elements.get("create")?.fire("click");
  await settle();
  assert.equal(boot.elements.get("create")?.disabled, true, "bootstrap");

  const registered = page("register", [...common, "register", "create-passkey"]);
  registered.elements.set("register", creationForm());
  registered.fakes.credentials.create = never as never;
  await script.start(registered.window);
  registered.elements.get("create-passkey")?.fire("click");
  await settle();
  assert.equal(registered.elements.get("create-passkey")?.disabled, true, "register");

  const out = page("sign-out", [...common, "sign-out"], { fetchImpl: () => never() });
  await script.start(out.window);
  out.elements.get("sign-out")?.fire("click");
  await settle();
  assert.equal(out.elements.get("sign-out")?.disabled, true, "sign-out");

  // A browser drops a click on a disabled button: after the first, the second changes nothing.
  let begins = 0;
  const twice = page("sign-in", [...common, "sign-in", "signed-in"], {
    fetchImpl: async (url) => {
      if (url.endsWith("/authentication/begin")) begins += 1;
      return held(url);
    },
  });
  await script.start(twice.window);
  const button = twice.elements.get("sign-in");
  for (let click = 0; click < 2; click += 1) if (!button?.disabled) button?.fire("click");
  await settle();
  assert.equal(begins, 1);
});

test("Enter in the enrollment's fields starts it once, any other key nothing, and Enter while it runs nothing (js-7)", async () => {
  let begins = 0;
  const boot = page("bootstrap", [...common, "token", "display-name", "create"], {
    hash: "#token=afb1.t",
    fetchImpl: async (url) => {
      if (url.endsWith("/authentication/begin")) {
        begins += 1;
        return never();
      }
      return signedOut();
    },
  });
  await script.start(boot.window);
  const token = boot.elements.get("token");
  const name = boot.elements.get("display-name");
  assert(token && name);
  name.value = "Owner";
  name.fire("keydown", { key: "a" });
  token.fire("keydown", { key: "Tab" });
  await settle();
  assert.equal(begins, 0, "a key other than Enter starts nothing");
  name.fire("keydown", { key: "Enter" });
  await settle();
  assert.equal(begins, 1, "Enter in the name field starts the enrollment");
  token.fire("keydown", { key: "Enter" });
  await settle();
  assert.equal(begins, 1, "Enter while it runs starts no second one");
});

test("a step-up sends the class and the target of its form, each in its own place (js-7)", async () => {
  const form = new Element();
  form.dataset.stepUpClass = "identity.revokeAllSessions";
  form.dataset.stepUpTarget = "b".repeat(64);
  const csrf = new Element();
  csrf.value = "C".repeat(43);
  form.elements.csrf = csrf;
  form.querySelectorAll = () => [new Element()];
  const bodies: unknown[] = [];
  const sessions = page("sessions", common, {
    forms: [form],
    fetchImpl: async (url, init) => {
      if (url.endsWith("/step-up/begin")) {
        bodies.push(JSON.parse(String(init.body)));
        return reply(200, challengeBody("stepUp"));
      }
      return reply(200, {});
    },
  });
  sessions.window.document.querySelectorAll = (() => [form]) as never;
  await script.start(sessions.window);
  form.fire("submit");
  await settle();
  assert.deepEqual(bodies, [
    { operationClass: "identity.revokeAllSessions", method: "passkey", targetHash: "b".repeat(64) },
  ]);
});

test("the operations review page proves the operator grant's step-up before its form is submitted, and the grant form of the operations page does not", async () => {
  const target = "c".repeat(64);
  const form = new Element();
  form.dataset.stepUpClass = "center.operatorGrant";
  form.dataset.stepUpTarget = target;
  const csrf = new Element();
  csrf.value = "C".repeat(43);
  form.elements.csrf = csrf;
  form.querySelectorAll = () => [new Element()];
  const bodies: unknown[] = [];
  const review = page("operations-review", common, {
    forms: [form],
    fetchImpl: async (url, init) => {
      if (url.endsWith("/step-up/begin")) {
        bodies.push(JSON.parse(String(init.body)));
        return reply(200, challengeBody("stepUp"));
      }
      return reply(200, {});
    },
  });
  review.window.document.querySelectorAll = (() => [form]) as never;
  await script.start(review.window);
  form.fire("submit");
  await settle();
  assert.deepEqual(bodies, [
    { operationClass: "center.operatorGrant", method: "passkey", targetHash: target },
  ]);
  // The request form (page name operations-grant) carries no step-up: the script wires nothing to it.
  const plain = new Element();
  const grant = page("operations-grant", common, { forms: [plain] });
  grant.window.document.querySelectorAll = (() => [plain]) as never;
  await script.start(grant.window);
  assert.equal(plain.listeners?.submit?.length ?? 0, 0);
});

test("a page that arrives with an error puts the focus on the error summary, not the heading (js-7)", async () => {
  const withError = page("passkeys", common);
  const summary = withError.elements.get("error-summary");
  assert(summary);
  summary.hidden = false;
  await script.start(withError.window);
  assert.equal(summary.focused, true);
  assert.equal(withError.elements.get("heading")?.focused, false);
  const plain = page("passkeys", common);
  await script.start(plain.window);
  assert.equal(plain.elements.get("heading")?.focused, true);
  assert.equal(plain.elements.get("error-summary")?.focused, false);
});

test("every code the center sends has a text of its own (js-7)", () => {
  const source = readFileSync(new URL("../../center/internal/arc/arc.go", import.meta.url), "utf8");
  const codes = [
    ...new Set([...source.matchAll(/Code:\s*"([a-z_]+)"/gu)].map((found) => found[1])),
  ];
  assert(codes.length >= 15, `the codes of package arc were found: ${codes.join(", ")}`);
  const generic = script.errorText(new script.ApiError(500, ""));
  const seen = new Map<string, string>();
  for (const code of codes as string[]) {
    const text = script.errorText(new script.ApiError(400, code));
    assert.notEqual(text, generic, `${code} has a text of its own`);
    seen.set(code, text);
  }
  assert(seen.size === codes.length);
});

test("code_invalid is described truly for an unknown code and for a code whose lookups are spent (AF-CTR-04 E2)", () => {
  // VALIDATION/code_invalid answers both an unknown user code and the sixth lookup of a live one: the text must not claim the code
  // was not recognized, and it names the way out (a new sign-in on the device).
  const text = script.errorText(new script.ApiError(400, "code_invalid"));
  assert.equal(
    text,
    "That code cannot be used. Check it, or start the sign-in again on the device.",
  );
  assert(!/not recognized|wrong|unknown/u.test(text));
});

test("an internal failure is not described as one to try again (E4-INTERNAL: retry NEVER, effect UNKNOWN)", () => {
  const text = script.errorText(new script.ApiError(503, "internal"));
  assert.match(text, /may or may not have been completed/u);
  assert.doesNotMatch(text, /try again/iu);
  assert.match(script.errorText(new script.ApiError(503, "overloaded")), /try again/iu);
});

test("a reply without a code never promises a retry: behind the hosted Worker an internal failure is a plain 503 (E4-INTERNAL)", () => {
  // The Worker turns the center's own 503 (an internal failure, retry NEVER with effect UNKNOWN) into its plain-text 503 with no
  // ArcError, so the script cannot tell it from any other failure and must not say to try again.
  for (const error of [new script.ApiError(503, ""), new script.ApiError(500, ""), undefined]) {
    const text = script.errorText(error);
    assert.match(text, /may or may not have taken effect/u);
    assert.doesNotMatch(text, /try again/iu);
  }
  // A code-carrying AFTER_TIME refusal keeps its busy text.
  assert.match(script.errorText(new script.ApiError(503, "overloaded")), /try again/iu);
});

test("the sign-out page reads the CSRF token, posts the logout with it and goes to the sign-in (js-7)", async () => {
  const seen: string[] = [];
  const out = page("sign-out", [...common, "sign-out"], {
    fetchImpl: async (url, init) => {
      seen.push(
        `${init.method} ${url} ${(init.headers as Record<string, string>)["X-AF-CSRF"] ?? ""}`,
      );
      return url.endsWith("/bootstrap")
        ? reply(200, { csrfToken: "S".repeat(43), authenticated: true })
        : reply(200, {});
    },
  });
  await script.start(out.window);
  const button = out.elements.get("sign-out");
  assert.equal(button?.disabled, false);
  button?.fire("click");
  await settle();
  assert.deepEqual(seen, [
    "GET /api/session/v1/web/bootstrap ",
    `POST /api/session/v1/web/logout ${"S".repeat(43)}`,
  ]);
  assert.deepEqual(out.assigned, ["/api/account/sign-in"]);
});

test("a browser without passkeys gets the text, no call and no usable button (js-7)", async () => {
  const fetched: string[] = [];
  const signIn = page("sign-in", [...common, "sign-in", "signed-in"], {
    fetchImpl: async (url) => {
      fetched.push(url);
      return signedOut();
    },
  });
  const button = signIn.elements.get("sign-in");
  assert(button);
  button.disabled = true; // the server renders it so
  delete (signIn.window as { PublicKeyCredential?: unknown }).PublicKeyCredential;
  await script.start(signIn.window);
  assert.match(signIn.elements.get("error-text")?.textContent ?? "", /cannot use passkeys/u);
  assert.equal(signIn.elements.get("error-summary")?.hidden, false);
  assert.equal(button.disabled, true);
  assert.deepEqual(fetched, []);

  const registered = page("register", [...common, "register", "create-passkey"]);
  registered.elements.set("register", creationForm());
  delete (registered.window as { PublicKeyCredential?: unknown }).PublicKeyCredential;
  await script.start(registered.window);
  assert.match(registered.elements.get("error-text")?.textContent ?? "", /cannot use passkeys/u);
  const create = registered.elements.get("create-passkey");
  assert.equal(create?.disabled, true);
  assert.equal((create?.listeners.click ?? []).length, 0);
});

test("the bootstrap page of a browser without passkeys, and the pages whose first read fails, keep their button disabled and unwired (worker-js-2)", async () => {
  const pagesWithButton: [string, string[], string][] = [
    ["bootstrap", ["create", "token", "display-name"], "create"],
    ["sign-in", ["sign-in", "signed-in"], "sign-in"],
  ];
  for (const [name, extra, buttonId] of pagesWithButton) {
    // No passkeys: the text, no call, the button as the server rendered it, and no click or Enter listener anywhere.
    const fetched: string[] = [];
    const bare = page(name, [...common, ...extra], {
      fetchImpl: async (url) => {
        fetched.push(url);
        return signedOut();
      },
    });
    const bareButton = bare.elements.get(buttonId);
    assert(bareButton);
    bareButton.disabled = true;
    delete (bare.window as { PublicKeyCredential?: unknown }).PublicKeyCredential;
    await script.start(bare.window);
    assert.match(bare.elements.get("error-text")?.textContent ?? "", /cannot use passkeys/u, name);
    assert.equal(bareButton.disabled, true, name);
    assert.deepEqual(fetched, [], `${name}: no call`);
    for (const element of bare.elements.values())
      assert.deepEqual(element.listeners, {}, `${name}: no listener at all`);

    // A first read that fails: the fixed text of the failure, the button disabled, nothing listening.
    const broken = page(name, [...common, ...extra], {
      fetchImpl: async () => reply(503, {}),
    });
    const brokenButton = broken.elements.get(buttonId);
    assert(brokenButton);
    brokenButton.disabled = true;
    await script.start(broken.window);
    assert.notEqual(broken.elements.get("error-text")?.textContent ?? "", "", name);
    assert.equal(broken.elements.get("error-summary")?.hidden, false, name);
    assert.equal(brokenButton.disabled, true, `${name}: the button stays disabled`);
    for (const element of broken.elements.values())
      assert.deepEqual(element.listeners, {}, `${name}: nothing is wired after a failed read`);
  }
});

test("the installation claim lives under one key of the storage (js-7)", () => {
  const keys: string[] = [];
  const stored = new Map([["af.installation", "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5"]]);
  const storage = {
    getItem: (key: string) => {
      keys.push(key);
      return stored.get(key) ?? null;
    },
    setItem: (key: string, value: string) => {
      keys.push(key);
      stored.set(key, value);
    },
  };
  const claim = script.installationClaim(storage, {
    randomUUID: () => "ffffffff-ffff-4fff-8fff-ffffffffffff",
  });
  assert.equal(claim.installationId, "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5");
  assert.deepEqual(keys, ["af.installation"]);
});

test("'already registered' is said of a create() an authenticator refused, and of nothing else (js-8)", async () => {
  const refused = Object.assign(new Error("excluded"), { name: "InvalidStateError" });
  // Enrollment and the creation page: create() refused by an authenticator that holds an excluded passkey.
  const enrolling = fakes();
  enrolling.credentials.create = async () => {
    throw refused;
  };
  await assert.rejects(
    script.enroll({
      api: enrolling.api,
      credentials: enrolling.credentials,
      claim,
      token: "afb1.t",
      displayName: "Owner",
    }),
    (error: unknown) =>
      error instanceof script.AlreadyRegisteredError &&
      /already registered/u.test(script.errorText(error)),
  );
  const registered = page("register", [...common, "register", "create-passkey"]);
  registered.elements.set("register", creationForm());
  registered.fakes.credentials.create = (async () => {
    throw refused;
  }) as never;
  await script.start(registered.window);
  registered.elements.get("create-passkey")?.fire("click");
  await settle();
  assert.match(registered.elements.get("error-text")?.textContent ?? "", /already registered/u);
  // The same error from get() (a request already pending) is a failure to try again, not a registered passkey.
  const signing = fakes();
  signing.credentials.get = async () => {
    throw refused;
  };
  await assert.rejects(
    script.signIn({ api: signing.api, credentials: signing.credentials, claim }),
    (error: unknown) => !/already registered/u.test(script.errorText(error)),
  );
  const stepping = fakes();
  stepping.credentials.get = signing.credentials.get;
  await assert.rejects(
    script.stepUp({
      api: stepping.api,
      credentials: stepping.credentials,
      operationClass: "identity.revokeSession",
      targetHash: "a".repeat(64),
    }),
    (error: unknown) => !/already registered/u.test(script.errorText(error)),
  );
});

test("a value the script cannot read is its own failure, not a network one (js-8)", () => {
  for (const unreadable of [
    () => script.decodeBase64Url("not base64url!"),
    () => script.creationOptions({ challenge: "AAAA", rpId: "x", options: {} }, "name"),
    () => script.requestOptions({ options: {} }),
    () => script.requestOptions({ challenge: "AAAA", options: { allowedCredentials: ["*"] } }),
  ])
    assert.throws(unreadable, (error: unknown) => {
      assert(error instanceof script.PageDataError && error instanceof TypeError);
      assert.match(script.errorText(error), /could not be completed/u);
      assert.doesNotMatch(script.errorText(error), /could not be reached/u);
      return true;
    });
});

// ---------------------------------------------------------------------------------------------------------------------------
// The fleet pages (AF-CTR-04 E3): /connect and /activate read the flow ID or the code from the fragment, drop the fragment before any
// request, check the value and only then ask who is signed in; the sign-in page drops its return fragment first and follows a return to
// these two pages with their exact fragment; the page of a decided browser sign-in follows only a loopback link of the exact shape.

const flowId = "3f2a9c4e-1b7d-4e8a-9c3b-5d6e7f8a9b0c";

test("a flow ID is the canonical lower-case UUID and a user code is 8 letters of the code alphabet", () => {
  assert.equal(script.isFlowId(flowId), true);
  for (const bad of [
    flowId.toUpperCase(),
    "00000000-0000-0000-0000-000000000000",
    `${flowId} `,
    flowId.replaceAll("-", ""),
    `{${flowId}}`,
    "3f2a9c4e-1b7d-4e8a-9c3b-5d6e7f8a9b0",
    undefined,
    42,
  ])
    assert.equal(script.isFlowId(bad), false, String(bad));
  assert.equal(script.normalizeUserCode("bcdf-ghjk"), "BCDFGHJK");
  assert.equal(script.normalizeUserCode("BCDF GHJK"), "BCDFGHJK");
  assert.equal(script.normalizeUserCode("BCDFGHJK"), "BCDFGHJK");
  for (const bad of [
    "BCDF-GHJA",
    "BCDF-GHJ",
    "BCDF-GHJKL",
    "BCDF--GHJK",
    "",
    "BCDF-GHJ1",
    "ÄCDF-GHJK",
    null,
  ])
    assert.equal(script.normalizeUserCode(bad), null, String(bad));
  assert.equal(script.displayUserCode("BCDFGHJK"), "BCDF-GHJK");
});

test("the sign-in page follows a return to /connect or /activate with its exact fragment, and nothing else with a fragment", () => {
  const base = "/api";
  assert.equal(
    script.safeFleetReturn(`/api/connect#flow=${flowId}`, origin, base),
    `/api/connect#flow=${flowId}`,
  );
  assert.equal(
    script.safeFleetReturn("/api/activate#code=BCDF-GHJK", origin, base),
    "/api/activate#code=BCDF-GHJK",
  );
  for (const hostile of [
    `/api/connect#flow=${flowId.toUpperCase()}`,
    `/api/connect#flow=${flowId}&x=1`,
    `/api/connect#flow=${flowId}#x`,
    `/api/connect%23flow=${flowId}`,
    `/api/connect/review#flow=${flowId}`,
    `/api/account/passkeys#flow=${flowId}`,
    `/connect#flow=${flowId}`,
    `//evil.example/api/connect#flow=${flowId}`,
    `https://evil.example/api/connect#flow=${flowId}`,
    "/api/activate#code=bcdf-ghjk",
    "/api/activate#code=BCDFGHJK",
    "/api/activate#code=BCDF-GHJA",
    "/api/activate#token=x",
    "/api/activate",
    `/api/connect#return=${flowId}`,
    42,
  ])
    assert.equal(script.safeFleetReturn(hostile, origin, base), null, String(hostile));
  // The nested return of the sign-in page: decoded once by parseFragment; a double encoding or a split value is no fleet return.
  const nested = script.parseFragment(
    `#return=${encodeURIComponent(`/api/connect#flow=${flowId}`)}`,
  ).return;
  assert.equal(script.safeFleetReturn(nested, origin, base), `/api/connect#flow=${flowId}`);
  const doubled = script.parseFragment(`#return=%2Fapi%2Fconnect%2523flow%3D${flowId}`).return;
  assert.equal(script.safeFleetReturn(doubled, origin, base), null);
  const split = script.parseFragment(`#return=%2Fapi%2Fconnect%23flow%3D${flowId}&x=1`).return;
  assert.equal(
    split,
    `/api/connect#flow=${flowId}`,
    "an extra parameter is another fragment value",
  );
  const extra = script.parseFragment(`#return=%2Fapi%2Fconnect%23flow%3D${flowId}%26x%3D1`).return;
  assert.equal(script.safeFleetReturn(extra, origin, base), null);
});

test("only the exact loopback link of a decided browser sign-in is followed", () => {
  const code = "A".repeat(43);
  const state = "s".repeat(16);
  for (const good of [
    `http://127.0.0.1:1024/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:65535/callback?code=${code}&state=${state}`,
    `http://[::1]:49152/callback?code=${code}&state=${"x".repeat(128)}`,
    `http://127.0.0.1:50000/callback?error=access_denied&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${"-_9aZ".repeat(8)}abc&state=a.b_c~d-0123456789`,
  ])
    assert.equal(script.isLoopbackResult(good), true, good);
  for (const bad of [
    `http://localhost:50000/callback?code=${code}&state=${state}`,
    `https://127.0.0.1:50000/callback?code=${code}&state=${state}`,
    `http://127.1:50000/callback?code=${code}&state=${state}`,
    `http://2130706433:50000/callback?code=${code}&state=${state}`,
    `http://0.0.0.0:50000/callback?code=${code}&state=${state}`,
    `http://[::ffff:127.0.0.1]:50000/callback?code=${code}&state=${state}`,
    `http://[0:0:0:0:0:0:0:1]:50000/callback?code=${code}&state=${state}`,
    `http://user@127.0.0.1:50000/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:1023/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:65536/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:099999/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:01024/callback?code=${code}&state=${state}`,
    `http://127.0.0.1/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:50000/callback/?code=${code}&state=${state}`,
    `http://127.0.0.1:50000/Callback?code=${code}&state=${state}`,
    `http://127.0.0.1:50000/other?code=${code}&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${code}`,
    `http://127.0.0.1:50000/callback?state=${state}&code=${code}`,
    `http://127.0.0.1:50000/callback?code=${code}&state=${state}&x=1`,
    `http://127.0.0.1:50000/callback?code=${code}&state=${state}#x`,
    `http://127.0.0.1:50000/callback?code=${"A".repeat(42)}&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${"A".repeat(44)}&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${"A".repeat(42)}=&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${"A".repeat(42)}+&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${code}&state=${"s".repeat(15)}`,
    `http://127.0.0.1:50000/callback?code=${code}&state=${"s".repeat(129)}`,
    `http://127.0.0.1:50000/callback?code=${code}&state=${"s".repeat(15)}%21`,
    `http://127.0.0.1:50000/callback?error=server_error&state=${state}`,
    `http://127.0.0.1:50000/callback?error=access_denied&code=${code}&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${code}&state=${state} `,
    ` http://127.0.0.1:50000/callback?code=${code}&state=${state}`,
    `javascript:alert(1)//http://127.0.0.1:50000/callback?code=${code}&state=${state}`,
    `HTTP://127.0.0.1:50000/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:5e4/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:+50000/callback?code=${code}&state=${state}`,
    `http://127.0.0.1:50000/%63allback?code=${code}&state=${state}`,
    `http://127.0.0.1:50000/callback?code=${code}&state=${state}\n`,
    "",
    null,
  ])
    assert.equal(script.isLoopbackResult(bad), false, String(bad));
});

function connectForm() {
  const form = new Element();
  form.elements.csrf = new Element();
  form.elements.flow_id = new Element();
  return form;
}

test("/connect drops the fragment before any request, refuses a malformed flow ID without a request, and reviews when signed in", async () => {
  const ids = ["heading", "error-summary", "error-text", "status"];
  // Signed in: the fragment is dropped first, then bootstrap, then the review form is submitted with the session's token.
  const form = connectForm();
  const signedIn = page("connect", ids, {
    hash: `#flow=${flowId}`,
    fetchImpl: async () => reply(200, { csrfToken: "S".repeat(43), authenticated: true }),
  });
  signedIn.elements.set("connect-review", form);
  await script.start(signedIn.window);
  assert.deepEqual(signedIn.events, ["replaceState", "fetch GET /api/session/v1/web/bootstrap"]);
  assert.deepEqual(signedIn.replaced, [[null, "", "/api/account/bootstrap"]]);
  assert.equal(form.submitted, true);
  assert.equal(form.elements.flow_id?.value, flowId);
  assert.equal(form.elements.csrf?.value, "S".repeat(43));
  // Signed out: the sign-in page is opened with this page and its fragment as the return.
  const signedOut = page("connect", ids, { hash: `#flow=${flowId}` });
  const other = connectForm();
  signedOut.elements.set("connect-review", other);
  await script.start(signedOut.window);
  assert.equal(signedOut.events[0], "replaceState");
  assert.equal(other.submitted, false);
  assert.deepEqual(signedOut.assigned, [
    `/api/account/sign-in#return=${encodeURIComponent(`/api/connect#flow=${flowId}`)}`,
  ]);
  // A malformed or missing flow ID: the fragment is dropped, no request leaves, the text says the link is incomplete.
  for (const hash of [`#flow=${flowId.toUpperCase()}`, "#flow=", "", `#flow=${flowId}x`]) {
    const malformed = page("connect", ids, { hash });
    malformed.elements.set("connect-review", connectForm());
    await script.start(malformed.window);
    assert.deepEqual(malformed.events, ["replaceState"], hash);
    assert.match(malformed.elements.get("error-text")?.textContent ?? "", /not complete/u);
    assert.deepEqual(malformed.assigned, []);
  }
});

test("/activate fills the code from the fragment after dropping it, and Continue signs in first when there is no session", async () => {
  const ids = ["heading", "error-summary", "error-text", "status", "user-code", "continue"];
  const form = new Element();
  form.elements.csrf = new Element();
  const signedOut = page("activate", ids, { hash: "#code=bcdf-ghjk" });
  signedOut.elements.set("activate-review", form);
  await script.start(signedOut.window);
  assert.deepEqual(signedOut.events, ["replaceState", "fetch GET /api/session/v1/web/bootstrap"]);
  assert.equal(signedOut.elements.get("user-code")?.value, "BCDF-GHJK");
  assert.equal(signedOut.elements.get("continue")?.disabled, false);
  assert.equal(form.fire("submit"), true, "a submission without a session is held back");
  assert.deepEqual(signedOut.assigned, [
    `/api/account/sign-in#return=${encodeURIComponent("/api/activate#code=BCDF-GHJK")}`,
  ]);
  // Signed in: the form goes with the session's token; a code of the wrong shape is refused before it goes.
  const signedForm = new Element();
  signedForm.elements.csrf = new Element();
  const signedIn = page("activate", ids, {
    fetchImpl: async () => reply(200, { csrfToken: "S".repeat(43), authenticated: true }),
  });
  signedIn.elements.set("activate-review", signedForm);
  await script.start(signedIn.window);
  assert.deepEqual(
    signedIn.events,
    ["fetch GET /api/session/v1/web/bootstrap"],
    "no fragment, nothing to drop",
  );
  const field = signedIn.elements.get("user-code");
  assert(field);
  field.value = "BCDF-GHJA";
  assert.equal(signedForm.fire("submit"), true);
  assert.match(signedIn.elements.get("error-text")?.textContent ?? "", /8 letters/u);
  field.value = "bcdfghjk";
  assert.equal(signedForm.fire("submit"), false);
  assert.equal(signedForm.elements.csrf?.value, "S".repeat(43));
  assert.equal(field.value, "BCDF-GHJK");
  // A malformed code in the fragment fills nothing and says so; the fragment is still dropped first.
  const malformed = page("activate", ids, { hash: "#code=BCDF-GHJ1" });
  malformed.elements.set("activate-review", new Element());
  await script.start(malformed.window);
  assert.equal(malformed.events[0], "replaceState");
  assert.equal(malformed.elements.get("user-code")?.value, "");
  assert.match(malformed.elements.get("error-text")?.textContent ?? "", /not complete/u);
});

test("the sign-in page drops its return fragment before anything else, also without passkeys or with a failing first read (P-16)", async () => {
  const ids = ["heading", "error-summary", "error-text", "status", "sign-in", "signed-in"];
  const nested = `#return=${encodeURIComponent(`/api/connect#flow=${flowId}`)}`;
  for (const hash of [
    nested,
    `#return=${encodeURIComponent("/api/activate#code=BCDF-GHJK")}`,
    "#return=%2Fapi%2Faccount%2Fsessions",
  ]) {
    const working = page("sign-in", ids, { hash });
    await script.start(working.window);
    assert.equal(working.events[0], "replaceState", hash);
    const unsupported = page("sign-in", ids, { hash });
    (unsupported.window as { PublicKeyCredential?: unknown }).PublicKeyCredential = undefined;
    await script.start(unsupported.window);
    assert.deepEqual(unsupported.events, ["replaceState"], `${hash} without passkeys`);
    const failing = page("sign-in", ids, { hash, fetchImpl: async () => reply(503, {}) });
    await script.start(failing.window);
    assert.equal(failing.events[0], "replaceState", `${hash} with a failing read`);
  }
  // A signed-in visitor's link returns to the fleet page with its fragment.
  const link = new Element();
  const signed = page("sign-in", ["heading", "error-summary", "error-text", "status", "sign-in"], {
    hash: nested,
    fetchImpl: async () => reply(200, { csrfToken: "S".repeat(43), authenticated: true }),
  });
  const holder = new Element();
  holder.hidden = true;
  holder.children.push(link);
  signed.elements.set("signed-in", holder);
  await script.start(signed.window);
  assert.equal(link.attributes.href, `/api/connect#flow=${flowId}`);
  // Without a fragment nothing is replaced.
  const plain = page("sign-in", ids);
  await script.start(plain.window);
  assert.deepEqual(plain.replaced, []);
});

test("the page of a decided browser sign-in follows a valid loopback link and nothing else", async () => {
  const ids = ["heading", "error-summary", "error-text", "status"];
  const good = page("connect-done", ids);
  const link = new Element();
  link.attributes.href = `http://127.0.0.1:50000/callback?code=${"A".repeat(43)}&state=${"s".repeat(16)}`;
  good.elements.set("return-link", link);
  await script.start(good.window);
  assert.deepEqual(good.assigned, [link.attributes.href]);
  assert.deepEqual(good.events, [], "no request and no address change before the navigation");
  const bad = page("connect-done", ids);
  const hostile = new Element();
  hostile.attributes.href = `https://evil.example/callback?code=${"A".repeat(43)}&state=${"s".repeat(16)}`;
  bad.elements.set("return-link", hostile);
  await script.start(bad.window);
  assert.deepEqual(bad.assigned, []);
  assert.equal(hostile.removed, true);
  assert.match(bad.elements.get("error-text")?.textContent ?? "", /not valid/u);
});

test("an /activate approval with a fingerprint tail of the wrong shape is refused before the passkey prompt", async () => {
  const form = new Element();
  form.dataset.stepUpClass = "fleet.approveDeviceCode";
  form.dataset.stepUpTarget = "d".repeat(64);
  form.elements.csrf = new Element();
  const tail = new Element();
  form.elements.fingerprint_tail = tail;
  form.querySelectorAll = () => [new Element()];
  const review = page("activate-review", common, { forms: [form] });
  review.window.document.querySelectorAll = (() => [form]) as never;
  await script.start(review.window);
  for (const value of ["", "AB", "ABCDE", "GHIJ", "12 4"]) {
    tail.value = value;
    assert.equal(form.fire("submit"), true, value);
    await settle();
  }
  assert.deepEqual(review.events, [], "no step-up began");
  assert.match(review.elements.get("error-text")?.textContent ?? "", /last 4 characters/u);
  tail.value = "a1F9";
  form.fire("submit");
  await settle();
  assert.deepEqual(review.events.slice(0, 1), ["fetch POST /api/session/v1/web/step-up/begin"]);
});

// AF-CTR-04 part M: the mobile pages.

test("the sign-in page follows a return to /mobile/authorize with its exact fragment and nothing else", () => {
  assert.equal(
    script.safeFleetReturn(`/api/mobile/authorize#flow=${flowId}`, origin, "/api"),
    `/api/mobile/authorize#flow=${flowId}`,
  );
  for (const hostile of [
    `/api/mobile/authorize#flow=${flowId.toUpperCase()}`,
    `/api/mobile/authorize#flow=${flowId}&x=1`,
    `/api/mobile/authorize/review#flow=${flowId}`,
    `/mobile/authorize#flow=${flowId}`,
    `https://evil.example/api/mobile/authorize#flow=${flowId}`,
    "/api/mobile/authorize#flow=00000000-0000-0000-0000-000000000000",
    "/api/mobile/authorize#code=x",
  ])
    assert.equal(script.safeFleetReturn(hostile, origin, "/api"), null, hostile);
});

test("only the exact callback of a decided mobile authorization is a link to the app", () => {
  const code = `${"A".repeat(42)}E`;
  const state = "s".repeat(16);
  const iss = encodeURIComponent(`${origin}/api`);
  for (const good of [
    `${origin}/app/callback#code=${code}&state=${state}&iss=${iss}`,
    `${origin}/app/callback#error=access_denied&state=${state}&iss=${iss}`,
    `com.arcforges.android.debug:/callback#code=${code}&state=${state}&iss=${iss}`,
  ])
    assert.equal(script.isMobileResult(good, origin), true, good);
  for (const bad of [
    `https://evil.example/app/callback#code=${code}&state=${state}&iss=${iss}`,
    `${origin}/app/callback?code=${code}&state=${state}&iss=${iss}`,
    `${origin}/app/callback#code=${"A".repeat(42)}B&state=${state}&iss=${iss}`,
    `${origin}/app/callback#code=${code}&state=${state}`,
    `${origin}/app/callback#error=server_error&state=${state}&iss=${iss}`,
    `javascript:/callback#code=${code}&state=${state}&iss=${iss}`,
    `${origin}/app/node#code=${code}&state=${state}&iss=${iss}`,
    42,
  ])
    assert.equal(script.isMobileResult(bad, origin), false, String(bad));
});

test("the mobile done page leaves a valid link to the person's tap and removes an invalid one", async () => {
  const ids = ["heading", "error-summary", "error-text", "status"];
  const good = page("mobile-authorize-done", ids);
  const link = new Element();
  link.attributes.href = `${origin}/app/callback#code=${"A".repeat(42)}E&state=${"s".repeat(16)}&iss=${encodeURIComponent(`${origin}/api`)}`;
  good.elements.set("app-link", link);
  await script.start(good.window);
  assert.deepEqual(good.assigned, [], "the script never follows the link (MB-7)");
  assert.deepEqual(good.events, []);
  assert.equal(link.removed, false);
  const bad = page("mobile-authorize-done", ids);
  const hostile = new Element();
  hostile.attributes.href = "https://evil.example/app/callback#code=x";
  bad.elements.set("app-link", hostile);
  await script.start(bad.window);
  assert.equal(hostile.removed, true);
  assert.match(bad.elements.get("error-text")?.textContent ?? "", /not valid/u);
});

test("the app callback page strips its fragment without reading it and sends nothing (Q-4)", async () => {
  const callback = page("app-callback", ["heading"]);
  let read = 0;
  Object.defineProperty(callback.window.location, "hash", {
    get() {
      read += 1;
      return "#code=x&state=y&iss=z";
    },
  });
  await script.start(callback.window);
  assert.equal(read, 0, "the fragment is never read");
  assert.deepEqual(callback.events, ["replaceState"]);
  assert.deepEqual(callback.replaced, [[null, "", "/api/account/bootstrap"]]);
});

test("the mobile authorization page reads the flow, drops the fragment first and submits the review when signed in", async () => {
  const form = new Element();
  form.elements.csrf = new Element();
  form.elements.flow_id = new Element();
  let submitted = 0;
  form.submit = () => {
    submitted += 1;
  };
  const authorize = page("mobile-authorize", ["heading", "error-summary", "error-text", "status"], {
    hash: `#flow=${flowId}`,
    fetchImpl: async () => reply(200, { csrfToken: "T".repeat(43), authenticated: true }),
  });
  authorize.elements.set("mobile-review", form);
  await script.start(authorize.window);
  assert.equal(authorize.events[0], "replaceState");
  assert.equal(form.elements.flow_id.value, flowId);
  assert.equal(submitted, 1);
});
