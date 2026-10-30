// SPDX-License-Identifier: AGPL-3.0-only
// The account pages' script (AF-CTR-03 A2; center/internal/pages/static/account.js), run without a browser: the open-redirect rule for
// the return path (DC-13), the base64url and WebAuthn conversions, the installation claim, the transport, the sign-in, enrollment,
// step-up and sign-out flows, and the pages' wiring against a minimal document (SEC-09: the one-time token leaves the address at
// once). The script is an ES module that starts itself only in a document; here its functions are called with fakes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

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
    errorText(Object.assign(new Error("x"), { name: "InvalidStateError" })),
    /already registered/u,
  );
  assert.match(errorText(new TypeError("Failed to fetch")), /could not be reached/u);
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
  setAttribute(name: string, value: string) {
    this.attributes[name] = value;
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
  const fakeFetch = async (url: string, init: RequestInit): Promise<FakeResponse> => {
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
    history: { replaceState: (...args: unknown[]) => void replaced.push(args) },
    localStorage: {
      getItem: (key: string) => stored.get(key) ?? null,
      setItem: (key: string, value: string) => void stored.set(key, value),
    },
    crypto: { randomUUID: () => "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5" },
    navigator: { credentials: fakes_.credentials },
    PublicKeyCredential: function PublicKeyCredential() {},
    fetch: fakeFetch,
  };
  return { window, elements, replaced, assigned, fakes: fakes_ };
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
  await script.start(registered.window);
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
