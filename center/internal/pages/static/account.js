// SPDX-License-Identifier: AGPL-3.0-only
//
// The one script of the center's account pages (AF-CTR-03 A2). It runs the browser's WebAuthn ceremonies and calls the
// WebBrowserSession routes under /session/v1/web (Contracts web-browser.schema.json); the pages themselves are rendered by the
// center. Under the pages' content security policy (script-src 'self', require-trusted-types-for 'script', trusted-types 'none') it
// writes text only with textContent, sets no markup, no inline handler and no style attribute, and loads nothing from another origin.
//
// It is an ES module: the browser runs it from the page, and the repository's tests import its pure functions (the open-redirect
// rule for the return path, the base64url and WebAuthn conversions, and the sign-in, enrollment, step-up and sign-out flows, which
// take their transport and credential store as arguments).

const BROWSER = "/session/v1/web";
const ACCOUNT = "/account";
const PRODUCT = "arcforges-web";
const PLATFORM = "web";
const APP_VERSION = "pages-1";
const INSTALLATION_KEY = "af.installation";
const PASSKEY_TIMEOUT_MS = 300000;

/** The longest return path the sign-in page follows. */
const MAX_RETURN_PATH = 512;

/** The texts of the refusals the routes answer, by ArcError code; the center never sends text to show. */
const ERROR_TEXT = {
  invalid_argument: "Some of the information was not accepted. Check it and try again.",
  invalid_cursor: "The list position is not valid. Open the list again.",
  unauthenticated: "That did not work. Check the details and try again.",
  token_expired: "Your session has ended. Sign in again.",
  credential_revoked: "Your session has ended. Sign in again.",
  step_up_required: "This change needs a passkey check first. Try again.",
  permission_denied: "This is not allowed.",
  code_reused: "That step was already used. Start again.",
  already_exists: "That passkey is already registered.",
  command_id_reused: "That request was already used for something else. Try again.",
  revision_conflict: "This item changed meanwhile. Reload the page and retry.",
  not_found: "That item no longer exists.",
  invalid_state: "The account's state does not allow this change.",
  expired: "This step took too long. Start again.",
  not_activated: "This page is not available.",
  rate_limited: "Too many attempts. Wait a little and try again.",
  overloaded: "The service is busy. Try again in a moment.",
  internal: "Something went wrong on our side. Try again in a moment.",
};

const CANCELLED_TEXT = "The passkey prompt was closed. Try again when you are ready.";
const UNSUPPORTED_TEXT = "This browser cannot use passkeys.";
const GENERIC_TEXT = "The request could not be completed. Try again in a moment.";
const NETWORK_TEXT = "The center could not be reached. Check the connection and try again.";

/** An error reply of a route (or a failure to reach it): its HTTP status and ArcError code. */
export class ApiError extends Error {
  constructor(status, code) {
    super(`The request failed with ${status}${code ? ` (${code})` : ""}.`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** The text to show for a failure of a flow: a refusal by its code, a cancelled prompt, a browser without passkeys. */
export function errorText(error) {
  if (error instanceof ApiError) return ERROR_TEXT[error.code] ?? GENERIC_TEXT;
  const name = error && typeof error === "object" ? error.name : "";
  if (name === "NotAllowedError" || name === "AbortError") return CANCELLED_TEXT;
  if (name === "NotSupportedError" || name === "SecurityError") return UNSUPPORTED_TEXT;
  if (name === "InvalidStateError") return ERROR_TEXT.already_exists;
  if (name === "TypeError") return NETWORK_TEXT;
  return GENERIC_TEXT;
}

// ---------------------------------------------------------------------------------------------------------------------------
// base64url (RFC 4648 section 5, unpadded), the encoding of every byte value in the routes' JSON

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function encodeBase64Url(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let text = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const chunk = (bytes[index] << 16) | ((bytes[index + 1] ?? 0) << 8) | (bytes[index + 2] ?? 0);
    text += ALPHABET[(chunk >> 18) & 63] + ALPHABET[(chunk >> 12) & 63];
    if (index + 1 < bytes.length) text += ALPHABET[(chunk >> 6) & 63];
    if (index + 2 < bytes.length) text += ALPHABET[chunk & 63];
  }
  return text;
}

export function decodeBase64Url(text) {
  if (typeof text !== "string" || text.length % 4 === 1) throw new TypeError("Not base64url text.");
  const values = [];
  for (const character of text) {
    const value = ALPHABET.indexOf(character);
    if (value < 0) throw new TypeError("Not base64url text.");
    values.push(value);
  }
  const bytes = new Uint8Array(Math.floor((values.length * 6) / 8));
  let position = 0;
  for (let index = 0; index < values.length; index += 4) {
    const chunk =
      (values[index] << 18) |
      ((values[index + 1] ?? 0) << 12) |
      ((values[index + 2] ?? 0) << 6) |
      (values[index + 3] ?? 0);
    if (position < bytes.length) bytes[position++] = (chunk >> 16) & 255;
    if (position < bytes.length) bytes[position++] = (chunk >> 8) & 255;
    if (position < bytes.length) bytes[position++] = chunk & 255;
  }
  return bytes;
}

// ---------------------------------------------------------------------------------------------------------------------------
// The return path (DC-13): the sign-in page returns to the page that sent the visitor there, which it reads from the URL's
// fragment (#return=<percent-encoded path>). A fragment is never sent to a server and any page can put anything in it, so the path
// is validated here: only a path of this origin is followed.

/**
 * The same-origin path in a return value, or null. A return value is followed only when it is a path: one slash and then not a slash
 * or a backslash (those start a network-path reference), no control characters, spaces or backslashes, a bounded length and, parsed
 * against the origin, still this origin. The path is returned as the parser normalised it, without a fragment.
 */
export function safeReturnPath(value, origin) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_RETURN_PATH)
    return null;
  if (value[0] !== "/" || value[1] === "/" || value[1] === "\\") return null;
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code <= 0x20 || code === 0x7f || character === "\\") return null;
  }
  let parsed;
  try {
    parsed = new URL(value, origin);
  } catch {
    return null;
  }
  if (
    parsed.origin !== origin ||
    !parsed.pathname.startsWith("/") ||
    parsed.pathname.startsWith("//")
  )
    return null;
  return parsed.pathname + parsed.search;
}

/** The values of a URL fragment of the form #name=value&name=value (percent-decoded); unknown or malformed parts are ignored. */
export function parseFragment(hash) {
  const result = {};
  const text = typeof hash === "string" && hash.startsWith("#") ? hash.slice(1) : "";
  for (const part of text.split("&")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    try {
      result[part.slice(0, separator)] = decodeURIComponent(part.slice(separator + 1));
    } catch {
      // A part that does not decode is ignored.
    }
  }
  return result;
}

// ---------------------------------------------------------------------------------------------------------------------------
// WebAuthn options and results

/** The PublicKeyCredentialRequestOptions of a WebBrowserAuthChallenge (sign-in and step-up). */
export function requestOptions(challenge) {
  const options = challenge.options ?? {};
  const result = {
    challenge: decodeBase64Url(challenge.challenge),
    rpId: options.rpId ?? challenge.rpId,
    userVerification: "required",
    timeout: PASSKEY_TIMEOUT_MS,
  };
  if (Array.isArray(options.allowedCredentials) && options.allowedCredentials.length > 0) {
    result.allowCredentials = options.allowedCredentials.map((id) => ({
      type: "public-key",
      id: decodeBase64Url(id),
    }));
  }
  return result;
}

/** The PublicKeyCredentialCreationOptions of a WebBrowserAuthChallenge: ES256 only, a discoverable credential, attestation none. */
export function creationOptions(challenge, accountName) {
  const options = challenge.options ?? {};
  return {
    rp: { id: options.rpId ?? challenge.rpId, name: "ArcForges" },
    user: { id: decodeBase64Url(options.userHandle), name: accountName, displayName: accountName },
    challenge: decodeBase64Url(challenge.challenge),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    },
    attestation: "none",
    excludeCredentials: (options.excludedCredentials ?? []).map((id) => ({
      type: "public-key",
      id: decodeBase64Url(id),
    })),
    timeout: PASSKEY_TIMEOUT_MS,
  };
}

/** The WebBrowserWebAuthnAssertion of a PublicKeyCredential obtained with get(). */
export function assertionBody(credential) {
  const response = credential.response;
  const body = {
    credentialId: encodeBase64Url(credential.rawId),
    clientDataJson: encodeBase64Url(response.clientDataJSON),
    authenticatorData: encodeBase64Url(response.authenticatorData),
    signature: encodeBase64Url(response.signature),
  };
  if (response.userHandle && response.userHandle.byteLength > 0)
    body.userHandle = encodeBase64Url(response.userHandle);
  return body;
}

/** The fields of a PublicKeyCredential obtained with create(), as the document names them. */
export function creationBody(credential) {
  const response = credential.response;
  const transports = typeof response.getTransports === "function" ? response.getTransports() : [];
  return {
    credentialId: encodeBase64Url(credential.rawId),
    clientDataJson: encodeBase64Url(response.clientDataJSON),
    attestationObject: encodeBase64Url(response.attestationObject),
    transports: transports.filter((name) => /^[A-Za-z0-9._:/-]{1,128}$/.test(name)).slice(0, 8),
  };
}

// ---------------------------------------------------------------------------------------------------------------------------
// The installation claim: the browser keeps one random UUID in its local storage and states it with every sign-in, so the same
// browser is the same device in the account's lists (a claim that belongs to another account gets new rows on the center).

export function newInstallationId(random) {
  return random.randomUUID();
}

/** The browser's WebBrowserInstallationClaim; the UUID is created once and kept when the storage allows it. */
export function installationClaim(storage, random) {
  let installationId = null;
  try {
    const stored = storage?.getItem(INSTALLATION_KEY) ?? null;
    if (
      stored &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(stored) &&
      stored !== "00000000-0000-0000-0000-000000000000"
    ) {
      installationId = stored;
    }
  } catch {
    // A storage that cannot be read gives the page a new claim.
  }
  if (!installationId) {
    installationId = newInstallationId(random);
    try {
      storage?.setItem(INSTALLATION_KEY, installationId);
    } catch {
      // A storage that cannot be written leaves the claim for this page load only.
    }
  }
  return { installationId, product: PRODUCT, platform: PLATFORM, appVersion: APP_VERSION };
}

// ---------------------------------------------------------------------------------------------------------------------------
// The transport: the WebBrowserSession routes as same-origin JSON calls

/** A transport to the routes below a base path; fetchImpl is the browser's fetch. */
export function createApi(base, fetchImpl) {
  let csrf = null;
  const call = async (method, path, body) => {
    const headers = { Accept: "application/json" };
    const init = {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "same-origin",
    };
    if (method === "POST") {
      if (csrf) headers["X-AF-CSRF"] = csrf;
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
    }
    let response;
    try {
      response = await fetchImpl(`${base}${path}`, init);
    } catch (error) {
      throw error instanceof TypeError ? error : new TypeError("The center could not be reached.");
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok) throw new ApiError(response.status, payload?.error?.code ?? "");
    return payload;
  };
  return {
    /** Reads who is signed in and the CSRF token the POSTs carry (the session's, or the origin's before there is a session). */
    async bootstrap() {
      const reply = await call("GET", `${BROWSER}/bootstrap`);
      csrf = reply.csrfToken;
      return reply;
    },
    /** Uses a token the page already holds (the forms carry the session's). */
    useToken(token) {
      csrf = token;
    },
    post: (path, body) => call("POST", `${BROWSER}${path}`, body),
  };
}

// ---------------------------------------------------------------------------------------------------------------------------
// The flows. Each takes the transport (api), the credential store (credentials: navigator.credentials) and what it needs; a
// refusal or a cancelled prompt is a rejected promise whose text is errorText(error).

/** Signs in with a passkey (authentication begin, the browser's get(), authentication complete). */
export async function signIn({ api, credentials, claim }) {
  const challenge = await api.post("/authentication/begin", {
    method: "passkey",
    purpose: "authenticate",
    installation: claim,
  });
  const credential = await credentials.get({ publicKey: requestOptions(challenge) });
  if (!credential) throw new DOMException("No credential.", "NotAllowedError");
  return api.post("/authentication/complete", {
    flowId: challenge.flowId,
    proof: { passkey: assertionBody(credential) },
  });
}

/** Creates the owner account (enrollment: begin, the browser's create(), enrollment complete with the one-time token). */
export async function enroll({ api, credentials, claim, token, displayName }) {
  const challenge = await api.post("/authentication/begin", {
    method: "passkey",
    purpose: "enroll",
    installation: claim,
  });
  const credential = await credentials.create({
    publicKey: creationOptions(challenge, displayName),
  });
  if (!credential) throw new DOMException("No credential.", "NotAllowedError");
  return api.post("/enrollment/complete", {
    flowId: challenge.flowId,
    proof: { localCode: token },
    credential: { passkey: creationBody(credential) },
    profile: { displayName },
  });
}

/** Proves a step-up for an operation class and target (step-up begin, get(), step-up complete); the evidence is single use. */
export async function stepUp({ api, credentials, operationClass, targetHash }) {
  const challenge = await api.post("/step-up/begin", {
    operationClass,
    method: "passkey",
    targetHash,
  });
  const credential = await credentials.get({ publicKey: requestOptions(challenge) });
  if (!credential) throw new DOMException("No credential.", "NotAllowedError");
  return api.post("/step-up/complete", {
    flowId: challenge.flowId,
    proof: { passkey: assertionBody(credential) },
  });
}

/** Ends this browser's session. */
export function signOut({ api }) {
  return api.post("/logout");
}

// ---------------------------------------------------------------------------------------------------------------------------
// The pages (browser only)

function showError(document, text) {
  const summary = document.getElementById("error-summary");
  const message = document.getElementById("error-text");
  if (!summary || !message) return;
  message.textContent = text;
  summary.hidden = false;
  summary.focus();
}

function clearError(document) {
  const summary = document.getElementById("error-summary");
  if (summary) summary.hidden = true;
}

function setStatus(document, text) {
  const status = document.getElementById("status");
  if (status) status.textContent = text;
}

function passkeysSupported(window) {
  return typeof window.PublicKeyCredential === "function" && Boolean(window.navigator?.credentials);
}

function context(window) {
  const document = window.document;
  const base = document.body.dataset.base ?? "";
  const api = createApi(base, window.fetch.bind(window));
  return { window, document, base, api, credentials: window.navigator.credentials };
}

/** Runs a flow behind a button: disabled and announced while it runs, its failure shown in the error summary. */
async function guarded(page, button, working, run) {
  clearError(page.document);
  button.disabled = true;
  setStatus(page.document, working);
  try {
    await run();
  } catch (error) {
    setStatus(page.document, "");
    showError(page.document, errorText(error));
    button.disabled = false;
  }
}

function go(page, path) {
  page.window.location.assign(path);
}

async function signInPage(page) {
  const button = page.document.getElementById("sign-in");
  const signedIn = page.document.getElementById("signed-in");
  if (!button) return;
  if (!passkeysSupported(page.window)) {
    showError(page.document, UNSUPPORTED_TEXT);
    return;
  }
  const origin = page.window.location.origin;
  const target =
    safeReturnPath(parseFragment(page.window.location.hash).return, origin) ??
    `${page.base}${ACCOUNT}/passkeys`;
  try {
    const state = await page.api.bootstrap();
    if (state.authenticated && signedIn) {
      signedIn.hidden = false;
      const link = signedIn.querySelector("a");
      if (link) link.setAttribute("href", target);
    }
  } catch (error) {
    showError(page.document, errorText(error));
    return;
  }
  const claim = installationClaim(page.window.localStorage, page.window.crypto);
  button.disabled = false;
  button.addEventListener("click", () =>
    guarded(page, button, "Waiting for your passkey.", async () => {
      await signIn({ api: page.api, credentials: page.credentials, claim });
      go(page, target);
    }),
  );
}

async function bootstrapPage(page) {
  const button = page.document.getElementById("create");
  const tokenField = page.document.getElementById("token");
  const nameField = page.document.getElementById("display-name");
  if (!button || !tokenField || !nameField) return;
  // The one-time token may arrive in the fragment (#token=...). It is read once and removed from the address at once (SEC-09), so
  // it is neither in the history entry nor in the next navigation; the field holds it.
  const fragment = parseFragment(page.window.location.hash);
  if (typeof fragment.token === "string") {
    tokenField.value = fragment.token;
    page.window.history.replaceState(
      null,
      "",
      page.window.location.pathname + page.window.location.search,
    );
  }
  if (!passkeysSupported(page.window)) {
    showError(page.document, UNSUPPORTED_TEXT);
    return;
  }
  try {
    await page.api.bootstrap();
  } catch (error) {
    showError(page.document, errorText(error));
    return;
  }
  const claim = installationClaim(page.window.localStorage, page.window.crypto);
  button.disabled = false;
  const run = () =>
    guarded(page, button, "Waiting for your passkey.", async () => {
      const token = tokenField.value.trim();
      const displayName = nameField.value.trim();
      if (!token || !displayName) {
        throw new ApiError(400, "invalid_argument");
      }
      await enroll({ api: page.api, credentials: page.credentials, claim, token, displayName });
      tokenField.value = "";
      go(page, `${page.base}${ACCOUNT}/passkeys`);
    });
  button.addEventListener("click", run);
  for (const field of [tokenField, nameField]) {
    field.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !button.disabled) run();
    });
  }
}

async function signOutPage(page) {
  const button = page.document.getElementById("sign-out");
  if (!button) return;
  button.disabled = false;
  button.addEventListener("click", () =>
    guarded(page, button, "Signing out.", async () => {
      await page.api.bootstrap();
      await signOut({ api: page.api });
      go(page, `${page.base}${ACCOUNT}/sign-in`);
    }),
  );
}

/** A form that needs a fresh step-up proves it first and is then submitted as it is. */
function stepUpForms(page) {
  for (const form of page.document.querySelectorAll("form[data-step-up-class]")) {
    form.addEventListener("submit", (event) => {
      if (form.dataset.stepUpDone === "1") return;
      event.preventDefault();
      const buttons = form.querySelectorAll("button");
      for (const button of buttons) button.disabled = true;
      clearError(page.document);
      setStatus(page.document, "Waiting for your passkey.");
      page.api.useToken(form.elements.csrf?.value ?? "");
      stepUp({
        api: page.api,
        credentials: page.credentials,
        operationClass: form.dataset.stepUpClass,
        targetHash: form.dataset.stepUpTarget,
      })
        .then(() => {
          form.dataset.stepUpDone = "1";
          form.submit();
        })
        .catch((error) => {
          setStatus(page.document, "");
          showError(page.document, errorText(error));
          for (const button of buttons) button.disabled = false;
        });
    });
  }
}

/** The page of a passkey being created: its options are in the form's attributes (the page has no inline script). */
function registerPage(page) {
  const form = page.document.getElementById("register");
  const button = page.document.getElementById("create-passkey");
  if (!form || !button) return;
  if (!passkeysSupported(page.window)) {
    showError(page.document, UNSUPPORTED_TEXT);
    button.disabled = true;
    return;
  }
  const data = form.dataset;
  const challenge = {
    challenge: data.challenge,
    rpId: data.rpId,
    options: {
      rpId: data.rpId,
      userHandle: data.userHandle,
      excludedCredentials: data.excluded ? data.excluded.split(",") : [],
    },
  };
  button.addEventListener("click", () =>
    guarded(page, button, "Waiting for your passkey.", async () => {
      const credential = await page.credentials.create({
        publicKey: creationOptions(challenge, data.accountName || "ArcForges account"),
      });
      if (!credential) throw new DOMException("No credential.", "NotAllowedError");
      const body = creationBody(credential);
      form.elements.credential_id.value = body.credentialId;
      form.elements.client_data_json.value = body.clientDataJson;
      form.elements.attestation_object.value = body.attestationObject;
      form.elements.transports.value = body.transports.join(",");
      form.submit();
    }),
  );
}

/** Starts the script of the page the document is: pages name themselves in the body's data-page attribute. */
export function start(window) {
  const page = context(window);
  const name = page.document.body.dataset.page;
  const heading = page.document.getElementById("heading");
  const summary = page.document.getElementById("error-summary");
  if (summary && !summary.hidden) summary.focus();
  else if (heading) heading.focus();
  switch (name) {
    case "sign-in":
      return signInPage(page);
    case "bootstrap":
      return bootstrapPage(page);
    case "sign-out":
      return signOutPage(page);
    case "register":
      return registerPage(page);
    case "passkeys":
    case "sessions":
    case "devices":
      return stepUpForms(page);
    default:
      return undefined;
  }
}

if (typeof document !== "undefined" && typeof window !== "undefined") start(window);
