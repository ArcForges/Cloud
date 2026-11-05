// SPDX-License-Identifier: AGPL-3.0-only
// What the acceptance script touches on the center's account pages. tests/worker/browser-acceptance.test.ts checks every id here
// against the center's own templates (center/internal/pages/templates), so a renamed element fails a test, not a live run.

/** The pages, as paths below the center's public base URL (https://proof.arcforges.com/api). */
export const pages = {
  signIn: "/account/sign-in",
  bootstrap: "/account/bootstrap",
  passkeys: "/account/passkeys",
  addPasskey: "/account/passkeys/add",
  sessions: "/account/sessions",
  devices: "/account/devices",
  signOut: "/account/sign-out",
  /** The operations surface's page (AF-CTR-03 B): a GET that needs a session of an operator. */
  operationsGrant: "/operations/grant",
} as const;

/** The POST-only routes of the operations page: the script submits their forms and never visits them. */
export const forms = {
  operationsReview: "/operations/grant/review",
  operationsConfirm: "/operations/grant/confirm",
} as const;

/** The JSON route that names the signed-in account (no account page lists the identifier, so the form field is filled from it): a GET from inside the page. */
export const sessionBootstrap = "/session/v1/web/bootstrap";

/** The JSON and form POSTs after which the saved credential is written before the request leaves the browser. */
export const persistBefore = {
  enrollment: "/session/v1/web/enrollment/complete",
  signIn: "/session/v1/web/authentication/complete",
  stepUp: "/session/v1/web/step-up/complete",
  newPasskey: "/account/passkeys/complete",
} as const;

export const ids = {
  heading: "heading",
  errorSummary: "error-summary",
  errorText: "error-text",
  status: "status",
  token: "token",
  displayName: "display-name",
  create: "create",
  signIn: "sign-in",
  signedIn: "signed-in",
  signOut: "sign-out",
  newPasskeyName: "display_name",
  createPasskey: "create-passkey",
  registerForm: "register",
} as const;

/** The elements of the operations pages (the templates operations-grant, operations-review and operations-done). */
export const operations = {
  account: "#account",
  days: "#expires_days",
  reason: "#reason",
  sourceRef: "#source_ref",
  selfApproval: "#self_approval",
  /** Every check box of the request form: one per feature of the catalogue, and "all" where the catalogue allows it. */
  featureBoxes: 'form[action$="/operations/grant/review"] fieldset input[type="checkbox"]',
  feature: (key: string) => `input[name="feature-${key}"]`,
  reviewSubmit: 'form[action$="/operations/grant/review"] button[type="submit"]',
  confirmForm: 'form[action$="/operations/grant/confirm"]',
  confirmSubmit: 'form[action$="/operations/grant/confirm"] button[type="submit"]',
  confirmHidden: 'form[action$="/operations/grant/confirm"] input[type="hidden"]',
  confirmField: (name: string) => `form[action$="/operations/grant/confirm"] input[name="${name}"]`,
  /** The sentence under the heading of the done page. */
  outcome: "#heading + p",
  /** The terms and details of the review and of the done page (one dl). */
  terms: "main dl dt",
  details: "main dl dd",
} as const;

/** The hidden fields of the confirmation form, in the order the template writes them. */
export const confirmFields = [
  "csrf",
  "command_id",
  "account",
  "features",
  "reason",
  "source_ref",
  "self_approval",
  "expires_at",
] as const;

export const selectors = {
  heading: `#${ids.heading}`,
  errorSummary: `#${ids.errorSummary}`,
  errorText: `#${ids.errorText}`,
  token: `#${ids.token}`,
  displayName: `#${ids.displayName}`,
  create: `#${ids.create}`,
  signIn: `#${ids.signIn}`,
  signOut: `#${ids.signOut}`,
  newPasskeyName: `#${ids.newPasskeyName}`,
  createPasskey: `#${ids.createPasskey}`,
  /** The button of the add-a-passkey form. */
  addPasskey: 'form[action$="/account/passkeys/add"] button[type="submit"]',
  /** The rows of the tables of passkeys, sessions and devices (one per item). */
  rows: "main table tbody tr",
  rowHeaders: "main table tbody tr th[scope=row]",
  /** A row's last-used cell of the passkeys table (the third column). */
  passkeyLastUsed: "main table tbody tr td:nth-child(3)",
  /** The End-session button of a session that is not this browser's. */
  endSession: 'form[action$="/account/sessions/revoke"] button',
  removePasskey: 'form[action$="/account/passkeys/remove"] button',
} as const;

/** The form attributes of the pages' step-up (the page's script proves a passkey before it submits the form). */
export const stepUpAttribute = "data-step-up-class";

/** The cookie of a session, and the rules the browser must have applied to it. */
export const sessionCookie = { name: "__Host-af_session", path: "/", sameSite: "Strict" } as const;

/**
 * The fleet surface's pages (AF-CTR-04 E3): the consent page of a node's browser sign-in, the activation page of its device-code
 * sign-in, their reviews and their results (the templates connect*, activate* and fleet-node).
 */
export const fleet = {
  connect: "/connect",
  activate: "/activate",
  connectReview: "/connect/review",
  activateReview: "/activate/review",
  codeField: "#user-code",
  continueButton: "#continue",
  nodeName: "#node-name",
  nodeSystem: "#node-system",
  nodeFingerprint: "#node-fingerprint",
  nodeOrigin: "#node-origin",
  nodeNameNote: "#node-name-note",
  tailField: "#fingerprint-tail",
  approve: '#approve button[type="submit"]',
  deny: '#deny button[type="submit"]',
  returnLink: "#return-link",
  /** The revoke button of the devices page's row of a device, by the device's name. */
  revokeDevice: (name: string) =>
    `tr:has(th bdi:text-is(${JSON.stringify(name)})) form[action$="/account/devices/revoke"] button`,
} as const;

/**
 * The mobile surface's pages (AF-CTR-04 part M): the authorization page of the mobile app's native authorization, its review, its
 * done page and the fixed callback page at the root of the host (the templates mobile-authorize* and app-callback).
 */
export const mobile = {
  authorize: "/mobile/authorize",
  review: "/mobile/authorize/review",
  /** The apex path of the release App Link, at the root of the host (not below the public base URL). */
  appCallback: "/app/callback",
  platform: "#mobile-platform",
  version: "#mobile-version",
  claimNote: "#mobile-claim-note",
  approve: '#approve button[type="submit"]',
  deny: '#deny button[type="submit"]',
  appLink: "#app-link",
} as const;
