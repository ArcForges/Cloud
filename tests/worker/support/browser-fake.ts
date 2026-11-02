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
// The operations pages (the operator grant) are as strict as the center's: only an operator reaches them, the step-up evidence is
// single use and bound to the target of the review it was proved for, a repeated command is answered by its stored result before any
// evidence is looked at (and only for the very same request), every 4xx document is logged by the browser as a console error, and
// a request the edge limiter refused (429) never reaches the center. Each FakeOptions switch below breaks one of these guards, so
// that a test can show the script notices.
// It is no evidence about the real center or a real browser; it checks the script's logic.
import { createHash } from "node:crypto";
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
  refusedStatus,
} from "../../../eng/verification/browser/driver.ts";
import { fixtureFeatures } from "../../../eng/verification/browser/flow.ts";
import {
  confirmFields,
  forms,
  operations,
  pages,
  persistBefore,
  selectors,
  sessionBootstrap,
  stepUpAttribute,
} from "../../../eng/verification/browser/selectors.ts";

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
  // ---- the operations surface
  /** The surface is not enabled: the Worker answers its plain 404 to every operations route. */
  operationsOff?: boolean;
  /** The signed-in account is no operator: the center audits the refusal and answers 403 on all three routes. */
  notOperator?: boolean;
  /** The center has no plan catalogue: the operations routes answer 400. */
  noCatalogue?: boolean;
  /**
   * The edge limiter answers the navigations to the operator form (GET, with or without a session) with a 429 (the center never
   * sees them): the first `skip` navigations pass, the next `times` are limited. The run's navigations to it are, in order, those of
   * the steps 1 and 2 (without a session), 3 to 6 (the form) and 7 (after the sign-out).
   */
  limitOperatorForm?: { skip: number; times: number; retryAfter: number };
  /** The edge limiter answers the next `times` POSTs to this route (a path below the base) with a 429 after `skip` have passed. */
  limitOperatorPost?: { route: string; skip: number; times: number; retryAfter: number };
  /** The sign-in page ignores the return fragment and always lands on the passkeys page. */
  signInIgnoresReturn?: boolean;
  /** The browser does not report the 4xx documents as console errors (the script's expectation of one is never met). */
  silentRefusals?: boolean;
  // Guard breakers of the center (each must be noticed by the script):
  /** The step-up evidence is not bound to the target it was proved for. */
  evidenceIgnoresTarget?: boolean;
  /** The step-up evidence is not consumed by the grant. */
  evidenceReusable?: boolean;
  /** A repeated command is not recognized: it is processed again. */
  noReplay?: boolean;
  /** A replay answers another entitlement version than the grant it repeats. */
  replayDiffers?: boolean;
  /** The grant is written without any step-up evidence. */
  noEvidenceNeeded?: boolean;
  /** The form lists only these features (a catalogue other than the development fixtures). */
  catalogue?: string[];
}

/** One step-up proof of an operator class: the evidence the center keeps until a write consumes it. */
interface Evidence {
  operationClass: string;
  target: string;
  userId: string;
  session: string;
  used: boolean;
}

interface Grant {
  account: string;
  features: string[];
  expiresAt: number;
  sourceRef: string;
  reason: string;
  termId: string;
  version: number;
  command: string;
  digest: string;
}

/** What an operations route answers: a document of the center. */
interface OpsReply {
  status: number;
  kind: "ops-review" | "ops-done" | "ops-error";
  heading: string;
  error?: string;
  terms?: string[];
  values?: string[];
  target?: string;
  hidden?: [string, string][];
}

export const operatorStepUpClass = "center.operatorGrant";
const uuidLike = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const opsRefusals: Record<string, string> = {
  stepUp: "This change needs a passkey check first. Go back and try again.",
  notAllowed: "This is not allowed.",
};

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
  // ---- the operations surface
  /** The one account of the environment: the bootstrap owner, who counts as operator. */
  readonly userId = "7b0c1f3e-5a42-4c1d-9e6a-3d2b8f4a1c90";
  readonly evidence: Evidence[] = [];
  readonly grants: Grant[] = [];
  /** The audit events of the operations routes, by outcome. */
  readonly audit: string[] = [];
  /** The commands the center has executed, by command id: the stored result a repeat is answered with. */
  readonly commands = new Map<string, Grant>();
  version = 0;
  private reviews = 0;
  private operatorForms = 0;
  private operatorPosts = new Map<string, number>();

  constructor(baseUrl: string, options: FakeOptions) {
    const url = new URL(baseUrl);
    this.basePath = url.pathname.replace(/\/$/u, "");
    this.host = url.host;
    this.options = options;
  }

  instant(): string {
    return new Date(this.clockSeconds * 1000).toISOString();
  }

  /** The catalogue the operator form offers (the development fixtures unless a test says otherwise). */
  features(): readonly string[] {
    return this.options.catalogue ?? fixtureFeatures;
  }

  csrf(handle: string): string {
    return Buffer.from(`csrf-${handle}`.padEnd(32, "c")).toString("base64url").slice(0, 43);
  }

  /** The edge limiter in front of the operator form: true when this navigation is answered 429. */
  limitsForm(): number | undefined {
    const limit = this.options.limitOperatorForm;
    this.operatorForms += 1;
    return limit !== undefined &&
      this.operatorForms > limit.skip &&
      this.operatorForms <= limit.skip + limit.times
      ? limit.retryAfter
      : undefined;
  }

  /** The edge limiter in front of a POST route: the Retry-After when this one is answered 429. */
  limitsPost(route: string): number | undefined {
    const limit = this.options.limitOperatorPost;
    if (limit === undefined || limit.route !== route) return undefined;
    const seen = (this.operatorPosts.get(route) ?? 0) + 1;
    this.operatorPosts.set(route, seen);
    return seen > limit.skip && seen <= limit.skip + limit.times ? limit.retryAfter : undefined;
  }

  /** The hash a review names and a confirmation proves: the request itself, so that nothing else can be confirmed by it. */
  target(request: {
    account: string;
    features: readonly string[];
    reason: string;
    expiresAt: number;
    sourceRef: string;
    selfApproval: string;
  }): string {
    return createHash("sha256")
      .update(
        JSON.stringify([
          this.userId,
          request.account,
          [...request.features].sort(),
          request.reason,
          request.expiresAt,
          request.sourceRef,
          request.selfApproval,
        ]),
      )
      .digest("hex");
  }

  private refusal(status: number, heading: string, error: string, audit?: string): OpsReply {
    if (audit !== undefined) this.audit.push(audit);
    return { status, kind: "ops-error", heading, error };
  }

  /** The common start of the three routes: who may reach them (the surface, the catalogue and the operator role). */
  operatorGate(): OpsReply | undefined {
    if (this.options.operationsOff === true) return { status: 404, kind: "ops-error", heading: "" };
    if (this.options.notOperator === true)
      return this.refusal(
        403,
        "This is not allowed",
        opsRefusals.notAllowed ?? "",
        "refused/permission_denied",
      );
    if (this.options.noCatalogue === true)
      return this.refusal(
        400,
        "The request was not accepted",
        "This center has no plan catalogue.",
      );
    return undefined;
  }

  /** The request form's rules, which the review and the grant both apply (the review writes nothing). */
  private checkRequest(request: {
    account: string;
    features: readonly string[];
    reason: string;
    expiresAt: number;
    sourceRef: string;
    selfApproval: string;
  }): OpsReply | undefined {
    const bad = (error: string): OpsReply =>
      this.refusal(400, "The request was not accepted", error);
    if (request.account !== this.userId) return bad("That account does not exist.");
    if (request.features.length === 0) return bad("Choose at least one feature.");
    if (!request.features.every((key) => this.features().includes(key)))
      return bad("That feature is not in the catalogue.");
    if (request.reason === "" || request.reason.length > 512) return bad("The reason is required.");
    if (!/^[A-Za-z0-9._:-]{1,96}$/u.test(request.sourceRef))
      return bad("The source reference is not valid.");
    if (request.selfApproval === "" || request.selfApproval.length > 512)
      return bad("A grant to your own account needs a justification.");
    const now = this.clockSeconds * 1_000_000;
    if (request.expiresAt <= now || request.expiresAt > now + 400 * 86_400 * 1_000_000)
      return bad("The end of the grant is out of range.");
    if (this.grants.some((grant) => grant.sourceRef === request.sourceRef))
      return bad("That source reference was already used.");
    return undefined;
  }

  /** POST /operations/grant/review: the request, checked as a grant would, shown with the target to prove. Nothing is written. */
  operatorReview(
    session: string,
    form: Map<string, string>,
    checked: ReadonlySet<string>,
  ): OpsReply {
    const gate = this.operatorGate();
    if (gate !== undefined) return gate;
    const days = form.get(operations.days) ?? "";
    if (!/^[0-9]+$/u.test(days) || Number(days) < 1 || Number(days) > 400)
      return this.refusal(
        400,
        "The request was not accepted",
        "The number of days is out of range.",
      );
    this.reviews += 1;
    // The instant is the center's clock plus the days; two reviews never share one, so the target moves with each.
    const request = {
      account: (form.get(operations.account) ?? "").trim(),
      features: this.features().filter((key) => checked.has(key)),
      reason: form.get(operations.reason) ?? "",
      sourceRef: form.get(operations.sourceRef) ?? "",
      selfApproval: form.get(operations.selfApproval) ?? "",
      expiresAt: this.clockSeconds * 1_000_000 + this.reviews + Number(days) * 86_400 * 1_000_000,
    };
    const refused = this.checkRequest(request);
    if (refused !== undefined) return refused;
    const hidden: [string, string][] = [
      ["csrf", this.csrf(session)],
      ["command_id", crypto.randomUUID()],
      ["account", request.account],
      ["features", request.features.join(",")],
      ["reason", request.reason],
      ["source_ref", request.sourceRef],
      ["self_approval", request.selfApproval],
      ["expires_at", String(request.expiresAt)],
    ];
    return {
      status: 200,
      kind: "ops-review",
      heading: "Review the operator grant",
      target: this.target(request),
      hidden,
      terms: ["Account", "Features", "Ends", "Reason", "Source reference", "Justification"],
      values: [
        `${request.account} (your own account)`,
        request.features.join(", "),
        new Date(request.expiresAt / 1000).toISOString(),
        request.reason,
        request.sourceRef,
        request.selfApproval,
      ],
    };
  }

  private write(
    request: {
      account: string;
      features: readonly string[];
      reason: string;
      expiresAt: number;
      sourceRef: string;
    },
    command: string,
    digest = "",
  ): Grant {
    this.version += 1;
    const grant: Grant = {
      account: request.account,
      features: [...request.features],
      expiresAt: request.expiresAt,
      sourceRef: request.sourceRef,
      reason: request.reason,
      termId: crypto.randomUUID(),
      version: this.version,
      command,
      digest,
    };
    this.grants.push(grant);
    this.commands.set(command, grant);
    return grant;
  }

  private done(grant: Grant, replayed: boolean): OpsReply {
    const shown =
      replayed && this.options.replayDiffers === true ? grant.version + 1 : grant.version;
    return {
      status: 200,
      kind: "ops-done",
      heading: "Operator grant issued",
      error: replayed
        ? "This grant had already been issued; nothing new was written."
        : "The grant was written.",
      terms: ["Account", "Features", "Ends", "Compensation term", "Entitlement version"],
      values: [
        grant.account,
        grant.features.join(", "),
        new Date(grant.expiresAt / 1000).toISOString(),
        grant.termId,
        String(shown),
      ],
    };
  }

  /** POST /operations/grant/confirm: the grant, with the evidence the page proved consumed in the same step. */
  operatorConfirm(session: string, userId: string, fields: Map<string, string>): OpsReply {
    const gate = this.operatorGate();
    if (gate !== undefined) return gate;
    const names = [...fields.keys()];
    // The form carries all eight fields and no other; the request token is the session's.
    if (
      confirmFields.some((name) => !names.includes(name)) ||
      names.length !== confirmFields.length
    )
      return this.refusal(400, "The request was not accepted", "The form is incomplete.");
    if (fields.get("csrf") !== this.csrf(session))
      return this.refusal(403, "This is not allowed", "Reload the page and try again.");
    const command = fields.get("command_id") ?? "";
    if (!uuidLike.test(command))
      return this.refusal(400, "The request was not accepted", "The command is not valid.");
    const list = fields.get("features") ?? "";
    const request = {
      account: fields.get("account") ?? "",
      features: list === "" ? [] : list.split(","),
      reason: fields.get("reason") ?? "",
      sourceRef: fields.get("source_ref") ?? "",
      selfApproval: fields.get("self_approval") ?? "",
      expiresAt: Number(fields.get("expires_at")),
    };
    if (!Number.isSafeInteger(request.expiresAt))
      return this.refusal(
        400,
        "The request was not accepted",
        "The end of the grant is not valid.",
      );
    const digest = JSON.stringify([
      request.account,
      [...request.features].sort(),
      request.reason,
      request.expiresAt,
      request.sourceRef,
      request.selfApproval,
    ]);
    // A command that was executed is answered by its stored result BEFORE anything else is looked at (a replay needs no evidence),
    // but only for the very same request.
    const stored = this.options.noReplay === true ? undefined : this.commands.get(command);
    if (stored !== undefined) {
      if (stored.digest !== digest)
        return this.refusal(
          400,
          "The request was not accepted",
          "That command was already used for another request.",
        );
      return this.done(stored, true);
    }
    const target = this.target(request);
    if (this.options.noEvidenceNeeded !== true) {
      const proof = this.evidence.find(
        (item) =>
          !item.used &&
          item.operationClass === operatorStepUpClass &&
          item.userId === userId &&
          item.session === session &&
          (this.options.evidenceIgnoresTarget === true || item.target === target),
      );
      if (proof === undefined)
        return this.refusal(
          403,
          "This is not allowed",
          opsRefusals.stepUp ?? "",
          "refused/step_up_required",
        );
      if (this.options.evidenceReusable !== true) proof.used = true;
    }
    const refused = this.checkRequest(request);
    if (refused !== undefined) return refused;
    this.audit.push("issued");
    return this.done(this.write(request, command, digest), false);
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
      kind:
        | "sign-in"
        | "bootstrap"
        | "passkeys"
        | "sessions"
        | "devices"
        | "sign-out"
        | "register"
        | "ops-grant"
        | "ops-review"
        | "ops-done"
        | "ops-error"
        | "limited";
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
  // ---- the operations pages the tab shows now
  private latest: Navigation | null = null;
  private expectedRefusals: number[] = [];
  private opsReply: OpsReply | undefined;
  /** The request form's fields (by selector) and the feature boxes ticked; a new page of the form starts empty, as a browser's. */
  private form = new Map<string, string>();
  private ticked = new Set<string>();
  /** The hidden fields of the review page as the browser holds them (a script may change them before the form is submitted). */
  private hidden: [string, string][] = [];
  /** The posts the tab has sent to the operations routes, by route. */
  readonly operatorPosts: string[] = [];
  /** The statuses of the 4xx documents the browser reported as console errors, in order (used up by an expectation or not). */
  readonly refusalsSeen: number[] = [];

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
      [pages.operationsGrant]: "ops-grant",
    };
    const kind = kinds[suffix];
    if (kind === undefined) return { status: 404, headers: {} };
    const protectedPage =
      kind === "passkeys" || kind === "sessions" || kind === "devices" || kind === "ops-grant";
    if (kind === "ops-grant" && options.operationsOff === true)
      return this.serveOperations({ status: 404, kind: "ops-error", heading: "" }, url);
    if (kind === "ops-grant") {
      const limited = this.center.limitsForm();
      if (limited !== undefined) return this.limited(limited);
    }
    if (protectedPage && !this.session()) {
      this.currentUrl = `${target.origin}${this.path(pages.signIn)}${
        options.noReturnFragment ? "" : `#return=${encodeURIComponent(target.pathname)}`
      }`;
      this.page = { kind: "sign-in" };
    } else if (kind === "ops-grant") {
      // The form of an operator: a gate that refuses (the role, the catalogue) answers instead of the form.
      const gate = this.center.operatorGate();
      return this.serveOperations(
        gate ?? { status: 200, kind: "ops-error", heading: "" },
        url,
        gate === undefined,
      );
    } else {
      this.currentUrl = url;
      this.page = { kind };
    }
    if (options.problems?.length) this.seenProblems.push(...options.problems.splice(0));
    return this.document200();
  }

  /** The status and headers of a page the center serves (the generated security headers, unless a test removes one). */
  private document200(status = 200): Navigation {
    const headers: Record<string, string> = { ...pageSecurityHeaders };
    if (this.center.options.badHeader) delete headers[this.center.options.badHeader];
    const navigation = {
      status,
      headers: { ...headers, "content-type": "text/html; charset=utf-8" },
    };
    this.latest = navigation;
    return navigation;
  }

  /** The edge limiter answers 429 to a request of the tab: the center never sees it, and the browser logs the refused document. */
  private limited(retryAfter: number): Navigation {
    this.retryAfter = retryAfter;
    this.page = { kind: "limited" };
    this.report(429);
    const navigation = { status: 429, headers: {} };
    this.latest = navigation;
    return navigation;
  }

  /** Chromium logs a console error for every document the server refused; a step that expects one says so (Tab.expectRefusal). */
  private report(status: number): void {
    if (status < 400 || this.center.options.silentRefusals === true) return;
    this.refusalsSeen.push(status);
    const text = `console error: Failed to load resource: the server responded with a status of ${status} (${status === 403 ? "Forbidden" : "error"})`;
    const found = refusedStatus(text);
    const at = found === undefined ? -1 : this.expectedRefusals.indexOf(found);
    if (at >= 0) this.expectedRefusals.splice(at, 1);
    else this.seenProblems.push(text);
  }

  /** Shows what an operations route answered. `form` is true for the request form itself (a 200 with the form's fields empty). */
  private serveOperations(reply: OpsReply, url: string, form = false): Navigation {
    this.opsReply = reply;
    this.currentUrl = url;
    if (form) {
      this.page = { kind: "ops-grant" };
      this.form = new Map();
      this.ticked = new Set();
    } else this.page = { kind: reply.kind };
    if (reply.kind === "ops-review") this.hidden = (reply.hidden ?? []).map(([n, v]) => [n, v]);
    if (reply.kind === "ops-error") this.errorText = reply.error ?? "";
    else this.errorText = "";
    this.report(reply.status);
    if (reply.status === 404) {
      const navigation = { status: 404, headers: {} };
      this.latest = navigation;
      return navigation;
    }
    return this.document200(reply.status);
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

  private async stepUp(proof?: { operationClass: string; target: string }): Promise<void> {
    const record = this.session();
    if (!record || !this.handle) throw new Error("no session for a step-up");
    const { credential } = this.assertWith();
    await this.post(persistBefore.stepUp);
    this.center.assertion(credential.credentialId, credential.signCount);
    record.stepUps += 1;
    this.accepted(persistBefore.stepUp);
    // A step-up for an operator class is kept as evidence of that class and target, for one write to consume.
    if (proof !== undefined)
      this.center.evidence.push({
        ...proof,
        userId: this.center.userId,
        session: this.handle,
        used: false,
      });
  }

  /** A form POST to one of the operations routes, as the browser sends it: the edge, then the center. */
  private async postOperations(
    route: string,
    fields: readonly (readonly [string, string])[],
  ): Promise<void> {
    const handle = this.handle;
    const record = this.session();
    this.operatorPosts.push(route);
    await this.post(route);
    const retry = this.center.limitsPost(route);
    if (retry !== undefined) {
      this.limited(retry);
      return;
    }
    const url = `https://${this.center.host}${this.path(route)}`;
    // No session: the center does not know the visitor (a POST has no sign-in page to be sent to).
    if (!record || !handle) {
      this.serveOperations(
        {
          status: 403,
          kind: "ops-error",
          heading: "This is not allowed",
          error: "This is not allowed.",
        },
        url,
      );
      return;
    }
    const reply =
      route === forms.operationsReview
        ? this.center.operatorReview(handle, this.form, this.ticked)
        : this.center.operatorConfirm(handle, this.center.userId, new Map(fields));
    this.serveOperations(reply, url);
    if (reply.status === 200) this.accepted(route);
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
      const returnTo =
        back && center.options.signInIgnoresReturn !== true ? decodeURIComponent(back) : undefined;
      if (returnTo === this.path(pages.operationsGrant)) {
        // The sign-in page returns to the page it came from; the operator form is served as to any request.
        const gate = center.operatorGate();
        this.serveOperations(
          gate ?? { status: 200, kind: "ops-error", heading: "" },
          `https://${host}${returnTo}`,
          gate === undefined,
        );
        return;
      }
      this.currentUrl = `https://${host}${returnTo ?? this.path(pages.passkeys)}`;
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
    if (this.page.kind === "ops-grant") {
      const box = /^input\[name="feature-(.+)"\]$/u.exec(selector)?.[1];
      if (box !== undefined) {
        if (this.ticked.has(box)) this.ticked.delete(box);
        else this.ticked.add(box);
        return;
      }
      if (selector === operations.reviewSubmit) {
        await this.postOperations(forms.operationsReview, []);
        return;
      }
    }
    if (this.page.kind === "ops-review" && selector === operations.confirmSubmit) {
      // The page's script proves a passkey for the class and target the form names (the review's, not what a field holds now),
      // then submits the form as it stands.
      const target = this.opsReply?.target;
      if (target === undefined) throw new Error("no review to confirm");
      await this.stepUp({ operationClass: operatorStepUpClass, target });
      await this.postOperations(forms.operationsConfirm, this.hidden);
      return;
    }
    throw new Error(`nothing to click for ${selector} on ${this.page.kind}`);
  }

  async setValue(selector: string, value: string): Promise<void> {
    const field = /^form\[action\$="\/operations\/grant\/confirm"\] input\[name="(.+)"\]$/u.exec(
      selector,
    )?.[1];
    if (field !== undefined && this.page.kind === "ops-review") {
      const at = this.hidden.findIndex(([name]) => name === field);
      if (at < 0) throw new Error("No such field.");
      this.hidden[at] = [field, value];
      return;
    }
    if (this.page.kind === "ops-grant") {
      this.form.set(selector, value);
      return;
    }
    this.values.set(selector, value);
  }

  async fetchJson(pathname: string): Promise<{ status: number; body: unknown }> {
    const record = this.session();
    if (pathname !== `${this.center.basePath}${sessionBootstrap}`)
      return { status: 404, body: null };
    if (!record || !this.handle)
      return { status: 200, body: { csrfToken: "x".repeat(43), authenticated: false } };
    const csrfToken = this.center.csrf(this.handle);
    this.secretsSeen.push(csrfToken);
    return {
      status: 200,
      body: { csrfToken, authenticated: true, session: { userId: this.center.userId } },
    };
  }

  async submitForm(action: string, fields: readonly (readonly [string, string])[]): Promise<void> {
    if (this.page.kind === "none") throw new Error("There is no page to submit a form from.");
    const route = action.slice(this.center.basePath.length);
    if (route !== forms.operationsConfirm && route !== forms.operationsReview)
      throw new Error(`nothing to submit to ${action}`);
    await this.postOperations(route, fields);
  }

  document(): Navigation | null {
    return this.latest;
  }

  expectRefusal(status: number): void {
    if (!Number.isInteger(status) || status < 400 || status > 499)
      throw new Error("An expected refusal is a 4xx status.");
    this.expectedRefusals = [status];
  }

  refusalsPending(): number {
    return this.expectedRefusals.length;
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
    if (selector === operations.outcome)
      return this.page.kind === "ops-done" ? (this.opsReply?.error ?? null) : null;
    if (selector !== selectors.heading) return null;
    if (this.page.kind.startsWith("ops-") && this.page.kind !== "ops-grant")
      return this.opsReply?.heading || null;
    const headings: Record<string, string> = {
      "ops-grant": "Operator grant",
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
    if (selector === operations.terms || selector === operations.details) {
      const reply = this.opsReply;
      if (this.page.kind !== "ops-review" && this.page.kind !== "ops-done") return [];
      return (selector === operations.terms ? reply?.terms : reply?.values) ?? [];
    }
    if (selector === selectors.rowHeaders) return this.rowTexts();
    if (selector === selectors.passkeyLastUsed)
      return this.center.passkeys.map((item) =>
        item.lastUsed ? item.lastUsed.slice(0, 10) : "Never",
      );
    return [];
  }

  async attributes(selector: string, name: string): Promise<(string | null)[]> {
    if (selector === operations.featureBoxes && name === "name" && this.page.kind === "ops-grant")
      return [...this.center.features().map((key) => `feature-${key}`), "all"];
    if (this.page.kind === "ops-review") {
      if (selector === operations.confirmForm && name === stepUpAttribute)
        return [operatorStepUpClass];
      if (selector === operations.confirmForm && name === "data-step-up-target")
        return [this.opsReply?.target ?? null];
      if (selector === operations.confirmHidden && name === "name")
        return this.hidden.map(([field]) => field);
      if (selector === operations.confirmHidden && name === "value")
        return this.hidden.map(([, value]) => value);
    }
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
    if (selector === operations.confirmForm) return this.page.kind === "ops-review" ? 1 : 0;
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
      [operations.confirmForm]: "ops-review",
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
