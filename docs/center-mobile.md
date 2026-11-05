# Mobile native authorization on the center

The ArcForges Android app signs in to an account through the center's own authorization page in a Custom Tab and redeems a
one-use code bound to the flow (AF-CTR-04 part M; Contracts `public/http/v1/mobile-native.schema.json`, MobileNativeAuth v1, at the
cohort `1.0.0-ci.430.1`, commit `5873dc2`; ArcForges-Design android.md; RFC 7636, RFC 8252 sections 7.1, 7.2 and 8, RFC 9207,
RFC 9700 section 4.4). It mirrors the browser node sign-in ([center fleet](center-fleet.md#browser-sign-in)) without a node key
proof, with the installation claim in place of the node and with a binding compare.

Evidence in this repository: **REAL** center, PostgreSQL, routes and Worker tables (the integration tests run the composed center
against a real PostgreSQL); **MOCKED** app (MobileProbe, `center/internal/mobiletest` and `center/cmd/mobile-probe`) and **MOCKED**
authenticator (the virtual authenticator); **NOT PROVEN** here: App Link verification on a device, the same-host hand-off from a
Custom Tab to the app, the fragment in the intent, a real passkey in Chrome for Android, the release app identity (AF-AND-01,
AR-08, H-02).

## Surface

`mobile` needs `identity` and `pages` and a public base URL that is a MobileNativeAuth issuer (https with a host of lower-case
letters, digits, hyphens and dots, or http for a loopback host; at most 453 characters). A list that names it without them, or with
a base URL that is no issuer, refuses to start; the self-hosted default enables it and leaves it out for such a base URL (and turns
it off with every other surface when its base URL cannot be a relying party). Production keeps it off (`FLAGSHIP_SURFACES` empty, no
route change); the acceptance environment (`proof`) enables it for H3. While it is off every row below is 404: the Worker's
plain-text reply of a path it does not know (`Unknown API method.`) and the center's empty 404 (the contract's `STATE/not_activated`
of begin and token is answered as that 404, as for the fleet pages).

## Routes

| Route                                     | Kind        | Credential       | Rules                                                                    |
| ----------------------------------------- | ----------- | ---------------- | ------------------------------------------------------------------------ |
| `POST /session/v1/mobile/begin`           | native JSON | none (anonymous) | exactly `application/json`, no cookie (refused), no Origin or CSRF, 4096 |
| `POST /session/v1/mobile/token`           | native JSON | the code         | as begin; the reply at most 65536 bytes                                  |
| `GET /mobile/authorize`                   | page        | none (script)    | static; the script reads `#flow=`, drops the fragment, asks bootstrap    |
| `POST /mobile/authorize/review`           | form        | cookie session   | exact Origin, the session's CSRF token                                   |
| `POST /mobile/authorize/decision`         | form        | cookie session   | as review; an approval consumes the step-up evidence                     |
| `GET /.well-known/assetlinks.json` (apex) | apex        | none             | the configured statement list, exactly; no redirect, no cookie           |
| `GET /app/callback` (apex)                | apex        | none             | a fixed page; its script only strips the fragment                        |

The first five are below the public base URL (`/api/...` on the hosted deployments); the two apex routes are at the root of the
host, mapped by the hosted Worker to the same center paths ([cloud ingress](cloud-ingress.md#mobile-rows-af-ctr-04-part-m)). A
self-hosted center at the root of its host serves them where they are; one below a path needs its proxy to map them. Every reply
carries the pages' security headers (`Cache-Control: no-store, no-transform`, `X-Content-Type-Options: nosniff`, the content
security policy). A native error is the pages' JSON error (`{"error": {category, code, ...}}`), with the statuses of the pages:
`VALIDATION` and `CONFLICT` 400, `AUTHENTICATION` and `AUTHORIZATION` 403, `STATE/not_found` 404, other `STATE` 400,
`RESOURCE/rate_limited` 429, `RESOURCE/overloaded` the Worker's 503.

The app sends no cookie on a native request (a client with a cookie jar must not attach one); a browser cannot make one without a
CORS preflight, which no route answers.

## Flow

1. **Begin** (anonymous). The center checks, before it counts or reads anything: the challenge (43 base64url, S256 only), the state
   (16 to 128 unreserved), the client and its redirect, and the claim. The release client `arcforges.android` takes exactly
   `<origin of the public base URL>/app/callback` (a center of an IP, loopback or http host admits none); the debug client
   `arcforges.android.local` takes exactly `<ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT>:/callback`, on a self-hosted center that sets it;
   anything else is `redirectUri: not_admitted` (`client_mismatch` when the form is the other client's). The claim's shape: product
   `arcforges-mobile`, an Android platform (the contract's lower-case `^android...` pattern), the claim text rules (a `+` is refused:
   the app sends its version without build metadata). No installation is read (no ownership oracle) and no other flow is touched
   (no supersession by installation, Q21/Q-10). Then `mobile_begin_prefix` (and the opt-in anonymous-flow ceiling) is taken and the
   flow is inserted PENDING for 10 minutes. The reply is `{flowId, authorizeUrl, expiresAt}` with
   `authorizeUrl = <public base URL>/mobile/authorize#flow=<flowId>`, which the app derives itself and requires byte-equal (MB-2).
2. **Review** (the page's script submits it once signed in). The latest reviewer wins. An unknown flow or one another account
   decided is `STATE/not_found`, a lapsed one `STATE/expired`. The page shows the client (the app, or "debug build" with a warning),
   the platform and the app version "as the app reports it" (HTML-escaped), the times, the account it signs in and the begin
   request's origin (official-hosted only), and, before any step-up, "This phone is signed in to another account. Sign out in the app
   first." or "This app installation was removed from your account." when the claimed installation cannot be this account's (Q-7);
   only the denial is then offered. A review that shows one of these two texts is counted in the account's `mobile_approve_account`
   bucket, as a decision is (an exhausted bucket refuses it `RESOURCE/rate_limited`), so the text is no unbounded oracle; it needs a
   known installation ID in any case (a random 122-bit UUID), and each probe also costs a begin in `mobile_begin_prefix`.
3. **Decision** (`identity.authorizeMobile`, a center-defined operation: R3, audited in its transaction, target the flow, evidence
   on approve only, restricted accounts admitted, Q-8). The review and the decision admit only a cookie session of scope `account`
   issued to sign in (purpose `authenticate`), because an approval issues a mobile session of scope `account`: a narrower session
   (`mobile.limited`, or another purpose) is `AUTHORIZATION/permission_denied` before anything is read, counted or written. The page
   takes the evidence rule from the operation's row and refuses the decision when the row is missing (fail closed). In the order of
   fleet's Decide (MB-4): `mobile_approve_account`; the flow row
   FOR UPDATE; foreign or unknown `not_found`, lapsed `expired`, final `invalid_state` (its state's name), not reviewed by this
   account within 10 minutes `invalid_state not_reviewed`. A denial needs no evidence: DENIED, and the callback
   `<redirect>#error=access_denied&state=<state>&iss=<issuer>`. An approval refuses a foreign installation (`permission_denied`) or a
   revoked one (`credential_revoked`), consumes the step-up evidence of class `identity.authorizeMobile` bound to the flow ID in its
   transaction, stores the approving session with its auth method, authentication time, `auth_epoch` and `recovery_generation`, and
   draws a fresh code that lives `mobileCodeLifetime` (default 2 minutes, at most 2 minutes, never past the flow); an approval of an
   APPROVED flow replaces the code. The callback is `<redirect>#code=<code>&state=<state>&iss=<issuer>`. Both callbacks are built
   from the stored redirect only, in this member order, with the issuer (the center's own public base URL, never the request's host)
   percent-encoded. The done page shows them as a link, "Open the ArcForges app", which the person taps (MB-7); the script checks the
   link and never follows it itself (a script navigation that the browser kept in the tab would load the fallback page and take the
   link away), and offers "Sign this browser out".
4. **Token** (anonymous, bound by the code and the verifier), in the order of fleet's Complete (protocol-1): an unknown flow is
   `STATE/not_found` (counted in `mobile_token_prefix`); a PENDING or APPROVED flow past its expiry or an APPROVED one whose code
   expired is `STATE/expired` before the compare; the code is compared first, in constant time, against a dummy digest when the flow
   has none: every mismatch is `AUTHENTICATION/unauthenticated`, counted, and changes nothing. A matching code on DENIED or PENDING is
   unauthenticated, on EXPIRED `STATE/expired`, on REVOKED `CONFLICT/code_reused`. On APPROVED, outside any transaction, the PKCE
   verifier (S256) and the binding (`clientId`, `redirectUri`, `installationId` exactly the begin request's) are checked. One
   transaction locks the flow row and decides again: COMPLETED is a reuse (REVOKED, the family it delivered revoked with reason 9,
   audited once, `code_reused`); a wrong verifier or binding ends the flow REVOKED (audited `verifier_failed`, answered
   unauthenticated); otherwise, in a savepoint and the global lock order (the flow row, `identity.user` FOR SHARE with MaySignIn, the
   installation and its device through `device.EnsureNative`, the approving session FOR SHARE through `session.ApprovalStands`): an
   installation of another account or product is `AUTHORIZATION/permission_denied`, a revoked one
   `AUTHENTICATION/credential_revoked` (the flow stays APPROVED); a lapsed approval (the account may no longer sign in, the approving
   session was revoked by the account, all sessions, its device or an operator, or an epoch moved) rolls the savepoint back and ends
   the flow EXPIRED (`STATE/expired`, audited `approval_lapsed`); else an account session (scope `account`, product
   `arcforges-mobile`, purpose `authenticate`) is issued on the claimed installation (a new installation gets a new device named
   "Android phone") and the flow is COMPLETED. Older sessions of the installation are not ended (Q-10). The reply is
   MobileTokenResponse; the session refreshes through `IdentityService.RefreshSession`.

The account participant (`mobileauth.ApprovalParticipant`, registered after the fleet's two) denies the account's APPROVED,
uncollected flows when it revokes all its other sessions or removes a credential (protocol-6), because the approving session itself
survives "sign out all other sessions".

The loser of two concurrent token requests with the correct code takes the reuse path, which also revokes the winner's family: the
app never resends a token request whose body was sent. A lost reply means beginning again; the delivered session can be ended in the
device list.

## Budgets

Policy keys of `ARCFORGES_CENTER_IDENTITY_POLICY` ([identity policy](center-identity.md#identity-policy)): `mobileCodeLifetime` 2m
(30s to 2m), `mobileBeginPrefix` 30 per 10m, `mobileTokenPrefix` 30 per 10m (failures only: an unknown flow or a code that does not
match; a matching code never waits on it), `mobileApproveAccount` 20 per hour (every decision, and every review that shows a foreign
or revoked installation). The step-up bucket (10 per account in 10 minutes)
bounds the approvals; the flow lifetime (10 minutes) and the review window (10 minutes) are contract values. There is no
per-installation bucket (Q21).

## Errors, audit and metrics

- begin: `VALIDATION/invalid_argument` (the member and the reason, for example `redirectUri: not_admitted`,
  `installation.platform: not_admitted`), `RESOURCE/rate_limited`.
- token: `STATE/not_found`, `STATE/expired`, `AUTHENTICATION/unauthenticated`, `CONFLICT/code_reused`,
  `AUTHORIZATION/permission_denied`, `AUTHENTICATION/credential_revoked`, `RESOURCE/rate_limited`, `RESOURCE/overloaded`.
- pages: the fleet pages' texts in the app's words, and the two installation texts above.
- Audit: `identity.mobile_authorization.{approved,denied,code_reissued,completed,code_reused,verifier_failed,approval_lapsed}` (target
  the flow), `identity.rate_limited`. No code, verifier or token is stored in clear (the code only as its SHA-256), and none of
  them, nor the client state, is logged by the center or the Worker, or audited (PostgreSQL's own statement logging is an operator
  setting: with it on, the server's log holds the statements' parameters, the state among them). The client state is stored only to return it in the callback
  (`identity.mobile_authorization.client_state`; `TestNoMobileSecretIsStoredLoggedOrAudited`).
- Metrics: `arcforges_center_mobile_events_total{event,outcome}`, closed labels (`observe.MobileOutcomes`).

## Configuration

| Variable                                 | Meaning                                                                                         |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `ARCFORGES_CENTER_ANDROID_APP`           | The asset links' app identity (below); unset or `[]` publishes `[]`; production leaves it unset |
| `ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT` | The debug app's scheme; self-hosted only (an official-hosted center refuses to start with it)   |

There is no `ARCFORGES_CENTER_APP_LINK_ORIGIN` (Q-3): the release redirect is the center's own origin with `/app/callback`. A release
app verifies only the hosts in its manifest, so its Custom Tab sign-in works only where the app verifies the host (the official host,
and proof for a proof build); against any other self-hosted center it signs in natively through IdentityService or by QR.

### Asset links

`ARCFORGES_CENTER_ANDROID_APP` is a JSON array of at most 4 objects of exactly `packageName` (an Android application ID),
`sha256CertFingerprints` (1 to 4 distinct `AB:CD:...` fingerprints: the upload key and the Play app-signing key) and optionally
`testOnly: true` (a label; the center logs it at start). `/.well-known/assetlinks.json` answers one statement per app with both
relations, `delegate_permission/common.handle_all_urls` (App Links) and `delegate_permission/common.get_login_creds` (the app's own
passkeys through Credential Manager), and the `android_app` target, as compact JSON in the configuration's order:

```json
[
  {
    "relation": [
      "delegate_permission/common.handle_all_urls",
      "delegate_permission/common.get_login_creds"
    ],
    "target": {
      "namespace": "android_app",
      "package_name": "com.arcforges.prooftest",
      "sha256_cert_fingerprints": ["33:58:..."]
    }
  }
]
```

Proof carries a labelled non-shipping test statement (Q-1): the package `com.arcforges.prooftest`, which no app will ever publish,
and the fingerprint of a throwaway self-signed certificate generated for this purpose; its private key was destroyed and only the
public fingerprint is committed. AF-AND-01 replaces it with the real identity. Zone bot protections must not challenge Google's
Digital Asset Links fetcher.

### The debug client

A debug build cannot reach `http://10.0.2.2`: the center refuses an http public base URL of a non-loopback host and an IP host as a
passkey relying party, and Chrome does not treat `10.0.2.2` as a secure context. The local stack is a self-hosted center at
`http://localhost:<port>` reached through `adb reverse tcp:<port> tcp:<port>`, with
`ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT=<scheme>` (a lower-case reverse-DNS name with at least one dot, never `http`, `https`, `file`,
`javascript`, `data`, `intent`, `content`, `android-app`, `about`, `blob`, `ws` or `wss`): the debug client is then admitted with
exactly `<scheme>:/callback`, and the review page says "debug build". A private-use scheme can be registered by any app: PKCE protects
against an interceptor, not against a hostile app that starts the flow itself, hence debug and self-hosted only.

## Custom Tab side effects

The Custom Tab shares Chrome's cookie jar: a phone already signed in to the center in Chrome skips the sign-in and only steps up. A
new sign-in creates an `arcforges-web` cookie session on a "Chrome on Android" web device that stays listed for the browser session's
lifetime; the done page offers "Sign this browser out". An ephemeral Custom Tab would create a new web device per sign-in (the
browser claim lives in local storage), so AF-AND-01 should not use ephemeral mode. The authorization page and the sign-in page drop
their fragment before any request (protocol-16). `/app/callback` reflects nothing and loads only the pages' same-origin script, which
removes the fragment with `history.replaceState` without reading it (Q-4), so a code from an unverified link stays in no history entry;
such a code is useless without the verifier and dies in at most 2 minutes.

## Expected divergences from the contract

`center/internal/pages/mobile_vectors_test.go` replays the 120 vendored vectors (`center/internal/mobileauth/testdata`, pinned to the
cohort, its commit, the SHA-256 of the document and of the upstream fixture, and the SHA-256 of the vendored vectors file itself):
requests through the route bound and the center's parsers,
callbacks and begin replies through MobileProbe's checks and the center's builders, token replies through the center's closed reply
type. Every verdict is the contract's; the patterns the parsers use are the document's, character for character. The rows below are
where the center's behaviour differs, each pinned by `TestTheExpectedMobileDivergences`:

| Vector                                      | Contract                                                      | Center                                                                                                          | Why it is safe                                                                       |
| ------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `mobile-begin-platform-uppercase`           | the platform is lower-case `^android...`                      | the begin route applies the contract's pattern; the shared `device.MobilePlatform` is case-insensitive          | display text only, escaped and labelled; the route refuses before ValidateClaim runs |
| `mobile-token-noncanonical-code`            | a code's last character is one of 16 (canonical base64url)    | the generator emits canonical codes only; the compare admits exactly the texts that re-encode to themselves     | equal on every 43-character input (all 64 last characters checked)                   |
| `mobile-callback-success-any-order`         | a callback fragment in any order, with an unencoded issuer    | the center writes the fixed order with a percent-encoded issuer; MobileProbe reads any order                    | the center's form is one of the valid forms (canonical vectors reproduced)           |
| `mobile-begin-debug-scheme-plus-and-hyphen` | the debug form admits `+`, empty labels, a trailing dot (N-6) | the configured scheme is strict reverse-DNS; the center admits only its exact value                             | stricter: no center admits a scheme outside the grammar                              |
| `mobile-callback-success-loopback-issuer`   | the issuer form                                               | the base URL grammar admits more; the configuration refuses the mobile surface for a base URL that is no issuer | every issuer the center writes is its checked base URL                               |

## MobileProbe and H3

MobileProbe is the MOCKED development stand-in of the Android app (the Plan's `fakes_allowed`): `center/internal/mobiletest` (fresh
verifier and state, begin with the derived-URL check, the callback's state and issuer checked before any request, token) and
`center/cmd/mobile-probe` (a handshake directory with the browser flow; its result file names the device ID of each session it was
delivered, which is not secret, so the clean-up revokes exactly those devices). The probe's scenarios and their expectations are
`mobiletest.RunScenario`, which `TestMobileProbesScenariosPassAgainstTheCenter` runs against the real center and PostgreSQL (the
person is a seam there: the harness's browser decides on the pages); every refusal is compared in the native JSON's form
(`conflict/code_reused`), a gRPC reply brought to it by `mobiletest.RefusalOf`. Both are kept out of the Docker context
(`.dockerignore`, pinned by `tests/worker/docker-context.test.ts`). The browser flow is `eng/verification/browser/mobile-approve.ts`
(`acceptance.ts --mobile-approve`).

### H3 checklist (run by the coordinator after the merge, on proof, without a phone or an emulator)

1. Production stays dark: its `center.surfaces` is `none`; proof's reads `identity,pages,operations,fleet,mobile`; proof's
   PostgreSQL gate is at version 6.
2. `curl` on proof: `/.well-known/assetlinks.json` answers 200, `application/json`, no redirect, the configured test statement byte
   for byte; `/app/callback` answers 200 with the fixed page and the security headers; production's apex is unchanged (whatever
   `arcforges-web` answers).
3. Regression first (the returning acceptance and `--operator-grant`), then a pause of at least 90 seconds and a health warm-up.
4. Real Chromium (the pinned revision) with the MOCKED virtual authenticator, and MobileProbe with the release redirect
   `https://proof.arcforges.com/app/callback`: `go run ./cmd/mobile-probe -center https://proof.arcforges.com/api -dir <dir> -case
<case> -scenario <scenario>` for the cases approve, deny, reuse and wrong-verifier, and `node eng/verification/browser/mobile-approve.ts
--watch <dir> --cases 4`. Each case signs in when needed, steps up, decides, hands the done page's link to the probe and taps it
   (the fallback page loads without the fragment). A sign-in on the way to the review waits for the review page's own elements, not
   its load event, within `--real-timeout-ms` (180 s by default, never less than `--timeout-ms`). Budget: 4 cases spend at most 8 step-ups (one per approval and one per revoked
   device; the center allows 10 per 10 minutes), 4 of the 20 decisions per hour, 4 of the 30 begins per 10 minutes, and the browser and
   the probe together stay within the edge minute (`acceptance.ts` fails a run that would not).
5. The approve case refreshes once through `IdentityService.RefreshSession`; the devices page lists the session's device as an
   "Android phone".
6. Optional, read-only, outward: Google's Digital Asset Links API `statements:list` for `https://proof.arcforges.com`.
7. Clean-up, also after a failure: the flow revokes exactly the devices the probe's results name, by device ID (no other phone of the
   account is touched); a case whose result never arrived names none, and the report counts such cases (`casesWithoutResult`):
   revoke its device by hand. Revoke the browser's web device by hand if it is new; record what stays on `arcforges_acceptance`.

REAL: proof, Neon, the Worker, the Container, Chromium. MOCKED: the authenticator and the app. Not covered and carried to AF-AND-01
(emulator checks: (a) a tap from the same-host Custom Tab page opens the app through the verified link; (b) a script navigation does
the same, or is recorded as not doing so (the done page has none); (c) the intent keeps the fragment), AR-08 and H-02 (a real passkey
in Chrome for Android and the release fingerprint).

## Owner items

- The real app identity (package and release and upload fingerprints) for `ARCFORGES_CENTER_ANDROID_APP`: AR-08 and H-02, owner only.
- No real phone, emulator, Play account or app signing key is used by this part; the proof statement is a labelled test value.
- AF-AND-01 carries: the app rules of the contract (derive `authorizeUrl`, check `iss` and `state`, one pending attempt, one token
  request per code, a new installation ID after `credential_revoked`, no cookie jar on the native client: the native rows refuse any
  Cookie, including a cookie the zone sets on its own such as Cloudflare's `__cf_bm`, so the client must not keep or send cookies
  the edge set; no ephemeral Custom Tab),
  the emulator checks above, and a Design change of the callback host only if a tap does not open the app (Q-5).
- AF-PROD-01: the two production zone routes and their precedence over the `arcforges-web` Custom Domain, the zone bot settings for
  Google's fetcher, and the retention sweep of `identity.mobile_authorization` (AF-PLAT-01).

## Residual risks

- An app that embeds the page in its own WebView can obtain a session with an e-mail-code step-up (a passkey ceremony fails in an
  unassociated WebView): nothing beyond the native IdentityService sign-in, which already admits any client claiming
  `arcforges-mobile`. Key-bound mobile installations are an AF-CTR-05 candidate.
- A center the person chose can proxy the official pages (ordinary AitM phishing); a passkey fails on the wrong RP ID, an e-mail code
  would not.
- `not_found` and `unauthenticated` tell an unknown flow from a known one to a caller without the code, as for the node (accepted).
- A crashed app can leave a session family that lives until its idle expiry; it is listed on the device page.
