# Accounts, sessions and devices on the center

AF-CTR-03 moves accounts, sessions and devices to the Go [center](center.md) (ArcForges-Design AD-0011, AD-0021 §3 to §7 and §10,
data/cloud-store.md §2 and §6). It lands in parts, each deployable dark:

- **A1a (this change):** the identity and device store (migration 0002, whole), the identity core, sign-in by passkey and e-mail
  code, the owner bootstrap, native sessions with rotating refresh tokens, the credential verifiers of the ingress, the account
  reads, rate limits, audit, the closed operation table and the `identity` surface switch in the center and the Worker.
- **A1b:** step-up, sign-out and session revocation, passkey registration of a signed-in account, profile, credential and device
  changes, device revocation and its cascade, command receipts for those writes and the incident command
  `admin revoke-sessions`. Until it lands, an account cannot sign out over the API, revoke a session or device, or step up: a session
  ends only at its expiry or by a refresh-token reuse.
- **A2:** the account pages and the contract `/session/v1` browser routes (cookie sessions, CSRF, the bootstrap page), the
  real-browser acceptance script and the proof bootstrap inputs.
- **B:** feature availability (AD-0021 §13a) and the operator commands.

Recovery, account deletion and export, e-mail change, recovery codes, API tokens and the security activity list are AF-ID-02's;
those methods stay unregistered.

## Packages

| Path                                         | Contents                                                                                                                       |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `center/internal/identity`                   | The identity core: the rules ported from the C# `IdentityRules`, sign-in flows, the e-mail code loop, the bootstrap, the reads |
| `center/internal/identity/passkey`           | The WebAuthn relying party over `github.com/go-webauthn/webauthn` with the center's fixed policy                               |
| `center/internal/identity/passkey/virtual`   | A software authenticator for tests only (never linked into the executable)                                                     |
| `center/internal/session`                    | Credential formats, native and browser sessions, refresh rotation and reuse detection, the ingress verifiers, the session list |
| `center/internal/device`                     | Devices and installations: native claims, browser installations, the device list                                               |
| `center/internal/access`                     | The closed operation table and the authorization of every identity call                                                        |
| `center/internal/identityapi`                | The Connect handlers of the served IdentityService and DeviceService methods                                                   |
| `center/internal/ratelimit`, `internal/page` | Fixed-window rate limits on `platform.rate_limit`; bounded paging with opaque keyset cursors                                   |
| `center/internal/mail`, `internal/arc`       | The e-mail sender (disabled, or the test fake); the domain refusals of errors.md and their `ArcError` rendering                |

## Served methods

A1a serves exactly these methods (`routes.IdentityMethods`); every other IdentityService, DeviceService and WorkspaceService
method stays unregistered, so the center answers `UNIMPLEMENTED` and the Worker table has no row for it
(`TestTheServedMethodsAreExactlyA1asSet` compares the set with the contract's service descriptors). Every identity request
carries a `RequestMeta`; a `RequestMeta.workspace_id` is refused with `VALIDATION/invalid_argument` (`meta.workspace_id:
not_admitted`): identity and device methods are account-scoped.

| Method                                 | Operation ID (con-07)             | Risk | Credential | mobile.limited | Restricted account |
| -------------------------------------- | --------------------------------- | ---- | ---------- | -------------- | ------------------ |
| IdentityService.BeginAuthentication    | `identity.beginAuthentication`    | R1   | anonymous  | —              | —                  |
| IdentityService.CompleteAuthentication | `identity.completeAuthentication` | R1   | anonymous  | —              | —                  |
| IdentityService.RequestEmailCode       | `identity.requestEmailCode`       | R1   | anonymous  | —              | —                  |
| IdentityService.RedeemEmailCode        | `identity.redeemEmailCode`        | R1   | anonymous  | —              | —                  |
| IdentityService.CompleteEnrollment     | `identity.completeEnrollment`     | R1   | anonymous  | —              | —                  |
| IdentityService.ListAuthProviders      | `identity.listAuthProviders`      | R1   | anonymous  | —              | —                  |
| IdentityService.RefreshSession         | `identity.refreshSession`         | R1   | anonymous  | —              | —                  |
| IdentityService.GetProfile             | `identity.getProfile`             | R1   | session    | allowed        | refused            |
| IdentityService.ListAuthIdentities     | `identity.listAuthIdentities`     | R1   | session    | allowed        | allowed            |
| IdentityService.ListSessions           | `identity.listSessions`           | R1   | session    | allowed        | allowed            |
| DeviceService.List                     | `device.list`                     | R1   | session    | allowed        | allowed            |

The table is `access.Operations`, closed: the composition refuses to start when a served method has no row, a row has no served
method or a row and the method's policy disagree about the session (`checkIdentityComposition`). A session method admits only the
account-session scopes, `account` and `mobile.limited`: a `node`, `push` or `automation` credential is refused with
`AUTHORIZATION/permission_denied` (state.reason = the operation ID) before the handler does anything, nothing is written, and the
refusal is audited as `access.refused` (`TestOnlyAccountSessionsReachTheSessionMethods`). A restricted account reaches only its
security operations. A1b adds its rows: the step-up rule for `mobile.limited` (`Upgrade`) and the step-up evidence of the risky
writes.

None of the A1a methods runs under a command receipt: the anonymous ones are one-use authentication steps, RefreshSession must never
replay tokens, and the session methods are queries. A1b's session-authenticated writes run under `platform.Execute`.

## Sign-in

**Passkeys** (AD-0011 §4). `BeginAuthentication(PASSKEY, AUTHENTICATE, installation)` creates a native flow with a 32-byte
challenge and returns discoverable request options (no allowed credentials, user verification `required`, algorithm ES256).
`CompleteAuthentication(flow_id, proof.passkey)` verifies the assertion with go-webauthn outside any transaction and then, in one
transaction, consumes the flow, advances the credential's counter, finds or creates the device and installation of the flow's
claim and issues an `account` session. The policy is fixed: the RP ID is the host of the public base URL and the only origin its
origin (no cross-origin, no top origins, no Android origins until the Android task); user verification is required on every
ceremony; ES256 only; attestation `none` only; the assertion's user handle must be the credential owner's; a counter that does not
advance is refused; every library error is one refusal. A public base URL whose host is an IP address cannot be a relying party: a
self-hosted center's default leaves identity off and logs why; an explicit surface list refuses to start.

**Native installation claims.** Every BeginAuthentication names an `InstallationClaim`; a native account sign-in admits the product
`arcforges-mobile` on an Android or iOS platform (nodes enroll with AF-CTR-04). The installation ID is the client's and global: an ID
that belongs to another account or product is refused with `AUTHORIZATION/permission_denied`, one on a revoked device with
`AUTHENTICATION/credential_revoked`. A browser's claimed installation ID (A2) is kept beside a center-generated installation ID,
unique per account over live rows, so a claim never links two accounts.

**E-mail codes** (DC-08). Native `BeginAuthentication(EMAIL, AUTHENTICATE, login_hint)` creates the flow without sending;
`RequestEmailCode(flow_id, email, purpose)` sends (and resends) the code; `RedeemEmailCode(flow_id, code)` or
`CompleteAuthentication(flow_id, proof.email_code)` completes it. A code is eight letters of `BCDFGHJKLMNPQRSTVWXZ`, stored as
PBKDF2-HMAC-SHA-256 with a 16-byte salt (20,000 iterations, at most two at a time, outside every transaction). A flow allows five
attempts, counted in their own transaction before the code is checked, and three sends; a resend replaces the code and never resets
the attempts. Every syntactically valid address gets the same reply and the same statements whether or not an account has it, and
the code is mailed after the response only when one does (`TestAnUnknownAddressLooksLikeAKnownOne`). E-mail sign-up does not exist
(accounts come from the bootstrap and, later, AF-ID-02); with the mail sender disabled, which every deployment uses until live
delivery is decided (AR-14, H-19), the e-mail method is left out of ListAuthProviders and refused with `VALIDATION/invalid_argument`
(`method: not_offered`). Tests inject the fake sender and close the loop through it.

**Owner bootstrap** (AD-0021 §6). The deployment configures the SHA-256 of a one-time token and its expiry
(`ARCFORGES_CENTER_BOOTSTRAP_SHA256`, `ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT`, at most seven days ahead). The owner runs
`BeginAuthentication(PASSKEY, ENROLL, installation)`, which always returns creation options, whatever the bootstrap's state, and is
rate limited, then `CompleteEnrollment(flow_id, proof.local_code = token, credential.passkey, profile.display_name)`. The token is
compared first, in constant time, before any WebAuthn verification or write; a disabled, expired, used or wrong bootstrap and an
existing account all answer `AUTHENTICATION/unauthenticated`, the reason only in the audit event `identity.bootstrap.refused`. A
wrong token counts in its client prefix's bucket; there is no global bucket, so nobody can lock the owner out. The creating
transaction takes the bootstrap's advisory lock and inserts the singleton `identity.bootstrap` row, so concurrent attempts create
one account (`TestConcurrentBootstrapsCreateOneAccount`). The token never appears in the repository, a log or a database row. A2
adds the operator script that generates it and the proof environment's dispatch inputs.

## Sessions

| Credential         | Format                             | Stored as                              | Lifetime (default)                                              |
| ------------------ | ---------------------------------- | -------------------------------------- | --------------------------------------------------------------- |
| Access token       | `afa1.` + 43 base64url             | SHA-256                                | 15 minutes, never beyond the refresh expiry                     |
| Refresh token      | `afr1.` + 43 base64url             | SHA-256; spent ones kept               | sliding 30 days, absolute 90 days                               |
| Browser cookie     | 43 base64url (`__Host-af_session`) | SHA-256                                | idle 30 minutes, absolute 12 hours; renewed only on a page load |
| Browser CSRF token | 43 base64url                       | not stored: HMAC-SHA-256 of the handle | the session's                                                   |
| E-mail code        | 8 letters                          | PBKDF2-HMAC-SHA-256                    | 10 minutes, 5 attempts, 3 sends                                 |
| Bootstrap token    | `afb1.` + 43 base64url             | SHA-256 in configuration               | its configured expiry                                           |

Every credential is drawn from the system's cryptographic source; lookups go through unique digest indexes. The ingress verifies a
bearer or a cookie against the store on every call: a revoked session, device or installation is the transport refusal
`auth.credential_revoked`, an expired access token `auth.token_expired` (the client refreshes and retries), anything unknown
`auth.unauthenticated`. A cookie needs the exact Origin of the public base URL and that session's own CSRF token.

**Refresh rotation and reuse** (n3). `RefreshSession(refresh_token, installation_id)` locks the session by the token's digest,
checks revocation and expiry, then the installation, the scope (`account` and `mobile.limited` only) and the account, records the
presented digest as spent and issues the next generation. A spent digest presented again is a reuse: every live session of its
family is revoked, `identity.session.refresh_reused` is audited and the call answers `AUTHENTICATION/credential_revoked`. There is
no grace window: a client that lost the response to a refresh must sign in again (`TestRefreshRotatesAndAReusedTokenRevokesTheFamily`
pins this). Two concurrent refreshes with one token serialize on the row and the second revokes the family.

**Lists.** ListSessions lists the account's live `account` and `mobile.limited` sessions, newest first, marking the caller's.
DeviceService.List lists the account's live devices with their live installations; a browser's device is listed only while it has
a live session, and a revoked device is not listed. ListAuthIdentities lists the live credentials. Pages hold at most 100 items
(default 50); a cursor is opaque and bound to its listing, and a malformed one is `VALIDATION/invalid_cursor`.

## Identity policy

Every lifetime and limit comes from one source, `config.IdentityPolicy`, with these defaults. An operator may override values
within their bounds with `ARCFORGES_CENTER_IDENTITY_POLICY`, a JSON object (durations as Go duration strings, counts as
integers; unknown or repeated keys and values out of bounds refuse to start). The hosted Worker never passes it.

| Setting                                                        | Default            | Bounds                       |
| -------------------------------------------------------------- | ------------------ | ---------------------------- |
| `accessTokenLifetime`                                          | 15m                | 1m to 1h                     |
| `refreshIdleLifetime` / `refreshAbsolute`                      | 720h / 2160h       | 1h to 2160h / 1h to 9600h    |
| `browserIdle` / `browserAbsolute`                              | 30m / 12h          | 1m to 24h / 10m to 168h      |
| `passkeyFlowLifetime` / `emailCodeLifetime`                    | 5m / 10m           | 1m to 15m / 1m to 30m        |
| `emailCodeAttempts` / `emailCodeSends` / `emailCodeIterations` | 5 / 3 / 20000      | 1–10 / 1–3 / 10000–600000    |
| `stepUpEvidenceTtl` (A1b)                                      | 5m                 | 1m to 5m                     |
| `signInPerPrefix` (begin, completion, redemption)              | 30 per 10m         | limit 1–10000, window 1m–24h |
| `signInFailuresAccount` (failed proofs per account)            | 10 per 10m         | as above                     |
| `emailPerPrefix` / `emailPerAddress` (code sends)              | 10 per h / 5 per h | as above                     |
| `redeemFailuresAddress` (wrong codes per address)              | 10 per h           | as above                     |
| `refreshPerPrefix`                                             | 120 per 10m        | as above                     |
| `stepUpPerAccount` (A1b)                                       | 10 per 10m         | as above                     |
| `bootstrapPerPrefix` (refused bootstraps)                      | 10 per h           | as above                     |

A prefix is the client address's /24 (IPv4) or /56 (IPv6) network; an IPv4-mapped address counts as IPv4. A bucket is the
SHA-256 of its kind and key in `platform.rate_limit`, counted in its own short transaction before the work it guards. A refusal is
`RESOURCE/rate_limited` with `retry_at` and a `LimitFailure` naming the bucket kind; the first refusal of a bucket's window is
audited as `identity.rate_limited`, the others only counted. The failed-proof buckets of an account (or of an unknown credential's
digest) and of an address count only failures, so two prefixes cannot together exceed an account's limit.

**Client address.** In official-hosted mode the Worker sets `x-arcforges-client-ip` from `cf-connecting-ip` (never from the
client's own header) and omits it when Cloudflare sent none; the center needs exactly one valid value, refuses a call without one
(`validation.invalid_request`) and refuses to start with a surface enabled unless `ARCFORGES_CENTER_CLIENT_IP_HEADER` names that
header. A self-hosted center keys by the TCP peer, or by exactly one valid header value when the peer is in
`ARCFORGES_CENTER_TRUSTED_PROXIES` (CIDR prefixes).

## Refusals

Every domain refusal is one row of ArcForges-Design `contracts/errors.md`, rendered as `ArcError` (snake_case code, category,
`message_key` `error.<category>.<code>`, retry advice, effect `DID_NOT_HAPPEN` except `INTERNAL/internal`) with the call's
correlation id, in the reply with gRPC `OK`:

| Refusal                             | When                                                                                             |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ |
| `VALIDATION/invalid_argument`       | a field outside its rule (`state.reason` = field path and rule), a method or purpose not offered |
| `VALIDATION/invalid_cursor`         | a malformed page cursor or one of another listing                                                |
| `AUTHENTICATION/unauthenticated`    | a wrong or unknown proof, an account that may not sign in, a refused bootstrap (all alike)       |
| `AUTHENTICATION/token_expired`      | an expired refresh token                                                                         |
| `AUTHENTICATION/credential_revoked` | a revoked session, device or installation; a reused refresh token                                |
| `AUTHORIZATION/permission_denied`   | a scope or account state the operation does not admit; another account's installation            |
| `CONFLICT/code_reused`              | a completed flow presented again, or a completion still in progress                              |
| `STATE/not_found`                   | an unknown flow, or one of another channel, kind, purpose or address                             |
| `STATE/expired`                     | an expired flow, or one whose attempts are exhausted                                             |
| `STATE/not_activated`               | a method of a disabled surface (`state.reason` = the surface)                                    |
| `RESOURCE/rate_limited`             | a rate-limit bucket over its limit, or a flow's sends exhausted (`email_code_sends`)             |
| `RESOURCE/overloaded`               | the store is unreachable or contended                                                            |
| `INTERNAL/internal`                 | anything else (logged with the correlation id, never with request content)                       |

The ingress adds two transport refusals for a known bearer (both gRPC 16 `UNAUTHENTICATED`): `auth.token_expired` and
`auth.credential_revoked`. They need companion rows in errors.md's center ingress table (DC-14).

## Audit

Events are appended to the platform audit chain (`platform.AppendAudit`) as the last statement of the transaction they describe,
or in their own transaction for a refusal: `identity.sign_in.succeeded`, `identity.sign_in.failed` (the first failure of a
bucket window), `identity.bootstrap.completed`, `identity.bootstrap.refused` (first per window, with the reason),
`identity.session.refresh_reused`, `identity.rate_limited` (first per window) and `access.refused`. Payloads are closed JSON:
method, channel, scope, reasons and counts, never a token, code, e-mail address or IP address. A sign-in whose audit event cannot be
written is refused and writes nothing (`TestARefusedAuditRefusesTheSignIn`).

## Transactions per request

| Call                             | Transactions                                                                                                                |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| BeginAuthentication              | 1 bucket count, 1 flow insert (+1 audit on a first refusal)                                                                 |
| CompleteAuthentication (passkey) | 1 bucket count, 1 credential read, 1 bucket check, 1 attempt, then 1 success transaction (or 1 flow end and 1 bucket count) |
| RequestEmailCode                 | 2 bucket counts, 1 flow update (PBKDF2 before it, the mail after the response)                                              |
| RedeemEmailCode                  | 1 bucket count, 1 flow read, 1 bucket check, 1 attempt, then 1 success transaction (or failure counts)                      |
| CompleteEnrollment               | 1 account check, 1 attempt, 1 creating transaction under the advisory lock (or 1 bucket count and 1 audit)                  |
| RefreshSession                   | 1 bucket count, 1 rotation, 1 device read                                                                                   |
| Session reads                    | 1 read-only credential check (ingress), 1 read-only query (+1 audit on an access refusal)                                   |

No transaction is open while PBKDF2, WebAuthn or the mail provider runs. The runtime pool stays four connections
([PostgreSQL store](postgres-store.md#connection-budgets)).

## Surface switch

The identity methods form the `identity` surface. The center and the generated Worker table tag them by surface
(`surfaceRoutes`, PLT-18: `productionRoutes` stay always on); `ARCFORGES_CENTER_SURFACES` (center) and `FLAGSHIP_SURFACES`
(Worker) list the enabled surfaces as exact generated names, comma-separated. Official-hosted mode enables none unless listed;
self-hosted mode enables every known surface unless listed (an explicit list pins the surfaces across upgrades; `none` enables
none). A disabled surface's method is answered with the domain refusal `STATE/not_activated` (`state.reason = identity`): by the
Worker from the generated reply, before any rate limit, credential, body or Container (`tests/worker/ingress-surfaces.test.ts`), and
by the center with the call's correlation id. An enabled one passes the Worker's own edge limit `IDENTITY_RATE_LIMITER` (over it, the
generated domain refusal `RESOURCE/rate_limited`) before it is forwarded. The Worker passes its parsed list to the Container as
`ARCFORGES_CENTER_SURFACES` (`none` when the list enables nothing, so a mistyped list never stops the center) and always
`ARCFORGES_CENTER_CLIENT_IP_HEADER`; surfaces take effect only with `ARCFORGES_HELLO_RUNTIME=go`.

Production carries `"FLAGSHIP_SURFACES": ""` (pinned by `tests/worker/center-config.test.ts`); the acceptance environment
(`proof`) carries `identity` and `ALLOWED_ORIGIN` = the origin of its public base URL. Only the `identity` surface exists yet;
AF-PLAT-01 owns the activation variable's other names, cron idling and kill switches. AF-PROD-01 enables identity in production only
after AF-PLAT-01's retention sweeps exist ([PostgreSQL store](postgres-store.md#identity-and-device-af-ctr-03)).

### Runbooks

- **Enable or withdraw the surface** in an environment: change `FLAGSHIP_SURFACES` in `wrangler.json` through a reviewed PR; the
  next deployment takes it. Withdrawing answers every identity call with `not_activated` at the edge; sessions and rows stay.
- **Rate-limit relief** (a legitimate client locked out): the buckets are fixed windows that reset by themselves within one window;
  an operator may raise a limit for a self-hosted center with `ARCFORGES_CENTER_IDENTITY_POLICY`. Never delete `platform.rate_limit`
  rows of a live attack.
- **Mass session revocation** before A1b's `admin revoke-sessions`: as the migration role,
  `UPDATE identity.session SET revoked_at = now(), revoke_reason = 6, rev = rev + 1 WHERE revoked_at IS NULL` (optionally
  `AND user_id = '<account>'`); every credential is refused at its next call.
- **Rollback**: an application rollback keeps migration 0002 and its `Schemas` and `RuntimeGrants` entries (the store never
  migrates down; [PostgreSQL store](postgres-store.md#recovery)).

## Native token documents

The Go center does not serve the version-1 native token documents (`public/http/v1/native-auth.schema.json`): their
`NativeTokenResponse` cannot list `arcforges-*` installations. Native sign-in is the IdentityService API above; the node and mobile
native flows bring their own versioned document with AF-CTR-04 and AF-CLD-02.
