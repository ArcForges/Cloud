# Accounts, sessions and devices on the center

AF-CTR-03 moves accounts, sessions and devices to the Go [center](center.md) (ArcForges-Design AD-0011, AD-0021 §3 to §7 and §10,
data/cloud-store.md §2 and §6). It lands in parts, each deployable dark:

- **A1a (merged):** the identity and device store (migration 0002, whole), the identity core, sign-in by passkey and e-mail
  code, the owner bootstrap, native sessions with rotating refresh tokens, the credential verifiers of the ingress, the account
  reads, rate limits, audit, the closed operation table and the `identity` surface switch in the center and the Worker.
- **A1b (this change):** step-up, sign-out and session revocation, passkey registration of a signed-in account, profile,
  credential and device changes, device revocation and its cascade, command receipts for those writes and the incident command
  `admin revoke-sessions`. It adds no migration: migration 0002 already holds every table it writes.
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
| `center/internal/device`                     | Devices and installations: native claims, browser installations, the device list, renames, the revocation cascade              |
| `center/internal/access`                     | The closed operation table and the authorization of every identity call                                                        |
| `center/internal/identityapi`                | The Connect handlers of the served IdentityService and DeviceService methods and the command receipts of the writes            |
| `center/internal/ratelimit`, `internal/page` | Fixed-window rate limits on `platform.rate_limit`; bounded paging with opaque keyset cursors                                   |
| `center/internal/mail`, `internal/arc`       | The e-mail sender (disabled, or the test fake); the domain refusals of errors.md and their `ArcError` rendering                |

## Served methods

The center serves exactly these methods (`routes.IdentityMethods`: A1a's eleven and A1b's eleven); every other IdentityService,
DeviceService and WorkspaceService method stays unregistered, so the center answers `UNIMPLEMENTED` and the Worker table has no row
for it (`TestTheServedMethodsAreExactlyTheIdentitySet` compares the set with the contract's service descriptors). Every identity
request carries a `RequestMeta`; a `RequestMeta.workspace_id` is refused with `VALIDATION/invalid_argument`
(`meta.workspace_id: not_admitted`): identity and device methods are account-scoped.

| Method                                      | Operation ID (con-07)                  | Risk | Credential | mobile.limited               | Restricted account | Step-up evidence       | Receipt |
| ------------------------------------------- | -------------------------------------- | ---- | ---------- | ---------------------------- | ------------------ | ---------------------- | ------- |
| IdentityService.BeginAuthentication         | `identity.beginAuthentication`         | R1   | anonymous  | —                            | —                  | —                      | —       |
| IdentityService.CompleteAuthentication      | `identity.completeAuthentication`      | R1   | anonymous  | —                            | —                  | —                      | —       |
| IdentityService.RequestEmailCode            | `identity.requestEmailCode`            | R1   | anonymous  | —                            | —                  | —                      | —       |
| IdentityService.RedeemEmailCode             | `identity.redeemEmailCode`             | R1   | anonymous  | —                            | —                  | —                      | —       |
| IdentityService.CompleteEnrollment          | `identity.completeEnrollment`          | R1   | anonymous  | —                            | —                  | —                      | —       |
| IdentityService.ListAuthProviders           | `identity.listAuthProviders`           | R1   | anonymous  | —                            | —                  | —                      | —       |
| IdentityService.RefreshSession              | `identity.refreshSession`              | R1   | anonymous  | —                            | —                  | —                      | —       |
| IdentityService.GetProfile                  | `identity.getProfile`                  | R1   | session    | allowed                      | refused            | —                      | —       |
| IdentityService.ListAuthIdentities          | `identity.listAuthIdentities`          | R1   | session    | allowed                      | allowed            | —                      | —       |
| IdentityService.ListSessions                | `identity.listSessions`                | R1   | session    | allowed                      | allowed            | —                      | —       |
| DeviceService.List                          | `device.list`                          | R1   | session    | allowed                      | allowed            | —                      | —       |
| IdentityService.BeginStepUp                 | `identity.beginStepUp`                 | R1   | session    | allowed                      | allowed            | —                      | —       |
| IdentityService.CompleteStepUp              | `identity.completeStepUp`              | R1   | session    | allowed                      | allowed            | —                      | —       |
| IdentityService.UpdateProfile               | `identity.updateProfile`               | R2   | session    | upgrade                      | refused            | —                      | yes     |
| IdentityService.BeginPasskeyRegistration    | `identity.beginPasskeyRegistration`    | R2   | session    | upgrade                      | refused            | account                | —       |
| IdentityService.CompletePasskeyRegistration | `identity.completePasskeyRegistration` | R2   | session    | upgrade                      | refused            | —                      | yes     |
| IdentityService.RenameAuthIdentity          | `identity.renameAuthIdentity`          | R2   | session    | upgrade                      | allowed            | —                      | yes     |
| IdentityService.RemoveAuthIdentity          | `identity.removeAuthIdentity`          | R3   | session    | upgrade                      | allowed            | credential             | yes     |
| IdentityService.RevokeSession               | `identity.revokeSession`               | R2   | session    | own: allowed; other: upgrade | allowed            | own: —; other: session | yes     |
| IdentityService.RevokeAllSessions           | `identity.revokeAllSessions`           | R3   | session    | upgrade                      | allowed            | account                | yes     |
| DeviceService.Rename                        | `device.rename`                        | R1   | session    | upgrade                      | allowed            | —                      | yes     |
| DeviceService.Revoke                        | `device.revoke`                        | R3   | session    | own: allowed; other: upgrade | allowed            | own: —; other: device  | yes     |

The table is `access.Operations`, closed: the composition refuses to start when a served method has no row, a row has no served
method or a row and the method's policy disagree about the session (`checkIdentityComposition`). A session method admits only the
account-session scopes, `account` and `mobile.limited`: a `node`, `push` or `automation` credential is refused with
`AUTHORIZATION/permission_denied` (state.reason = the operation ID) before the handler does anything, nothing is written, and the
refusal is audited as `access.refused` (`TestOnlyAccountSessionsReachTheSessionMethods`). A restricted account reaches only its
security operations. A `mobile.limited` session (a phone that signed in without verifying its user, android.md A-09) is refused an
`upgrade` row with `AUTHENTICATION/step_up_required` (retry the same command) before the handler runs, and an `own: allowed` row on
another session or device by the handler before anything is written; signing itself out and removing its own phone stay open to it
(T-19, `TestMobileLimitedNeedsStepUp`, which walks the table and fails for a row it has no request for). Proving any step-up
upgrades the session to `account`; the center's own class `identity.upgradeSession` exists for a phone that only wants to unlock
everything.

The anonymous methods and the queries run under no receipt: the anonymous ones are one-use authentication steps, RefreshSession
must never replay tokens. The step-up methods and BeginPasskeyRegistration run under none either: each creates a new challenge or
flow, so a lost reply is a new begin. Every other write runs under a command receipt ([command receipts](#command-receipts)).

## Step-up

Step-up evidence (DC-01, SEC-02) is one proved challenge of the caller's session for one operation class and one target object.
Authentication time is never evidence.

- **Begin.** `BeginStepUp(operation_class, method, target_hash)` names the operation ID of a row that needs evidence (the table's
  step-up column), or `identity.upgradeSession` from a `mobile.limited` session for that session itself (otherwise the reason is
  `target_hash: not_the_session`). The target hash is canonical (`identity.TargetHash`): the lowercase hexadecimal SHA-256 of three
  lines, the class, the account ID and the target ID, the IDs in their canonical lowercase UUID text. The target is the account
  (`identity.beginPasskeyRegistration`, `identity.revokeAllSessions`), the credential (`identity.removeAuthIdentity`), the session
  (`identity.revokeSession`, the upgrade) or the device (`device.revoke`). The method is a passkey of the account (one assertion
  per challenge) or, when mail is enabled, an e-mail code sent to the account's address (the policy's code attempts, at most five).
  The account's `stepUpPerAccount` bucket counts each begin.
- **Complete.** `CompleteStepUp(flow_id, proof)` checks the account's failed-proof bucket, counts the challenge's attempt, and
  reserves one failure in that bucket under its limit (the reservation of a wrong e-mail code, E6), so concurrent proofs cannot pass
  it. A wrong proof keeps the reservation as the counted failure, ends a challenge out of attempts and is audited once per window
  (`identity.step_up.failed`); a passkey proof runs the F14 counter rule under the credential's row lock. A right proof marks the
  challenge proved with an expiry of `stepUpEvidenceTtl` (at most five minutes) from now, keeps the session's authentication epoch
  and recovery generation, gives the reservation back and upgrades a `mobile.limited` session. A right proof whose transaction
  failed in the store gets its reservation and its attempt back (F9, D2), except after an unanswered commit, whose effect is
  unknown. A challenge of another session is `STATE/not_found`; a proved one presented again `CONFLICT/code_reused`.
- **Consume.** The sensitive call consumes the evidence in its own transaction (`identity.ConsumeEvidence`): same account,
  session, class and target hash, unexpired, and the session's current authentication epoch and recovery generation. It locks the
  challenge, so two concurrent calls cannot use one proof, and consumes it once; without evidence the call is
  `AUTHENTICATION/step_up_required` and rolls back, so the same command succeeds after a step-up. Removing a credential moves the
  authentication epoch of the account's live sessions, which spends every evidence proved before it
  (`TestStepUpEvidenceIsSingleUse` covers each case).

## Account writes

- **Passkey registration.** `BeginPasskeyRegistration(display_name)` consumes the account's `identity.beginPasskeyRegistration`
  evidence in the transaction that creates a registration flow bound to the account, the session and its channel (a cookie
  session's flow to the browser channel and the relying party's origin), and returns creation options that exclude the account's
  passkeys; the account must be active. The display name becomes the credential's label and follows the credential label rule: 1
  to 64 UTF-16 units of plain text that is not only white space. The contract allows up to 256 characters; a longer name is refused
  with `VALIDATION/invalid_argument` (`display_name: length`), a blank one with `display_name: pattern`.
  `CompletePasskeyRegistration(flow_id, credential)` answers a replay from its receipt first, then counts the flow's one attempt,
  verifies the creation outside any transaction (attestation `none` only, read from the attestation object before go-webauthn
  parses it, G3) and, under the receipt, consumes the flow and stores the credential. A creation that does not verify is
  `VALIDATION/invalid_argument` (`credential: not_verified`) and ends the flow; a credential ID registered already, to this
  account or another, revoked ones included, is `CONFLICT/already_exists` (`state.resource` kind `credential`; the caller named it
  by its WebAuthn ID). Two completions of one flow store one credential (`TestAPasskeyRegistersOnceWithItsLabel`).
- **Profile.** `UpdateProfile(patch)` changes `display_name`, `locale` and `timezone` (the profile values above; field paths
  `patch.*`); an avatar change is `VALIDATION/invalid_argument` (`patch.avatar: not_offered`) until avatars exist.
- **Credential names and removal.** `RenameAuthIdentity` sets a credential's label by the label rule (field `name`).
  `RemoveAuthIdentity` revokes a credential: it locks the account, so concurrent removals run one after the other, refuses the last
  live credential with `STATE/invalid_state` (`state.reason = last_credential`; there is no recovery path yet,
  `TestTheLastCredentialStays`) and moves the authentication epoch of the account's live sessions.
- **Sessions.** `RevokeSession(session_id)` revokes an `account` or `mobile.limited` session of the account: the caller's own is a
  sign-out without evidence, another needs the session's evidence. A node, push or automation session, another account's and an
  ended one are `STATE/not_found`. `RevokeAllSessions` revokes every account session but the caller's; node and push credentials
  stay (DC-03).
- **Devices.** `DeviceService.Rename` names a live device (1 to 64 characters of plain text). `DeviceService.Revoke` revokes a live
  device in one transaction (DC-17): the device (trust level revoked, remote control off), its installations, every session on it
  whatever its scope, and each registered participant's rows (the participants of AF-CTR-04's node enrolment and AF-CLD-02's
  pairing; the interface is `device.Participant`, `TestRevocationReachesEachCredentialKindOfItsTarget`). The next call of any of
  those credentials is the transport refusal `auth.credential_revoked`, and a refresh `AUTHENTICATION/credential_revoked`. The
  caller's own device needs no evidence; its revocation signs the caller out. A sign-in that claims an installation of the revoked
  device is refused with `AUTHENTICATION/credential_revoked` until AF-PLAT-01's sweep deletes the device and its installations,
  30 days after the revocation ([PostgreSQL store](postgres-store.md#identity-and-device-af-ctr-03)); the same client
  installation ID is then accepted as new, so revoking an installation ID lasts 30 days (the ID is not a credential).

A write whose `meta.expected_rev` is set changes only that revision of its object (`CONFLICT/revision_conflict` with both
revisions otherwise): the account for UpdateProfile, the credential for RenameAuthIdentity, the device for DeviceService.Rename. An
object of another account is `STATE/not_found` with the ID the caller sent, exactly as an unknown one
(`TestAnAccountCannotReachAnotherAccountsObjects`).

## Command receipts

Every write with a receipt in the table requires `meta.command_id` (`VALIDATION/invalid_argument`, `meta.command_id: required`)
and runs at most once per account and command ID under `platform.Execute` (AD-0021 §10): the receipt row, then the evidence's
consumption, the change and its audit event, in one transaction. A success keeps the reply message (never a token) and a refusal
whose retry advice is `NEVER` keeps its `ArcError`; a replay of the same request answers either again, with the replay's own
correlation id, without new evidence or a second effect. Any other refusal (`step_up_required`, `rate_limited`, `overloaded`) or
failure rolls the receipt back, so the same command can succeed after the step-up or the wait its advice names. The same command ID
with another request is `CONFLICT/command_id_reused`; one whose first execution is still running is `RESOURCE/overloaded`. A
receipt's reply states the command ID, the effect `HAPPENED` and, for a write of one object, the revision it produced
(RevokeAllSessions changes many and states none).

## Sign-in

**Passkeys** (AD-0011 §4). `BeginAuthentication(PASSKEY, AUTHENTICATE, installation)` creates a native flow with a 32-byte
challenge and returns discoverable request options (no allowed credentials, user verification `required`, algorithm ES256).
`CompleteAuthentication(flow_id, proof.passkey)` verifies the assertion with go-webauthn outside any transaction and then, in one
transaction, consumes the flow, advances the credential's counter, finds or creates the device and installation of the flow's
claim and issues an `account` session. The policy is fixed: the RP ID is the host of the public base URL and the only origin its
origin (no cross-origin, no top origins, no Android origins until the Android task); user verification is required on every
ceremony; ES256 only; attestation `none` only; the assertion's user handle must be the credential owner's; a counter that does not
advance is refused; every library error is one refusal. The attestation object's `fmt` is read (CBOR) before go-webauthn parses
it, so another format never reaches the library's attestation verifiers (G3, `TestOnlyANoneAttestationReachesTheLibrary`; the
fuzz target `FuzzCeremonyPayloads` runs both ceremonies' payloads through the relying party). A credential ID may have up to 1023
bytes, the contract's and WebAuthn's bound (`TestThePasskeyCredentialIDBoundIsTheContracts`). A public base URL whose host is an
IP address cannot be a relying party: a self-hosted center's default leaves identity off and logs why; an explicit surface list
refuses to start.

**Profile values.** A display name is plain text of 1 to 128 UTF-16 units; a locale a BCP 47 shaped tag of at most 35 characters; a
time zone an IANA name shape of at most 64 characters within the contract's timezone pattern, which has no `+` (so `Etc/GMT+5`
is refused and `Etc/GMT-5` admitted).

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
(`ARCFORGES_CENTER_BOOTSTRAP_SHA256`, `ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT`, at most seven days ahead). The digest is the SHA-256 of
the exact token text, its `afb1.` prefix included, in lowercase hexadecimal: `printf %s "$TOKEN" | sha256sum`
(`session.BootstrapDigest`, pinned by a known-answer test). A past expiry still starts the center: the bootstrap is refused as
expired, and the start-up log warns that the two variables can be removed, which the owner does once the account exists. The owner runs
`BeginAuthentication(PASSKEY, ENROLL, installation)`, which always returns creation options, whatever the bootstrap's state, and is
rate limited, then `CompleteEnrollment(flow_id, proof.local_code = token, credential.passkey, profile.display_name)`. The token is
compared first, in constant time, before any WebAuthn verification or write; a disabled, expired, used or wrong bootstrap and an
existing account all answer `AUTHENTICATION/unauthenticated`, the reason only in the audit event `identity.bootstrap.refused`. A
wrong token counts in its client prefix's bucket; there is no global bucket, so nobody can lock the owner out. The creating
transaction takes the bootstrap's advisory lock and inserts the singleton `identity.bootstrap` row, so concurrent attempts create
one account (`TestConcurrentBootstrapsCreateOneAccount`). The token never appears in the repository, a log or a database row. A2
adds the operator script that generates it and the proof environment's dispatch inputs.

**A store failure after a verified proof** (F9). A flow's attempt is taken before its proof is checked. When the proof verified (a
passkey assertion, an e-mail code, the bootstrap token and creation) but the success transaction failed in the store, the reply is
`RESOURCE/overloaded` with `AFTER_TIME` and the attempt is given back, best effort, so the identical retry succeeds; a wrong proof
never gets its attempt back, and a flow consumed meanwhile is never changed (`TestAStoreFailureAfterTheProofGivesTheAttemptBack`).
A right e-mail code gives back its failure reservation as well (D2, `TestARightCodeWhoseSignInFailedGetsItsReservationBack`), and a
first sign-in that loses the race for a new installation to another credential's is such a store failure (a contention, D4,
`TestALostRaceForANewInstallationGivesTheAttemptBack`).
The passkey counter is checked again under the credential's row lock with go-webauthn's rule: a counter that does not exceed the
stored one is refused unless both are zero (`TestThePasskeyCounterIsRecheckedUnderTheRowLock`).

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
presented digest as spent and issues the next generation, and reads the session's device for the reply in the same transaction, so a
reply that cannot be built leaves the token unspent. A spent digest presented again is a reuse: every live session of its family is
revoked, `identity.session.refresh_reused` is audited when the reuse revoked a session (later presentations of the family's spent
tokens are only counted, in the `refresh`/`reused` metric) and the call answers `AUTHENTICATION/credential_revoked`. There is
no grace window: a client that lost the response to a refresh must sign in again (`TestRefreshRotatesAndAReusedTokenRevokesTheFamily`
pins this). Two concurrent refreshes with one token serialize on the row and the second revokes the family.

**Lists.** ListSessions lists the account's live `account` and `mobile.limited` sessions, newest first, marking the caller's; a
session is live while it is not revoked and within its absolute and its sliding expiry (a browser session's idle expiry, a native
session's refresh expiry).
DeviceService.List lists the account's live devices with their live installations; a browser's device is listed only while it has
a live session, and a revoked device is not listed. ListAuthIdentities lists the live credentials. Pages hold at most 100 items
(default 50); a cursor is opaque and bound to its listing, and a malformed one, or one whose instant is outside the contract's
range (years 1 to 9999), is `VALIDATION/invalid_cursor`. A full page of 100 devices fits the method's 64 KiB reply budget, which the
center's Connect writer admits (`TestAFullDevicePageIsSent`).

## Identity policy

Every lifetime and limit comes from one source, `config.IdentityPolicy`, with these defaults. An operator may override values
within their bounds with `ARCFORGES_CENTER_IDENTITY_POLICY`, a JSON object (durations as Go duration strings, counts as
integers; unknown or repeated keys and values out of bounds refuse to start). The hosted Worker passes it only where `wrangler.json`
sets it: only the acceptance environment does, with its anonymous-flow ceiling (below).

| Setting                                                        | Default              | Bounds                       |
| -------------------------------------------------------------- | -------------------- | ---------------------------- |
| `accessTokenLifetime`                                          | 15m                  | 1m to 1h                     |
| `refreshIdleLifetime` / `refreshAbsolute`                      | 720h / 2160h         | 1h to 2160h / 1h to 9600h    |
| `browserIdle` / `browserAbsolute`                              | 30m / 12h            | 1m to 24h / 10m to 168h      |
| `passkeyFlowLifetime` / `emailCodeLifetime`                    | 5m / 10m             | 1m to 15m / 1m to 30m        |
| `emailCodeAttempts` / `emailCodeSends` / `emailCodeIterations` | 5 / 3 / 20000        | 1–10 / 1–3 / 10000–600000    |
| `stepUpEvidenceTtl` (A1b)                                      | 5m                   | 1m to 5m                     |
| `signInPerPrefix` (begin, completion, redemption)              | 30 per 10m           | limit 1–10000, window 1m–24h |
| `signInFailuresAccount` (failed proofs per account)            | 10 per 10m           | as above                     |
| `emailPerPrefix` / `emailPerAddress` (code sends)              | 10 per h / 5 per h   | as above                     |
| `redeemFailuresAddress` (wrong codes per address)              | 10 per h             | as above                     |
| `refreshPerPrefix`                                             | 120 per 10m          | as above                     |
| `stepUpPerAccount` (A1b)                                       | 10 per 10m           | as above                     |
| `bootstrapPerPrefix` (refused bootstraps)                      | 10 per h             | as above                     |
| `anonymousFlows` (every flow an anonymous call creates)        | none (limit 0) per h | limit 0–10000, window 1m–24h |

A prefix is the client address's /24 (IPv4) or /56 (IPv6) network; an IPv4-mapped address counts as IPv4. A bucket is the
SHA-256 of its kind and key in `platform.rate_limit`, counted in its own short transaction before the work it guards. A refusal is
`RESOURCE/rate_limited` with `retry_at` and a `LimitFailure` naming the bucket kind; the first refusal of a request bucket's window
is audited as `identity.rate_limited`, the others only counted. The failed-proof buckets of an account (or of an unknown credential's
digest) and of an address count only failures, so two prefixes cannot together exceed an account's limit. A wrong e-mail code is
reserved in its address's bucket before the code is checked, in one statement that counts only under the limit, so concurrent codes
over several flows reach the check at most the limit's number of times; a refused reservation gives the flow attempt back, and a
right code gives its reservation back with its sign-in, or in its own short transaction when the sign-in failed in the store
(`TestConcurrentWrongCodesNeverPassTheAddressLimit`). A failed proof is audited once per window: a failure that names an account
once per account, an anonymous one (an unknown credential, any e-mail code) once per client prefix, whatever keys it names, through
a marker of its own class, so an account's failure never takes it (D3, `TestAnonymousFailuresAreAuditedOncePerPrefix`).

**Anonymous-flow ceiling** (C1). `anonymousFlows` is an opt-in global bucket (`anonymous_flows`, one key for every client): every
flow an anonymous call creates counts in it (BeginAuthentication of every method and purpose, the owner's enrollment included), and
past it BeginAuthentication is `RESOURCE/rate_limited` with `retry_at`, the first refusal of a window audited. A limit of 0, the
default, sets none. Only the acceptance environment sets one, 600 flows per hour (`wrangler.json`, pinned by
`tests/worker/center-config.test.ts` and `TestTheProofCompositionRequiresTheWorkersClientAddress`): `proof` shares the production
Neon project and compute, and the runtime role can never delete, so until AF-PLAT-01's retention sweeps exist its identity tables
only grow. The ceiling bounds the flows anonymous calls create and the failure rows and audit markers that need a flow
(CompleteAuthentication, RedeemEmailCode). It does not bound the prefix-keyed request and bootstrap buckets (`sign_in_prefix`,
`refresh_prefix`, `bootstrap_prefix`: one row per distinct client /24 or /56, reset in place each window), which are counted before
any flow is read, or the once-per-window refusal audits (`identity.rate_limited`, `identity.bootstrap.refused`): those grow with
distinct client prefixes, and the audits with prefixes times windows, until the sweeps. Production sets none: one global bucket
would let anyone lock every sign-in out, so AF-PROD-01 decides about it together with the sweeps. The owner can also drop the whole
acceptance database `arcforges_acceptance` ([PostgreSQL store](postgres-store.md#acceptance-environment)).

**Client address.** In official-hosted mode the Worker sets `x-arcforges-client-ip` from `cf-connecting-ip` (never from the
client's own header) and omits it when Cloudflare sent none; the center needs exactly one valid value, refuses a call without one
(`validation.invalid_request`) and refuses to start with a surface enabled unless `ARCFORGES_CENTER_CLIENT_IP_HEADER` names that
header. A self-hosted center keys by the TCP peer, or by exactly one valid header value when the peer is in
`ARCFORGES_CENTER_TRUSTED_PROXIES` (CIDR prefixes). The acceptance composition is tested as deployed: official-hosted, identity on,
that header without trusted proxies, the proof host as relying party; a call without exactly one address is refused before the store
(`TestTheProofCompositionRequiresTheWorkersClientAddress`). The Worker's own edge limits key a client by its address, an IPv6 client by
its /64 ([deployment](deployment.md)).

## Refusals

Every domain refusal is one row of ArcForges-Design `contracts/errors.md`, rendered as `ArcError` (snake_case code, category,
`message_key` `error.<category>.<code>`, retry advice, effect `DID_NOT_HAPPEN` except `INTERNAL/internal`, whose effect is `UNKNOWN`) with the call's
correlation id, in the reply with gRPC `OK`:

| Refusal                             | When                                                                                                                                                                                    |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VALIDATION/invalid_argument`       | a field outside its rule (`state.reason` = field path and rule), a method or purpose not offered                                                                                        |
| `VALIDATION/invalid_cursor`         | a malformed page cursor, one of another listing or one whose instant is out of range                                                                                                    |
| `AUTHENTICATION/unauthenticated`    | a wrong or unknown proof, an account that may not sign in, a refused bootstrap (all alike)                                                                                              |
| `AUTHENTICATION/token_expired`      | an expired refresh token                                                                                                                                                                |
| `AUTHENTICATION/credential_revoked` | a revoked session, device or installation; a reused refresh token                                                                                                                       |
| `AUTHENTICATION/step_up_required`   | a write without its evidence, or a `mobile.limited` session on an `upgrade` row (retry the same command after a step-up)                                                                |
| `AUTHORIZATION/permission_denied`   | a scope or account state the operation does not admit; another account's installation                                                                                                   |
| `CONFLICT/code_reused`              | a completed flow or proved step-up presented again, or a completion still in progress                                                                                                   |
| `CONFLICT/already_exists`           | a passkey whose credential ID is registered already (`state.resource` kind `credential`)                                                                                                |
| `CONFLICT/revision_conflict`        | a stale `meta.expected_rev` (`RevisionConflict` with the expected and the current revision)                                                                                             |
| `CONFLICT/command_id_reused`        | a command ID used before with another request                                                                                                                                           |
| `STATE/not_found`                   | an unknown or invisible flow, step-up challenge, session, credential, device or account; `state.resource` names its kind and the ID the caller sent (F19)                               |
| `STATE/invalid_state`               | the last live credential (`last_credential`); an account whose state does not allow the change (`credentials_locked`)                                                                   |
| `STATE/expired`                     | an expired flow, or one whose attempts are exhausted                                                                                                                                    |
| `STATE/not_activated`               | a method of a disabled surface (`state.reason` = the surface)                                                                                                                           |
| `RESOURCE/rate_limited`             | a rate-limit bucket over its limit, or a flow's sends exhausted (`email_code_sends`)                                                                                                    |
| `RESOURCE/overloaded`               | the store is unreachable or contended (before any commit, or an unanswered commit of a transaction that carries no effect of the call: retry after a while)                             |
| `INTERNAL/internal`                 | the call's effect write whose commit went unanswered (effect `UNKNOWN`, retry `NEVER`); anything else (retry after a while); logged with the correlation id, never with request content |

The ingress adds two transport refusals for a known bearer (both gRPC 16 `UNAUTHENTICATED`): `auth.token_expired` and
`auth.credential_revoked`. They need companion rows in errors.md's center ingress table (DC-14).

## Audit

Events are appended to the platform audit chain (`platform.AppendAudit`) as the last statement of the transaction they describe,
or in their own transaction for a refusal: `identity.sign_in.succeeded`, `identity.sign_in.failed` (the first failure of a window
per account, or per client prefix for an anonymous failure), `identity.bootstrap.completed`, `identity.bootstrap.refused` (first per
window, with the reason), `identity.session.refresh_reused` (when a reuse revoked a session), `identity.rate_limited` (first per
window) and `access.refused`; since A1b `identity.step_up.proved`, `identity.step_up.failed` (first per window),
`identity.passkey.registered`, `identity.profile.updated`, `identity.credential.renamed`, `identity.credential.removed`,
`identity.session.revoked`, `identity.sessions.revoked_all`, `device.renamed`, `device.revoked` (with the revoked installations,
sessions per scope and participant rows) and the operator's `identity.sessions.revoked_by_operator`. Payloads are closed JSON:
method, channel, scope, reasons and counts, never a token, code, e-mail address or IP address. A sign-in, a credential removal or a
device revocation whose audit event cannot be written is refused and writes nothing (`TestARefusedAuditRefusesTheSignIn`,
`TestARefusedAuditRefusesTheWrites`).

## Transactions per request

| Call                             | Transactions                                                                                                                                                                                               |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BeginAuthentication              | 1 bucket count (2 with the anonymous-flow ceiling), 1 flow insert (+1 audit on a first refusal)                                                                                                            |
| CompleteAuthentication (passkey) | 1 bucket count, 1 credential read, 1 bucket check, 1 attempt, then 1 success transaction (or 1 flow end and 2 failure counts; 1 attempt release after a store failure)                                     |
| RequestEmailCode                 | 2 bucket counts, 1 flow update (PBKDF2 before it, the mail after the response)                                                                                                                             |
| RedeemEmailCode                  | 1 bucket count, 1 flow read, 1 bucket check, 1 attempt, 1 failure reservation, then 1 success transaction (or 1 failure marker count; 1 attempt release and 1 reservation give-back after a store failure) |
| CompleteEnrollment               | 1 account check, 1 attempt, 1 creating transaction under the advisory lock (or 1 bucket count and 1 audit)                                                                                                 |
| RefreshSession                   | 1 bucket count, 1 rotation that also reads the device                                                                                                                                                      |
| Session reads                    | 1 read-only credential check (ingress), 1 read-only query (+1 audit on an access refusal)                                                                                                                  |
| BeginStepUp                      | 1 bucket count, 1 challenge insert (PBKDF2 before it for an e-mail code, the mail after the response)                                                                                                      |
| CompleteStepUp                   | 1 bucket check, 1 attempt, 1 failure reservation, then 1 proof transaction (or 1 denial and 1 failure marker count; 1 attempt release and 1 reservation give-back after a store failure)                   |
| BeginPasskeyRegistration         | 1 transaction: the evidence's consumption and the flow                                                                                                                                                     |
| CompletePasskeyRegistration      | 1 receipt lookup, 1 attempt, then 1 receipt transaction (or 1 flow end after a refusal; 1 attempt release after a store failure)                                                                           |
| Other writes                     | 1 receipt transaction: the receipt, the evidence's consumption, the change and its audit event                                                                                                             |

No transaction is open while PBKDF2, WebAuthn or the mail provider runs. Each transaction is the call's effect or auxiliary
bookkeeping (counts, reservations, denials, give-backs, refusal audits; D10), which decides what an unanswered commit answers
([PostgreSQL store](postgres-store.md#guarantees)); `TestEveryTransactionOfTheSurfaceStatesItsRole` pins the role of each by
name, and `TestALostCommitOfTheCallsEffectIsUnknown` and `TestALostCommitOfBookkeepingIsRetryable` lose a commit of each kind. The
runtime pool stays four connections ([PostgreSQL store](postgres-store.md#connection-budgets)).

## Surface switch

The identity methods form the `identity` surface. The center and the generated Worker table tag them by surface
(`surfaceRoutes`, PLT-18: `productionRoutes` stay always on); `ARCFORGES_CENTER_SURFACES` (center) and `FLAGSHIP_SURFACES`
(Worker) list the enabled surfaces as exact generated names, comma-separated. Official-hosted mode enables none unless listed;
self-hosted mode enables every known surface unless listed (an explicit list pins the surfaces across upgrades; `none` enables
none). A disabled surface's method is answered with the domain refusal `STATE/not_activated` (`state.reason = identity`): by the
Worker from the generated reply, before any rate limit, credential, body or Container (`tests/worker/ingress-surfaces.test.ts`), and
by the center with the call's correlation id (logged and counted as an OK reply with that id). An enabled one passes the Worker's own
edge limit `IDENTITY_RATE_LIMITER` (over it, the generated domain refusal `RESOURCE/rate_limited` with its `retry_at`: the refusal's
time rounded up to the second plus the limiter's 60-second period) before it is forwarded. The Worker passes its parsed list to the Container as
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
- **The acceptance ceiling is reached** (every new proof sign-in answers `anonymous_flows`): it resets after its window. To change it,
  edit the acceptance environment's `ARCFORGES_CENTER_IDENTITY_POLICY` in `wrangler.json` through a reviewed PR; to reclaim the
  space, the owner may drop `arcforges_acceptance` (the next acceptance deployment recreates and migrates it).
- **Mass session revocation** (an incident): `arcforges-center admin revoke-sessions --account <uuid>` revokes every unrevoked
  session of one account, `--all` of every account, whatever the scope. It reads the migration role's variables
  (`ARCFORGES_CENTER_MODE`, `ARCFORGES_CENTER_MIGRATION_DATABASE_URL`), revokes and audits
  `identity.sessions.revoked_by_operator` (actor `operator:cli`) in one transaction and prints the counts per scope as JSON;
  every revoked credential is refused at its next call.
- **Rollback**: an application rollback keeps migration 0002 and its `Schemas` and `RuntimeGrants` entries (the store never
  migrates down; [PostgreSQL store](postgres-store.md#recovery)).

## Native token documents

The Go center does not serve the version-1 native token documents (`public/http/v1/native-auth.schema.json`): their
`NativeTokenResponse` cannot list `arcforges-*` installations. An `arcforges-mobile` installation signs in through the
IdentityService API above. A node signs in through `fleet.v1.NodeEnrollmentService` (AF-CTR-04); AF-CLD-02 is QR pairing only. The
document of the Android Custom Tab's native authorization is still open and owned by the Plan.
