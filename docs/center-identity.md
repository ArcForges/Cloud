# Accounts, sessions and devices on the center

AF-CTR-03 moves accounts, sessions and devices to the Go [center](center.md) (ArcForges-Design AD-0011, AD-0021 §3 to §7 and §10,
data/cloud-store.md §2 and §6). It lands in parts, each deployable dark:

- **A1a (merged):** the identity and device store (migration 0002, whole), the identity core, sign-in by passkey and e-mail
  code, the owner bootstrap, native sessions with rotating refresh tokens, the credential verifiers of the ingress, the account
  reads, rate limits, audit, the closed operation table and the `identity` surface switch in the center and the Worker.
- **A1b (merged):** step-up, sign-out and session revocation, passkey registration of a signed-in account, profile,
  credential and device changes, device revocation and its cascade, command receipts for those writes and the incident command
  `admin revoke-sessions`. It adds no migration: migration 0002 already holds every table it writes.
- **A2 (this change):** the account pages and the contract `/session/v1/web` browser routes (cookie sessions, CSRF, the bootstrap
  page) on the new `pages` surface, the Worker's page handler, the proof bootstrap script and dispatch inputs and the real-browser
  acceptance script ([account pages](#account-pages-and-browser-sessions), [proof bootstrap and acceptance](#proof-bootstrap-and-acceptance)).
  It adds no migration: the browser session, device and installation rows were migration 0002's.
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
| `center/internal/pages`                      | The account pages (`html/template`), their one script and style sheet, the `/session/v1/web` routes and the forms (A2)         |
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
account-session scopes, `account` and `mobile.limited` (the HUMAN principal): a `node`, `push` or `automation` credential is
refused with `AUTHORIZATION/permission_denied` (state.reason = the operation ID) before the handler does anything, nothing is
written, and the refusal is audited as `access.refused` with the reason `principal` (a node or automation credential, the AGENT
principal, on a HUMAN operation) or `scope` (a push or unknown scope); no production policy admits them (SEC-15). A restricted account reaches only its security
operations, the rows marked restricted (`TestOnlyAccountSessionsReachTheSessionMethods` walks every session row of the table for
each refused scope and for a restricted account, and fails for a row it has no request for). A `mobile.limited` session (a phone
that signed in without verifying its user, android.md A-09) is refused an `upgrade` row with `AUTHENTICATION/step_up_required`
(retry the same command) before the handler runs, and an `own: allowed` row on another session or device by the handler before
anything is written; signing itself out and removing its own phone stay open to it (T-19, `TestMobileLimitedNeedsStepUp`, which
walks the table and fails for a row it has no request for). Proving any step-up upgrades the session to `account`; the center's
own class `identity.upgradeSession` exists for a phone that only wants to unlock everything.

Since AF-CTR-03 part B `Authorize` decides a session call in seven ordered stages, and a stage that refuses ends the decision:
authentication, ownership of the object the call addresses (another account's object is `STATE/not_found`; a row names an `Object`
and the handler hands `AuthorizeSubject` its owner), scope and risk (known scope, restricted account, session upgrade),
AGENT/HUMAN separation, the resource controls (a hook for the quotas and budgets of AF-CTR-04, DC-07), the audit that comes before
the call (`access.authorized`, a failed append refuses the call) and the feature gate (`ENTITLEMENT/feature_not_entitled`,
`state.reason` = the feature key, audited as `access.gated`). A row carries the gate's key as `Feature`; every identity row is an
essential operation with none, so nothing here is gated, and the R3 rows keep appending their audit event in the transaction of
their effect (`AuditInTransaction`). The gate and its tests are described in [feature availability](center-entitlement.md#the-gate).

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
  reserves one failure in that bucket under its limit (the reservation of a wrong e-mail code, E6), so concurrent proofs cannot
  pass it. A wrong proof keeps the reservation as the counted failure, ends a challenge out of attempts and is audited once per
  window (`identity.step_up.failed`); a passkey proof runs the F14 counter rule under the credential's row lock. A right proof
  marks the challenge proved with an expiry of `stepUpEvidenceTtl` (at most five minutes) from now, keeps the session's
  authentication epoch and recovery generation, gives the reservation back and upgrades a `mobile.limited` session; a challenge
  whose session's epochs moved since it began (a credential removed meanwhile) is `STATE/expired` and upgrades nothing. A passkey
  proof must be a passkey of the caller's own account. A right proof whose transaction failed in the store gets its reservation
  and its attempt back (F9, D2), except after an unanswered commit, whose effect is unknown. A challenge of another session is
  `STATE/not_found`; a proved one presented again `CONFLICT/code_reused`.
- **Consume.** The sensitive call consumes the evidence in its own transaction (`identity.ConsumeEvidence`): same account,
  session, class and target hash, unexpired, and the session's current authentication epoch and recovery generation. It first
  locks the account's row, the lock a credential removal holds while it moves the authentication epoch, so the account lock orders
  a consumption after a concurrent removal: the evidence is read only once the removal committed, and evidence proved before it is
  spent (`TestARemovalSpendsTheEvidenceProvedBeforeIt`). It then locks the challenge, so two concurrent calls cannot use one proof,
  and consumes it once; without evidence the call is `AUTHENTICATION/step_up_required` and rolls back, so the same command succeeds
  after a step-up. Removing a credential moves the authentication epoch of the account's live sessions, which spends every evidence
  proved before it (`TestStepUpEvidenceIsSingleUse` covers each case, including evidence of another class whose target hash names
  the same target).

## Account writes

- **Passkey registration.** `BeginPasskeyRegistration(display_name)` consumes the account's `identity.beginPasskeyRegistration`
  evidence in the transaction that creates a registration flow bound to the account, the session and its channel (a cookie
  session's flow to the browser channel and the relying party's origin), and returns creation options that exclude the account's
  passkeys; the account must be active. The display name becomes the credential's label and follows the credential label rule: 1
  to 64 UTF-16 units of plain text that is not only white space. The contract allows up to 256 characters; a longer name is refused
  with `VALIDATION/invalid_argument` (`display_name: length`), a blank one with `display_name: pattern`.
  `CompletePasskeyRegistration(flow_id, credential)` answers a replay from its receipt first, then counts the flow's one attempt,
  verifies the creation outside any transaction (attestation `none` with exactly the empty statement, read from the attestation
  object before go-webauthn parses it, so no statement parser of another format runs, G3) and, under the receipt, consumes the flow
  and stores the credential. A flow of another account or of another session of the account is `STATE/not_found`
  (`TestARegistrationFlowIsItsBeginningSessions`). A creation that does not verify is `VALIDATION/invalid_argument`
  (`credential: not_verified`) and ends the flow. Every refusal of this method decided before the receipt (`not_found`,
  `expired`, `code_reused`, `invalid_argument` including a missing `meta.command_id`, `flow_id` or `credential`,
  `permission_denied`) is not kept by a receipt, and its replay is decided afresh; `not_verified` is the one that ends the flow,
  so its identical replay, like any later completion of that flow, answers `STATE/expired`. A credential ID registered
  already, to this account or another, revoked ones included, is `CONFLICT/already_exists` (`state.state` `credential`); its
  `state.resource` names the account's own live credential with that ID and is left out otherwise, so another account's credential
  is never named. Two completions of one flow store one credential (`TestAPasskeyRegistersOnceWithItsLabel`); a duplicate of the
  command sent while its first execution still runs is `RESOURCE/overloaded` (retry after a while) and its retry answers the
  receipt (`TestADuplicateOfARunningRegistrationIsBusy`). The first execution takes its attempt before the flow expires, and its
  success transaction ends within the store's transaction bound (10 s) after that, so the flow's attempt counts as held by a
  running completion until the flow's expiry plus `identity.RunningGrace` (15 s): a duplicate that arrives after the flow's
  five-minute expiry while the first execution is still in its transaction is told the same (A-1,
  `TestADuplicateAfterTheFlowsExpiryWhileTheFirstRunsIsBusy`), never the final `STATE/expired` of a command that then commits. A
  duplicate whose attempt comes just after the first execution committed finds the flow consumed and answers that receipt too,
  from a second receipt lookup (`TestADuplicateRefusedAfterItsFirstCommittedAnswersTheReceipt`); a duplicate with the same command
  ID and other request bytes meets the first's receipt there and is `CONFLICT/command_id_reused`
  (`TestADuplicateWithAnotherPayloadIsACommandIDReusedAfterTheFirstCommitted`). When that second lookup fails, the command may have
  committed, so the duplicate answers the lookup's own failure (`RESOURCE/overloaded` with its `retry_at`), never the consumed
  flow's final `code_reused`, and its retry replays the receipt (`TestADuplicateWhoseSecondLookupFailsIsRetryable`). Only the
  refusals a committed first execution causes look again (`code_reused`, `expired`, the busy store and a store failure); a creation
  that does not verify, a flow that is not the caller's and a malformed request are decided by the request alone (a duplicate never
  verifies: the first execution took the flow's only attempt), so a failing lookup cannot replace `credential: not_verified` with
  `RESOURCE/overloaded`, after which the retry would find the flow ended and the reason lost
  (`TestAVerificationFailureIsAnsweredWhenTheSecondLookupWouldFail`). An attempt that is never settled answers
  `RESOURCE/overloaded` until the flow's expiry plus `identity.RunningGrace`, then `STATE/expired`
  (`TestAnAttemptNeverSettledTurnsExpiredAfterTheGrace`): the process stopped before the attempt was settled, or the store failed
  when the attempt was to be given back or the flow ended (the flow's end after `not_verified` or an abandoned registration). That
  store failure after a verification failure is the one double fault left: the flow's attempt stays unsettled, the first answer is
  `RESOURCE/overloaded`, and the advised retries meet `STATE/expired` once the flow and its grace have ended, so the
  `not_verified` reason is not delivered; nothing is stored, and the client begins a new registration.
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
- **Devices.** `DeviceService.Rename` names a live device by the label rule (field `name`: 1 to 64 UTF-16 units of plain text that
  is not only white space; a longer name is `name: length`, a control character or a blank name `name: pattern`). Every name it
  admits meets the contract's 256-character bound and the store's 64 code points. `DeviceService.Revoke` revokes a live
  device in one transaction (DC-17): the device (trust level revoked, remote control off), its installations, every session on it
  whatever its scope, and each registered participant's rows (DC-06, DC-17: AF-CTR-07's agent grants and AF-CLD-06's push
  registrations register one; none is registered in AF-CTR-03, and the tests use a stand-in; the interface is
  `device.Participant`, `TestRevocationReachesEachCredentialKindOfItsTarget`). The next call of any of
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
consumption, the change and its audit event, in one transaction. A success keeps the reply message (never a token, never an e-mail
address) and a refusal whose retry advice is `NEVER` keeps its `ArcError`; a replay of the same request answers either again, with
the replay's own correlation id, without new evidence or a second effect. Any other refusal (`step_up_required`, `rate_limited`,
`overloaded`) or failure rolls the receipt back, so the same command can succeed after the step-up or the wait its advice names.
A refusal decided before the receipt is not kept either, and a replay is decided afresh: the access check's
(`permission_denied`, `step_up_required` on an `upgrade` row), the request's validation (a `RequestMeta` that names a workspace, a
missing `meta.command_id`, a missing `patch`, `patch.avatar: not_offered`, a missing `credential` or a missing object ID:
`flow_id`, `credential_id`, `session_id` or `device_id`) and CompletePasskeyRegistration's flow and creation checks; of these only CompletePasskeyRegistration's
`credential: not_verified` changes what its replay meets: it ends the flow, so the replay answers `STATE/expired`
([passkey registration](#account-writes)).

The same request is decided by a digest of the request message as transmitted, without `RequestMeta.correlation_id`
(`platform.RequestDigestInput`): the correlation is per attempt, so a retry under a new correlation id replays the receipt. The
message is walked field by field on the wire and the kept bytes are copied, never re-encoded: every other field counts, the body,
`meta.command_id` and `meta.expected_rev` included, so a request that differs in any of them is `CONFLICT/command_id_reused`
(`TestARetryWithItsOwnCorrelationReplaysTheReceipt`). The node's payload digest leaves out the whole `RequestMeta`; the center
keeps the rest of it because `expected_rev` changes what the command does. One whose first execution is still running is
`RESOURCE/overloaded`. A receipt's reply states the command ID, the effect `HAPPENED` and, for a write of one object, the revision
it produced (RevokeAllSessions changes many and states none).

UpdateProfile's receipt keeps the profile without `primary_email`: the first answer and every replay take the address from the
account's current live e-mail identity, so a replay never returns an address the account no longer holds
(`TestNoReceiptHoldsAnAddress` scans every receipt-guarded write's stored result). Receipt results still hold personal data for the
receipts' 90 days ([PostgreSQL store](postgres-store.md#identity-and-device-af-ctr-03)): UpdateProfile's the profile (display
name, locale, time zone, revision); CompletePasskeyRegistration's and RenameAuthIdentity's a credential summary (credential ID,
kind, label, creation and last-use times); DeviceService.Rename's the full device view (device ID, name, platform, trust level,
remote-control flag, revision, revocation time, and each installed product with its version and install time); the others only
the receipt (command ID, effect and the revision it produced, except RevokeAllSessions, which states none); a kept refusal its
`ArcError`, which can name the object the caller sent or, for `already_exists`, the account's own credential row ID.

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
one account (`TestConcurrentBootstrapsCreateOneAccount`). The token never appears in the repository, a log or a database row. The
operator script that generates it and the proof environment's dispatch inputs are described under
[proof bootstrap and acceptance](#proof-bootstrap-and-acceptance); the bootstrap page of the browser is described under
[account pages](#account-pages-and-browser-sessions).

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

## Account pages and browser sessions

The `pages` surface (A2; PLT-1, AD-0021 §7) is the center's own account UI and the contract's browser session routes
(`public/http/v1/web-browser.schema.json`, Contracts 62ccef1). A self-hosted center serves them without any Web deployment; the
hosted Worker forwards the same exact paths through its [page handler](cloud-ingress.md#page-routes-plt-1). The pages decide nothing the
API does not. The three list pages (passkeys, sessions, devices) and the profile the account page shows, the forms, the bootstrap
read's profile and the two step-up routes call the handler of the API method they stand for, in process, with the session of the
browser's cookie (`identityapi.Direct`); the sign-in and enrollment routes and the logout call
the identity core after the same operation-table decision (`access.Authorize`). So a page and the API share the operation table,
the step-up evidence, the rate-limit buckets and the audit events, and the forms share the command receipts as well. The logout
receipt is a reply shape only: the contract's logout has no command ID, so its reply carries a new one, nothing is stored and
nothing replays. A page never reads or writes a table.

| Route                                                                                       | Kind | Credential       |
| ------------------------------------------------------------------------------------------- | ---- | ---------------- |
| `GET /account/sign-in`, `/account/bootstrap`, `/account/account.js`, `/account/account.css` | page | none             |
| `GET /account/passkeys`, `/account/sessions`, `/account/devices`, `/account/sign-out`       | page | cookie session   |
| `POST /account/passkeys/{add,complete,rename,remove}`                                       | form | cookie session   |
| `POST /account/sessions/{revoke,revoke-all}`, `POST /account/devices/{rename,revoke}`       | form | cookie session   |
| `GET /session/v1/web/bootstrap`                                                             | JSON | optional session |
| `POST /session/v1/web/{authentication/begin,authentication/complete,enrollment/complete}`   | JSON | none (see CSRF)  |
| `POST /session/v1/web/{step-up/begin,step-up/complete,logout}`                              | JSON | cookie session   |

All paths are below the public base URL (`/api/...` on the hosted deployments). `/account` itself, profile editing (`UpdateProfile`
stays an API method), recovery, e-mail change and the provider callback are not pages; recovery and the callback are AF-ID-02's.
The browser channel offers the passkey method only: e-mail (and password and OIDC) is `not_offered` on it until the mail sender is
live (the mail PR), exactly as the API's e-mail method is left out while the sender is disabled.

**Cookie.** A sign-in (or the bootstrap) sets exactly one cookie in this byte form, and nothing else sets or reads another:
`__Host-af_session=<43 base64url characters>; Path=/; Max-Age=<seconds>; Secure; HttpOnly; SameSite=Strict`; a sign-out removes it with
`Max-Age=0`. There is no `Domain`. The session is idle for 30 minutes and absolute for 12 hours; it is renewed only by a page load
or the bootstrap read (`session.Renew`, one auxiliary transaction, never beyond the absolute expiry), never by a POST. A browser's
device and installation are created on its first sign-in: the installation claim (`WebBrowserInstallationClaim`, product
`arcforges-web`, platform `web`) is a random UUID the script keeps in the browser's local storage; a claim that belongs to another
account gets new rows. The device is named from the `User-Agent` by a closed set of families and systems ("Edge on Windows", a family alone,
"Browser on Linux", else "Web browser"), never by the header's text.

**Origin and CSRF.** Every POST needs exactly one `Origin` header equal, byte for byte, to the origin of the public base URL;
anything else is 403 before the session or the body is read. A GET may carry no `Origin` (a browser sends none for a same-origin
read) but one it carries must be exact. A route that needs a session also needs that session's CSRF token, derived (not stored) as
`HMAC-SHA-256(handle, "af-csrf-v1")` in base64url: the `X-AF-CSRF` header on a JSON route, the `csrf` field on a form (both, when
present, must agree). Before there is a session the three sign-in steps accept instead a public constant of the origin,
`base64url(SHA-256("af-csrf-pre-v1\n" + origin))`: it keeps a cross-site page from submitting them blindly, and nothing more is
claimed for it, because the steps are protected by the flow ID, the challenge, the WebAuthn origin binding and the rate limits as the
API methods are. The bootstrap read returns the token for the session that is there, or the constant. There is no flow cookie: the
flow ID travels in the JSON bodies, and a browser flow is bound to the origin it began on (`flow_origin`).

**Request rules** (every refusal of the center carries the security headers below; the Worker's own refusals are plain text with
`Cache-Control: no-store` and nothing else). Any query string, even an empty one, and any `Authorization`
header are 400; a body on a GET is 400; a POST has one `Content-Type` of the route's type (JSON routes `application/json`, forms
`application/x-www-form-urlencoded`, with at most the UTF-8 charset) or is 415, no `Content-Encoding`, and a body within the route's
bound (the contract's `x-arcforges-max-bytes`), declared or streamed, or is 413; JSON bodies are read strictly (unknown and repeated
keys refused). A method a path does not have is 405 and an unknown path 404. A disabled `pages` surface answers every page path 404: on the hosted
center that is the Worker's reply of a path it does not know (plain text, before anything about the request is read), on a
self-hosted center the handler's 404 with the security headers and no body. The statuses of a reply of the center that the Worker
keeps are 200, 303, 400, 403, 404, 413, 415 and 429 (a rate limit: the center's carries the ArcError's retry advice in its body); the
Worker turns any other status of the Container into its own 503. The statuses the Worker answers itself, without the Container, are
the 400, 403, 413, 415 and 429 of the request rules above (its edge limit sets `Retry-After`), 405 for a method a path does not
have, 408 for a body not read within the body budget, 499 for a client that went away and 504 for a call that outlasted
`pageDurationMs`. The contract defines no error body for these routes, so a refusal of a JSON route is the
[ArcError](center.md#arcerror-and-grpc-status) as JSON, `{"error": {"category", "code", "messageKey", "retry", "effect",
"correlationId", "details"}}`, and of a page an HTML page with a fixed text of its code (the center never sends text to show).
This is a gap of the contract document, routed to the Contracts and Design owners.

**Security headers.** Every reply of the center to a page route, refusals included, carries exactly these seven, and the Worker
rejects (503) a reply of the Container that lacks one or has another value. The Worker's own refusals (the request rules it applies
before the Container, 405, 408, 499, 504 and its own 503) are plain text with `Cache-Control: no-store` only:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'
X-Frame-Options: DENY
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)
Cache-Control: no-store, no-transform
X-Content-Type-Options: nosniff
```

`no-transform` is there for the edge, not for caches: Cloudflare's Web Analytics adds its beacon (a `<script>` from
`static.cloudflareinsights.com` and a `data-cf-beacon` attribute) to the HTML of a zone that has the automatic setup on, and a
`Cache-Control` header with `no-transform` stops it from touching the payload. The policy above blocks the script, but the browser
reports the block as a console error (the acceptance script rightly fails on it), and an edge-injected third-party script contradicts
"nothing external". Only a hosted run shows it, and plain `curl` does not (the edge injects into a browser's `Accept: text/html`
requests); the value is the generated one in `pageSecurityHeaders`, which the Worker, the acceptance script and the Go tests all hold
a reply to. The Worker's own plain-text refusals keep `no-store`: text/plain is never injected.

The pages are rendered with `html/template` (templates are `*.gohtml` files, so the formatter leaves them alone) and carry no inline
script, inline style, event handler or `style` attribute. The one script, `account.js` (an ES module), writes text only with
`textContent`, builds no markup and loads nothing from another origin; under `require-trusted-types-for 'script'` with
`trusted-types 'none'` a markup sink would fail in the browser. It runs the WebAuthn ceremonies and calls the JSON routes; every
account change itself is a plain form (POST, then a 303 back to the page), and a form that needs a step-up
(`data-step-up-class`) proves a passkey first and is then submitted as it is. The pages do not cache and are not transformed (`no-store, no-transform`).

**Return path.** A protected page without a session answers 303 to `<base>/account/sign-in#return=<percent-encoded path>`. The
fragment never reaches a server. The sign-in script follows a return value only when it is a path of its own origin (one slash and
then neither a slash nor a backslash, no control character or space, at most 512 characters, and still this origin and not `//` after
the parser has normalised it); anything else goes to the passkeys page (`tests/worker/account-script.test.ts`). The Worker admits a
`Location` only of the form `/api/account/<words>` with at most that fragment.

**Accessibility.** The pages are one column of semantic HTML: a skip link, one `h1` that takes focus on load, labelled fields, a
status line with `aria-live`, an error summary with `role="alert"` that takes focus, tables with captions and scoped headers (on a
narrow screen the header row is off screen and each cell shows the name of its column), buttons named for their row (the accessible
name begins with the text the button shows), `lang` and the viewport meta, and a style sheet with visible focus rings and light and
dark colours. A page lists at most 30 passkeys, sessions or devices and says when there are more, so that a full page stays within
the reply bound the Worker enforces. Everything but the three WebAuthn ceremonies, the step-up and the sign-out button works without
script. A page that needs its script says so in a `noscript` paragraph (the sign-in, bootstrap, creation and sign-out pages, and the
passkeys, sessions and devices pages for the changes that ask for a passkey first) and, for a script that is refused, blocked or fails
to load while scripting is on, in a line (`needs-script`) that the script removes when it starts. The rendered HTML is checked by `TestEveryPageIsAccessibleHTMLWithNothingExternal` (no inline script, style or event
handler and no reference to another origin either); the style sheet's focus rings and colours are not tested, and none of this is an
accessibility audit with assistive technology.

**Tests.** `center/internal/pages/*_integration_test.go` run the handler on real PostgreSQL: a success test for every route (a
`TestMain` gate fails when a route has none), the owner's bootstrap and its refusals, cross-account isolation (another account's passkeys,
sessions and devices are not found), Origin, CSRF, flow and media-type refusals, the rate limits shared with the API
methods, the cookie's byte form and lifetime, renewal, and a scan of the database, every `Set-Cookie`, the logs and the audit rows
for every generated token and handle. The Worker's page handler has byte-exact tests for its headers and its `Set-Cookie`
(`tests/worker/pages.test.ts`).

## Proof bootstrap and acceptance

The acceptance environment (`proof.arcforges.com`) is created by the owner's bootstrap and exercised by a real browser.

1. **Make the token** on the owner's own machine: `node eng/verification/proof-bootstrap.ts [--hours 24]`. It writes the token
   (`afb1.` and 43 base64url characters) to `~/.arcforges/proof-bootstrap/owner-bootstrap.json`, a new file only the current user can
   read (mode 0600 in a 0700 directory; on Windows one `icacls` entry for the user, set on the directory first, then verified), and
   prints only two lines: `bootstrap_sha256:` (the SHA-256 of the token text) and `bootstrap_expires_at:` (to the second, at most
   seven days ahead). An existing file is never replaced: the bootstrap is **one-shot**, and a second token needs the first file
   deleted by hand.
2. **Dispatch the deployment** with those two values as the inputs `bootstrap_sha256` and `bootstrap_expires_at` of the `CI`
   workflow's `proof: deploy` run (main only). `buildProofConfig` checks them (both or neither; 64 lowercase hexadecimal characters;
   an RFC 3339 UTC instant, in the future and at most seven days ahead; the messages never repeat a value, so a token pasted into the
   wrong field is not copied into a log, although the run's inputs are visible to people who see the run, which is why the token
   itself must never be pasted), sets them as the proof environment's `ARCFORGES_CENTER_BOOTSTRAP_SHA256` and `_EXPIRES_AT`, and
   `artifacts/proof-deployment.json` records them (`center.bootstrap`, `null` when the dispatch carried none). No checked-in
   `wrangler.json` environment carries either (`tests/worker/center-config.test.ts`, `tests/worker/proof-bootstrap.test.ts`). The
   Worker passes them to the center, whose start digest changes with them, so the center restarts with the bootstrap.
3. **Run the acceptance** on the Windows host. In `eng/verification/browser` install the package with
   `npm ci --engine-strict=false` (the owner's PowerShell has npm 12 first on its path, the package's `engines` say `<12` and its
   `.npmrc` keeps `engine-strict`, so a plain `npm ci` stops; with the flag npm only warns and installs the locked
   `playwright-core`), then run `node eng/verification/browser/acceptance.ts` from the repository root. The first run enrolls the
   owner through the bootstrap page (the script types the token into the page's field from the file; it is in no address, log or
   report) and saves the owner's credential; later runs sign in with it. Every run signs in, steps up, registers a second passkey,
   lists sessions and devices, ends a session from a second browser, removes the second passkey and signs out, and writes
   `artifacts/browser-acceptance.json` (steps, counts and flags; no secret). The authenticator is Chromium's virtual authenticator:
   **MOCKED hardware in a real browser**. The browser is the Playwright Chromium revision 1243 that the pinned `playwright-core`
   1.63.0 names, started by its explicit path (`%LOCALAPPDATA%\ms-playwright\chromium-1243\chrome-win64\chrome.exe`, version
   153.0.8010.12); the script downloads nothing, tracing and screenshots are never switched on, and the script drives only
   `proof.arcforges.com` (or a center on localhost), never production.
   - **One virtual authenticator per credential.** All passkeys of an account share one user handle, and Chromium keeps one
     discoverable credential of a relying party and user handle on an authenticator (a second replaces the first, and
     `WebAuthn.addCredential` of it is refused). The page also lists every passkey of the account in `excludeCredentials`, so a
     creation on an authenticator that holds one fails with `InvalidStateError` ("That passkey is already registered."). The owner's
     credential therefore lives on the tab's one `internal` authenticator and every further one on an authenticator of its own with
     another transport, recorded with it in the saved file; the registration runs on a fresh empty authenticator with the others
     taken off (their counters read first), and afterwards each credential goes back on its own. Every write of the saved file is
     the union over the tab's authenticators.
   - **Requests.** The hosted Worker counts every request that comes from this machine against one edge limit of 60 per minute,
     however many tabs there are: a page load is three requests, the assets included, and the redirect after a form POST is one
     more that the browser follows by itself (the script's route never sees it). One run sends about a hundred (95 when it enrolls
     and 81 when it returns, against a local center). The driver therefore holds the whole browser, all its tabs together, to ONE
     budget (`--requests-per-minute`, 40 by default, a burst of four) and charges every redirect hop to it after the hop left, so
     that the requests behind it wait. The run also counts what the browser really sent: the report's facts `requestsSent` and
     `requestsBusiest60s` (the most requests inside any rolling 60 seconds, hops included) say it, and a run is failed, with the
     429 it would meet, when that number is above 55; in the real-browser runs against a local center it was 43 (44 counted at the
     center itself). A run takes about two minutes. If a 429 arrives anyway, a step starts again from its navigation after the
     advised time, at most three times, but only when no request of the attempt had changed anything (a sign-in, a registration, a
     removal, a sign-out): after a change the step fails and says so. The budget may be lifted (`0`, or above 40) only for a
     center on localhost, where the busiest minute is recorded and not held to 55.
   - **A first run that stopped.** If every reply to the enrollment request was a definite refusal (a 4xx, the edge limiter's 429
     included), the center accepted nothing and the credential file this run wrote is removed again, so that the next run enrolls
     with the same token while it is valid. If the center accepted the enrollment and the tab did not arrive (a lost or slow
     redirect), or if the request has no definite answer (its reply was lost, the connection failed, or the Worker answered with a
     server error), the account may exist and the file is the only copy of the owner's key: the file is kept, the run says "The
     account may exist; do not delete the credential file", and the next run signs in with it as a returning run. A 429 that meets
     the page after an accepted enrollment keeps that warning in its message too (`Tab.unsettled` in the driver counts the requests a
     step cannot repeat that have no definite answer).
   - **A run that stopped after the second passkey was registered.** The new key is saved before the request that carries it leaves,
     so a run that fails afterwards leaves that passkey (`acceptance-<time>`) on the account and its key in the file; a key made for a
     passkey the center never accepted is in the file as well. The next run signs in with the owner's own credential (the one on the
     `internal` authenticator; the others are not put on an authenticator, so that a key the center does not know cannot answer
     the sign-in) and, in the step "remove the passkeys an earlier run left behind", removes every passkey named `acceptance-*` from
     the account (the step-up and the remove form, as the last step does) and forgets every saved key but the owner's. The owner's
     first passkey and the Windows Hello passkey of AR-23 (`Windows Hello AR-23 <date>`) have other names and are never touched. A
     registration that finds no free transport in the file names the passkeys of earlier runs in its error; that cannot happen with
     the cleanup working, and the total-loss path below is then the way back.
   - **One center per directory.** A saved credential belongs to the center it was made for. A run against another base URL than the
     one in the file is refused before anything is driven, with a message that names `--state-dir` (or `PROOF_ACCEPTANCE_DIR`): use
     a directory of its own for each center.
   - **Directories.** The bootstrap and credential directories are made private only when they are new, empty or hold nothing but
     the tool's own files; a directory someone else filled (`--dir .` in a checkout, a profile folder) is refused untouched, because
     the Windows grant would strip every other entry of it and of what it holds. Name a new directory.
4. **Afterwards** dispatch without the two inputs: the Worker then starts the center without a bootstrap, and the spent or expired
   values leave the configuration.

**The credential file grants the owner's and the operator's rights.** `~/.arcforges/proof-acceptance/owner-credential.json` holds the
virtual authenticator's private key, which signs in as the proof owner (the account that holds every right of the acceptance
environment, step-up included). It is created exclusively and rewritten whole after every assertion (the F14 counter rule needs the
counters to rise: a restored older copy is refused), it is never printed, logged or committed, and it must be treated as a
credential: keep it on that machine, and delete it when the owner's rights are retired. Losing the file locks the script out of the
account: before AR-23 the virtual passkey is the account's only credential (the bootstrap is spent and the e-mail and recovery
methods are not offered), so nobody can sign in and the total-loss path below is the only way back; after AR-23 the owner can sign
in by hand with the Windows Hello passkey and remove the old one.

**After a total loss** (the credential file is gone, or the owner account must be started again) the owner drops the database
`arcforges_acceptance` in the Neon Console; the next `deploy` dispatch recreates and migrates it. Then repeat the steps from the token
(delete the old bootstrap and credential files first, or the script refuses to overwrite them). Nothing else holds the owner's keys.
This also reclaims the acceptance ceiling's space ([surface switch](#surface-switch)). The same applies when a first run saved its
credential and the account never came to exist and the file could not be removed: delete `owner-credential.json` and run again while
the token is valid.

### Post-deploy checks that only the hosted path shows

The first real-browser run on the proof environment found two defects that no local test, stand-in or review could show, because
they live between the Worker, the platform's fetch and the Cloudflare edge (AF-CTR-03 A2 hotfix 1). After a deployment of the pages
surface, check both from any machine:

1. **A page without a session is the center's 303, not the Worker's 503.** `curl -si https://proof.arcforges.com/api/account/passkeys`
   (also `/sessions`, `/devices`, `/sign-out`) must answer `303` with `Location: /api/account/sign-in#return=...`. The Worker's
   Container request used the platform's default `redirect: "follow"`, so the Durable Object stub followed the 303 to a path the center
   does not serve (`http://container/api/account/sign-in`), and the 404 it got lacked the security headers: every protected page
   answered the Worker's plain-text 503 "Cloud container is temporarily unavailable." A POST without a session was fine (a 403 is not a
   redirect), which is why only the 303s failed. Every Worker request to the Container now says `redirect: "manual"` and the stand-in
   Container of the tests follows a redirect as the platform does (`tests/worker/support/platform-fetch.ts`).
2. **The pages carry no injected beacon and say `no-transform`.** The headers are part of the check, so the reply is read whole
   (`curl -si`, not `curl -s`), and the beacon is counted, not looked for by eye:

   ```sh
   curl -si -H 'User-Agent: Mozilla/5.0 Chrome/153.0.0.0' -H 'Accept: text/html' \
     https://proof.arcforges.com/api/account/sign-in > sign-in.txt
   grep -ci 'cloudflareinsights\|data-cf-beacon' sign-in.txt   # must print 0
   grep -i '^cache-control:' sign-in.txt                       # must be: cache-control: no-store, no-transform
   ```

   If the count is not `0`, turn off the zone's Web Analytics automatic setup.

If check 1 fails (a protected page answers the Worker's plain-text 503 instead of the 303), capture `wrangler tail` of the proof
Worker while repeating the request, confirm that the Container is up (`curl -si https://proof.arcforges.com/api/health` answers
200 with the health document), and escalate to the coordinator with both; do not retry the deployment to see whether it goes away.

### Running the acceptance against a center on this machine

The same script runs against a throwaway self-hosted center, in a real Chromium, with nothing to install but the pinned package's
browser. This is how the flow was run for real before the proof environment is deployed (REAL browser, MOCKED hardware):

1. **The browser.** In `eng/verification/browser`: `npm ci`, then `node node_modules/playwright-core/cli.js install chromium` (the
   pinned `playwright-core` downloads the revision its manifest names, 1243, to `~/.cache/ms-playwright/chromium-1243`; on a bare
   Linux host `... install-deps chromium`, as root, adds the shared libraries). That install fetches three things: Chromium 1243
   (Chrome for Testing 153.0.8010.12), FFmpeg 1011 and, unless `--no-shell` is given, the Chromium headless shell of the same
   release. The script launches only the first, by its explicit path; the other two are never started.
2. **PostgreSQL 18 and the center.** A throwaway container of the image `eng/center.py` pins (`POSTGRES_IMAGE`), published on a
   loopback port; then, with `ARCFORGES_CENTER_MODE=self-hosted` and the container's direct URL as
   `ARCFORGES_CENTER_MIGRATION_DATABASE_URL` and `ARCFORGES_CENTER_DATABASE_NAME=center`, the center built from this tree
   (`cd center && go build -o /tmp/arcforges-center ./cmd/arcforges-center`) runs `admin ensure-database`, `migrate` and
   `admin rotate-runtime-credential` (with `ARCFORGES_CENTER_RUNTIME_SECRET_FILE` and `ARCFORGES_CENTER_RUNTIME_POOLED_HOST` set to
   the container's address; the file holds the runtime role's URL).
3. **The bootstrap.** `node eng/verification/proof-bootstrap.ts --hours 2 --dir <new directory>` prints the digest and the expiry.
4. **Serve.** `arcforges-center serve` with `ARCFORGES_CENTER_MODE=self-hosted`, `ARCFORGES_CENTER_PUBLIC_BASE_URL=http://localhost:18080`
   (the host must be `localhost`: an IP literal cannot be a WebAuthn relying party), `ARCFORGES_CENTER_HTTP_ADDRESS=127.0.0.1:18080`,
   `ARCFORGES_CENTER_GRPC_ADDRESS=off`, `ARCFORGES_CENTER_SURFACES=identity,pages`, `ARCFORGES_CENTER_DATABASE_URL` from the runtime
   file and the digest and expiry as `ARCFORGES_CENTER_BOOTSTRAP_SHA256` and `_EXPIRES_AT`.
5. **Run**, from the repository root, once as the first run and once more as a returning run (the bootstrap is one-shot, so a new
   center and token for every first run):
   `node eng/verification/browser/acceptance.ts --base-url http://localhost:18080 --chromium ~/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome --state-dir <new directory> --bootstrap-file <directory of step 3>/owner-bootstrap.json --report <file> --requests-per-minute 0`.
   Stop and remove the container afterwards.

**What stays pending.** AR-23 (a real Windows Hello authenticator) is the only acceptance item that needs a person; its procedure is
[`ar-23-owner-procedure.md`](ar-23-owner-procedure.md). The browser acceptance of the pages against the proof environment is
post-merge evidence. Against a center on this machine it has run for real: see the pull request's evidence (REAL browser, Chromium
153.0.8010.12, MOCKED hardware).

## Operator role

An operator is an account that may issue [operator grants](center-entitlement.md#operator-grants) of features to accounts (decision
n2). The role is a row of `identity.operator` (the account, when it was granted and when it ends, never longer than 400 days; who
granted it; a reason of up to 512 characters) or the owner who bootstrapped the center (`identity.bootstrap`), which needs no row.
Only the migration role writes the table, with two audited commands (the runtime role has no INSERT or UPDATE on it, so no request
can make an operator):

```sh
arcforges-center admin grant-operator --account <uuid> --reason <text> [--days N]   # 1 to 90 days, default 30
arcforges-center admin revoke-operator --account <uuid>
```

`grant-operator` refuses an account that does not exist, is not active, has a reason that is not valid UTF-8 or already holds a live
row. Both commands lock the account's `identity.user` row (`FOR UPDATE`) before they read or change the operator's rows, so two
`grant-operator` runs for one account leave one live row (the second finds it and is refused) and a `revoke-operator` is ordered
against an operator grant in flight (the grant takes the same lock before it reads the role). Both commands append
`identity.operator.granted` or `.revoked` (actor `operator:cli`) in the transaction that writes the row, with the digest and length of
the reason and never the reason. The owner's standing comes from the bootstrap and is not ended by `revoke-operator`. The operator
grant checks the role again in its own transaction, after taking that lock, so a revocation that committed in between is honoured
and one that is still open is waited for. An account that is restricted, suspended or deleted is no operator while it is (the row is
untouched; the role is live again with the account), like any other account it reaches only security operations.

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
| `VALIDATION/invalid_argument`       | a field outside its rule (`state.state` = the field path, `state.reason` = field path and rule), a method or purpose not offered                                                        |
| `VALIDATION/invalid_cursor`         | a malformed page cursor, one of another listing or one whose instant is out of range                                                                                                    |
| `AUTHENTICATION/unauthenticated`    | a wrong or unknown proof, an account that may not sign in, a refused bootstrap (all alike)                                                                                              |
| `AUTHENTICATION/token_expired`      | an expired refresh token                                                                                                                                                                |
| `AUTHENTICATION/credential_revoked` | a revoked session, device or installation; a reused refresh token                                                                                                                       |
| `AUTHENTICATION/step_up_required`   | a write without its evidence, or a `mobile.limited` session on an `upgrade` row (retry the same command after a step-up)                                                                |
| `AUTHORIZATION/permission_denied`   | a scope or account state the operation does not admit (`state.state` `operation`, `state.reason` = the operation ID); another account's installation                                    |
| `CONFLICT/code_reused`              | a completed flow or proved step-up presented again, or a sign-in completion still in progress (a passkey registration's is `RESOURCE/overloaded`)                                       |
| `CONFLICT/already_exists`           | a passkey whose credential ID is registered already (`state.state` `credential`; `state.resource` only for the account's own live credential)                                           |
| `CONFLICT/revision_conflict`        | a stale `meta.expected_rev` (`RevisionConflict` with the expected and the current revision)                                                                                             |
| `CONFLICT/command_id_reused`        | a command ID used before with another request                                                                                                                                           |
| `STATE/not_found`                   | an unknown or invisible flow, step-up challenge, session, credential, device or account (`state.state` = its kind; `state.resource` = the ID the caller sent, F19, or its own account)  |
| `STATE/invalid_state`               | the last live credential (`last_credential`); an account whose state does not allow the change (`credentials_locked`)                                                                   |
| `STATE/expired`                     | an expired flow, or one whose attempts are exhausted                                                                                                                                    |
| `STATE/not_activated`               | a method of a disabled surface (`state.state` `surface`, `state.reason` = the surface)                                                                                                  |
| `RESOURCE/rate_limited`             | a rate-limit bucket over its limit, or a flow's sends exhausted (`email_code_sends`)                                                                                                    |
| `RESOURCE/overloaded`               | the store is unreachable or contended (before any commit, or an unanswered commit of a transaction that carries no effect of the call), or a command still running: retry after a while |
| `INTERNAL/internal`                 | the call's effect write whose commit went unanswered (effect `UNKNOWN`, retry `NEVER`); anything else (retry after a while); logged with the correlation id, never with request content |

Every `StateFailure` detail is a valid foundation message (Contracts `foundation-baseline.json`): `state` and `reason` are always
set, `state` matches `^[A-Za-z0-9._:/-]{1,128}$`, and a `state.resource` (`AggregateRef`) always carries a 16-byte, nonzero `id`;
a refusal without such an ID carries no resource. For not_found and already_exists `state` is the object's kind and `reason` the
code. Every `AFTER_TIME` advice carries `retry.retry_at` (rule `retryAdvice`): a rate-limit bucket's is the end of its window, a
flow's exhausted e-mail code sends (`email_code_sends`) name the flow's expiry, after which a new flow is needed, and a refusal
that names no instant (`RESOURCE/overloaded`, `INTERNAL/internal` with `AFTER_TIME`) is dated where it becomes the reply's
`ArcError`, one second after the refusal plus up to one second of jitter (`arc.Refusal.Dated`, E4). `TestEveryRefusalIsAnErrorsRow`
checks every constructor's rendering against those rules, the integration tests check every refusal they decode against
`retryAdvice`, and the Worker's generated replies meet it (`rate_limited` carries the instant the Worker writes, `not_activated` is
`NEVER`). The Worker's generated replies carry the correlation id Contracts requires in `ArcError.correlation_id` (E4-1): each
template holds a 16-byte slot, which the Worker fills with the call's identity before it answers, and `arctest.Violations` (the
check every test applies to a refusal, now with no uncorrelated exemption) is applied to the templates as the Worker completes them
(`TestTheSurfaceRepliesAreTheCentersRefusals`, `tests/worker/ingress-surfaces.test.ts`). One contract gap predates this part (#118):
`INTERNAL/internal` pairs `AFTER_TIME` with effect `UNKNOWN`, as Design errors.md prescribes but the Contracts `arcError` rule
forbids (the test's one named exemption, which needs both the category `INTERNAL` and the code `internal`; routed to the AF-CTR-03
Design companion, E4-INTERNAL).

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
sessions per scope and participant rows) and the operator's `identity.sessions.revoked_by_operator`; since part B `access.authorized` and `access.gated` (the stages of
`Authorize`, nothing yet for an identity row), `entitlement.operator_grant.issued` and `.refused` (the operator grant) and the
operator role's `identity.operator.granted` and `.revoked` ([operator role](#operator-role)). Payloads are closed JSON:
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
| CompletePasskeyRegistration      | 1 receipt lookup, 1 attempt (+1 receipt lookup after a refusal before the receipt), then 1 receipt transaction (or 1 flow end after a refusal; 1 attempt release after a store failure)                    |
| Other writes                     | 1 receipt transaction: the receipt, the evidence's consumption, the change and its audit event                                                                                                             |

No transaction is open while PBKDF2, WebAuthn or the mail provider runs. Each transaction is the call's effect or auxiliary
bookkeeping (counts, reservations, denials, give-backs, refusal audits; D10), which decides what an unanswered commit answers
([PostgreSQL store](postgres-store.md#guarantees)); `TestEveryTransactionOfTheSurfaceStatesItsRole` pins the role of each by
name, and `TestALostCommitOfTheCallsEffectIsUnknown` and `TestALostCommitOfBookkeepingIsRetryable` lose a commit of each kind. The
runtime pool stays four connections ([PostgreSQL store](postgres-store.md#connection-budgets)).

## Surface switch

The identity methods form the `identity` surface; the [account pages](#account-pages-and-browser-sessions) and the browser session
routes form the `pages` surface, which needs `identity` (a list with `pages` and without `identity` refuses to start, and a
self-hosted center whose base URL cannot be a relying party leaves both off). The center and the generated Worker table tag them by surface
(`surfaceRoutes`, PLT-18: `productionRoutes` stay always on); `ARCFORGES_CENTER_SURFACES` (center) and `FLAGSHIP_SURFACES`
(Worker) list the enabled surfaces as exact generated names, comma-separated. Official-hosted mode enables none unless listed;
self-hosted mode enables the default surfaces (`identity` and `pages`) unless listed (an explicit list pins the surfaces across
upgrades; `none` enables none; `operations` is never a default). A disabled surface's method is answered with the domain refusal `STATE/not_activated` (`state.reason = identity`): by the
Worker from the generated reply, before any rate limit, credential, body or Container (`tests/worker/ingress-surfaces.test.ts`), and
by the center with the call's correlation id (logged and counted as an OK reply with that id); a disabled `pages` surface answers every
page route with 404, the Worker's reply of a path it does not know (plain text), from the Worker's page handler before anything else is read. An enabled one passes the Worker's own
edge limit `IDENTITY_RATE_LIMITER` (over it, the generated domain refusal `RESOURCE/rate_limited` with its `retry_at`: the refusal's
time rounded up to the second plus the limiter's 60-second period) before it is forwarded. The Worker passes its parsed list to the Container as
`ARCFORGES_CENTER_SURFACES` (`none` when the list enables nothing, so a mistyped list never stops the center) and always
`ARCFORGES_CENTER_CLIENT_IP_HEADER`; surfaces take effect only with `ARCFORGES_HELLO_RUNTIME=go`.

Production carries `"FLAGSHIP_SURFACES": ""` (pinned by `tests/worker/center-config.test.ts`: production stays dark, no page is
served there); the acceptance environment (`proof`) carries `identity,pages` and `ALLOWED_ORIGIN` = the origin of its public base
URL. The `identity`, `pages` and `operations` surfaces exist (the last is described below); AF-PLAT-01 owns the activation variable's other names, cron idling and kill switches. AF-PROD-01 enables identity in production only
after AF-PLAT-01's retention sweeps exist ([PostgreSQL store](postgres-store.md#identity-and-device-af-ctr-03)).

The operator grant has a third surface, `operations`: the interim page `/operations/grant` of the operator grant ([center
entitlement](center-entitlement.md#the-operations-page)). It needs `identity` and `pages`, exists only in official-hosted mode, is
never a default of either mode (a list that names it on a self-hosted center, or without the other two, refuses to start), and
is in no checked-in environment: production carries none, and the acceptance environment (`proof`) keeps `identity,pages` until the
coordinator enables `operations` for the hosted proof of the grant.

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
