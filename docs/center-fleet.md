# Node enrollment on the center (the fleet surface)

AF-CTR-04 connects an ArcForges node to an account on a center: a person approves the node's sign-in in a browser (PKCE loopback) or
with a device code, and the node then holds a node credential that it refreshes and can sign out. This page describes what the center
serves for it. Parts E1a, E1b and E2 serve the browser sign-in, the device-code sign-in, the node's refresh, report and sign-out, and
hold the enrollment function both sign-in flows call; part E3 serves the pages `/connect` and `/activate` where an account reviews and
decides a sign-in, adds the development stand-in of a node (`center/cmd/node-probe`) and the real-browser run that drives both, and
enables the surface on the acceptance environment. The node side is the ArcForges CloudLink (parts N1 and N2).

Enrollment is an account and device operation and is never gated (AD-0021 section 13a): every fleet row of the operation table has
no `Feature` (`TestFleetRowsCarryNoFeature`, `TestFleetRowsAreTheServedMethods`). The gated `center.nodes` key is the node's
connection, which AF-CTR-05 serves.

## Surface

The methods and the six pages belong to the switchable surface `fleet`. It needs `identity` and `pages` (a list without them refuses to
start). Production `FLAGSHIP_SURFACES` stays `""` (AF-PROD-01 activates it); the acceptance environment (`proof`) carries
`identity,pages,operations,fleet` (pinned by `tests/worker/center-config.test.ts` and `tests/worker/proof-deploy.test.ts`); a
self-hosted center enables it by default together with `identity` and `pages`
(`TestTheFleetSurfaceNeedsIdentityAndPagesAndIsInTheSelfHostedDefault`). With the surface off, every fleet method answers `STATE/not_activated`
with `state.reason` `fleet`, from the Worker's generated reply before anything else is read, and from the center. Each method's Worker
budget is the contract's deadline: 5 s for GetNodeSignInFlow and LookupDeviceCode, 15 s for CompleteNodeSignIn, 10 s for the others. A center that serves
`fleet` needs a public base URL of at most 462 characters (it refuses to start otherwise), so every URL it derives for a node stays
within the contract's 512 (`TestTheFleetSurfaceRefusesABaseURLTooLongForItsURLs`). A self-hosted center whose base URL cannot be a WebAuthn relying
party clears the default surfaces and serves none (`TestASelfHostedCenterOnAnAddressServesNoSurface`); a list that names a surface
refuses to start there.

## Served methods

| Method                                         | Operation ID                     | Risk | Credential                            | Restricted account's node | Receipt                                       |
| ---------------------------------------------- | -------------------------------- | ---- | ------------------------------------- | ------------------------- | --------------------------------------------- |
| NodeEnrollmentService.BeginNodeSignIn          | `fleet.beginNodeSignIn`          | R1   | anonymous                             | (no credential)           | never (`meta.command_id` is correlation only) |
| NodeEnrollmentService.GetNodeSignInFlow        | `fleet.getNodeSignInFlow`        | R2   | account session                       | refused (the account)     | never (a mark)                                |
| NodeEnrollmentService.ApproveNodeSignIn        | `fleet.approveNodeSignIn`        | R3   | account session, step-up to approve   | refused (the account)     | never (the reply holds the code)              |
| NodeEnrollmentService.CompleteNodeSignIn       | `fleet.completeNodeSignIn`       | R1   | anonymous (the flow-bound proof)      | (no credential)           | never (a one-use code)                        |
| NodeEnrollmentService.StartDeviceAuthorization | `fleet.startDeviceAuthorization` | R1   | anonymous                             | (no credential)           | never (the reply holds the device code)       |
| NodeEnrollmentService.PollDeviceAuthorization  | `fleet.pollDeviceAuthorization`  | R1   | anonymous (device code and key proof) | (no credential)           | never (a one-use secret)                      |
| NodeEnrollmentService.LookupDeviceCode         | `fleet.lookupDeviceCode`         | R2   | account session                       | refused (the account)     | never (a review)                              |
| NodeEnrollmentService.ApproveDeviceCode        | `fleet.approveDeviceCode`        | R3   | account session, step-up to approve   | refused (the account)     | yes (`account:<id>`)                          |
| NodeEnrollmentService.RefreshNodeSession       | `fleet.refreshNodeSession`       | R1   | anonymous (refresh token)             | allowed                   | never                                         |
| NodeEnrollmentService.ReportNodeInfo           | `fleet.reportNodeInfo`           | R1   | node credential                       | refused                   | yes (`node:<installation id>`)                |
| NodeEnrollmentService.SignOutNode              | `fleet.signOutNode`              | R2   | node credential                       | allowed                   | yes (`node:<installation id>`)                |

con-07 names no fleet operation, so the IDs are the center's own (`fleet.<method>`). Every other `NodeEnrollmentService` method stays
unregistered (`UNIMPLEMENTED`, no Worker row): the phone pairing, certificate, LAN, entitlement-token, entitlement-key and
support-upload methods of later tasks. `GetEntitlementKeys` is not
used to deliver the center's keys: a node needs the next key at every refresh without a second round trip, and that method is
anonymous.

An AGENT row of the operation table names the exact credential scopes it admits: the two node rows admit a `node` credential only.
An account or `mobile.limited` session is refused with `AUTHORIZATION/permission_denied` and audited `access.refused` with the reason
`principal`; an `automation` or `push` credential with the reason `scope` (`TestScopeMatrixOverFleetRows`). The reply is always
`state.state` `operation`, `state.reason` the operation ID; `restricted`, `scope` and `principal` are audit reasons only.

## Browser sign-in

The node starts a flow, an account reviews and decides it in a browser, and the node completes it with what the browser brought to its
loopback receiver (CTR4-FLW-01..08 as amended by the plan review's protocol-1, protocol-4 and protocol-6 and by the C0 comments of
`fleet.proto`). A caller that holds only the flow ID can neither revoke a node nor end an approved flow.

**Begin** (anonymous). The request is checked field by field before anything is counted: `code_challenge` (43 characters of
`[A-Za-z0-9_-]`; S256 is the only method), `redirect_uri` (byte for byte `http://127.0.0.1:<port>/callback` or
`http://[::1]:<port>/callback`, `<port>` a decimal 1024..65535 without a leading zero; anything else is `not_admitted`), the node's
description (name, OS, architecture, SemVer version, role), `state` (16 to 128 characters of `[A-Za-z0-9._~-]`) and
`node_public_key` (the 91-byte PKIX DER of a P-256 key). Then the client network's and the node ID's buckets are counted (and, where
the policy sets it, the opt-in `anonymous_flows` ceiling every anonymous flow counts in), and a key
that an installation holds or held is refused before approval with `CONFLICT/already_exists` (`state.state` `node_key`,
`state.reason` `already_registered`); the node replaces its key once and starts again (a sign-in after a sign-out therefore brings a
new key). A newer Begin of the same node ID and the same key expires the node's PENDING flows; a Begin of the node ID with another key
leaves them alone. The flow lives 10 minutes; `authorize_url` is `<public base URL>/connect#flow=<flow ID>`, the flow ID in its
lower-case 8-4-4-4-12 form of the 16 bytes in order, which the node derives itself and requires to match. `meta.command_id` is
correlation only: every call starts a new flow. `RESOURCE/kill_switch_active` is not produced in AF-CTR-04 (no kill switch exists).
On the official hosted center Begin also records the country and the network of the request (`begin_country`, `begin_asn`; see
"The pages": origin line); a self-hosted center records neither.

**Review** (account session; `mobile.limited` upgrades first; a restricted account is refused). Reviewing a PENDING flow records the
reviewing account and time; the latest review wins, so an account whose review another account displaced gets `not_reviewed` when it
decides. Any other flow is shown with its state and records nothing; an unknown flow and a flow another account decided are
`STATE/not_found` alike, an expired one `STATE/expired`.

**Decision** (account session). Only a flow this account reviewed within the last 10 minutes can be decided (`STATE/invalid_state`
reason `not_reviewed`; with the flow's 10-minute life every review of a live flow is younger, so this is the contract's guard). An
approval needs a proved step-up (passkey or e-mail code) of class `fleet.approveNodeSignIn` bound to the flow ID, consumed in the
approval's transaction; a denial needs none. While the flow is APPROVED and its code unredeemed, the approving account may deny it, or
approve it again, which replaces the code. An approval checks the node cap early (`RESOURCE/quota_exceeded`, `max_nodes_per_account`;
Enroll enforces it), stores the approving session, its authentication method and time and its epochs, and draws a one-use code
(32 random bytes in 43 base64url characters, stored only as the SHA-256 of the bytes) that lives `nodeCodeLifetime` (2 minutes) and
never past the flow. The reply is the redirect `<stored redirect_uri>?code=<code>&state=<state>` (a denial:
`?error=access_denied&state=<state>`); the center never takes a redirect target from the request. An absent `approve` is refused
(`approve: required`): a decision names itself.

**Completion** (anonymous). The shape of `flow_id`, `code_verifier` and `node_key_proof` is checked first (`VALIDATION/
invalid_argument`); a malformed code is a failed proof like a wrong one. Then, in this order: an unknown flow is `STATE/not_found`; a
PENDING or APPROVED flow past its expiry, or an APPROVED flow whose code expired, is `STATE/expired` (a correct code presented after
its lifetime consumes nothing and leaves the flow APPROVED); the presented code is compared with the flow's digest in constant time,
against a fixed dummy when the flow has none, and any mismatch, in every state, is `AUTHENTICATION/unauthenticated` with nothing
written, so the flow's state is never visible to a caller who does not hold the code. With the matching code: a DENIED flow is
`unauthenticated`, an EXPIRED one (superseded, or an approval that lapsed) `STATE/expired`, a REVOKED one `CONFLICT/code_reused`. On an
APPROVED flow the PKCE verifier (`BASE64URL(SHA-256(verifier)) = code_challenge`) and the node key proof are verified outside any
transaction: ES256 in IEEE P1363 form, 64 bytes, r and s in [1, n-1], low-S (a high-S proof is refused), over `"ArcForges
node-key-proof v1\n" || 0x01 || SHA-256(public base URL) || node ID || flow ID || code`. The audience is the center's own public base
URL, never a request's host: a self-hosted center's `ARCFORGES_CENTER_PUBLIC_BASE_URL` must equal the URL its nodes are configured
with, or every sign-in answers `unauthenticated`. One transaction then locks the flow row and decides again under the lock:

- both proofs held: `fleet.Enroll` runs in this transaction and the flow becomes COMPLETED with its session and enrollment (written
  before `fleet.node.enrolled`, the transaction's last statement); the reply is the node credential (`NodeCredentials`: tokens, the
  access lifetime, the family's absolute end, the installation, the account's ID, display name and masked e-mail address, the
  published keys; no entitlement token);
- a failed verifier or key proof: the flow becomes REVOKED with its code redeemed (the code may have been intercepted), audited
  `fleet.node_sign_in.verifier_failed`, and the reply is `unauthenticated` like any failed proof;
- the matching code on a COMPLETED flow is a reuse: the flow becomes REVOKED and the credential family it delivered is revoked
  (session revoke reason 8), audited `fleet.node_sign_in.code_reused` once; the reply is `CONFLICT/code_reused`. The loser of two
  concurrent presentations of the correct code takes this path and revokes the winner's credentials, so a node never resends a
  Complete whose body was sent;
- an approval that lapsed (`fleet.ErrApprovalLapsed`: the approving session revoked by the account, by revoking all sessions, with
  its device or by an operator, an epoch moved, or the account not Active) ends the flow EXPIRED in the same transaction (Enroll rolled
  its savepoint back), audited `fleet.node_sign_in.approval_lapsed`, and answers `STATE/expired`;
- any other refusal of Enroll (`already_exists` for the node ID or the key, `credential_revoked`, `quota_exceeded`, `node.os:
mismatch`) rolls everything back: the flow stays APPROVED with its code unredeemed and the identical retry answers the same rule.

A store failure leaves the code unredeemed (`RESOURCE/overloaded`, and the identical retry succeeds); an unanswered commit of the
completion is `INTERNAL/internal` (effect `UNKNOWN`, retry `NEVER`) and the node signs in again.

**Approvals end with the account's remediation.** RevokeAllSessions and RemoveAuthIdentity first deny the account's APPROVED flows
(an APPROVED flow's code is always unredeemed), in their own transaction and before their step-up evidence locks the account, and
count them in `identity.sessions.revoked_all` and `identity.credential.removed` (`participants`, `fleet.node_sign_in`). "Sign out all
other sessions" from the approving session revokes neither that session nor its epoch, so this is what ends its pending approvals;
the other remediations (a revocation of the approving session by another session, a credential removal, a device revocation, an
operator's revocation, a suspension) also lapse the approval in Enroll. A step-up refusal rolls the cancellation back. The
cancellation is two statements: the first locks, in flow ID order, the account's APPROVED flows and the PENDING flows it reviewed
last, the second denies the locked flows that are APPROVED with a snapshot taken after the locks; so an approval that holds one of
those rows when the remediation starts commits first and is then denied, while an approval by the remediating session itself that
reaches its row after the lock waits for the remediation and stands (it is the user's own act). An enrolled node is removed by
revoking its device.

**Buckets.** `node_flow_prefix` (10 per 10 minutes per client network) and `node_flow_node` (10 per 10 minutes per node ID; C0 "rate
limited per IP and per node ID") count every Begin past its validation (with the opt-in `anonymous_flows` ceiling where the policy
sets one); `node_complete_prefix` (30 per 10 minutes per client network)
counts only the Completes that name no flow or present no matching code, so a full bucket refuses junk and never a matching code;
`node_approve_account` (20 per hour per account) counts approvals and denials. Malformed requests cost no budget. Each limit and window
is a policy key (`nodeFlowPrefixLimit`/`Window`, `nodeFlowNodeLimit`/`Window`, `nodeCompletePrefixLimit`/`Window`,
`nodeApproveAccountLimit`/`Window`; counts 1..10000, windows 1m..24h; `nodeCodeLifetime` 30s..10m). The flow lifetime and the review
window are the contract's 10 minutes and no keys.

## Device-code sign-in

A headless node starts an authorization and shows its user code; an account looks the code up (LookupDeviceCode) and approves or
denies it (ApproveDeviceCode), on the `/activate` page or through these two API methods; the node polls with its device code and a proof by its node key
(CTR4-DEV-01..09 as amended by the plan review's Q8, protocol-8, protocol-9, protocol-19, contracts-9, cloud-5 and cloud-10, and by
the C0 comments of `fleet.proto`). A caller that holds the device code but not the node key learns nothing of the authorization's
state and writes nothing to it.

**Start** (anonymous). The request is checked field by field before anything is counted: the node's description (as for Begin) and
`node_public_key`. Then the client network's and the node ID's buckets, which BeginNodeSignIn counts too, are counted (with the
opt-in `anonymous_flows` ceiling), and a key that an installation holds or held is refused before approval with
`CONFLICT/already_exists` (`state.state` `node_key`, `state.reason` `already_registered`). A newer Start of the same node ID and the
same key expires the node's PENDING authorizations that present that key (one with another key, and a browser flow of the node,
are left alone). The authorization is PENDING for 600
seconds with a poll interval of 5,000 ms (the contract's values; no policy keys). The device code is 32 random bytes in 43 base64url
characters, stored only as the SHA-256 of the bytes; the user code is 8 letters of `BCDFGHJKLMNPQRSTVWXZ` drawn without bias
(a random byte below 240, modulo 20), returned as the 8 letters and stored as the SHA-256 of them, and no other PENDING or APPROVED
authorization holds it (a collision draws again, five times at most, then `RESOURCE/overloaded`). `verification_uri` is
`<public base URL>/activate` and `verification_uri_complete` `<public base URL>/activate#code=XXXX-XXXX`, which the node derives itself
and requires to match. `meta.command_id` is correlation only: every call starts a new authorization.

**Entries and the budgets** (Q8 as merged). A user code is read case-insensitively with `-` and spaces ignored (ASCII letters only);
anything else is `VALIDATION/invalid_argument` (`user_code: required` or `user_code: pattern`). "Malformed input costs nothing.
Every other entry first reserves one unit of the account budget and one of the network budget; a right lookup gives both back."
"Once the account or network budget is spent, every entry (also a right one) is RESOURCE/rate_limited with retry_at until the
window ends." The budgets are `device_entry_account` (5 per 15 minutes per account) and `device_entry_prefix` (20 per 15 minutes per
client network); the account's unit is reserved first, and when the network's is refused the account's is given back. An entry is
a lookup or a decision. The center gives the units back exactly when the entry names a live code the caller may act on: a lookup
that shows the node, a decision made, and a decision of a code the caller reviewed that is refused `step_up_required` or
`quota_exceeded`; a store failure gives them back too (not after a commit whose answer was lost). Every other entry keeps them
(the F7 resolution of the E2 decisions): an unknown code or one another account decided (`VALIDATION/code_invalid`,
`limit.limit_name` `device_entry_account`, `limit.maximum` the window's cap, `limit.available` the account's entries left), an
expired code (`STATE/expired`), a code in another state (`STATE/invalid_state`, `state.state` `device_authorization`, the state
name), the decision of a code the caller did not review, and the sixth lookup of a live code. The center deviates here from the plan
review's protocol-9 corrected fix item 3 on both halves: a decision of a code another account reviewed, and of a code nobody
reviewed, is `STATE/invalid_state` `not_reviewed` and keeps the reservation, because a free `not_reviewed` would let a denial (which
needs no step-up) probe the live codes under review. Its cost: a reviewer displaced by another account that holds the code pays
for the `not_reviewed` it then meets (residual risks below). The kept unit that fills a budget is audited `identity.rate_limited`; every
kept unit is counted by its kind (`entry` unknown, expired, state, unreviewed, lookups), the alert signal for guessing across
accounts.

**Lookup** (account session; `mobile.limited` upgrades first; a restricted account is refused). For a PENDING, unexpired code it
counts one lookup, records the reviewing account and time (the latest review wins: a displaced reviewer's decision is
`not_reviewed`) and returns the node as it described itself. "The sixth and later lookups of one live code are refused with
VALIDATION/code_invalid (limit.limit_name device_code_lookups, limit.available 0); the authorization stays PENDING"; every lookup
counts, the same account's too, and the fifth is audited `fleet.device_authorization.lookups_exhausted`. A code another account
decided is answered as an unknown code, also after its expiry. Neither a lookup nor a refusal writes the authorization except the
counted lookup itself.

**Decision** (account session, under the account's command receipt; the reply is a `Receipt`). "Only a code this account looked up
within the last 10 minutes can be decided" (`STATE/invalid_state` `not_reviewed`; with the 600-second life every review of a live
code is younger). An approval needs a proved step-up of class `fleet.approveDeviceCode` bound to the normalized user code (8
upper-case letters: the target hash is the SHA-256 of the class, the account ID and the code, each on its own line, as
`identity.TextTargetHash` computes it), consumed in the approval's transaction; a denial needs none. "The approving account may deny
an APPROVED authorization whose credentials are not yet delivered"; approving it again is `invalid_state` `approved`. An approval
checks the node cap early (`RESOURCE/quota_exceeded`, `max_nodes_per_account`; Enroll enforces it) and stores the approving session,
its authentication method and time and its epochs. An absent `approve` is refused (`approve: required`). A replay of a committed
decision is answered with its receipt and counts nothing; a final refusal is kept by the receipt, `step_up_required` is not. The
account's decisions of both sign-in flows count in `node_approve_account` (20 per hour).

**Poll** (anonymous). The shape of `device_code` and `node_key_proof` (64 bytes) is checked first. Then, in this order:

1. the device code is looked up by its digest (one point read; the code is the lookup key, so there is no stored value to compare in
   constant time): a code that names nothing is counted in the client network's failure bucket `node_poll_prefix` (120 per 10
   minutes) and is `STATE/not_found`, refused `RESOURCE/rate_limited` with nothing counted once that bucket holds its limit;
2. the node key proof is verified outside any transaction, in every state: ES256 in IEEE P1363 form, 64 bytes, r and s in [1, n-1],
   low-S, over `"ArcForges node-key-proof v1\n" || 0x02 || SHA-256(public base URL) || node ID || device code`. A failure is
   `AUTHENTICATION/unauthenticated`, counted like an unknown code, with nothing written ("A bad node key proof on an APPROVED
   authorization is AUTHENTICATION/unauthenticated and leaves it APPROVED"), so a holder of the device code alone cannot learn the
   state, slow the node down or spend its bucket;
3. a proved poll counts in its authorization's bucket `node_poll_authorization` (6 per 10 seconds, a constant): over it,
   `RESOURCE/rate_limited`, nothing written; a proved poll never waits on `node_poll_prefix`;
4. one transaction locks the authorization and decides under the lock: PENDING or APPROVED past its expiry becomes EXPIRED; DENIED,
   EXPIRED and COMPLETED are answered as they are and never written, except the first poll after delivery, which records the reuse
   (`reused_at`), revokes the delivered credential family (session revoke reason 8, audited
   `fleet.device_authorization.code_reused` once) and answers COMPLETED without credentials; a PENDING or APPROVED authorization
   polled sooner than its interval less 500 ms after its previous poll is SLOW_DOWN with the interval grown by 5,000 ms up to
   60,000 ms (the center's cap) and nothing else, while the first poll is never early; PENDING records the poll; APPROVED runs
   `fleet.Enroll` in this transaction, becomes COMPLETED and answers APPROVED with the node credential (as CompleteNodeSignIn's). An
   approval that lapsed ends it EXPIRED in the same transaction, audited `fleet.device_authorization.approval_lapsed`, answered
   EXPIRED; any other refusal of Enroll (`already_exists` for the node ID or the key, `credential_revoked`, `quota_exceeded`,
   `node.os: mismatch`) rolls everything back and leaves it APPROVED.

A store failure of the delivery leaves the authorization APPROVED (the next poll delivers); an unanswered commit of it is
`INTERNAL/internal` (effect `UNKNOWN`, retry `NEVER`) and the node signs in again. The transaction's kind follows the unlocked read:
a poll that read the authorization APPROVED runs in the delivery's effect transaction whatever the lock then decides (also
SLOW_DOWN, an expiry or a DENIED that the account's remediation set meanwhile), so an unanswered commit of such a poll is
`INTERNAL/internal` too, and the node signs in again although nothing was issued; a poll that read another state and finds a
delivery or a reuse to do under the lock runs again as an effect transaction. A node never sends a poll before the reply of its
previous one: the loser of two concurrent polls of an APPROVED authorization finds it COMPLETED and takes the reuse path, which
revokes the winner's credentials (strict, as refresh reuse). An approved authorization no poll collects within its 600 seconds ends
EXPIRED; nothing was issued, so nothing is revoked.

**Approvals end with the account's remediation** as for the browser sign-in: RevokeAllSessions and RemoveAuthIdentity deny the
account's APPROVED device authorizations (credentials not yet delivered) in their own transaction, after its browser flows and before
their step-up evidence locks the account, counted in their audit events (`participants`, `fleet.device_authorization`), with the same
two statements: the first locks, in authorization ID order, the account's APPROVED authorizations and the PENDING ones it reviewed
last, the second denies the locked ones that are APPROVED with a snapshot taken after the locks.

**Buckets.** `node_poll_prefix`, `device_entry_account` and `device_entry_prefix` are policy keys (`nodePollPrefixLimit`/`Window`,
`deviceEntryAccountLimit`/`Window`, `deviceEntryPrefixLimit`/`Window`; counts 1..10000, windows 1m..24h); Start shares Begin's
`nodeFlowPrefix*`, `nodeFlowNode*` and the decision `nodeApproveAccount*`. The 600 seconds, the 5,000 ms interval and its step, the
5 lookups and the per-authorization poll bucket are the contract's or constant values and no keys.

## Node credentials

A node credential is an `identity.session` row of scope `node` (3), product `arcforges-node`, bound to the node's own device and
installation, with the formats of the account sessions (access `afa1.`, refresh `afr1.`, only SHA-256 digests stored). Its lifetimes
come from the node keys of the identity policy:

| Setting                   | Default | Bounds      | Meaning                                                                          |
| ------------------------- | ------- | ----------- | -------------------------------------------------------------------------------- |
| `nodeAccessLifetime`      | 60m     | 15m to 60m  | the access token; the node refreshes at two thirds of it (36 refreshes a day)    |
| `nodeRefreshIdleLifetime` | 2160h   | 1h to 2160h | the refresh token's sliding idle limit (90 days)                                 |
| `nodeRefreshAbsolute`     | 8760h   | 1h to 9600h | the absolute end of the credential family (365 days); a refresh never extends it |
| `maxNodesPerAccount`      | 100     | 1 to 1000   | live enrolled nodes per account (signed-out nodes count)                         |
| `nodeRefreshPrefix`       | 120/10m | as identity | refresh tokens that name nothing, per client prefix (a failure bucket)           |
| `nodeRefreshSession`      | 60/10m  | as identity | refreshes of one session's current token                                         |
| `nodeReportInstallation`  | 12/1h   | as identity | ReportNodeInfo calls per installation                                            |

The relations are checked at start: access at most idle, idle at most absolute.

**RefreshNodeSession** takes the refresh token alone (the token is bound to its row; there is no installation in the request). An
empty token or one over 8,192 bytes is `VALIDATION/invalid_argument` (`refresh_token`, `length`) and counts nowhere. The token is then
looked up first, with one point read and no lock. A token that names nothing (malformed or unknown) is `RESOURCE/rate_limited` with
`retry_at` when its client prefix's failure bucket already holds its limit (nothing is written then); otherwise its failure is
counted and it is `AUTHENTICATION/unauthenticated`, and the failure that fills the window is audited `identity.rate_limited` once. A
token that names a session never waits on that bucket, so junk from a neighbour on the same network cannot lock its nodes out
(`TestJunkRefreshesDoNotLockOutAPrefix`, `TestAThousandJunkRefreshesThenAValidOne`). A session's current token counts in its own
bucket; a spent token is never limited, so its reuse always runs. The rotation is strict: there is no grace window. Presenting a spent
refresh token (also a retry whose reply was lost) revokes the credential family, and the node signs in again. A live account token
is refused with `AUTHORIZATION/permission_denied`; a revoked session, device or installation is `AUTHENTICATION/credential_revoked`,
an expired family `AUTHENTICATION/token_expired`, a suspended account `AUTHENTICATION/unauthenticated`, and a restricted account's
node keeps refreshing. The rotating transaction marks the node seen and reads the published keys; a session whose installation has no
live node row is `credential_revoked` and nothing rotates. The reply carries the new pair, `access_expires_at`, `access_lifetime_ms`
(the lifetime as issued), `session_expires_at` (the family's absolute end) and the center's published `command_keys` and
`entitlement_keys`. A refresh is not audited; a reuse is (`identity.session.refresh_reused`, whose payload names the scope).

**What strict rotation costs.** The refresh credential is a bearer token; the node key plays no role in refresh (in AF-CTR-04 it is
not used after enrollment). A reply lost after the center committed the rotation (a Worker deadline during a cold start, a deploy)
leaves the node holding a spent token: its next refresh revokes the family and the node must sign in again. On the hosted center the
Container sleeps after 60 seconds idle, so nearly every unattended refresh meets a cold start. At 36 refreshes a day (13,140 a year)
and an assumed post-commit loss of 1 in 10,000 refreshes, a node would be signed out about 1.3 times a year; the real rate will
be measured in the end-to-end acceptance and the hosted run H2. Key-authenticated recovery is a later task's decision.

**ReportNodeInfo** updates what the node says about itself. The node ID must be the credential's (`node.node_id: mismatch`), the OS
cannot change (`node.os: mismatch`: another OS is another machine, which signs in under its own node ID), the name passes the node-name
rule below and the version is SemVer 2.0.0. A changed name, architecture or version (compared in canonical form, so a rebuild at
another commit is no change) updates the node row and the installation's version, and the device takes the new name only while it
still bears the name the node reported before: a name the account gave the device wins. The node is marked seen; the event
`fleet.node.info_reported` is appended only when something changed. A restricted account's node is refused. A replay of a committed
report (the same command ID) is answered with its receipt before the installation's bucket is counted.

**SignOutNode** revokes the calling node credential (revoke reason 1, signed out); the node record, device and installation stay, so
the node signs in again in place. A restricted account's node may call it. A retry after the revocation (also a retry whose reply was
lost) is refused at the ingress as credential_revoked before any receipt is read; the node treats that as signed out. Both node
methods answer `AUTHENTICATION/unauthenticated` when the credential's installation has no live node row.

## Enrollment

`fleet.Enroll` is the one function the sign-in flows call in their success transaction: CompleteNodeSignIn (part E1b) and the
delivering PollDeviceAuthorization (part E2); its own rules are also exercised by SEEDED function-level tests that call it directly. Its rules, in the order the code applies them:

1. The approving account is locked and must be Active (else the approval lapses).
2. A node ID live in another account is `CONFLICT/already_exists` (`state.state` `node`, no resource).
3. A node ID live in this account on another OS is `VALIDATION/invalid_argument` (`node.os: mismatch`), after the account lock and
   before the device lock and any write: another OS is another machine, which signs in under a node ID of its own.
4. A key an installation holds is registered once ever: held by a live installation (other than the node's own, re-used in rule 6)
   it is `CONFLICT/already_exists` (`state.state` `node_key`, `state.reason` `already_registered`); held by a revoked one (the key was
   retired) it is `AUTHENTICATION/credential_revoked`, and the node deletes its key and starts again. For a new node, the cap must
   admit one more live node (`RESOURCE/quota_exceeded`, `limit_name` `max_nodes_per_account`, `maximum` the cap).
5. After the locks of the order below, the approving session is locked (in the session slot) and the approval lapses when that
   session was revoked by the account, by revoking all sessions, with its device or by an operator, or when its authentication or
   recovery epoch moved since the approval (a sign-out or an expiry does not lapse it). So a refusal of rules 2 to 4 is answered
   before a lapse.
6. A node ID live in this account is re-enrolled in place: its older sessions are revoked (reason 7, superseded), its name, version
   and architecture are updated, a different key replaces the stored one at the next key version, and the device follows the
   reported name as for ReportNodeInfo. Otherwise the node gets a new device (platform mapped by name: Windows is `windows` (1),
   Linux is `linux` (3), never the OsFamily number), an `arcforges-node` installation holding the key at version 1, and a node row.

Enroll runs in a savepoint of the caller's transaction and rolls it back on a lapse, on every refusal and on a store failure, so
nothing of the enrollment remains even when the caller then commits (as a flow that ends EXPIRED will): no device, installation,
session, superseded session or key (`TestNothingOfARefusedEnrollmentRemains`). The node session it issues gets the node lifetimes;
`fleet.node.enrolled` (node ID, OS, architecture, canonical version, key fingerprint, flow `pkce` or `device`, `first` or
`reenrolled`, key version) is its last statement. A concurrent enrollment of the same node ID or key is store contention, and the
identical retry answers the rule that then applies. BeginNodeSignIn and StartDeviceAuthorization refuse a key an installation holds
or held before approval, so a sign-in after a sign-out replaces the node key, and an in-place re-enrollment
normally arrives with a new key. A caller may record its result in Enroll's transaction before `fleet.node.enrolled`
(`EnrollRequest.Record`: the browser sign-in's COMPLETED flow, the device authorization's COMPLETED row).

**Node names and versions.** A node name is 1 to 64 UTF-16 units of letters, marks, numbers, punctuation, symbols and the single
space, without a leading, trailing or doubled space, at most three combining marks in a row, no braille blank and at least one
visible letter or number (`device.ValidNodeName`); control, format, private-use, unassigned and other space characters are refused,
so bidirectional overrides and invisible padding cannot reach a page. Look-alike letters of other scripts stay possible: the pages
label the name as reported by the node. A version is at most 128 characters of SemVer 2.0.0; the center stores the canonical form,
the text before the first `+` (`fleet.ValidNodeVersion`).

## Lock order

One global order, cited by the threat model (SEC-12): a sign-in flow row (a browser flow or a device authorization), `identity.user`, `device.device`, `device.installation`,
the `identity.session` rows, `fleet.node`. It is the order of `device.Revoke` (device, installations, sessions, then the cascade
participants, so `fleet.node` last) with the flow row and the account in front. The writers that lock more than one of these rows
take them in this order:

- Enroll: the account, then for a node live in the account its device (re-checking that it is not revoked) and installation, then
  the approving session `FOR SHARE`, then the supersession of the installation's sessions, then the node row (locked and re-read);
  new rows are inserted after the locks, and their only waits are unique-index waits.
- BeginNodeSignIn: the node ID's PENDING flows that present its key, in flow ID order (the one order of every writer that locks several
  flow rows), then its insert.
- GetNodeSignInFlow: one PENDING flow row (its review mark). ApproveNodeSignIn: the flow row, then (approving) the account through
  the step-up evidence and the proved challenge. CompleteNodeSignIn: the flow row, then Enroll's locks (the account, the device and
  installation, the approving session `FOR SHARE`, the superseded sessions, the node row); a reuse: the flow row, then the delivered
  family's sessions. The foreign keys of the review mark, the approval and the denial take `FOR KEY SHARE` on the deciding account
  (and, for an approval, on its session) after the flow row; no writer that holds an account or a session `FOR UPDATE` then waits for
  a flow row, so they close no cycle.
- StartDeviceAuthorization: the node ID's PENDING authorizations that present its key, in authorization ID order (the one order of
  every writer that locks several authorization rows), then its insert. LookupDeviceCode: one authorization row (its review's
  foreign key then takes `FOR KEY SHARE` on the account). ApproveDeviceCode: its command receipt row, the authorization row, then
  (approving) the account through the step-up evidence and the proved challenge; the update's foreign keys take `FOR KEY SHARE` on
  the account and the approving session. PollDeviceAuthorization: the authorization row, then Enroll's locks; a reuse: the
  authorization row, then the delivered family's sessions. Lookup and Approve give the entry budgets back (the `platform.rate_limit`
  rows, the account's then the network's) after every row of the order and before the audit chain head; every other user of those
  rows locks one row in its own transaction, except the give-back of an entry outside its decision, which takes the same two rows in
  the same order. No writer locks a device authorization and then a browser flow.
- RevokeAllSessions and RemoveAuthIdentity: the account's APPROVED flows and the PENDING flows it reviewed last, in flow ID order (the
  approval participant `fleet.node_sign_in`), then the account's APPROVED device authorizations and the PENDING ones it reviewed last,
  in authorization ID order (`fleet.device_authorization`, registered after it: the only writer that locks rows of both tables, in
  that order), then the account through the step-up evidence.
- ReportNodeInfo: the device only when it renames it, then the installation, then the node row.
- RefreshNodeSession: its session, then the node row.
- The account's step-up evidence path (RevokeSession of another session, RevokeAllSessions, RemoveAuthIdentity, DeviceService.Revoke
  of another device): the account first, then (for a device) `device.Revoke`.
- The operator's `admin revoke-sessions` and `admin revoke-device`: the accounts first, then the sessions, or `device.Revoke`; neither
  takes a flow or authorization row. A poll that waits for `revoke-sessions` holds only its authorization row, an approval only its receipt row and its
  authorization row (`revoke-sessions` takes neither), and an
  approval it overtakes lapses in Enroll (`TestOperatorRevokeSessionsRacingADeviceApprovalOrPollNeverDeadlocks`).
  `revoke-sessions` locks its account (every account in account order for `--all`) `FOR NO KEY UPDATE`; `revoke-device` locks the
  device's account `FOR UPDATE`.

**The `identity.user` rows.** Every writer that locks an account row locks one account, its own or its caller's: Enroll and the
step-up evidence path (`FOR UPDATE`), the profile and credential commands (`identity` manage), the operator role commands
(`entitlement` role, `FOR UPDATE`), `admin revoke-device`, and the sign-in and the passkey registration (`FOR SHARE`). Two
transactions touch two or more accounts:

- `admin revoke-sessions --all` locks every account in account order, `FOR NO KEY UPDATE`.
- The AF-CTR-03 operator grant (OperatorService, `entitlement.Operator`) locks its caller's account `FOR UPDATE` and then inserts the
  target account's entitlement rows; each insert's foreign key takes `FOR KEY SHARE` on the target's row, as every insert of a row
  that references an account does.

`FOR KEY SHARE` conflicts only with `FOR UPDATE`, so the grant's insert never waits for revoke-sessions' lock, and the two never close
a cycle whichever account sorts first (`TestOperatorRevocationOfEveryAccountAndAnOperatorGrantNeverDeadlock`). `FOR NO KEY UPDATE`
still conflicts with Enroll's `FOR UPDATE` and the sign-in's `FOR SHARE`, so an enrollment and the tool still wait for each other.

The writers that lock fewer rows skip slots: SignOutNode, a sign-out of the caller's own session and a browser session's renewal lock
one session row; the own-device DeviceService.Revoke takes no account lock and starts at the device; a step-up proof and the session
upgrade lock the proving session. One writer goes back in the order: a sign-in (`device.EnsureNative`, `EnsureBrowser`, AF-CTR-03
code) locks its installation and its device in one statement, the installation first, and then inserts its session. It meets a
writer of the order only on the same installation: `device.Revoke` of its device, or Enroll and ReportNodeInfo when a native claim
names a node's installation ID (refused after the lock). PostgreSQL breaks such a deadlock: the sign-in, DeviceService.Revoke and
ReportNodeInfo retry it as store contention (default attempts, as Enroll's sign-in flows do); the operator's `admin revoke-device` runs once and reports the
failure, and the operator runs it again. Reordering the statement is routed to a later Cloud change of the device package. In every
transaction a command receipt is the first row written and the audit chain head the last.

`TestCompleteTakesItsLocksInTheGlobalOrder`, `TestApproveTakesTheFlowBeforeTheAccount`, `TestTheApprovalHookTakesTheFlowsBeforeTheAccount`,
`TestPollTakesItsLocksInTheGlobalOrder`, `TestApproveDeviceCodeTakesTheAuthorizationBeforeTheAccount`,
`TestTheApprovalHooksTakeTheFlowsThenTheAuthorizationsBeforeTheAccount`, `TestTheLoserOfTwoPollsRevokesTheWinner`,
`TestEnrollTakesItsLocksInTheGlobalOrder`, `TestReportNodeInfoAndRevokeNeverDeadlock` and
`TestOperatorRevocationTakesTheAccountLocksFirst` hold one row at a time and check which rows the waiting transaction already holds;
`TestAnOSMismatchIsRefusedBeforeTheDeviceLock` holds the node's device and expects the OS refusal at once. In the race tests
(enrollment, refresh, report and the operator's revoke-sessions against revocation and re-enrollment) every transaction that locks rows
of the order runs with one attempt (the refresh through `fleet.Options.RefreshAttempts`; the rate-limit, audit and lookup
transactions, which lock no row of the order, keep the default), so a deadlock is an error of the round, and each race test also
fails when `pg_stat_database.deadlocks` of its database grew.

## Revocation

The center always registers `fleet.NodeParticipant` with the device revocation, whether or not the fleet surface is on: revoking a
node's device (DeviceService.Revoke, or the operator's command) revokes its node row (revoke reason 1) in the same transaction and
counts it in `device.revoked`; the node's next call is the transport refusal `auth.credential_revoked` and its next refresh
`AUTHENTICATION/credential_revoked`. RevokeAllSessions leaves node rows and node sessions as they are (DC-03). The node ID is then
free to enroll again with a new key; the revoked installation keeps holding the old one.

## The center's signing keys

The center delivers the public keys of `fleet.signing_key` with every sign-in and refresh: every key of a purpose that is neither
retired nor expired, including a registered successor whose `not_before` lies ahead, so a node holds it before the center signs with
it (`platform.PublishedKeys`); a key whose retirement is scheduled ahead is published with that instant as its `not_after`. Until keys
are registered the sets are empty. Generating the private keys and holding them in platform
secrets is AF-CTR-05's.

**Runbook.** With the migration role:

- `arcforges-center admin register-signing-key --purpose command|entitlement --kid <id> --public-key-file <pem|der>
--secret-binding <NAME> --not-before <rfc3339> --not-after <rfc3339>` records the public half of an ES256 P-256 key whose private
  half the named platform secret holds (at most 400 days; while keys of the purpose are valid, a successor must become valid at least
  7 days before they expire and outlive them), audited `fleet.signing_key.registered`.
- `arcforges-center admin retire-signing-key --kid <id> [--at <rfc3339>]` retires a key now or later (never backdated), audited
  `fleet.signing_key.retired`, and prints how many valid keys of its purpose remain; an emergency retirement may leave none until a
  new key is registered.
- `arcforges-center admin revoke-device --device <uuid> | --node <uuid>` releases a node ID that another account holds: the device
  (named, or as the device of the node ID's live enrollment) is revoked by the operator with its installations, every session and
  its node rows, audited `device.revoked` with the actor `operator:cli`.

The overlap rule consults only the keys valid at registration, so two successors registered ahead of time are not checked against
each other (AF-CTR-05's custody owns the schedule).

## Store

Migration `0004_fleet_enrollment.sql` ([PostgreSQL store](postgres-store.md#fleet-af-ctr-04)) holds `fleet.node` and the two sign-in
flow tables; `0005_device_user_code_index.sql` indexes the user code of every device authorization (0004 indexes only the live ones),
because a lookup and a decision answer an expired code or one in another state, and the approver may deny an APPROVED one. `identity.spent_refresh` gains one row per node refresh: at the default cadence about 13,140 rows per node-year (an
estimate of 3 MB with its indexes), removed at the family's absolute end by AF-PLAT-01's sweep; until then they only grow, and
`SELECT count(*) FROM identity.spent_refresh` is the operator's measure.

## Metrics, audit and transactions

`arcforges_center_fleet_events_total{event,outcome}` counts closed pairs (`refresh` rotated, reused, refused, rate_limited; `report`
changed, unchanged, rate_limited; `sign_out` signed_out; `enroll` first, reenrolled, node_conflict, key_registered, key_retired,
quota, lapsed; `begin` started, refused, rate_limited; `review` reviewed, shown, refused; `approve` approved, reissued, denied,
refused, rate_limited; `complete` completed, refused, reused, proof_failed, lapsed, rate_limited; `start` started, refused,
rate_limited; `poll` pending, slow_down, delivered, denied, expired, reused, lapsed, not_found, proof_failed, refused, rate_limited;
`lookup` shown, refused, rate_limited; `device_decide` approved, denied, refused, rate_limited; `entry` unknown, expired, state,
unreviewed, lookups: every user-code entry that keeps its reservation, by kind); any other pair is counted as
`unlisted`, and the fleet integration harness fails a test after which the composed center counted one. Audit events:
`fleet.node.enrolled`, `fleet.node_sign_in.approved`, `.code_reissued`, `.denied`, `.verifier_failed`, `.code_reused`,
`.approval_lapsed`, `fleet.device_authorization.approved`, `.denied`, `.lookups_exhausted`, `.code_reused`, `.approval_lapsed`,
`fleet.node.info_reported`, `fleet.node.signed_out`, `fleet.signing_key.registered`, `fleet.signing_key.retired`,
`device.revoked` (with the participant count), `identity.session.refresh_reused` (with the scope), `identity.sessions.revoked_all` and
`identity.credential.removed` (with the cancelled approvals), `access.refused`, `identity.rate_limited`; no payload holds a token,
code, verifier, proof, address or e-mail. Transactions per request: BeginNodeSignIn its bucket counts, one read of the key's holder (no
transaction held) and one effect transaction (the supersession and the insert); GetNodeSignInFlow one auxiliary transaction (the
review mark); ApproveNodeSignIn one bucket count and one effect transaction (the evidence, the decision, its audit);
CompleteNodeSignIn one read (no transaction held), the failure bucket's count only for a mismatch, then one effect transaction (the
completion, a reuse or a lapse) or one auxiliary transaction (the failure marker, which carries the reuse revocation when it finds
the flow completed by a racing presentation of the code; an unanswered commit of it is then answered `RESOURCE/overloaded` although
the revocation may have committed, and the retry answers `code_reused`), with no transaction open while PKCE or ES256 is verified; RefreshNodeSession one lookup (no transaction held), one bucket count, one rotation; ReportNodeInfo one bucket count and one
receipt transaction; SignOutNode one receipt transaction; StartDeviceAuthorization its bucket counts, one read of the key's holder
and one effect transaction (the supersession and the insert, a savepoint per user-code draw); LookupDeviceCode two reservations
(their own transactions) and one auxiliary transaction (the review mark and the give-back); ApproveDeviceCode a receipt lookup, one
bucket count, two reservations and the receipt's effect transaction (the evidence, the decision, the give-back, its audit), and the
give-back in a transaction of its own after a refusal of a reviewed code or a store failure; PollDeviceAuthorization one read (no
transaction held), the failure bucket's check and count only for a code that names nothing or a failed proof, the
per-authorization bucket's count, then one auxiliary transaction (an expiry, SLOW_DOWN or the last poll) or one effect transaction
(the delivery, a lapse or the reuse revocation; it is also the transaction of every answer to a poll whose unlocked read was
APPROVED), with no transaction open while ES256 is verified.

**Exchange captures.** `TestFleetExchangeCapture` records the node-facing exchanges as the binary gRPC-Web frames on the wire, with
the request headers that matter (the bearer's placeholder, the client address): every outcome the center produces without a store
failure of BeginNodeSignIn (success, `invalid_argument`, `rate_limited`, `already_exists` node key, `not_activated`) and
CompleteNodeSignIn (success, `not_found`, `expired`, `code_reused`, `unauthenticated`, `invalid_argument`, `already_exists` node and
node key, `credential_revoked`, `quota_exceeded`, `rate_limited`, `not_activated`), and the success and the refusals a node reacts to
of RefreshNodeSession, ReportNodeInfo and SignOutNode, StartDeviceAuthorization (success, `invalid_argument`, `rate_limited`,
`already_exists` node key, `not_activated`) and PollDeviceAuthorization (every state value: PENDING, SLOW_DOWN, APPROVED with the
credentials, COMPLETED after delivery, DENIED, EXPIRED; and `not_found`, `unauthenticated`, `invalid_argument`, `rate_limited`,
`already_exists` node and node key, `credential_revoked`, `quota_exceeded`, `not_activated`); each file names its outcome and the test fails when one of that per-method list
has no case. Not captured: the store failures `RESOURCE/overloaded` (retry after a while, the effect did not happen) and
`INTERNAL/internal` (effect unknown, never retried), which need fault injection and are covered at the service level by the
fault-injection tests (E1-16, E1-17), StartDeviceAuthorization's `RESOURCE/overloaded` after five live user-code collisions (a domain
outcome, covered by `TestLiveUserCodeCollisionRetries`), `RESOURCE/kill_switch_active`, which AF-CTR-04 does not produce, and Poll's
`invalid_argument` `node.os: mismatch` (an Enroll rule). The browser-facing LookupDeviceCode and ApproveDeviceCode are not captured. Only
the values the center or a random source produced are normalized (correlation, flow, installation and account IDs, tokens, the
one-use codes, the device and user codes, the proofs, every instant as an offset), each distinct value to its own placeholder of the same shape, wherever it
appears; the test's own constants stay. The files live in `center/internal/fleetapi/testdata/exchanges`; the test fails when a fresh
capture differs and rewrites the directory with `ARCFORGES_UPDATE_EXCHANGES=1` (`ARCFORGES_CENTER_COMMIT` names the commit in the
headers; `npx prettier --write` formats the files, and the comparison reads them as JSON). Parts N1 and N2 will copy the directory
verbatim for the ArcForges node's FakeCenter conformance test; nothing checks it against a node yet.

## The pages

Six page routes of the `fleet` surface (`routes.FleetPageRoutes`; the Worker's generated page table carries them, and forwards them
only while `fleet` is enabled: otherwise both the Worker and the center answer 404 before anything else). They follow every rule of
the center's pages ([center-identity.md](center-identity.md), "Account pages"): the seven security headers (`Cache-Control:
no-store, no-transform` among them), no query string (400), exactly one `Origin` on a POST (403), the session's CSRF token (403),
the form media type (415) and a 4096-byte bound (413). None of them redirects or sets a cookie.

| Route                     | Credential                                                                                                     | What it calls in process (`fleetapi.Direct`, the cookie session as the caller)                    |
| ------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `GET /connect`            | none (static; the script asks the bootstrap route)                                                             | nothing                                                                                           |
| `POST /connect/review`    | cookie session + CSRF                                                                                          | GetNodeSignInFlow                                                                                 |
| `POST /connect/decision`  | cookie session + CSRF; step-up of `fleet.approveNodeSignIn` bound to the flow ID on approval only              | ApproveNodeSignIn (and GetNodeSignInFlow to show the review again)                                |
| `GET /activate`           | none (static)                                                                                                  | nothing                                                                                           |
| `POST /activate/review`   | cookie session + CSRF                                                                                          | LookupDeviceCode                                                                                  |
| `POST /activate/decision` | cookie session + CSRF; step-up of `fleet.approveDeviceCode` bound to the normalized user code on approval only | ApproveDeviceCode under the account's command receipt (and the review read that counts no lookup) |

The pages decide nothing the API does not: `fleetapi.Direct` runs the same functions as the Connect methods (the operation table, the
domain call, the receipt and the entry choreography of a device decision), so a page and the API share the review window, the
budgets, the receipts and the audit events.

**The fragment.** A node opens `<public base URL>/connect#flow=<flow ID>` or `<public base URL>/activate#code=XXXX-XXXX`. The flow ID
and the code travel in the URL fragment: never sent to a server (so not in a server, Worker or edge log) and never in a Referer;
browsers can keep it in history, so the flow ID and the code are short-lived (10 minutes) and single-use, and the pages and the
sign-in page drop it from the address bar at once. The page's script reads the fragment and calls `history.replaceState` before any
request, then checks it (a flow ID is the canonical lower-case 8-4-4-4-12 form; a code is 8 letters of the code alphabet, case and
separators ignored); a malformed value is never sent. Signed in, `/connect` submits its review at once and `/activate` fills the
"Activation code" field. Signed out, `/connect`'s script opens the sign-in page at once, while `/activate` fills the field and opens the
sign-in page only when the person presses Continue; either way the return value is the page and its fragment, and the sign-in page
follows a return with a fragment only for these two exact paths and shapes.

**The review page** shows the node as it described itself: its name in quotes, in its own `<bdi>` isolate, followed by the line "The
name is reported by the node and is not verified."; its OS, architecture and version; its key's fingerprint (on `/activate` without
the last group, which the person approving types from the node's own output; a wrong group is refused before any step-up evidence is
consumed and counts as a wrong entry of the account's budget); when it was requested and how long ago; when it expires; the account it
joins (display name and masked e-mail address); and the origin line. Deny comes first.

**The origin line** is the country and the network (autonomous system number) Cloudflare reports for the node's Begin or Start: the
hosted Worker sets `X-Arcforges-Client-Country` and `X-Arcforges-Client-Asn` from `request.cf` on every surface call (a client's
header of the same name never reaches the Container), and an official-hosted center stores exactly one valid value of each
(`begin_country`, `begin_asn`). It is a hint, without "same network" or "different network" text. A self-hosted center always stores
neither and shows "Origin unknown", also behind a trusted proxy: a proxy configured for the client address header passes other client
headers through, and the line would then be the node's own claim.

**Decisions.** An approval needs the proved step-up; a denial needs none. A decision refused with `AUTHENTICATION/step_up_required` (or,
on `/activate`, a wrong fingerprint group) shows the review page again with the refusal's own status: `/connect` reads it again
through GetNodeSignInFlow, `/activate` through a read that counts no lookup and writes nothing, run only after those two refusals
(both come after the decision's own review check), never through LookupDeviceCode. Every rendering of the `/activate` review carries a
new command ID, and the typed group joins the receipt's request digest, so a corrected group is a new command and a command ID replayed
with another group is `CONFLICT/command_id_reused`. The Connect method ApproveDeviceCode carries no fingerprint group (the contract has
no field for it). The result of a `/connect` decision is a 200 page that carries the link back to the node's loopback receiver
(`rel="noopener noreferrer"`); the script follows it only after checking its exact shape (`http://127.0.0.1:<port>/callback` or
`http://[::1]:<port>/callback` with the code and state, or `error=access_denied` and state), and the page says that the browser must
run on the computer that runs the node. The result of an `/activate` approval offers the denial while the node has not collected
its credentials.

**Texts** (the center never sends text to show): `VALIDATION/code_invalid` by its limit (the entries left of the account's budget, none
left, or a code whose five lookups are spent), the node cap with its maximum (`RESOURCE/quota_exceeded`, 400 on the pages), each state
of a request (`STATE/invalid_state` with its reason, `not_reviewed` among them, one text whether another account reviewed it later or the
review is older than 10 minutes), a restricted account, and the fleet's own texts of `STATE/expired`, `STATE/not_found`,
`CONFLICT/command_id_reused` and `AUTHENTICATION/step_up_required`.

The devices page shows each name in an isolate and, for a node, when its credential ends at the latest (the live node session's
absolute expiry).

## node-probe and the node-approve run

`center/cmd/node-probe` is a development stand-in for a node (**MOCKED**: a Go program with a software P-256 key, not the ArcForges
node, which parts N1, N2 and X prove; never in the image). `go run ./cmd/node-probe -center <public base URL> -flow pkce|device -dir
<handshake dir> -case <name> [-decision approve|deny] [-idle 75s] [-poll-floor 10s]` signs in over the public routes, writes
`<case>.begin.json` (the URL, the user code, the fingerprint, the node's description; no secret) and, after the person's decision, checks
the credentials, refreshes, waits `-idle`, refreshes again, presents the spent refresh token (a reuse: the family is revoked; a device
sign-in also polls its device code again and gets COMPLETED without credentials) and the current one (refused), and writes
`<case>.result.json` (each step's outcome and the instant of each request; no token, code, device code or proof). A center behind a
throwaway certificate authority is trusted through `SSL_CERT_FILE`.

`node eng/verification/browser/node-approve.ts --base-url <public base URL> --watch <handshake dir> [--cases <n>] [--negative]` (the
browser acceptance's node-approve mode) decides those sign-ins in the pinned Chromium with the saved owner credential (**MOCKED**
hardware: the virtual authenticator in a real browser), checks each review page against the begin file, hands a browser sign-in's
result back to the probe's loopback receiver (the first browser sign-in of a run by the page's manual link, the others by the page's
script), waits for each probe result, and at the end, also after a failed step, revokes the devices its approvals may have created:
each approval's node name is recorded before its decision is sent, so an approval the center committed before a later check failed is
revoked too, and the report always carries `devicesLeft` (0, the count, or `unknown` when the clean-up could not look). The probe runs
on the browser's machine (its loopback receiver must be the browser's).

A 429 during a run: only the steps that open a link, and the clean-up's visit of the devices page, start again from their navigation
after a 429. Every other step starts from the page an earlier step left (a review, a lookup, a decision with its step-up proof, a wrong
fingerprint group, a revocation) and fails the run on a 429 instead, so none of them is ever sent twice. Besides, the driver counts as a
change (after which even a restartable step fails on a 429) every POST the center accepted below 400 other than a flow's begin, a
step-up proof and the operator grant's review, and every `/connect/decision` or `/activate/decision` POST the center answered below 500
(the wrong group's 400 and a step-up refusal included; the edge's 429 is no change). A 429 on a run may be the edge's or one of the
center's limits below (`step_up` of the account, `node_approve_account`, `device_entry_account`): the center's come from regression runs
less than 10 minutes earlier, from a repeated attempt, or from a `--cases` larger than the checklist's.

What a run spends:

| Limit                                                       | Value                                         | A run                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The hosted edge (browser and probe share the machine's key) | 60 requests per 60 s per client               | the browser paces itself at 36 requests a minute after a burst of 4 (at most 40 in any minute); the run fails when the browser's busiest minute and the probe's together exceed 55                                                                                            |
| Step-ups per account                                        | 10 in 10 minutes                              | one per approval, one per revoked device, one for `--negative`; `--cases` refuses a set that could spend more than 10 (2 per case, 1 for `--negative`); the returning acceptance spends 3 and `--operator-grant` 2: wait 10 minutes between those runs and a node-approve run |
| `node_approve_account`                                      | 20 decisions an hour                          | one per decision                                                                                                                                                                                                                                                              |
| `device_entry_account`                                      | 5 wrong entries per window                    | `--negative` spends one                                                                                                                                                                                                                                                       |
| `node_flow_prefix`                                          | 10 Begin and Start per 10 minutes per network | one per case, from the probe's address                                                                                                                                                                                                                                        |

The handshake directory holds display user codes and the URLs that carry them: delete it after a run and keep it out of the evidence.

## Post-deploy checklist (H1)

The coordinator runs it after the merge and the `proof=deploy` dispatch. It needs the saved proof owner credential (on the Windows
host `deku`, never copied) and the operator checkout there at the merge commit (`npm ci` in `eng/verification/browser`). Leave at least
90 seconds between two browser runs and warm the Container with the healthz `curl` 10 to 20 seconds before each; the healthz request
counts against the Hello limiter, not the edge limit of the pages. In the regression runs of step 4 a 429 of the edge starts a step
again from its navigation, unless a change was made in it (the run then fails and says so; see the Worker reply table of
[center-entitlement.md](center-entitlement.md), "Post-deploy checklist"). In the node-approve run of step 5 only the steps that open a
link start again; every later step fails on a 429, and a 429 there may also be a limit of the center (see "node-probe and the
node-approve run" above): do not repeat the run within 10 minutes. REAL: the hosted Worker, Container, PostgreSQL (`arcforges_acceptance`) and Chromium. **MOCKED**: the
authenticator (Chromium's virtual authenticator through CDP) and the node (`node-probe`, a Go stand-in, not the ArcForges node: N2, X
and H2 prove the real node). The run shows how the one Chromium version it records treats the navigation from the hosted page to the
loopback receiver; it proves nothing about other browsers.

1. **Production stays dark.** `curl -si https://arcforges.com/api/healthz`: `revision` the merge commit, `center.surfaces` `none`;
   `https://arcforges.com/api/connect` and `/api/activate` answer the Worker's plain 404; a fleet method answers `STATE/not_activated`
   with `state.reason` `fleet`.
2. **Proof carries the surface.** `curl -si https://proof.arcforges.com/api/healthz`: `center.surfaces`
   `identity,pages,operations,fleet`, equal to `center.configuredSurfaces` of `artifacts/proof-deployment.json`; the migration gate shows
   `arcforges_acceptance` at version 5.
3. **The pages' replies** (from the Linux host, a key of its own): `curl -si https://proof.arcforges.com/api/connect` and `/api/activate`:
   200, the seven security headers exactly, `Cache-Control: no-store, no-transform`, no `cloudflareinsights` and no `data-cf-beacon` in the
   body; `curl -si -X POST https://proof.arcforges.com/api/connect/review` without an `Origin`: 403;
   `curl -si 'https://proof.arcforges.com/api/connect?flow=x'`: 400.
4. **Regression with `fleet` on** (`deku`): the returning acceptance (`acceptance.ts`) and then `acceptance.ts --operator-grant` print
   PASSED (E3 changed the sign-in page's script, the devices page and the shared script both runs use). Then wait 10 minutes (step-ups).
5. **Node approvals** (`deku`): build the probe from the operator checkout (`cd center; go build -o <tmp>/node-probe ./cmd/node-probe`;
   if the module download fails there, the coordinator cross-compiles it on Linux from the merge commit and records its sha256), start
   `node-probe -center https://proof.arcforges.com/api -flow pkce -case pkce-1 -dir <dir>`, `-flow device -case device-1` and
   `-flow pkce -case pkce-2`, then `node eng/verification/browser/node-approve.ts --watch <dir> --cases 3`. The run approves all three
   (the first browser sign-in, `pkce-1`, hands the code back by the page's manual link; `pkce-2` by the page's own script, the
   navigation from the hosted page to the loopback receiver an owner normally sees); each probe receives credentials, refreshes,
   refreshes again after 75 s idle (a Container that slept), sees a reuse revoked, and prints PASSED; the run prints PASSED with the
   request counts (browser busiest minute plus the probe's at most 55). What it spends: 6 step-ups (3 approvals, 3 revocations; 10 in
   10 minutes allowed), 3 decisions of `node_approve_account` (20 an hour), no wrong entry, 3 Begin/Start of `node_flow_prefix` (10 in
   10 minutes); about 75 browser requests and 20 probe requests over the run.
6. **Clean-up.** The run revokes the probe devices itself, also after a failed step; it lists any device it left (`devicesLeft`): revoke
   such a device on `/account/devices` by hand. Delete the handshake directory.
7. **Afterwards.** Production dark and proof's `center.surfaces` as in steps 1 and 2. What stays on `arcforges_acceptance`: the flows and
   authorizations (append-only until AF-PLAT-01's sweeps), the revoked devices, installations and nodes, the revoked node sessions,
   the account's command receipts of the device approval (ApproveDeviceCode), the `identity.spent_refresh` rows of the probes'
   refreshes (kept to their family's absolute end), the rate-limit rows of the run (step-ups, decisions, flows), the step-up challenges,
   the run's browser session (it ends by itself), and the audit events.

**What is proven, and how.**

| Evidence                                                                                                                              | Label                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The pages, `fleetapi.Direct`, the origin columns, the tail check and the review read                                                  | REAL in the Go integration tests (real ingress, cookie session, PostgreSQL); the authenticator is **MOCKED** (a virtual one)                                                                        |
| The node-approve flow (`runNodeApprove`) against the pages and node-probe (E3-11)                                                     | exercised by the local rehearsal only (below); its logic (clean-up, restarts, redaction, budgets) by unit tests against a fleet stand-in                                                            |
| node-probe (E3-12)                                                                                                                    | unit tests only (flags, begin and result files, the loopback receiver); its run against a center in the local rehearsal                                                                             |
| The local official-hosted rehearsal                                                                                                   | REAL browser (the pinned Chromium), center binary, PostgreSQL and the Worker's page code on this machine; **MOCKED** edge (country `DE`, ASN 64496, a documentation number), authenticator and node |
| The hosted behaviour: the origin headers from `request.cf`, the fleet pages through the real Worker, the proof-to-loopback navigation | **NOT PROVEN** until H1 (above) passes                                                                                                                                                              |

## Residual risks

- A key replaced by a same-account re-enrollment is overwritten and no longer guarded.
- A node ID is a global namespace among live rows: another account that enrolls it first holds it until the operator releases it
  (`admin revoke-device --node`); per-account node IDs are AF-CTR-05's backlog.
- Strict rotation signs out a node whose refresh reply was lost after the commit (above).
- The prefix buckets are per /24 or /56: a co-tenant can spend the failure bucket of a network, which delays only tokens that name
  nothing.
- Unsalted digests (client prefixes in rate-limit keys) are reversible by trying values within their short lives.
- A flow ID is not a secret (it is in the URL the node opens): any account that holds it may review a PENDING flow, displacing an
  earlier review, and deny it; the node then starts again. It can neither revoke a node nor end an APPROVED flow.
- A party that knows a node ID can spend that node ID's Begin bucket and delay the node's next sign-in by one window.
- A completed or revoked flow is decided by its state and its code with no time limit, and the approval's redirect
  (`http://127.0.0.1:<port>/callback?code=...`) stays in the browser's history: a later presentation of that code revokes the node's
  credential family until AF-PLAT-01's sweep removes the row (flow rows: 7 days after their end).
- A user who approves a convincing request for an attacker's node lets it in; the remedy afterwards is revoking its device.
- User codes are 8 letters of 20 (2.56e10 codes), stored as unsalted SHA-256: a reader of the database reverses a live one within its
  600 seconds (SEC-22; a keyed digest needs a center secret, AF-CTR-05's custody). The same holds for the other digests that name a
  user code: `identity.step_up_challenge.target_hash` of an approval (the SHA-256 of the class, the account and the code) and
  `platform.command_receipt.request_sha256` of a decision (the SHA-256 of the request, which holds the code). Guessing is bounded per account and per network;
  across networks the real limiter is the cost of an account: with 50 live codes a 1% chance in one 15-minute window takes about a
  million accounts of 5 guesses each.
- An account that knows a live user code (shoulder-surfed, pasted) may look it up five times, which leaves the node's own user unable
  to review and approve it (the authorization stays PENDING until it expires and the node starts again), and may deny it, which needs
  no step-up. It cannot approve it without a step-up of its own, and its approval would enroll the node into its own account. Each of
  its lookups also displaces the latest review (the latest review wins), and the displaced reviewer's decision is then `not_reviewed`
  and keeps one unit of that reviewer's budget (the F7 resolution charges every `not_reviewed`), up to four times within the code's
  five lookups.
- The network budget (20 per 15 minutes per /24 or /56) can be spent by any account on a shared network, which blocks code entry
  there for the window (availability only).
- A captured poll request replays: at APPROVED it collects the credentials, and the real node's next poll then takes the reuse path
  and revokes them (without the node key the device code alone is useless; no log holds either).
- A step-up of `fleet.approveDeviceCode` is bound to the user code, not to the authorization: a code drawn again after its row ended
  could reuse evidence of the same account within the evidence's 5 minutes, which also needs that account's review.
- The origin line is a hint: a VPN, a proxy or a mobile network shows another country or network, an attacker's server in the
  victim's country matches it, and a self-hosted center shows none. The typed fingerprint group defeats only the plain "enter this
  code" lure: a coached victim can read the group out, and an API client of ApproveDeviceCode is asked for none.
- `begin_country` and `begin_asn` are personal data like the client prefixes; their retention (7 days after the flow's end) is a target
  that AF-PLAT-01's sweeps will enforce, not delivered: until then the rows stay.
- The sign-in page's return value travels in its fragment until the page drops it; a browser's history can keep the URL a node opened.
