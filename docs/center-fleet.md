# Node enrollment on the center (the fleet surface)

AF-CTR-04 connects an ArcForges node to an account on a center: a person approves the node's sign-in in a browser (PKCE loopback) or
with a device code, and the node then holds a node credential that it refreshes and can sign out. This page describes what the center
serves for it. Parts E1a and E1b (this state) serve the browser sign-in, the node's refresh, report and sign-out, and hold the
enrollment function both sign-in flows call; the device-code sign-in (part E2) and the pages `/connect` and `/activate` (part E3)
follow. The node side is the ArcForges CloudLink (parts N1 and N2).

Enrollment is an account and device operation and is never gated (AD-0021 section 13a): every fleet row of the operation table has
no `Feature` (`TestFleetRowsCarryNoFeature`, `TestFleetRowsAreTheServedMethods`). The gated `center.nodes` key is the node's
connection, which AF-CTR-05 serves.

## Surface

The methods belong to the switchable surface `fleet`. It needs `identity` and `pages` (a list without them refuses to start), it is a
known name from part E1a, and it is enabled nowhere yet: production `FLAGSHIP_SURFACES` stays `""`, the acceptance environment keeps
`identity,pages,operations` until part E3's hosted run, and the self-hosted default stays `identity,pages` until the pages exist
(`TestTheFleetSurfaceNeedsIdentityAndPagesAndIsNoDefaultYet`). With the surface off, every fleet method answers `STATE/not_activated`
with `state.reason` `fleet`, from the Worker's generated reply before anything else is read, and from the center. Each method's Worker
budget is the contract's deadline: 5 s for GetNodeSignInFlow, 15 s for CompleteNodeSignIn, 10 s for the others. A center that serves
`fleet` needs a public base URL of at most 462 characters (it refuses to start otherwise), so every URL it derives for a node stays
within the contract's 512 (`TestTheFleetSurfaceRefusesABaseURLTooLongForItsURLs`). A self-hosted center whose base URL cannot be a WebAuthn relying
party clears the default surfaces and serves none (`TestASelfHostedCenterOnAnAddressServesNoSurface`); a list that names a surface
refuses to start there.

## Served methods

| Method                                   | Operation ID               | Risk | Credential                          | Restricted account's node | Receipt                                       |
| ---------------------------------------- | -------------------------- | ---- | ----------------------------------- | ------------------------- | --------------------------------------------- |
| NodeEnrollmentService.BeginNodeSignIn    | `fleet.beginNodeSignIn`    | R1   | anonymous                           | (no credential)           | never (`meta.command_id` is correlation only) |
| NodeEnrollmentService.GetNodeSignInFlow  | `fleet.getNodeSignInFlow`  | R2   | account session                     | refused (the account)     | never (a mark)                                |
| NodeEnrollmentService.ApproveNodeSignIn  | `fleet.approveNodeSignIn`  | R3   | account session, step-up to approve | refused (the account)     | never (the reply holds the code)              |
| NodeEnrollmentService.CompleteNodeSignIn | `fleet.completeNodeSignIn` | R1   | anonymous (the flow-bound proof)    | (no credential)           | never (a one-use code)                        |
| NodeEnrollmentService.RefreshNodeSession | `fleet.refreshNodeSession` | R1   | anonymous (refresh token)           | allowed                   | never                                         |
| NodeEnrollmentService.ReportNodeInfo     | `fleet.reportNodeInfo`     | R1   | node credential                     | refused                   | yes (`node:<installation id>`)                |
| NodeEnrollmentService.SignOutNode        | `fleet.signOutNode`        | R2   | node credential                     | allowed                   | yes (`node:<installation id>`)                |

con-07 names no fleet operation, so the IDs are the center's own (`fleet.<method>`). Every other `NodeEnrollmentService` method stays
unregistered (`UNIMPLEMENTED`, no Worker row): the device-code sign-in methods until part E2, and the phone
pairing, certificate, LAN, entitlement-token, entitlement-key and support-upload methods of later tasks. `GetEntitlementKeys` is not
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
The country and network of the request (`begin_country`, `begin_asn`) are not recorded until part E3, which shows them.

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

`fleet.Enroll` is the one function the sign-in flows call in their success transaction: CompleteNodeSignIn since part E1b, and part
E2's device poll will; its own rules are also exercised by SEEDED function-level tests that call it directly. Its rules, in the order the code applies them:

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
identical retry answers the rule that then applies. BeginNodeSignIn refuses a key an installation holds or held before approval
(part E2's StartDeviceAuthorization will too), so a sign-in after a sign-out replaces the node key, and an in-place re-enrollment
normally arrives with a new key. A caller may record its result in Enroll's transaction before `fleet.node.enrolled`
(`EnrollRequest.Record`: the browser sign-in's COMPLETED flow).

**Node names and versions.** A node name is 1 to 64 UTF-16 units of letters, marks, numbers, punctuation, symbols and the single
space, without a leading, trailing or doubled space, at most three combining marks in a row, no braille blank and at least one
visible letter or number (`device.ValidNodeName`); control, format, private-use, unassigned and other space characters are refused,
so bidirectional overrides and invisible padding cannot reach a page. Look-alike letters of other scripts stay possible: the pages
label the name as reported by the node. A version is at most 128 characters of SemVer 2.0.0; the center stores the canonical form,
the text before the first `+` (`fleet.ValidNodeVersion`).

## Lock order

One global order, cited by the threat model (SEC-12): a sign-in flow row, `identity.user`, `device.device`, `device.installation`,
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
- RevokeAllSessions and RemoveAuthIdentity: the account's APPROVED flows and the PENDING flows it reviewed last, in flow ID order (the
  approval participant `fleet.node_sign_in`; part E2's `fleet.device_authorization` participant will run after it), then the account
  through the step-up evidence.
- ReportNodeInfo: the device only when it renames it, then the installation, then the node row.
- RefreshNodeSession: its session, then the node row.
- The account's step-up evidence path (RevokeSession of another session, RevokeAllSessions, RemoveAuthIdentity, DeviceService.Revoke
  of another device): the account first, then (for a device) `device.Revoke`.
- The operator's `admin revoke-sessions` and `admin revoke-device`: the accounts first, then the sessions, or `device.Revoke`.
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
ReportNodeInfo retry it as store contention (default attempts; Enroll's sign-in flows, parts E1b and E2, will too); the operator's `admin revoke-device` runs once and reports the
failure, and the operator runs it again. Reordering the statement is routed to a later Cloud change of the device package. In every
transaction a command receipt is the first row written and the audit chain head the last.

`TestCompleteTakesItsLocksInTheGlobalOrder`, `TestApproveTakesTheFlowBeforeTheAccount`, `TestTheApprovalHookTakesTheFlowsBeforeTheAccount`,
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
flow tables. `identity.spent_refresh` gains one row per node refresh: at the default cadence about 13,140 rows per node-year (an
estimate of 3 MB with its indexes), removed at the family's absolute end by AF-PLAT-01's sweep; until then they only grow, and
`SELECT count(*) FROM identity.spent_refresh` is the operator's measure.

## Metrics, audit and transactions

`arcforges_center_fleet_events_total{event,outcome}` counts closed pairs (`refresh` rotated, reused, refused, rate_limited; `report`
changed, unchanged, rate_limited; `sign_out` signed_out; `enroll` first, reenrolled, node_conflict, key_registered, key_retired,
quota, lapsed; `begin` started, refused, rate_limited; `review` reviewed, shown, refused; `approve` approved, reissued, denied,
refused, rate_limited; `complete` completed, refused, reused, proof_failed, lapsed, rate_limited); any other pair is counted as
`unlisted`, and the fleet integration harness fails a test after which the composed center counted one. Audit events:
`fleet.node.enrolled`, `fleet.node_sign_in.approved`, `.code_reissued`, `.denied`, `.verifier_failed`, `.code_reused`,
`.approval_lapsed`, `fleet.node.info_reported`, `fleet.node.signed_out`, `fleet.signing_key.registered`, `fleet.signing_key.retired`,
`device.revoked` (with the participant count), `identity.session.refresh_reused` (with the scope), `identity.sessions.revoked_all` and
`identity.credential.removed` (with the cancelled approvals), `access.refused`, `identity.rate_limited`; no payload holds a token,
code, verifier, proof, address or e-mail. Transactions per request: BeginNodeSignIn its bucket counts, one read of the key's holder (no
transaction held) and one effect transaction (the supersession and the insert); GetNodeSignInFlow one auxiliary transaction (the
review mark); ApproveNodeSignIn one bucket count and one effect transaction (the evidence, the decision, its audit);
CompleteNodeSignIn one read (no transaction held), the failure bucket's count only for a mismatch, then one effect transaction (the
completion, a reuse or a lapse) or one auxiliary transaction (the failure marker, which carries the reuse revocation when it finds
the flow completed by a racing presentation of the code; an unanswered commit of it is then answered `RESOURCE/overloaded` although
the revocation may have committed, and the retry answers `code_reused`), with no transaction open while PKCE or ES256 is verified; RefreshNodeSession one lookup (no transaction held), one bucket count, one rotation; ReportNodeInfo one bucket count and one
receipt transaction; SignOutNode one receipt transaction.

**Exchange captures.** `TestFleetExchangeCapture` records the node-facing exchanges as the binary gRPC-Web frames on the wire, with
the request headers that matter (the bearer's placeholder, the client address): every outcome the center produces of BeginNodeSignIn
(success, `invalid_argument`, `rate_limited`, `already_exists` node key, `not_activated`) and CompleteNodeSignIn (success,
`not_found`, `expired`, `code_reused`, `unauthenticated`, `invalid_argument`, `already_exists` node and node key, `credential_revoked`,
`quota_exceeded`, `rate_limited`, `not_activated`), and the success and the refusals a node reacts to of RefreshNodeSession,
ReportNodeInfo and SignOutNode; each file names its outcome and the test fails when one of that per-method list has no case. Only
the values the center or a random source produced are normalized (correlation, flow, installation and account IDs, tokens, the
one-use codes, the proofs, every instant as an offset), each distinct value to its own placeholder of the same shape, wherever it
appears; the test's own constants stay. The files live in `center/internal/fleetapi/testdata/exchanges`; the test fails when a fresh
capture differs and rewrites the directory with `ARCFORGES_UPDATE_EXCHANGES=1` (`ARCFORGES_CENTER_COMMIT` names the commit in the
headers; `npx prettier --write` formats the files, and the comparison reads them as JSON). Parts N1 and N2 will copy the directory
verbatim for the ArcForges node's FakeCenter conformance test; nothing checks it against a node yet.

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
