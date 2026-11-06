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

The methods and the six pages belong to the switchable surface `fleet`; the node channel is the surface `relay` ([node channel](#node-channel)). It needs `identity` and `pages` (a list without them refuses to
start). Production `FLAGSHIP_SURFACES` stays `""` (AF-PROD-01 activates it); the acceptance environment (`proof`) carries
`identity,pages,operations,fleet,mobile` (`mobile` since AF-CTR-04 part M; pinned by `tests/worker/center-config.test.ts` and `tests/worker/proof-deploy.test.ts`); a
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

## Node registry

AF-CTR-05 part E2a serves FleetService's node registry on the switchable surface `nodes` (Plan CTR5-SUR-01, Q10): it needs `identity`,
`fleet` and `relay` (a list without them refuses to start), is in the self-hosted default (and leaves it with `relay` when no command
key is configured), and production keeps it off: there, and on proof until AF-CTR-05 part E3, the four methods answer
`STATE/not_activated` with `state.reason` `nodes` from the Worker. The registry is never gated (Q20: a lapsed account still lists,
renames and revokes its nodes), and it stands behind no per-account control: ListNodes and GetNode, relayed calls included, are
bounded only by the Worker's per-client edge limit (and a relayed read by the verification's one read-only transaction). The routed task methods are served from part E2b ([Routed calls](#routed-calls)); every other FleetService method stays
unregistered (`UNIMPLEMENTED`, no Worker row; Plan CTR5-API-01: SendNodeCommand, GetNodeCommand, ListNodeCommands, CancelNodeCommand,
the push preferences, IssueRelayToken, OpenFleetWatch and WatchFleet; `TestTheRegistryRowsAreTheServedMethods`).

| Method                  | Operation ID       | Risk | Credential                                                     | Restricted account | Receipt              |
| ----------------------- | ------------------ | ---- | -------------------------------------------------------------- | ------------------ | -------------------- |
| FleetService.ListNodes  | `fleet.listNodes`  | R1   | account session (`mobile.limited` included); node-relayed      | refused            | never (a read)       |
| FleetService.GetNode    | `fleet.getNode`    | R1   | account session (`mobile.limited` included); node-relayed      | refused            | never (a read)       |
| FleetService.RenameNode | `fleet.renameNode` | R2   | account session (`mobile.limited` upgrades first)              | allowed            | yes (`account:<id>`) |
| FleetService.RevokeNode | `fleet.revokeNode` | R3   | account session with step-up (`mobile.limited` upgrades first) | allowed            | yes (`account:<id>`) |

- **Node-relayed reads (C-N6; decisions B-4).** A node credential reaches ListNodes and GetNode only as the relay of its own node: its
  request carries a routed caller (`NODE_RELAY`, the relaying node, the local origin) and a relay assertion, and the authorizer itself
  verifies the assertion with the hub (`access.Authorizer.AuthorizeRelayed` with `hub.Hub.RelayVerifier`, `access.WithRelayVerifier`)
  before ownership, scope, the controls or the audit, then checks that the relay it receives is verified and verified for the bearer
  credential's own installation. The assertion's request digest is SHA-256 of the request's top-level fields as transmitted, every
  occurrence of `relay_assertion` left out (Contracts relay.proto `RelayAssertion`; binary encoding only, which is all the ingress admits).
  A bearer token alone, or a caller without an assertion, is refused `AUTHENTICATION/unauthenticated` (`state.state` `relay_assertion`,
  `state.reason` `missing`); a nonce spent again `nonce_reused`; another target, another origin or a field changed after signing
  `request_mismatch`; another node's credential `signature_invalid`. None of these refusals writes anything, and a read writes nothing:
  the verification reads the credential's node and key, and spends the nonce in memory (`TestATokenWithoutTheNodeKeyReadsNothing`).
  The authorizer's later stages write their refusal audit as for any row: a restricted account's relayed read, for one, is audited
  `access.refused` (`restricted`). The authorizer compares the relay's installation with the bearer credential's; that the relaying node
  is the credential's live node of that installation is checked by the hub's verifier (`hub.VerifyRelayAssertion`), one live node per
  installation making the two the same binding. A relay
  assertion refusal is a metric (`assertion`), not an audit row: it carries nothing trustworthy to record, and a row per refusal would let
  a token thief write. The rows that admit a relayed caller are a person's rows with `RelayedScopes` `node`; `CheckRow` holds them to
  RelayedOperations (the two reads here and the six routed task methods of E2b), never `Restricted`, gated or R1, addressing a node or
  nothing, and their `mobile.limited` and step-up rules apply to the account-session half only (`TestTheRelayedRowsFollowTheirRules`,
  `TestAuthorizeVerifiesTheRelayOfANodeCaller`). An account session whose request names a `NODE_RELAY` caller or carries an assertion is
  refused `AUTHORIZATION/permission_denied` (`principal`), audited `access.refused`, and so is an automation credential; a routed caller
  of any other kind is `VALIDATION/invalid_argument` (`caller.kind`), refused before authorization and not audited
  (`TestAPersonSessionCannotSendANodeRelayCaller`).
- **Values (CTR5-API-02).** ListNodes answers the account's live enrollments, oldest first (`node_id` is unique among the live rows
  only), each with `online` (`ONLINE` while the node's channel is open in this process, `OFFLINE` once a channel was accepted,
  `NEVER_CONNECTED` before; a process that does not hold the hub lease has no channel, so it states no node `ONLINE`), `last_seen_at` (the
  later of the node's last contact and its channel's last recorded heartbeat), `enrolled_at`, `device_id`, OS, architecture, the canonical
  version, `credential_expires_at` (the latest `expires_at` of the node's sessions that are neither revoked nor expired, absent when it
  holds none) and `reported_name`; no summary (AF-CLD-04), and no `role` (the store keeps none: the host and guest roles were retired by
  AD-0018). GetNode answers one live node of the account and no `recent_commands` (routing records are not command views).
  An unknown, another account's and a revoked node are the same `STATE/not_found`, answered at the ownership stage before anything is
  written, for RenameNode and RevokeNode too, evidence for that node ID held or not (`TestTheRegistryListsTheAccountsLiveNodes`,
  `TestAForeignNodeIsNotFoundAndWritesNothing`). ListNodes answers every live node in one reply, up to the enrollment cap's upper
  bound of 1,000 (`config.MaxNodesPerAccountBound`): its reply budget, 640 KiB, holds 1,000 FleetNodes as large as the rules admit
  (`TestTheListNodesReplyFitsItsBoundAtTheCap`). A restricted account may rename and revoke its nodes (as DeviceService.Rename and
  Revoke) but not list or read them through FleetService, because a row that admits a relayed caller is never `Restricted`;
  DeviceService.List still shows it its devices.
- **RenameNode (CTR5-API-03, Q25: the account's name wins).** The name follows the rule of the name a node reports (`device.ValidNodeName`: 1 to 64
  UTF-16 units of letters, marks, numbers, punctuation, symbols and single spaces); the node's registry name (`fleet.node.display_name`) and its device's name take it in the
  receipt's transaction, the node is marked `named_by_account`, its reported name is kept (a row from before 0009, without
  `reported_name`, keeps its `display_name` as such in the same UPDATE: `TestARenameOfAnEarlierRowKeepsTheReportedName`), and
  `fleet.node.renamed` is audited without the name. From then on a
  report (ReportNodeInfo, a sign-in in place) only keeps the node's own name as `reported_name`, and changes neither the node's nor the
  device's name. The node adopts the account's name at its next accepted channel (`ChannelAccepted.node_name`, the name the upgrade read).
  The reply is the renamed node, kept in the receipt, so a replay answers the node as it was renamed
  (`TestRenameNodeKeepsTheReportedNameAndTheNodeAdoptsIt`). A node that is revoked and then enrolled again is a new enrollment: it
  starts with the name it reports, not the account's earlier name.
- **RevokeNode (CTR5-API-04).** In the receipt's transaction: the step-up evidence of class `fleet.revokeNode` bound to the node ID
  (`access.TargetNode`; `identity.TargetHash` of the class, the account and the node ID), then `device.Revoke` of the node's device with
  the cascade (installations, sessions, `fleet.NodeParticipant`'s node rows, then the hub's participant, which closes the channel 4401
  once the transaction commits), and `device.revoked` audited. Without evidence, or with evidence bound to another node, the call is
  `AUTHENTICATION/step_up_required` and writes nothing. A replay answers the stored receipt; a new command for a revoked node is
  `STATE/not_found`, kept in its receipt (`TestRevokeNodeNeedsEvidenceBoundToTheNode`). Ownership for the two receipted writes finds the
  caller's own enrollments of the node ID, revoked ones included, before any other account's, so the caller's replay of a committed
  command reaches its receipt even after the node ID was enrolled again under another account
  (`TestAReplayAfterTheNodeIsEnrolledElsewhereAnswersItsReceipt`).
- **mobile.limited (T-19).** A `mobile.limited` session lists and reads; RenameNode and RevokeNode answer it
  `AUTHENTICATION/step_up_required` before anything is written (`TestAMobileLimitedSessionReadsTheRegistryButUpgradesToChangeIt`).

An AGENT row of the operation table names the exact credential scopes it admits: the two node rows admit a `node` credential only.
An account or `mobile.limited` session is refused with `AUTHORIZATION/permission_denied` and audited `access.refused` with the reason
`principal`; an `automation` or `push` credential with the reason `scope` (`TestScopeMatrixOverFleetRows`). The reply is always
`state.state` `operation`, `state.reason` the operation ID; `restricted`, `scope` and `principal` are audit reasons only.

## Routed calls

AF-CTR-05 part E2b serves FleetService's six routed task methods on the `nodes` surface (Plan CTR5-RTE-01..07, CTR5-CALL-01..03 as
amended by PB-1, PB-2, D0-B1, C-N1, C-N6, PN-1 and PN-6; the coordinator's decisions B-1..B-3, Q-1..Q-15 and section 4): SubmitNodeTask,
GetNodeTask, ListNodeTasks, WaitNodeTask, ReadNodeTaskOutput and CancelNodeTask (`internal/fleetapi/routed.go`). EVIDENCE: REAL
PostgreSQL, the REAL composed center and hub; MOCKED: the nodes (nodetest with software keys) and the step-up ceremony (its proved
challenge is seeded); NOT PROVEN: a hosted run, the real node (N1, N2). Production and proof keep `nodes` off.

**Rows.** Each method admits an account session, and a node credential only as the verified relay of its own node (the authorizer
verifies the relay assertion, whose request digest is SHA-256 of the inner request bytes, before anything else). It addresses one of
the account's live nodes (`not_found` for an unknown, revoked or foreign node, before anything is written), is gated by its group's key
(submission `center.execute`, status and output `remote.view`, control `remote.control`), stands behind `routed_calls_per_account`
and `routed_in_flight_per_account`, and appends `access.authorized` before the gate. Risks follow Design's classes: Submit R3, Cancel R2,
the reads R1. Submit and Cancel are a person's medium or high operations (PB-1): a `mobile.limited` session upgrades first, and an
account session needs step-up evidence of the row's class (`fleet.submitNodeTask`, `fleet.cancelNodeTask`) bound to the node on every
delivery; a relayed caller carries neither rule. The call header's caller is the verified session's or the verified relay's, never the
request's `caller` field.

**The inner request.** The center decodes a copy only to check its shape: Submit a `TaskSpec`; Get, Wait and Cancel a task ID;
ReadOutput an attempt ID; Submit and Cancel an inner `meta.command_id` equal to the outer one; Wait `wait_ms` at most 50,000; ReadOutput
`max_bytes` at most 262,144 and `wait_ms` at most 20,000; Submit 1..253,952 bytes, the others 1..3,072. It stores none of it and routes
the bytes unchanged. The node's response bytes are answered unchanged in `value.response` with `value.node_id`; a node's signed refusal
is the method's error, rebuilt from its closed fields.

**Deadlines (CTR5-RTE-06).** 10 s; Wait `wait_ms` + 5 s (at most 55 s); ReadOutput `wait_ms` + 10 s with `wait_ms` (at most 30 s).
The hub waits the method's deadline less a second, so the reply never passes it (Q-7). PN-1: Wait and ReadOutput set their
connection's read and write deadlines to their budget plus 5 s (`ingress.Policy.WithDeadline`), so a long poll is not cut by the
server's 20 s timeouts (`TestARoutedLongPollOutlastsTheServerTimeouts`); the routed long polls (Wait, and ReadOutput with `wait_ms`)
of all accounts hold at most half of the request connections (`config.RoutedLongPolls`; a further one is `RESOURCE/overloaded`), and
a center that serves `nodes` refuses to start when `routedInFlightPerAccount` exceeds half of `ARCFORGES_CENTER_MAX_CONNECTIONS`
(`TestTheLongPollsHoldAtMostHalfTheConnections`). The default `routedInFlightPerAccount` is 16 for that reason (an owner placeholder,
H-07).

**Reads** are routed with no record and no `fleet.routed.*` audit row (Q-10): `access.authorized` is their audit, `node_offline` a
metric.

**The routing record** (`fleet.routed_call`, migration 0010) is the receipt of Submit and Cancel (PN-6), keyed by the account and the
command ID. It holds digests, sizes, the task ID, the states and their instants, never a request or response byte, a specification,
an argument, a working directory, an environment or output (`TestTheStoreHoldsNoRoutedPayload`). The center stores no request bytes
(decisions B-3): a resend routes the resend's own bytes, accepted only when its record digest equals the record's. The record digest is
SHA-256 over the method, the node, the caller class (an account session's user, or a relay's relaying node and local origin) and the
inner request's `RequestDigestInput` (its correlation ID left out), so a resend from a refreshed session or a new local process of the
same origin converges, and another caller class under the same command ID is `CONFLICT/command_id_reused` (Q-4). Its states:

| State                | Final                                    | Meaning                                                                                                                 |
| -------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| ACCEPTED (1)         | no                                       | an attempt was admitted; while no attempt is in flight in this process it counts as one that may have reached the node  |
| SUCCEEDED (3)        | yes                                      | a verified EXECUTED result whose response is a value (Submit: its task ID)                                              |
| FAILED (4)           | yes                                      | a verified EXECUTED result whose response is the TaskService handler's own ArcError, with an effect other than UNKNOWN  |
| REJECTED_BY_NODE (5) | when the node did not say DID_NOT_HAPPEN | a verified refusal by the node's verification or policy                                                                 |
| EXPIRED (6)          | as REJECTED_BY_NODE                      | a verified EXPIRED result                                                                                               |
| UNKNOWN (7)          | no                                       | no verified result although the call may have reached the node, a node answer whose effect is UNKNOWN, or swept at boot |
| NOT_DELIVERED (8)    | no                                       | the hub answered DID_NOT_HAPPEN and no earlier attempt may have reached the node                                        |

DELIVERED (2) is reserved and never written (Q-2): delivery is known from the hub's answer (E1b's definition: the writer took the
frame), and the record's monotonic `delivered` keeps it. The record is never less conservative than the reply. For a command's first
attempt, `delivered` is set exactly when the hub's answer was UNKNOWN or a verified result (`TestARecordIsDeliveredExactlyWhenTheReplyIsUnknown`).
The record is more conservative than a reply in three places, each without a hub answer of delivery: a resend's admission sets
`delivered` for a record that was ACCEPTED (an attempt whose answer never landed may have reached the node); a resend's own
DID_NOT_HAPPEN keeps a delivered record UNKNOWN; and the boot sweep makes every ACCEPTED record UNKNOWN and delivered. The reply follows
the record in turn: a resend of a record that may have reached the node (delivered, or ACCEPTED) is never answered DID_NOT_HAPPEN; its
refusals about delivery (the node offline, the lease moved, a full queue or a bound, its deadline before delivery) are
`STATE/node_unreachable` with UNKNOWN and SAME_COMMAND, and `replay_window_passed` is UNKNOWN with NEVER
(`TestAResendThatMayHaveReachedTheNodeIsNeverDidNotHappen`). Refusals that ask the caller to act (step-up, `command_id_reused`, a
validation error) keep their own pairs. A refusal code is a smallint of the fixed, append-only table
`fleet.refusal_code` (decisions B-2; `fleet.RefusalCode`, 0 for a code outside it; `TestTheRefusalCodesAreFixed`,
`TestTheRefusalCodeTableIsTheMigrations`).

**No double execution (decisions B-1).** The record is never less conservative than the reply:

- The admission (Tx1, `fleet.AcceptRouted`) checks, in this order: an existing record's digest (`command_id_reused`); its replay window
  (a record that may have reached the node, delivered or ACCEPTED with no attempt in flight here, past `routedReplayWindow` is
  `STATE/invalid_state` `replay_window_passed`, online or not, and is never routed); the node's presence (`node_offline`, nothing
  written but one `fleet.routed.refused` audit row for a mutation, decisions Q-8, bounded by the account's routed-call quota); the
  evidence; the account's live node; the record, inserted or locked and decided again; its audit row; and, last, the hub lease row
  `FOR SHARE` under the routing fence, so a process that lost the lease commits no record and a take-over waits for the admissions in
  flight (a renewal waits only for an admission's commit, never for its audit append). The `FOR SHARE` is defence in depth: an ACCEPTED
  record with no attempt in flight already counts as delivered.
- The hub routes nothing under a fence before its boot sweep committed (`fleet.SweepRouted`, retried at every lease wake): every
  ACCEPTED record then becomes UNKNOWN and delivered (`TestALeaseTakeOverSweepsTheRecordsBeforeRouting`).
- The attempt runs on a context detached from the request; its settlement (Tx2, `fleet.SettleRouted`, guarded by the attempt number) is
  detached too and retried; a settlement that is never written leaves the record ACCEPTED, which counts as delivered
  (`TestALostSettlementCountsAsDeliveredAndTheWindowComesFirst`). Only the hub's DID_NOT_HAPPEN answer recorded by Tx2 makes a record
  NOT_DELIVERED.
- The replay window (Q-1) is 23 h by default, at most 23 h 52 min: the node's deduplication keeps an entry 24 h from its execution,
  which may come 120 s (the node's clock skew) before the record's creation; a resend admitted at the window's end reaches the node at
  most 300 s (a call's longest lifetime) later; a minute of margin: 24 h - 120 s - 300 s - 60 s.

**Joins (Q-15).** A duplicate of an attempt in flight in this process joins it: one routed call, every caller the same answer within
its own deadline, each with its own evidence consumed and its own `fleet.routed.accepted` row (reason `joined`); a caller that goes away
ends only its own wait (`TestALeaderThatGoesAwayDoesNotEndTheJoinedCall`). There is no join across processes: after a lease move only the
node's command deduplication prevents a second effect (`TestALeaseMoveDuringAnInFlightCallIsUnknownAndReplayedLater`). The per-account
in-flight bound (`routed_in_flight_per_account`) is released when the caller's request ends, while a detached attempt may run on until its
deadline: what bounds the attempts in flight is the hub's per-node (8) and per-center (1024) bounds, the routed-call bucket, and one
step-up evidence (account session) or one center relay nonce (relay) per delivery.

**Resends.** The center never answers a resend from its record: a final record's resend is routed again (fresh step-up evidence for an
account session, N-3; a fresh relay assertion for a relay) and the node's deduplication replays the recorded outcome. The replayed
EXECUTED outcome is compared with the record's outcome digest: SHA-256 of the node.v1 response as transmitted with its `ResponseMeta`
(field 1) left out and, in every `ArcError` of the outcome, its `correlation_id` and `retry.retry_at` left out (`OutcomeDigest`,
decisions Q-5). Another digest is `STATE/node_unreachable` `replay_digest_differs` (UNKNOWN, NEVER), audited
`fleet.routed.replay_differs` (`TestAReplayedOutcomeWithAnotherDigestIsUnknownAndAudited`). **Binding for N2:** the node replays a
recorded outcome byte for byte outside those three fields.

**Plan departures (decisions section 4).** REJECTED_BY_NODE and EXPIRED are not final when the node's signed result says the call did
not happen (refused before any effect), so a resend is routed again; a node answer whose effect is UNKNOWN (a duplicate answered while
the first is still executing) is UNKNOWN, never FAILED or final (`TestANodeRefusalThatDidNotHappenIsNotFinal`, `TestTheFinalityOfANodeRefusalFollowsItsEffect`, `TestTheNodePolicyRefusalIsForwardedAndAudited`).
**Binding for N2:** the
node's in-progress answer to a duplicate carries effect UNKNOWN (its code from the existing catalogue).

**Audit.** `fleet.routed.accepted` (each admitted attempt or join), `fleet.routed.result` (each settlement), `fleet.routed.refused`
(a mutation refused `node_offline`) and `fleet.routed.replay_differs`: method, node, attempt, closed codes, digests and sizes, never
payload text. Each `fleet.routed.accepted` and `fleet.routed.refused` row names its own attempt's caller (Q-4): an account session's
`sessionId`, or a relay's `relayingNodeId`, `localOrigin` and `localSessionId`, so two resends from two sessions, or two local
processes, are told apart (`TestEachAttemptAuditsItsOwnCaller`); the record keeps the first attempt's caller. A settlement of a superseded
attempt is audited with reason `superseded` and changes nothing (`TestASupersededAttemptsAnswerChangesNothing`); a settlement is retried
three times (`TestASettlementIsRetried`). Metrics: the event family `routed` (`accepted`, `joined`, `offline`, `settled`, `settle_lost`, `replay_differs`,
`long_polls`, counted on a long poll refused over the bound), and `lease` `swept` / `sweep_failed`.

**The node's `routed_call_log`** (N2) and the center's routing record are different records (PN-7).

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
- RenameNode (AF-CTR-05 E2a): its command receipt row, then the node's device, then the node row (re-read live), then the audit chain
  head. RevokeNode: its command receipt row, then the account through the step-up evidence and the proved challenge, then
  `device.Revoke`'s order (device, installations, sessions, the participants' node rows). ReportNodeInfo and Enroll keep their orders;
  they read `named_by_account` under the node row's lock.
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
node key, `credential_revoked`, `quota_exceeded`, `rate_limited`, `not_activated`), RefreshNodeSession (success, `unauthenticated`,
`credential_revoked` for a spent token and for a revoked device, `permission_denied`, `token_expired`, `rate_limited` from the
session's own bucket), ReportNodeInfo (success, `invalid_argument`, `command_id_reused`, a restricted account's `permission_denied`,
the ingress refusals `auth.token_expired` and `auth.credential_revoked`) and SignOutNode (success, the ingress refusal
`auth.credential_revoked` of a retry, `unauthenticated` for a credential whose node row is not live), StartDeviceAuthorization (success, `invalid_argument`, `rate_limited`,
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
headers of the files it writes; a file whose capture is unchanged keeps its bytes and its commit, so the 46 files of commit `3ab4fe0`
stay as they were when the seven node-credential cases of commit `2686a73` were added; `npx prettier --write` formats the files, and
the comparison reads them as JSON). Parts N1 and N2 will copy the directory
verbatim for the ArcForges node's FakeCenter conformance test; nothing checks it against a node yet.

## Node channel

AF-CTR-05 part E1a (ArcForges-Design AD-0021 sections 9 to 11, 11-security-privacy section 3 "Channel proof of possession"; Plan
CTR5-HUB-01 to 12 as amended by PB-4, PB-5, D0-B2, PN-1 to PN-4 and Q21 to Q23). A signed-in node holds one outbound WebSocket to the
center, `GET <center>/fleet/v1/node` with the subprotocol `arcforges.relay.v1`, binary messages, one relay.v1 `RelayFrame` per message
with `frame_version` 1 and `frame_seq` per connection and direction (`center/internal/hub`). The center's `frame_seq` increases
on each connection but may have gaps (a skipped abandoned call frame, a frame the send queue refused, the `RelayClose` written
outside the queue), so a node must not check that it is contiguous. It is the switchable surface `relay`
(it needs `identity` and `fleet`; in the self-hosted default; off in production until AF-PROD-01, and on proof only from AF-CTR-05 E3).
E1a built the channel; E1b adds the signed calls and results, the in-flight bounds, the relay nonces and the relay assertion's verifier
(below, "Signed calls and results"); the routed API that uses them is E2's.

**Command keys** (CTR5-KEY-01, CTR5-SIG-02, moved into E1a). A center that serves `relay` holds at least one valid command-signing key
whose private half it loaded, or it does not start. The private half of a key lives only in the environment variable its
`fleet.signing_key` row names (`secret_binding`, registered with `admin register-signing-key`): every `ARCFORGES_CENTER_KEY_<NAME>`
(`<NAME>` 1 to 40 of `A-Z0-9_`, at most eight) holds the standard base64 of a PKCS#8 ECDSA P-256 key, is read once at start and
unset from the process environment at once (every variable with the prefix, a malformed one and the ones after it included), and is
never logged or printed (`config.CommandKey` prints its binding only). The unset reaches later `os.Getenv` calls and child processes;
it does not reach the kernel's copy of the start environment (`/proc/<pid>/environ`, readable by the same user and root for the life
of the process) or the Go heap copies, which a core dump can contain. At the start (`Center.CheckCommandKeys`) a loaded key that is
not the public half of every row naming its binding (valid now, or a successor whose `not_before` lies ahead) refuses the start,
naming the binding and the kid; a center whose loaded keys match no valid row refuses too. A list that names `relay` without a key refuses to start; the self-hosted
default leaves `relay` out when no key is configured and logs why. `ChannelAccepted.signing_kids` lists the held keys valid at each
acceptance, from the hub's live keyring (re-read at the hello itself; AF-CTR-05 E1b), never from a snapshot of the start, and is never
sent empty: when no held key may sign, a proved hello closes 4500 `no_signing_key`. Its first kid is the key calls are signed with and
the health document's `center.signingKid` (E1b), so the three always agree. The hosted Worker passes no key variable yet: proof gains its key with the surface in
AF-CTR-05 E3 (Q11), production with AF-PROD-01 (H-16).

**Admission, before the upgrade** (CTR5-HUB-02). The hosted Worker passes only the route's exact upgrade through
([cloud ingress](cloud-ingress.md#upgrade-route-af-ctr-05-part-e1a)); the center then checks, in this order, each refusal an HTTP answer
whose closed reason is also in the `ArcForges-Refusal` header (`<CATEGORY>/<code>`, with `Retry-After` for a retry after time; PN-3:
.NET's `ClientWebSocket` sees only the status and headers of a reply that is not 101) and whose body is the refusal as a JSON ArcError
(`{"error": ...}`, the pages' body):

| Step                                                                                                                                                                                                                                                                                                                                                    | Refusal                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| GET with `Upgrade: websocket`, `Connection: Upgrade`, version 13, one key, exactly the subprotocol, no query, no body                                                                                                                                                                                                                                   | 405 or 400 `VALIDATION/invalid_argument`                                                                               |
| The hub lease is this process's and it is not stopping (PB-5)                                                                                                                                                                                                                                                                                           | 503 `RESOURCE/overloaded`                                                                                              |
| A native bearer (`session.Verifier`); a cookie is never read on this route (PN-4, SEC-22: a cookie-only upgrade is unauthenticated)                                                                                                                                                                                                                     | 401 `AUTHENTICATION/unauthenticated`, `token_expired` (the node refreshes) or `credential_revoked` (it signs in again) |
| The row `fleet.nodeChannel` through `access.Authorize`: the node scope only (an account session is `AUTHORIZATION/permission_denied`, audited `access.refused`), the upgrade-rate buckets `channel_upgrades_per_account` and `channel_upgrades_per_node` (Q21: no connected-node cap), `access.authorized`, the gate of `center.nodes` (`access.gated`) | 403, 429 `RESOURCE/rate_limited`, 403 `ENTITLEMENT/feature_not_entitled`                                               |
| A live node row for the credential's installation in its account, with the installation's registered key                                                                                                                                                                                                                                                | 401 `AUTHENTICATION/unauthenticated`                                                                                   |
| A free node connection slot (`ARCFORGES_CENTER_MAX_NODE_CONNECTIONS`, 256)                                                                                                                                                                                                                                                                              | 503 `RESOURCE/overloaded`                                                                                              |

The upgrade itself accepts only `arcforges.relay.v1`, with compression off and the default origin check (never widened); the server's
read and write deadlines are cleared before the hijack, and the connection moves from the listener's request slots
(`ARCFORGES_CENTER_MAX_CONNECTIONS`) to a node slot, so a channel neither starves the requests nor is cut by the server's 20 s
timeouts (PN-1; Go's Hijack clears the deadlines too).

**The hello** (PB-4, D0-B2). The center's first frame is `ChannelChallenge`: 32 random bytes of nonce, the connection ID and the hello
deadline, 10 s after the upgrade. The node answers `NodeHello` with `node_id`, `installation_id` and `hello_signature`, an ES256
signature (P1363, low-S) by its node key over `"ArcForges relay-hello v1\n"` (25 bytes), the nonce (32), the connection ID (16), the
SHA-256 of the canonical center URL (32; the center uses its own public base URL), the node ID (16) and the installation ID (16). The hub
first refuses a hello whose IDs are absent, not 16 bytes or zero, or whose signature is not 64 bytes, before it builds the message (C2
review N-4); then it verifies the signature against the key registered for the bearer credential's installation, never against a key
the hello names (`hello_signature`); then it checks that the hello names the credential's node and installation (`hello_mismatch`).
Each failure closes 4403 and is audited `fleet.channel.violation`. The nonce is spent by the first hello and is void at the deadline
(4408 `hello_deadline`) or when the connection closes; a challenge belongs to one connection, so a hello proved for another connection
fails. Only then is the connection the node's: an older connection of the node is closed 4409 (`replaced`) after the newer one is
registered, the acceptance is audited `fleet.channel.accepted` (naming the connection it replaced), presence is written and the hub
sends `ChannelAccepted` with the connection ID, the node's registry name (`node_name`, AF-CTR-05 E2a: the account's name once it renamed the node), the limits (`max_frame_bytes` 1 MiB, `max_in_flight_calls` 8, `heartbeat_interval_ms`
25000, `heartbeat_deadline_ms` 60000, `max_relay_nonces` 8) and the kids of the held command keys valid now (the live keyring, at most eight,
newest first; the first is the key calls are signed with). A token without the node key therefore never displaces a live channel
(`TestATokenWithoutTheNodeKeyCannotReplaceTheChannel`, `TestAHelloSignedByAnotherInstallationsKeyIsRefused`). The binding is to the
WebSocket connection, not to TLS, which ends at the Worker; a same-user process that can use the node key still proves possession (T-25).

**While open.**

| Rule                                   | Behaviour                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Heartbeats (CTR5-HUB-06)               | the center sends `ChannelHeartbeat` every 25 s (`channelHeartbeat`), the node answers with its seq; 60 s without any frame (`channelHeartbeatDeadline`) closes 4408: a half-open connection is found by this deadline, never by TCP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Presence                               | `fleet.node.online_since`, `last_heartbeat_at` and `connection_id` (migration 0008, [PostgreSQL store](postgres-store.md#node-channel-af-ctr-05-part-e1a)) written at accept, at most once a minute from heartbeats and at close, each write fenced by the hub lease; a replaced connection's close leaves its successor's record. The states (`hub.Presence`, served by E2): ONLINE while a connection is open in this process, OFFLINE after one was, NEVER_CONNECTED when `online_since` is unset, REVOKED without a live enrollment                                                                                                                                                                                                                                                                                                                                                                                   |
| `TokenRefresh` (CTR5-HUB-07)           | the node refreshes over gRPC-Web as before and sends the new access token on the channel; it must be a valid token of the same session and installation, whose live node row is this connection's node (another installation's or node's token closes 4403 `installation_mismatch` or `node_mismatch`, so the connection's installation key never changes; another session's 4401 `token_mismatch`; a token of an account that may no longer sign in 4403 `account_state`); the connection is rebound to its expiry. A refresh has its own bound before any store work: the first is free, each later one comes at least 30 s after the last one admitted (`hub.DefaultTokenRefreshInterval`), else 4429 `token_refresh_rate`; the token the connection is already bound to is answered without the store. A connection whose bound token expired without one for 120 s (`channelTokenGrace`) closes 4401 `token_expired` |
| Credential re-check (CTR5-HUB-07, -08) | at the hello, every 60 s (`channelSessionRecheck`) and at every `TokenRefresh` with a new token: a revoked session, device or installation closes 4401 `revoked`, an account that may no longer sign in 4403 `account_state`; a store that does not answer keeps the connection                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Lapse (CTR5-HUB-09, Q23)               | the gate is asked for `center.nodes` every 10 minutes (`channelLapseRecheck`) and at every `TokenRefresh` with a new token: unavailable closes 4403 `feature_not_entitled`, audited `access.gated` once for the close; a gate that cannot decide keeps the connection until the next check (every routed call is gated itself, so an open channel grants nothing alone)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Frames (CTR5-HUB-10)                   | a message over 1 MiB closes 4413, more than 100 frames a second (`channelInboundFramesPerSecond`) 4429, a text message, an unreadable frame, a frame before the hello or one a node may not send 4403; a `RelayNonceRequest` is answered with a relay nonce (E1b, below). The send queue holds 64 frames and 4 MiB (`channelSendQueueFrames`, `channelSendQueueBytes`); a write that does not finish in 10 s closes 4408                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Revocation (CTR5-HUB-08)               | the device revocation cascade's participant `fleet.channel` (after `fleet.node`) closes the device's channels 4401 once the revocation commits (`store.AfterCommit`; a revocation that rolls back closes nothing); the other session revocations of this process (a node's sign-out, a re-enrollment's supersession, a refresh token's reuse, a reused enrollment code, the operator's revocation run in this process) announce their sessions after commit (`session.Announce`), and the hub re-checks each named connection's credential before it closes it. A revocation committed by another process (`admin revoke-sessions`) is found by the periodic re-check                                                                                                                                                                                                                                                     |
| Graceful stop (CTR5-HUB-11)            | on `SIGTERM` the hub closes every channel 4500 before the listeners stop, with a jittered reconnect hint of 1 to 30 s in `RelayClose.reconnect_after_ms` (meaningful with 4500 only, 0 to 300000), then releases the lease                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

Every close sends `RelayClose` with its code and closed reason before the WebSocket close with the same code (the close handshake waits
at most a second), and is audited `fleet.channel.closed`. The frames queued before the close are written first (a call the close
abandoned is skipped: it was answered DID_NOT_HAPPEN, so its frame is never written), then the `RelayClose`, both within 2 s
(`closeFlush`); nothing ends the connection before: the reader's end waits for the close to be sent, and every write's
context descends from a context of the writes, not the reader's (AF-CTR-05 E2a). coder/websocket closes the whole connection when a
write's context ends while the write is in progress, even after its bytes were flushed, so a close decided by the reader (the node's
own `RelayClose`, a malformed frame) used to lose its `RelayClose` and close handshake under load
(`TestACloseWaitsForTheWriteInFlightAndSendsItsCloseFrame`). A node that stopped reading never lets a write finish: the close flush
ends the write in flight, so the connection ends and its close is recorded within seconds, not after the write timeout
(`TestACloseToANodeThatStopsReadingEndsWithinTheFlush`). The codes: 4401 credential expired or revoked, 4403 refused, 4408 hello or
heartbeat deadline (or a write that timed out), 4409 replaced, 4413 frame too large, 4429 rate limited, 4500 center going away
(shutdown, or this process lost the hub lease), 4503 reserved (kill switch). A node treats any close without a preceding `RelayClose`
like 4500 and reconnects with its backoff: through the hosted Durable Object an abnormal close (1005, 1006) reaches it as 1000
(`@cloudflare/containers` rewrites it), so the code alone does not tell a transport loss. The node side is N1's.

**Signed calls and results** (AF-CTR-05 E1b; Plan CTR5-SIG-01 to 04, CTR5-HUB-08 and 10, PN-6; Contracts relay.proto `CallHeader`,
`ResultHeader`, the rule `routedRefusal` and "Signatures of the node channel"). `hub.Call` is the routing seam the routed API (E2) calls
with a caller it has already verified; nothing of a call or of its result is stored.

| Step                        | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shape first                 | the call (IDs of 16 non-zero bytes, a routed task method 1..6 with its command ID exactly for `SubmitNodeTask` and `CancelNodeTask`, a payload of 1..253,952 bytes, a caller complete for its kind, the assertion digest exactly for a node relay, a deadline within 300 s) is checked before anything is built from it, and the built header is checked by the Go mirror of the contract's validators before it is signed (C2 review N-11; Go has no generated validators)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Routing                     | no hub lease, or no accepted connection of the node in this process: `STATE/node_offline` (`AFTER_TIME` 5 s plus jitter, `DID_NOT_HAPPEN`); a connection of another account: `STATE/not_found`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| In flight (CTR5-HUB-10)     | at most `routedInFlightPerNode` (8) calls wait on a node's channel and `routedInFlightPerCenter` (1024) in the process; a call over either, or one whose frame the bounded send queue cannot take, is `RESOURCE/overloaded` (`AFTER_TIME`, `DID_NOT_HAPPEN`) and nothing is sent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| The header (CTR5-SIG-01)    | `CallHeader{call_id, kid, center_url_sha256, account_id, target_node_id, caller, command_id, method, request_sha256, request_size, issued_at, expires_at = now + min(deadline + 30 s, 300 s), deadline, relay_assertion_sha256}`; the caller only as verified (an account session's user and session, or a verified relay assertion's relaying node, local origin and local session); the payload is the caller's node.v1 request bytes, never re-encoded                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| The signature (CTR5-SIG-02) | ES256 by the newest command key valid at the call's instant whose private half the center holds (the keyring: the rows of `fleet.signing_key` re-read every minute by the hub's key loop and at every hello, a slower read never replacing the rows of one that started later, so a successor signs from its `not_before` and an expiry is checked at each call), over `"ArcForges relay-call v1\n"` (24 bytes) and the exact header bytes, P1363 with s normalized to the lower half; an expired key never signs, and a retirement takes effect at the next successful read, so a retired key may still sign for at most about 3 minutes after its retirement: the keyring stops signing once it has gone 3 refresh periods (180 s) without a successful read, even while the store does not answer. With no held key that may sign, a call fails `STATE/node_unreachable` (`channel_closed`, `DID_NOT_HAPPEN`) unsent, logged once per transition. The health document names the signing kid (`center.signingKid`), never key material                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| The result (CTR5-SIG-03)    | the `ChannelResult`'s shape first (a call ID, a `SignedHeader` without kid, `ES256`, 64 signature bytes, 1..2,048 header bytes, a payload within 1,040,384), then the signature by the key registered for the connection's installation over `"ArcForges relay-result v1\n"` (26 bytes) and the header bytes as received (low-S), then the header's shape (the rule `routedRefusal` included) and its bindings: an open call of this connection, the connection's node, the echoed method, command and request digest (none for `REFUSED_VERIFICATION`), the response's size and SHA-256 for `EXECUTED` and no payload otherwise                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| The answer                  | `EXECUTED`: the response bytes unchanged, with their digest; any other outcome: the node's refusal rebuilt from its closed fields (category, code, retry advice and `retry_at`, the approval's `GetApproval`, effect, `state.state`, `state.reason`, the approval resource), so its bytes, its message key and its correlation ID never reach the caller, who sees the center's own correlation ID (PN-6)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| A violation (CTR5-SIG-04)   | a result that fails any check fails its call `STATE/node_unreachable` (`result_unverifiable`), closes the channel 4403 with the closed reason (`result_malformed`, `result_signature`, `result_other_call`, `result_mismatch`) and is audited `fleet.channel.violation`; a result that arrives after its call's deadline is verified and bound like any other (a mismatch is a violation), then dropped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| A lost call                 | a closed, replaced or revoked connection fails its calls `STATE/node_unreachable` (`channel_closed`), a deadline or a caller that goes away (`deadline_passed`): `UNKNOWN` with `SAME_COMMAND` for a delivered mutation, `DID_NOT_HAPPEN` with `AFTER_TIME` for a read or an undelivered call (errors.md). A call is delivered once the writer starts to write its frame: each call is queued, delivered or abandoned, moved by compare-and-swap under the connection's lock; the writer writes a frame only after moving its call from queued to delivered, while the call is still waited for and the connection is not closing, and a deadline, a caller that went away or a close moves a queued call to abandoned, whose frame is skipped, never written. So `DID_NOT_HAPPEN` holds for every undelivered call. This differs from CTR5-RTE-03's `DELIVERED` (counted when the frame is queued): the routed API (E2) must use this definition, so its routing record and the reply's effect agree. A delivered call past its deadline still counts against the node's in-flight bound until its late result or until it can no longer run (its `expires_at` plus the node's 120 s skew), and its late result is verified and bound, then dropped. Once it can no longer run, its call ID is kept among the connection's 256 newest forgotten IDs, which hold no slot: a result naming one is still signature-checked, then dropped without a violation (AF-CTR-05 E2a; E1b review A C-N2); a result for any other unknown call ID stays `result_other_call` (4403) |

**Relay nonces and the relay assertion** (Plan addendum D0-B1, C-N1, C-N2, C-N6). A `RelayNonceRequest` with a valid request ID is
answered with `RelayNonce`: 32 random bytes that only this connection's node may spend, once, within 120 s, at most eight unspent (a
newer one voids the oldest), void when the connection closes or is replaced; a request without its ID closes 4403
(`nonce_request_malformed`). `Hub.VerifyRelayAssertion` is the function E2 calls before it serves or routes a node-relayed call,
ListNodes and GetNode included: the assertion present (`missing`), of the exact layout before any signing input (`signature_invalid`),
signed under `"ArcForges relay-origin v1\n"` over its 228 canonical bytes by the key registered for the bearer credential's
installation (`signature_invalid`), naming that credential's live node and installation (`credential_mismatch`), not expired
(`expired`), over a nonce of the relaying node's open channel, which it spends (`nonce_reused`), and stating the routed request's
method, request digest, target, command and caller (`request_mismatch`). Each refusal is `AUTHENTICATION/unauthenticated` with
`state.state` `relay_assertion`; `expired` and `nonce_reused` advise `SAME_COMMAND` (a fresh nonce, no sign-in, C-N4). A verified relay
(`hub.VerifiedRelay`) is the call header's caller and its digest the header's `relay_assertion_sha256`; its fields are unexported and
read through accessors, so it cannot be hand-built (`hub.Call` refuses an unverified one) or changed after verification, and a copy
keeps exactly the verified fields.

**Tests of E1b** (`center/internal/hub`; EVIDENCE: REAL PostgreSQL, the composed center and the real WebSocket server, and the Contracts
golden vectors vendored byte for byte in `center/internal/hub/testdata` with their SHA-256 pinned; MOCKED: the node, nodetest's channel
client with a software key, honest or hostile): `TestCallHeaderSignatureVerifiesInGoAndAgainstTheVector` (E1-13: the center rebuilds the
vector's header and frame byte for byte), `TestTheResultVectorVerifiesAndIsBoundToItsCall`, `TestTheRelayAssertionVectorsVerify`,
`TestTheRelayNonceFramesAreTheVectors`, `TestTheDomainStringsAreTheContracts`, the validator mirror (`TestTheCallHeaderRulesAreTheContracts`,
`TestTheResultHeaderAndRoutedRefusalRulesAreTheContracts`, `TestTheRelayAssertionRulesAreTheContracts`, `TestTheChannelFrameRulesAreTheContracts`,
`TestTheRefusalCatalogueIsTheContracts`), `TestAMalformedMessageNeverReachesASigningInput`, `TestANodesRefusalIsRebuiltFromItsClosedFields`,
`TestTheKeyringPicksTheNewestValidHeldKey`, `TestARoutedCallIsSignedAndItsResultForwardedUnchanged`,
`TestAResultSignedByAnotherNodeKeyClosesTheChannel` (E1-17), `TestANodesRefusalIsAnsweredRebuilt`, `TestInFlightBoundsHold` and
`TestAFullSendQueueRefusesNewCalls` (E1-18), `TestInFlightCallsFailWhenTheChannelCloses`, `TestADeviceRevocationFailsTheNodesCalls`, `TestADeadlinePassedCallIsUnreachableAndItsLateResultIsDropped`, `TestAQueuedCallWhoseCallerGoesAwayIsNeverWritten`, `TestAQueuedCallWhoseDeadlinePassesIsNeverWritten`,
`TestAQueuedCallOfAReplacedOrRevokedConnectionIsNeverWritten`, `TestALateResultIsStillBoundAndCountsAgainstTheNodesBound`,
`TestTwoConcurrentSpendsOfOneNonceAdmitOne`, `TestAVerifiedRelayIsReadOnly`, `TestASlowKeyReadNeverOverwritesANewerOne`, `TestTheKeyLoopRotatesOnItsOwnAndFailsClosedWhenStale`,
`TestTheCenterSignsWithTheNewestValidKeyItHolds` (E1-14), `TestARelayNonceIsOneUseAndVoidAtClose`, `TestARelayAssertionIsVerifiedBeforeRouting`,
and the captures `call-executed`, `call-refused`, `call-unverifiable` and `relay-nonce` (E1-26).

**One hub per database** (CTR5-HUB-05, PB-5, Q22). The connections live in one process's memory, so the hub holds the fenced singleton
lease `fleet.hub_lease`: taken when free, expired or released, renewed every 10 s for 30 s, released at a graceful stop. Its expiry
is the database's clock (`clock_timestamp()`), so a replica whose clock runs ahead never takes a live lease early. Every presence write
(the accept's, the heartbeats', the close's and the clearing of a previous holder's rows) names the fence it was made under and is
refused once that fence is not the live one; the audit appends are not fenced. A process that does not hold it serves no channel (the
upgrade is 503 `RESOURCE/overloaded`, and E2's routed calls answer `STATE/node_offline`), and logs once when another process holds
it. The claim keeps a local expiry too, 25 s (the time to live less a sixth) after the start of its last successful renewal on the
process's own clock: a process whose renewals fail (a store that does not answer, a saturated pool) holds nothing once it passes. The
lease loop wakes at that instant (its timer is re-armed to the earlier of the next renewal and the local expiry, and a renewal waits
for the store at most until then), so admission stops and every channel's close starts at the local expiry, 5 s before the database's
expiry lets another process take over; a close takes at most about 3 s (the queued frames and the `RelayClose` are bounded by 2 s
together and the close handshake by 1 s, all connections in parallel), so the channels are closed before then (`TestAHubWhoseRenewalsFailStandsDown`, at the
3 : 1 ratio of PB-5). A renewal that finds the lease another process's closes them the same way. Once the store answers again, the
process takes its own lapsed row over at once under a higher fence (it never takes it for another process's), so the lapsed epoch's
writes stay refused. The accept lock is one of 64 striped locks, chosen by a hash of the whole node ID, and its wait ends with the hello's
context (4500 `unavailable`). A hello whose accept write the lease refuses closes 4500
`lease_lost`, without `ChannelAccepted` and without displacing the node's older connection; one whose node row was revoked since the
admission closes 4401 `revoked`. A killed center's lease is taken over after its 30 s; the new holder clears the connections the
previous one left recorded.

**Audit, metrics, logs.** Audit: `fleet.channel.accepted`, `fleet.channel.closed` (code and reason), `fleet.channel.violation`, as the
node (`node:<installation>`) on its enrollment, and `access.authorized`, `access.refused`, `access.gated` of the row. Metrics:
`arcforges_center_channel_events_total{event,outcome}` (closed pairs, `observe.ChannelOutcomes`: upgrades, refusals by stage, hellos,
closes by code, missed heartbeats, violations, token refreshes, lapse checks, lease changes and failed renewals) and the gauge
`arcforges_center_channel_connected_nodes`, which the periodic `metrics` log line carries too (`channel connected_nodes`). No log line, audit row or metric label carries a token, a frame's content or any text the
node supplied (its version, a close reason it sent).

**Tests** (`center/internal/hub`, `center/internal/server`, `tests/worker/channel-upgrade.test.ts`; EVIDENCE: REAL PostgreSQL, the
composed center and the real WebSocket server; MOCKED: the node, the `nodetest` channel client with a software key, never an end-to-end
claim): `TestUpgradeAdmission`, `TestUpgradeRefusesUnknownRevokedExpiredAndAccountTokens`, `TestTheChannelIsGatedInBothModes`,
`TestTheChannelsUpgradeRateIsBoundedPerNodeAndPerAccount`, `TestAHubWithoutTheLeaseAdmitsNoChannel`, `TestHelloMustNameTheEnrolledNode`,
`TestAHelloSignedByAnotherInstallationsKeyIsRefused`, `TestAMalformedHelloIsRefusedBeforeAnySigningInput`,
`TestATokenWithoutTheNodeKeyCannotReplaceTheChannel`, `TestTheHelloNonceIsOneUseAndVoidAtTheDeadline`,
`TestANewConnectionReplacesTheOldAndBothAreAudited`, `TestHeartbeatDeadlineMarksTheNodeOffline`, `TestPresenceWritesAreBounded`,
`TestTokenRefreshRebindsAndExpiryCloses`, `TestDeviceRevocationClosesTheChannelAndRefusesNewCalls`,
`TestALapsedAccountsChannelClosesAtTheNextRefresh`, `TestAnOversizedFrameClosesTheChannel`, `TestGracefulShutdownClosesWith4500`,
`TestASecondHubOnTheSameDatabaseRefusesToStart`, `TestConnectReplaceRevokeAndCloseConcurrently` (`-race`), `TestTheExchangeOfAChannel`,
`TestTheServersDeadlinesNeverCutAnUpgradedChannel` (24 s on the server's real timeouts), `TestAnUpgradedChannelLeavesTheRequestBound`,
`TestStartRefusesAMismatchedOrMissingCommandKey`, `TestTheCommandKeyNeverAppearsInLogsOrHealth`, `TestTokenRefreshHasItsOwnBound`,
`TestABarredAccountsRefreshCloses4403`, `TestALateHelloIsRefusedByItsNonce`, `TestARevocationBeforeTheHelloIsFound`,
`TestAHelloUnderAStaleFenceIsClosedNotAccepted`, `TestAHubWhoseRenewalsFailStandsDown`, `TestALeaseTakenOverClosesTheChannels`,
`TestAClaimWhoseRenewalsFailLapsesLocally`, `TestTheAcceptWriteTellsAStaleFenceFromAGoneNode`, `TestTheAcceptLockSpreadsAndIsBounded`,
`TestNoValidCommandKeyNeverSendsEmptySigningKids`, `TestAFailedHandshakeGivesTheNodeSlotBack`, `TestTheHelloMatchesTheContractsVector`
(the C2 golden hello vector, `testdata/relay-hello-vector.json`) and, through the account's devices page and its real revoke path,
`TestRevokingANodesDeviceOnTheDevicesPageClosesItsChannel`.

**Exchange captures for the node** (E1-26). `TestChannelExchangeCapture` captures the channel's exchanges as the messages on the wire
and normalized, in the format of the enrollment captures (schema version 2): `center/internal/hub/testdata/exchanges/NodeChannel-*.json`,
one file per case (an accepted channel closed by the node; a hello refused for a mismatch, a signature, a malformed shape and the
deadline; a replaced, revoked, expired, lapsed and shut-down channel; four refusals before the upgrade). `request.frames` are the node's
messages and `reply.frames` the center's, each a RelayFrame in hex; `reply.trailers` is the WebSocket close; a refusal has its HTTP
status, its reason headers and its JSON body. Part N1 copies the directory for the FakeCenter's conformance test; a fresh capture must
equal it (`ARCFORGES_UPDATE_EXCHANGES=1` rewrites it).

## Test vectors for the node

Two files in `center/internal/fleet/testdata` hold the center's side of the vector lists the ArcForges node is to share with it
(protocol-4 item 3, node-13). `url-vectors.json` lists public base URLs (the official `https://arcforges.com/api`, a path prefix, a
port, a punycode host, loopback `http`, the 462- and 463-character fleet bound, and refused forms) with the verdicts of
`config.ParsePublicBaseURL` and of the whole configuration loader of a fleet center in both modes, the URLs a fleet center derives
for an accepted one (`/connect#flow=`, `/activate`, `/activate#code=`) and the proof audience digest, and the loopback redirect URIs
with the approval and denial redirects. `node-key-proof-vectors.json` holds fixed test-only keys, never a node's key, as public
keys only (the private scalars are public test values: SHA-256 of a public label for the two P-256 test keys, the capture harness's
32 bytes of 0x2a for the capture node's key, 48 bytes of 0x2b for a refused P-384 key) with their fingerprints, the proof message of
both purposes byte for byte, deterministic (RFC 6979) low-S proofs (one with a leading zero byte in r, one in s, three normalized
from a high s) and refused proofs (high-S, DER, wrong lengths, out-of-range r or s, another audience, purpose, node, flow, code or
key, a reordered or truncated message), each with `fleet.VerifyNodeKeyProof`'s verdict. `TestFleetVectorFiles` generates both from
the production functions and fails when a committed file differs; `ARCFORGES_UPDATE_VECTORS=1 go test -run TestFleetVectorFiles
./internal/fleet` rewrites them, then `npx prettier --write` formats them (the comparison reads them as JSON). They are made for the
ArcForges node (AF-CTR-04 part N1) to vendor byte for byte with their source commit, as it is to vendor the exchange captures;
nothing in this repository checks a node against them.

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
script), waits for each probe result, and at the end, also after a failed step, revokes the devices its approvals may have created.
Each approval's node name is recorded before its decision is sent. An approval enrolls no device: the device appears when the node's
next poll collects the approval (Enroll), seconds after the decision. So before the clean-up reads the devices page it waits, within
`--wait-ms` in all, for the result of every case whose approval was sent and whose result it has not read (node-probe writes it after
its poll and its checks). The report always carries `devicesLeft`: 0 or the count, or `unknown` when the clean-up could not look or a
probe never answered; the run then names those cases (`casesToCheckByHand`). The probe runs on the browser's machine (its loopback
receiver must be the browser's).

A 429 during a run: only the steps that open a link, and the clean-up's visit of the devices page, start again from their navigation
after a 429. Every other step starts from the page an earlier step left (a review, a lookup, a decision with its step-up proof, a wrong
fingerprint group, a revocation) and fails the run on a 429 instead, so none of them is ever sent twice. Besides, the driver counts as a
change (after which even a restartable step fails on a 429) every POST the center accepted below 400 other than a flow's begin, a
step-up proof and the operator grant's review, and every `/connect/decision` or `/activate/decision` POST the center answered below 500
(the wrong group's 400 and a step-up refusal included; the edge's 429 is no change). A 429 on a run may be the edge's or one of the
center's limits below (`step_up` of the account, `node_approve_account`, `device_entry_account`): the center's come from regression runs
less than 10 minutes earlier, from a repeated attempt, or from a `--cases` larger than the checklist's.

What a run spends:

| Limit                                                       | Value                                         | A run                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The hosted edge (browser and probe share the machine's key) | 60 requests per 60 s per client               | the browser paces itself at 36 requests a minute after a burst of 4 (at most 40 in any minute); the run fails when the browser's busiest minute and the node's together exceed 55; the node's minute counts the requests its result files list, so a real node's later refreshes are not in it (`requestsBusiest60sBoundCovers`) |
| Step-ups per account                                        | 10 in 10 minutes                              | one per approval, one per revoked device, one for `--negative`; `--cases` refuses a set that could spend more than 10 (2 per case, 1 for `--negative`); the returning acceptance spends 3 and `--operator-grant` 2: wait 10 minutes between those runs and a node-approve run                                                    |
| `node_approve_account`                                      | 20 decisions an hour                          | one per decision                                                                                                                                                                                                                                                                                                                 |
| `device_entry_account`                                      | 5 wrong entries per window                    | `--negative` spends one                                                                                                                                                                                                                                                                                                          |
| `node_flow_prefix`                                          | 10 Begin and Start per 10 minutes per network | one per case, from the probe's address                                                                                                                                                                                                                                                                                           |

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
   `identity,pages,operations,fleet` (`identity,pages,operations,fleet,mobile` since AF-CTR-04 part M), equal to `center.configuredSurfaces` of `artifacts/proof-deployment.json`; the migration gate shows
   `arcforges_acceptance` at version 5 (6 since AF-CTR-04 part M).
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
6. **Clean-up.** The run revokes the probe devices itself, also after a failed step, once each approved case's probe has answered; it
   lists any device it left (`devicesLeft`). After any failed run, or a `devicesLeft` other than 0, wait until the probes have exited,
   then check `/account/devices` for `node-probe-*` devices of the run's cases and revoke them by hand. Delete the handshake directory.
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
