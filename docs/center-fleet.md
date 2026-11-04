# Node enrollment on the center (the fleet surface)

AF-CTR-04 connects an ArcForges node to an account on a center: a person approves the node's sign-in in a browser (PKCE loopback) or
with a device code, and the node then holds a node credential that it refreshes and can sign out. This page describes what the center
serves for it. Part E1a (this state) serves the node's refresh, report and sign-out and holds the enrollment function both sign-in
flows call; the browser sign-in (part E1b), the device-code sign-in (part E2) and the pages `/connect` and `/activate` (part E3)
follow. The node side is the ArcForges CloudLink (parts N1 and N2).

Enrollment is an account and device operation and is never gated (AD-0021 section 13a): every fleet row of the operation table has
no `Feature` (`TestFleetRowsCarryNoFeature`, `TestFleetRowsAreTheServedMethods`). The gated `center.nodes` key is the node's
connection, which AF-CTR-05 serves.

## Surface

The methods belong to the switchable surface `fleet`. It needs `identity` and `pages` (a list without them refuses to start), it is a
known name from part E1a, and it is enabled nowhere yet: production `FLAGSHIP_SURFACES` stays `""`, the acceptance environment keeps
`identity,pages,operations` until part E3's hosted run, and the self-hosted default stays `identity,pages` until the pages exist
(`TestTheFleetSurfaceNeedsIdentityAndPagesAndIsNoDefaultYet`). With the surface off, every fleet method answers `STATE/not_activated`
with `state.reason` `fleet`, from the Worker's generated reply before anything else is read, and from the center. The three methods' Worker budget is the contract's 10 s deadline. A self-hosted center whose base URL cannot be a WebAuthn relying
party clears the default surfaces and serves none (`TestASelfHostedCenterOnAnAddressServesNoSurface`); a list that names a surface
refuses to start there.

## Served methods

| Method                                   | Operation ID               | Risk | Credential                | Restricted account's node | Receipt                        |
| ---------------------------------------- | -------------------------- | ---- | ------------------------- | ------------------------- | ------------------------------ |
| NodeEnrollmentService.RefreshNodeSession | `fleet.refreshNodeSession` | R1   | anonymous (refresh token) | allowed                   | never                          |
| NodeEnrollmentService.ReportNodeInfo     | `fleet.reportNodeInfo`     | R1   | node credential           | refused                   | yes (`node:<installation id>`) |
| NodeEnrollmentService.SignOutNode        | `fleet.signOutNode`        | R2   | node credential           | allowed                   | yes (`node:<installation id>`) |

con-07 names no fleet operation, so the IDs are the center's own (`fleet.<method>`). Every other `NodeEnrollmentService` method stays
unregistered (`UNIMPLEMENTED`, no Worker row): the browser and device-code sign-in methods until parts E1b and E2, and the phone
pairing, certificate, LAN, entitlement-token, entitlement-key and support-upload methods of later tasks. `GetEntitlementKeys` is not
used to deliver the center's keys: a node needs the next key at every refresh without a second round trip, and that method is
anonymous.

An AGENT row of the operation table names the exact credential scopes it admits: the two node rows admit a `node` credential only.
An account or `mobile.limited` session is refused with `AUTHORIZATION/permission_denied` and audited `access.refused` with the reason
`principal`; an `automation` or `push` credential with the reason `scope` (`TestScopeMatrixOverFleetRows`). The reply is always
`state.state` `operation`, `state.reason` the operation ID; `restricted`, `scope` and `principal` are audit reasons only.

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

`fleet.Enroll` is the one function both sign-in flows will call in their success transaction (parts E1b and E2); until then it is
exercised by SEEDED function-level tests that call it directly. Its rules, in the order the code applies them:

1. The approving account is locked and must be Active (else the approval lapses).
2. A node ID live in another account is `CONFLICT/already_exists` (`state.state` `node`, no resource).
3. A node ID live in this account on another OS is `VALIDATION/invalid_argument` (`node.os: mismatch`): another OS is another
   machine, which signs in under a node ID of its own.
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
identical retry answers the rule that then applies. The sign-in methods will refuse a key an installation holds or held before
approval (parts E1b and E2), so a sign-in after a sign-out will replace the node key, and an in-place re-enrollment will normally
arrive with a new key.

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
- ReportNodeInfo: the device only when it renames it, then the installation, then the node row.
- RefreshNodeSession: its session, then the node row.
- The account's step-up evidence path (RevokeSession of another session, RevokeAllSessions, RemoveAuthIdentity, DeviceService.Revoke
  of another device): the account first, then (for a device) `device.Revoke`.
- The operator's `admin revoke-sessions` and `admin revoke-device`: the accounts first (in account order for `revoke-sessions
--all`), then the sessions, or `device.Revoke`.

The writers that lock fewer rows skip slots and never go back: SignOutNode, a sign-out of the caller's own session and a browser
session's renewal lock one session row; the own-device DeviceService.Revoke takes no account lock and starts at the device; a sign-in
(`device.EnsureNative`, `EnsureBrowser`) locks its own installation and device and then inserts its session; a step-up proof and the
session upgrade lock the proving session. In every transaction a command receipt is the first row written and the audit chain head the
last. `TestEnrollTakesItsLocksInTheGlobalOrder`, `TestReportNodeInfoAndRevokeNeverDeadlock` and
`TestOperatorRevocationTakesTheAccountLocksFirst` hold one row at a time and check which rows the waiting transaction already holds. The race tests (enrollment, refresh, report and the operator's revoke-sessions against
revocation and re-enrollment) run every transaction with one attempt (the refresh through `fleet.Options.RefreshAttempts`), so a
deadlock is an error of the round and fails them.

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
changed, unchanged, rate_limited; `sign_out` signed_out; `enroll` outcomes once the sign-in methods call it); any other pair is counted as `unlisted`, and the fleet integration harness fails
a test after which the composed center counted one. Audit events: `fleet.node.enrolled`,
`fleet.node.info_reported`, `fleet.node.signed_out`, `fleet.signing_key.registered`, `fleet.signing_key.retired`, `device.revoked`
(with the participant count), `identity.session.refresh_reused` (with the scope), `access.refused`, `identity.rate_limited`; no
payload holds a token, code, address or e-mail. Transactions per request: RefreshNodeSession one lookup (no transaction held), one
bucket count, one rotation; ReportNodeInfo one bucket count and one receipt transaction; SignOutNode one receipt transaction.

## Residual risks

- A key replaced by a same-account re-enrollment is overwritten and no longer guarded.
- A node ID is a global namespace among live rows: another account that enrolls it first holds it until the operator releases it
  (`admin revoke-device --node`); per-account node IDs are AF-CTR-05's backlog.
- Strict rotation signs out a node whose refresh reply was lost after the commit (above).
- The prefix buckets are per /24 or /56: a co-tenant can spend the failure bucket of a network, which delays only tokens that name
  nothing.
- Unsalted digests (client prefixes in rate-limit keys) are reversible by trying values within their short lives.
