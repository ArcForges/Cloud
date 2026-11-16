# AFV2-CENTER-01 implementation and evidence boundaries

Design baseline: `493022fbf643b484665b2713c9eb8670f2fb2234`. Cloud source
baseline: `f4708b36fd799025ad7d6fa9e5845e4558e492b3`.

This slice appends management storage in 0012; applied 0001–0011 remain unchanged.
It keeps identity, device, enrollment, entitlement and audit history. The target
account-lifecycle and commerce additions belong to ID-01/HOST-02. It introduces
no Run database, body storage, terminal control or V2 network route.

`management.Store` uses the existing bounded `store.InTx` and explicit runtime
grants. Reservation is atomic with its content-free routing record. Exact retries
join the retained identity; changed intent, method, enrollment or Node owner epoch
conflicts. An account-scoped keyset cursor only positions a bounded listing.
It does not authorize access. A transport must authenticate, authorize, check the
local grant and verify Node observations before using this storage boundary.

The SQL checks immutable identities, current protocol/lease at admission,
monotonic delivery and unknown state, and immutable final outcomes. Migration
owns the method catalogue and cutover evidence. Runtime cannot change either.
Unknown or delivered legacy Task/file records are imported as non-executable
identities with their original outcome facts and source-row digest, not as Runs.
Old routing writers are frozen by 0012. Historical V1 test fixtures remain on
schema11; they are not evidence that old routing works after V2 expansion.

## Finite transition

- Fresh: the ordinary migrator runs the unchanged bootstrap and 0011 guards,
  then 0012 in the same invocation. No predecessor backup or old-writer set is
  invented: the receipt explicitly binds fixed fresh-state absence labels.
- Valid schema11: `migrate management --archive <new absolute path> --metadata
<new absolute path>` first captures a real exported-snapshot logical backup.
  Under the direct migration lock and full legacy table locks it rechecks data,
  catalogue, sequences and large objects, refuses surviving writer sessions or
  unknown privilege/membership paths, fences old roles and creates a new NOLOGIN
  runtime generation. The new floor, target-specific cutover receipt and 0012
  commit atomically. Normal credential provisioning follows; no secret is in the
  receipt. Use the returned `runtimeRole` with the existing protected
  `admin rotate-runtime-credential` procedure; the retired generation is not
  silently re-enabled. Failures preserve the backup and require inspection
  before retry with distinct new output paths.
- Checked schema10: the same finite entry captures the exact schema10 snapshot
  and proves the complete writer fence under its same-invocation private
  connection/database capability. The unchanged 0011 transaction records a new
  floor bound to the actual transition executable/source, backup and retired
  writer evidence; it never records the obsolete 8e5 producer as executed.
  Then 0012 expands management storage. If 0011 commits and 0012 fails, the
  committed floor and retired writers remain in maintenance. Inspect migration
  status for the actual current runtime generation, then repair forward with
  distinct new backup paths. No code restores the old writer's privileges.

The old `RequireCTR06SecurityBridge` and hosted publisher entry remain unavailable.
The finite maintenance path is independently reviewed engineering, not a force
flag, user-supplied promotion assertion or a claim that an old bootstrap ran.

A revoked protocol cannot reserve a new identity or increase an operation's
delivery count/change its channel. An existing UNKNOWN can still accept a definite
final observation under the current hub with its original identity, owner epoch,
digest, channel and delivery count. The transport must verify the observation;
this database transition supplies no signature or delivery authority. Final
outcomes remain immutable.

The transition artifact digest binds actual executing bytes, compiled
source/compiler/platform facts, the supplied run label and the exact 0012 hash.
It is an identity receipt, not a publication
attestation or activation authority. Native post-push gates, independent review
and the protected artifact path remain separate. H-03 production/destructive
operator admission stays closed; no deployment switch is changed here.

The existing schema11 backup and quarantined restore retain their exact supported
0001–0011 prefix and fixed catalogue/inventory. The same logical-backup commands
also select the closed schema12 catalogue and object inventory, derived from the
real H-22 fresh migration at `c0d9a62c`. Source archives cannot supply their own
definition oracle. Capture checks every table, sequence and large object in its
exported snapshot; restore rechecks them against the actual quarantined target.

A checked schema10 archive restores first into a new quarantined database with
no source ACL or login authority. The manager verifies every original table,
sequence, large object and applied checksum before the unchanged 0011 and 0012
transactions run. Its same-invocation capability binds the target database,
archive, metadata and actual executable. New NOLOGIN roles are created inside
0011; the target floor remains PENDING until the transformed closed catalogue,
retained rows and legacy tombstones are checked. Target READY and its cutover
receipt commit together. Restoring another database never revokes cluster roles
still serving the source. Inconsistent history or a later fault preserves the
quarantined target; an ordinary command or a later invocation cannot adopt it
by name. Preserve it and the original backup for explicit investigation.

V2 restore excludes the source cutover receipt's data and preserves the target's
native floor/admission. The private same-invocation restore capability completes
the target-specific cutover and original restore admission atomically. Old
protocols are revoked and channel presence is cleared before READY. Saved command
and unknown/final outcome identities remain; old protocol authority cannot admit
new work. Fresh enrollment/local authorization belongs to the later channel
integration, and no Node owner epoch or native effect is invented here. Source
readiness copied into another database never authorizes that destination.

Exact native source, backup/restore results and remaining qualification blockers
are recorded separately in Plan. Source identity or compilation alone is never
a restore pass or production activation.

## Targeted checks

```text
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test ./internal/store/migrate -run '^TestManagement' -count=1 -v
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test ./cmd/arcforges-center -run '^TestManagementFlags' -count=1
```

Run from `center/`. PostgreSQL tests use the repository's real isolated `pgtest`
database/roles and pinned native `eng.center.Postgres` helper on H-22. That host
must set the existing PostgreSQL-required flag and use real `pg_dump/pg_restore`.
Windows compilation or a skipped integration test is never PostgreSQL acceptance.
Fixture legacy rows and reconciliation digests are supplied historical inputs;
no signature verification, publication, external delivery or Run success is mocked.
