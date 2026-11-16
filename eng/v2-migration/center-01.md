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
  receipt. Failures preserve the backup and require inspection before retry.
- Existing schema10: this entry refuses before backup or SQL changes. The old
  `RequireCTR06SecurityBridge` hard stop remains. No published qualified V2
  successor has been admitted, and neither a supplied test key nor an executable
  self-hash can replace that prerequisite. This is negative evidence, never a
  successful schema10 upgrade.

The transition artifact digest binds actual executing bytes, the supplied build
label and the exact 0012 hash. It is an identity receipt, not a publication
attestation or activation authority. Native post-push gates, independent review
and the protected artifact path remain separate. H-03 production/destructive
operator admission stays closed; no deployment switch is changed here.

The existing schema11 backup and quarantined restore retain their exact supported
0001–0011 prefix and fixed catalogue/inventory. The same logical-backup commands
also select the closed schema12 catalogue and object inventory, derived from the
real H-22 fresh migration at `0aba947d`. Source archives cannot supply their own
definition oracle. Capture checks every table, sequence and large object in its
exported snapshot; restore rechecks them against the actual quarantined target.

V2 restore excludes the source cutover receipt's data and preserves the target's
native floor/admission. The private same-invocation restore capability completes
the target-specific cutover and original restore admission atomically. Old
protocols are revoked and channel presence is cleared before READY. Saved command
and unknown/final outcome identities remain; old protocol authority cannot admit
new work. Fresh enrollment/local authorization belongs to the later channel
integration, and no Node owner epoch or native effect is invented here. Source
readiness copied into another database never authorizes that destination.

This candidate's new backup/restore code has compiled on Windows. Its native
round-trip and failure fixtures still require the exact pushed source on H-22;
source identity and compilation are not a restore pass.

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
