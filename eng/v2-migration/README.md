<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Center read-only preflight

```sh
python eng/v2-migration/preflight.py --database operator_selected_database > center-preflight.json
python eng/v2-migration/preflight.py --container explicit_fixture --user postgres --database fixture
python eng/v2-migration/test_preflight.py InventoryModelTests
```

The first command uses existing psql environment/service authentication. Never
put a connection URL/password on the command line or export credentials into
reports. The optional container must already exist. Preflight creates no database
or container. It uses psql `-X -w` with fixed SQL in a single repeatable-read,
read-only transaction, bounded statement/lock waits and an explicit rollback.
Only the fixed catalogue and ordinary metadata tables are read. The migration
ledger observation is limited to the 17 known entries and one overflow entry.

Classification distinguishes `fresh`, `center10`, `center11`, `center16`, `center17`,
`unknown` and `newer`. Versions, contiguous migration names and source checksums
must agree. The historical schema 10 and 11 reports keep their original keys and
source window. Schema 12 through 15, missing required metadata and mismatched
history return `unknown`. Versions past 17 are refused.

Schema 16 adds counts of legacy Task and file receipts in state `UNKNOWN`
(`state = 7`) and unresolved/`UNKNOWN` outcomes preserved by expansion in
`management.legacy_outcome`. The frozen source rows and retained records can
describe the same work. Keep their counts distinct. Routed rows with no final
timestamp are not necessarily actively dispatching. The shared platform queue,
lease, session, migration lock and restore-floor counts remain visible.

Schema 17 observes the retained legacy outcomes without requiring the retired
live objects. It checks that the six old relations are absent and sees exactly
one ready contraction receipt. This metadata observation still does not
establish the receipt's authority, source backup or reader floor.

The report includes migration names and checksums and aggregate counts. It
excludes receipt bodies, account identities, credentials and database error
text. `deployment` always remains `unknown` and
`destructive_contraction_allowed` always remains `false`. Actual authority,
backup and restore provenance, writer fencing and full schema identity require
their guarded operator and runner checks. Exit 2 is refusal for an unknown or
newer input. Exit 0 reports an observation only.

`InventoryModelTests` exercise report parsing and fixed SQL generation without
a database. To run the existing Linux metadata fixtures explicitly, use
`python eng/v2-migration/test_preflight.py PostgresInventoryTests`. These replay
immutable SQL in owned synthetic databases with the pinned disposable PostgreSQL
context. Neither suite establishes managed migration or production admission.

The operator sequence and rollback boundaries are in ArcForges
`docs/v2-migration/README.md` and Design `docs/data/migrations.md`. H-03 blocks
destructive admission. Keep the applied migration history, the schema11 guards,
unresolved routed receipts and published package bytes immutable. The explicit
`arcforges-center migrate contract` command takes a schema-16 archive and restores
it into a separately named, isolated witness before applying migration 0017.
The resulting schema needs a new runtime credential generation. Preserve the
archive, metadata and original IDs for offline rollback or historical review.
