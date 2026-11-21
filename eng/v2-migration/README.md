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
ledger observation is limited to the 16 known entries and one overflow entry.

Classification distinguishes `fresh`, `center10`, `center11`, `center16`,
`unknown` and `newer`. Versions, contiguous migration names and source checksums
must agree. The historical schema 10 and 11 reports keep their original keys and
source window. Schema 12 through 15, missing required metadata and mismatched
history return `unknown`. Versions past 16 are refused.

Schema 16 adds counts of legacy Task and file receipts in state `UNKNOWN`
(`state = 7`) and unresolved/`UNKNOWN` outcomes preserved by expansion in
`management.legacy_outcome`. The frozen source rows and retained records can
describe the same work. Keep their counts distinct. Routed rows with no final
timestamp are not necessarily actively dispatching. The shared platform queue,
lease, session, migration lock and restore-floor counts remain visible.

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
destructive admission. Keep applied 0001..0016, the schema11 guards, unresolved
routed receipts and published package bytes immutable.
