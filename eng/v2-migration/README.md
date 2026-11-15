<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Center read-only preflight

```sh
python eng/v2-migration/preflight.py --database operator_selected_database > center-preflight.json
python eng/v2-migration/preflight.py --container explicit_fixture --user postgres --database fixture
python eng/v2-migration/test_preflight.py
```

The first command uses existing psql environment/service authentication. Never
put a connection URL/password on the command line or export credentials into
reports. The optional container must already exist. Preflight creates no database
or container. It uses psql `-X -w` with fixed SQL in a single repeatable-read,
read-only transaction, bounded statement/lock waits and an explicit rollback.

Classification distinguishes `fresh`, `center10`, `center11`, `unknown` and
`newer`. Versions, contiguous migration names and source checksums must agree.
Reports expose counts, not receipt bodies/credentials or database error text.
Active sessions, migration locks, unresolved work and missing restore/floor facts
are blockers. `deployment` always remains `unknown` and contraction is always
false: even a matching ledger does not prove full schema, binary provenance,
approved backups or security-successor/provider authority. Exit 2 means an unknown
or newer input; exit 0 is an inventory result, never admission.

The explicit Linux test command uses the existing `eng/center.py` disposable
PostgreSQL context and pinned image. It replays immutable SQL only inside its
owned synthetic databases, checks metadata/lock/session/negative cases, and removes
its fixture container. It does not qualify the guarded migration runner, create
a production runtime floor or establish that schema11 was deployed. Required
CENTER-01 migration/backup/restore/security acceptance remains pending.

The operator sequence and rollback boundaries are in ArcForges
`docs/v2-migration/README.md` and Design `docs/data/migrations.md`. H-03 blocks
destructive admission, not this preparation. Keep 0001..0011, schema11 guards,
unresolved routed receipts and published package bytes immutable. This task
enables no deployment or public channel.
