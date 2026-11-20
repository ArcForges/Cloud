# Official deployment preflight

Run the preflight from the clean checkout that built the sealed Cloud candidate, using its stock `artifacts/candidate` directory. The existing candidate verifier checks every member digest, the Worker source closure, the image provenance and legal files, and the source and build identity. The production configuration must select the Go Center in `official-hosted` mode and disable both Worker preview surfaces.

```sh
node tooling/cloudflare.ts preflight artifacts/candidate /absolute/path/to/external-fixture.json
```

The fixture document uses schema `1` and source `external-fixture`. Supply these fields using reviewable fixture values.

| Field                                    | Input                                                                                                                                                                                                                                                            |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.dispatch` and `github.responses` | The commit and exact endpoint-to-response map consumed by the existing proof producer gate. The recorded example is [the proof gate fixture](../../tests/worker/fixtures/proof-gate-9085b12.json). Use its `sha` as the dispatch and its `responses` as the map. |
| `d1`                                     | `target`, `revision` and `status` from the sealed D1 migrator's gate format. Use `production`, the candidate's revision, and the fixture decision `passed` or `not-applicable`.                                                                                  |
| `postgres`                               | `target`, `revision`, `status`, `version`, `database` and `runtimeRole` in the PostgreSQL gate format. Use the same target and revision and the exact checked-in migration version.                                                                              |
| `databaseRoles`                          | Synthetic role names in `migration` and `hello`, and the synthetic `database` name. The PostgreSQL runtime role and the migration role must differ.                                                                                                              |
| `worker`                                 | A `deployments` response and a `versions` map keyed by Worker version ID. The preflight uses the live-slot parser and refuses incomplete or contradictory inventory.                                                                                             |

A successful report includes the sealed candidate identity, schema version and protected slot from the fixture. For a local candidate it reports `local_unpublished`. For a CI-format candidate, `fixture_context_matched` means the build and source identities match the verified fixture run, commit and tree. The result always records `archiveCustody: not_assessed`, `authority: not_assessed` and `applied: false`. The live proof handoff verifies the downloaded ZIP digest and producer custody separately. An unresolved candidate or gate yields a nonzero exit with fixed diagnostics. Keep the fixture values synthetic and credentials out of the document.

The exact guarded production path separately requires the reviewed CTR06 security-bridge successor, a successful main producer, exact migration admission and the protected credential rotation. H-03 covers approved backup and live provider inventory and authority. The deployment workflow stays disabled pending that approval. Use the existing [deployment and recovery procedure](../deployment.md#recovery) for a reviewed rollback compatible with the verified schema and credential floor.

After a real local candidate build, exercise the command against that candidate with the repository fixture. The command uses the existing candidate files and can run with provider credentials absent.

```sh
ARCFORGES_HOST03_CANDIDATE=artifacts/candidate node --test tooling/deployment-preflight.test.ts
```
