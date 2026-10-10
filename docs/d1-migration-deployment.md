# D1 migration deployment step

CLOUD.70 adds the one place where migrations reach a deployed D1 database: a gated step of the deployment jobs of
`.github/workflows/ci.yml`, run before the Worker or image is promoted. It is never run from the Container, and it
adds no runner behavior: the migration engine (lease, fence, receipts and gating) is the CLOUD.03 design
([D1 physical schema](d1-physical-schema.md)).

Since CLOUD.84 U9 and U10 (S41), every decision of the step is C#: the migration engine in
`src/ArcForges.Cloud.Storage.D1/MigrationRunner`, its REST transport, and the deploy decisions in
`src/ArcForges.Cloud.Storage.D1/Deploy` (the environment-to-database selection, the release plan and the excluded-build and
gate refusals). They run in the sealed migrator, `migrate` in `tools/ArcForges.Cloud.Generation`. The candidate job publishes that
binary self-contained for linux-x64 and seals its SHA-256 in the candidate manifest; the deploy jobs verify the hash and run the sealed
binary, with no .NET build. `eng/migrations/deploy.ts` is a shim that forwards argv and environment only. The one authority that
decides is the C# step; Node only starts it.

## Where it runs

| Job            | Trigger                                   | Command                                                    | Target database                             |
| -------------- | ----------------------------------------- | ---------------------------------------------------------- | ------------------------------------------- |
| `deploy`       | push to `main`                            | `node eng/migrations/deploy.ts deploy --target production` | top-level `d1_databases` of `wrangler.json` |
| `deploy-proof` | manual dispatch on `main`, `proof=deploy` | `node eng/migrations/deploy.ts deploy --target proof`      | `env.proof` binding `DB` of `wrangler.json` |

Pull-request jobs gain no secret and no migration step, and the live step refuses any context that is not the
gated job: not GitHub Actions, another repository, a ref other than `refs/heads/main`, or the wrong event
(`push` for production, `workflow_dispatch` for proof). A fork pull request can therefore never reach it. The
production Worker declares no D1 binding today, so for production the step reports "not applicable" and records it;
the day `wrangler.json` declares one, the same step resolves and migrates it with no workflow change. The proof
database is looked up by its exact configured name (nothing is created here; `proof-access` provisioned it) unless
`D1_DATABASE_ID` is set.

Environment variables used, by name only: `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` (the existing deployment
secret, sent only as the request `authorization` header and removed from anything printed), optional
`D1_DATABASE_ID`, and the runner-provided `GITHUB_ACTIONS`, `GITHUB_REPOSITORY`, `GITHUB_REF`,
`GITHUB_EVENT_NAME`, `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_JOB`. `PLAN_MANIFEST_HASH`,
`ABI_VERSION` and `RUNTIME_VERSION` are optional receipt fields.

## Order of the step

1. The sealed candidate must be the commit being deployed (`artifacts/candidate/manifest.json` revision equals
   `GITHUB_SHA`).
2. The catalog is loaded against its lock (a merged migration that was edited is refused).
3. The database status is read. A database that holds migrations this build does not contain is refused
   (`database-ahead`: an older build is never promoted over a newer schema).
4. The release plan is resolved (below). If the build's schema is below the database's write horizon the build is
   refused (`build-excluded`) before anything is written, not even a lease.
5. The runner applies the pending migrations in sequence under the migrator lease and fence, with receipts. The
   runner identity is `gh-<run id>-<attempt>-<job>`; the lease is released at the end.
6. The status is read again and the compatible-rollback rule (`compatibility()`) is applied to the build being
   promoted; a build that cannot write is refused.
7. The job prints the receipts, the fence, the horizons and the compatibility record as JSON (no secret), and writes
   `artifacts/migration-gate-<target>.json` with the candidate revision and the result, which the job uploads with its other evidence artifacts (it holds no secret).

## The release plan: expand, backfill, cutover, contract across deployments

The candidate's release manifest may carry `"migrations": { "through": <sequence>, "allowContract": true }`.
`through` is the highest migration this deployment applies and the schema the promoted build is built for.

- Without the entry, only expand migrations are applied: the step continues from the schema the database is at while
  the next migration is an expand, and stops before any backfill, cutover or contract.
- A backfill or cutover is applied only when `through` reaches it. The runner still requires a cutover's backfills to
  be verified and moves the horizons in one fenced batch.
- A contract (irreversible) is applied only when `through` reaches it and `allowContract` is `true`; a plan that
  reaches one without consent is refused before the database is touched, and the runner still waits for the declared
  soak after its cutover. Expand, backfill, cutover and contract thereby land in separate deployments.

The manifest entry is an input: the candidate builder (CLOUD.10) owns producing it; this task only reads it, and an
unknown or malformed entry is refused (`bad-plan`).

## A failing step stops promotion

Any refusal or runner failure makes `deploy.ts` print `migration step REFUSED (<code>)` and `Nothing is promoted.`,
write a `refused` gate record and exit with code 1. Three independent mechanisms keep the Worker and image where
they are:

- the migration step sits before the promotion step in the job and neither carries `if: always()` or
  `continue-on-error`, so the failed step fails the job and the later steps do not run (a workflow test asserts the
  order and the absence of an escape);
- `tooling/cloudflare.ts` calls `requireGatePassed("production", <candidate revision>)` before it loads or pushes the
  image or runs `wrangler deploy`, and refuses a missing record, a record of another revision or target, and a
  record that is not `passed` or `not-applicable`;
- the proof job runs the step before `npm run deploy:proof`, in the same job, in the same order. It relies on that
  order and the exit code: `eng/verification/proof-cloudflare.ts` is outside this task's scope and does not read the
  gate record.

## Compatible rollback

A rollback is the promotion of an earlier build. It is compatible only while the database horizons allow it: a
build older than the read horizon cannot read, older than the write horizon cannot write, and a build newer than
the applied schema cannot start. The step enforces the rule at promotion time (steps 3, 4 and 6), so a rollback of
the Worker or image to a build the cutover excluded fails the migration step and is not promoted. Before a cutover
the earlier build is still within the horizons and is compatible.

## Offline proof and the proof-environment run

The offline proof is the C# suite `tests/ArcForges.Cloud.Tests/Reduction` (`DeployTests` and `MigrationRunnerTests`, the one-for-one
replacement of the retired `tests/worker/d1-migration-deploy.test.ts` and `d1-migration-runner.test.ts`; S41(4) and S42(5)). The
`npm run migrate:dry-run` command is retired: its statement lists are covered by `DeployTests`, and the dry run needs no token.
The suite runs the step against the SQLite bridge (`SqliteBridgeExecutor`) directly and through a fake Cloudflare REST endpoint
backed by it: the order,
the printed receipts, the plan, a contract refused without consent and before its soak, an excluded build, a failing
step that stops promotion, no secret in any output (including an error message that echoes the token), the
pull-request and fork refusal, and the workflow shape. SQLite and a fake endpoint do not prove Cloudflare's D1: that
a REST `batch` is one atomic transaction and real latencies remain the deferred live check of CLOUD.03, performed by
the single proof-environment run of this step under the `RES-cloud-deployment` lease (manual dispatch with
`proof=deploy` after the change merges). Its job result and receipt report (receipt and fence values, never a
secret) are recorded in the task's ledger; until then no migration has run against a deployed database.
