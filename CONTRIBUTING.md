# Contributing

Use an isolated branch and worktree. Describe the intended behavior and acceptance checks before changing code, and keep changes scoped to Cloud. [Validation policy](docs/validation-policy.md) · [Development](docs/development.md)

Use the existing pinned toolchains and run the checks relevant to the change.

```sh
npm ci --ignore-scripts
dotnet restore Cloud.slnx --locked-mode
npm run check
npm run check:dotnet
python eng/center.py check
```

The Go center (`center/`) uses the Go release pinned in `center/toolchain.json` with `GOTOOLCHAIN=local` and read-only modules.
Linux Go race/cgo checks select the verified LLVM and GNU tools in `eng/native-toolchain.json`.
Normal checks verify the existing installation. `ARCFORGES_TOOLCHAIN_ROOT` may name its private tool root.
The Linux candidate builds the sole application executable, `arcforges-center`, with the verified Go archive
in the pinned Python builder. It includes the required legal bundle.
`python eng/center.py check` runs every Go control of the host's leg: module integrity and tidiness, dependency admission
(`center/dependencies.json`), `gofmt -s`, `go vet`, staticcheck, the tests (with the race detector on Linux), the generated
Worker table's drift, the fuzz targets (Linux), govulncheck and a native build that is started as a self-hosted center
([engineering controls](docs/engineering-controls.md)). On Linux it also starts a PostgreSQL container (`postgres:18.7-alpine3.24`
pinned by digest in `eng/center.py`; Docker Engine required) for the store's integration tests and the logical-backup
restore drill ([PostgreSQL store](docs/postgres-store.md)). To run the store tests yourself, point
`ARCFORGES_TEST_POSTGRES_URL` at a disposable server's superuser URL (each test creates and drops its own database and
roles); without it they skip. A schema change is a new file in `center/internal/schema/migrations` with its runtime grants
in `center/internal/schema`; applied migrations are never edited. After a change to the center's registrations run
`python eng/center.py generate`; after a Go dependency change update `center/dependencies.json` and its review receipt.

The full native profile also reconstructs the reviewed 8e5 bridge with its historical Go 1.27.3 identity. When the
current center's pinned Go is installed elsewhere, set process-local `ARCFORGES_CENTER_GO` to the absolute path of its
native executable: the tool fingerprint and center check use that same file, and the check verifies its version and
Linux or Windows amd64 target. This selection takes effect after the Linux login profile. When the historical compiler
is installed elsewhere, set process-local `ARCFORGES_CTR06_BRIDGE_GO` to the absolute path of the existing native Go
1.27.3 executable; only the bridge check uses it and verifies its version and target. Without either variable its
corresponding step uses PATH as before. The original bridge source, executable and sealed asset hashes remain fixed.

For formal PR verification, fetch the same pushed GitHub commit in an isolated worktree on each designated host.
Run `python eng/verify.py run-and-report` in Windows PowerShell and in the native Linux host's SSH session.
The Linux leg includes the candidate build. The verifier reports `arcforges/windows` and `arcforges/linux` on the tested commit.
External PRs also run the required hosted checks. [Verification after the push](AGENTS.md#verification-after-the-push-ad-0020)

Install the pre-commit hook with `python eng/verify.py install` to check staged whitespace and the `gofmt -s` formatting
of staged Go files. Use `npm run format` and `dotnet format Cloud.slnx` to format intentional changes.
Runtime diagnostics are local opt-in. For example, `npm run test:d1:entitlement:local` runs the retained Entitlement
plan fixture on workerd's D1.

`Cloud.slnx` contains the independent published-contract Consumer and ArchitectureTests. Update their central NuGet
versions and regenerate their project locks with `dotnet restore Cloud.slnx --force-evaluate`. Use
`npm install --ignore-scripts` for npm lock changes. Keep locked mode and regenerate dependency graphs through the package tools.

The former managed host, generator and D1 tools remain at Cloud commit
`9b8796eac760982d9814f371b820b736ddd945c4`. Use `npm run check:legacy-cloud-history` to verify the archive and retained
inputs. Dated evidence continues to describe the revision and scope that produced it. [D1 migration history](docs/d1-physical-schema.md#migrations)

Write meaningful tests for protocol, failure or security behavior changed. Local mocks are unit evidence only. A dependency PR must pass relevant locked compilation and packaging checks; local runtime testing is scoped to the changed behavior.

All original source and tooling in this repository use AGPL-3.0-only. Preserve third-party licenses and record any copied code with its source and license. Report vulnerabilities privately as described in SECURITY.md.

Follow [the provenance process](docs/provenance.md) before introducing reused material.
The source gate includes immutable records, complete inventory and deterministic NOTICE;
the candidate gate also verifies the actual Worker and image legal contents.

Dependency additions and upgrades follow [the enforced admission policy](docs/dependency-policy.md); update its input-bound review and retain the existing class and provenance gates.
