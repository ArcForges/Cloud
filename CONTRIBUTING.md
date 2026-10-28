# Contributing

Use an isolated branch/worktree and describe the intended behavior and acceptance checks before changing code. Keep changes scoped to Cloud. Follow [validation policy](docs/validation-policy.md) and [development](docs/development.md).

Use the existing pinned toolchains for relevant checks:

```sh
npm ci --ignore-scripts
dotnet restore Cloud.slnx --locked-mode
npm run check
npm run check:dotnet
python eng/center.py check
npm run candidate
```

The Go center (`center/`) uses the Go release pinned in `center/toolchain.json` with `GOTOOLCHAIN=local` and read-only modules.
`python eng/center.py check` runs every Go control of the host's leg: module integrity and tidiness, dependency admission
(`center/dependencies.json`), `gofmt -s`, `go vet`, staticcheck, the tests (with the race detector on Linux), the generated
Worker table's drift, the fuzz targets (Linux), govulncheck and a native build that is started as a self-hosted center
([engineering controls](docs/engineering-controls.md)). After a change to the center's registrations run
`python eng/center.py generate`; after a Go dependency change update `center/dependencies.json` and its review receipt.

Every pull request is verified after the push on the owner's two verification hosts, a Windows leg on native Windows and a Linux leg on native Linux, which run these checks and the candidate build and report the commit statuses `arcforges/windows` and `arcforges/linux` that `main` requires (see [AGENTS.md](AGENTS.md), Verification after the push); external pull requests also run the full hosted CI and need no local hook. Runtime commands are local opt-in only (for example `npm run test:d1:entitlement:local`, the Entitlement plans on workerd's D1). The pre-commit hook checks only the staged whitespace and the `gofmt -s` formatting of staged Go files; install it with `python eng/verify.py install`. Use `npm run format` and `dotnet format Cloud.slnx` to format intentional changes.

Update central NuGet versions and regenerate the per-project locks with `dotnet restore Cloud.slnx --force-evaluate`; use `npm install --ignore-scripts` for npm lock changes. Do not hand-edit lock dependency graphs or disable locked mode. The Cloud host explicitly lists Windows/Linux x64 restore targets so its lock is portable between development and production builds.

Write meaningful tests for protocol, failure or security behavior changed. Local mocks are unit evidence only. A dependency PR must pass relevant locked compilation and packaging checks; local runtime testing is scoped to the changed behavior.

All original source and tooling in this repository use AGPL-3.0-only. Preserve third-party licenses and record any copied code with its source and license. Report vulnerabilities privately as described in SECURITY.md.

Follow [the provenance process](docs/provenance.md) before introducing reused material.
The source gate includes immutable records, complete inventory and deterministic NOTICE;
the candidate gate also verifies the actual Worker and image legal contents.

Dependency additions and upgrades follow [the enforced admission policy](docs/dependency-policy.md); update its input-bound review and retain the existing class and provenance gates.
