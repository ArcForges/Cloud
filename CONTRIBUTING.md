# Contributing

Use an isolated branch/worktree and describe the intended behavior and acceptance checks before changing code. Keep changes scoped to Cloud. Follow [validation policy](docs/validation-policy.md) and [development](docs/development.md).

Use the existing pinned toolchains for relevant checks:

```sh
npm ci --ignore-scripts
dotnet restore Cloud.slnx --locked-mode
npm run hooks
npm run check
npm run check:dotnet
npm run check:kotlin
```

The candidate build belongs to hosted Linux CI. Runtime commands are local opt-in only. Hooks are opt-in, scoped to this worktree and check whitespace without rebuilding or testing. Use `npm run format` and `dotnet format Cloud.slnx` to format intentional changes.

Update central NuGet versions and regenerate the per-project locks with `dotnet restore Cloud.slnx --force-evaluate`; use `npm install --ignore-scripts` for npm lock changes. Do not hand-edit lock dependency graphs or disable locked mode. The Cloud host explicitly lists Windows/Linux x64 restore targets so its lock is portable between development and production builds.

Write meaningful tests for protocol, failure or security behavior changed. Local mocks are unit evidence only. A dependency PR must pass relevant locked compilation and packaging checks; local runtime testing is scoped to the changed behavior.

All original source and tooling in this repository use AGPL-3.0-only. Preserve third-party licenses and record any copied code with its source and license. Report vulnerabilities privately as described in SECURITY.md.

Follow [the provenance process](docs/provenance.md) before introducing reused material.
The source gate includes immutable records, complete inventory and deterministic NOTICE;
the candidate gate also verifies the actual Worker and image legal contents.
