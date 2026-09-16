# Contributing

Use an isolated branch/worktree and describe the intended behavior and acceptance checks before changing code. Keep changes scoped to Cloud. See [the bootstrap plan](docs/bootstrap-plan.md) and [development](docs/development.md).

Install the pinned .NET SDK and Node release plus JDK 17 (`JAVA_HOME`), then run:

```sh
npm ci --ignore-scripts
dotnet restore Cloud.slnx --locked-mode
npm run hooks
npm run check
npm run check:dotnet
npm run check:kotlin
npm run candidate
npm run test:worker
```

The last command requires Linux/WSL and Docker; source checks also run on Windows. Hooks are opt-in and configured for the current worktree only. CI is authoritative and repeats the checks regardless of local hooks. Use `npm run format` and `dotnet format Cloud.slnx` to format intentional changes.

Update central NuGet versions and regenerate the per-project locks with `dotnet restore Cloud.slnx --force-evaluate`; use `npm install --ignore-scripts` for npm lock changes. Do not hand-edit lock dependency graphs or disable locked mode. The Cloud host explicitly lists Windows/Linux x64 restore targets so its lock is portable between development and production builds.

Write meaningful tests for protocol, failure or security behavior changed. Local mocks are unit evidence only. A dependency PR must also pass AOT compilation and real container/client integration.

All original source and tooling in this repository use AGPL-3.0-only. Preserve third-party licenses and record any copied code with its source and license. Report vulnerabilities privately as described in SECURITY.md.
