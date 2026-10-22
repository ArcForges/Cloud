# Validation policy

The accepted [Design policy](https://github.com/ArcForges/ArcForges-Design-Parallel/blob/47db6670a727317939b91245e8c0b288834acf99/docs/assurance/ci-and-local-validation-policy.md) replaces earlier mandatory runtime and publication verification during WP02.04.

- CI has no macOS runner, device/emulator, desktop GUI, browser E2E, live API, real inference/Workflow, installed-consumer or public-release installation/upgrade execution. This includes nested scripts and scheduled/manual workflows.
- Retain necessary Windows/Linux compilation, packaging, static checks, targeted offline units and non-duplicated security scans. Pure fixtures do not establish live runtime behavior.
- Build once. Keep dependency locks/checksums, signing, licence/provenance and one necessary identity/integrity check at each actual trust handoff. Do not download public packages or assets to repeat archive/hash/runtime checks.
- Runtime checks are explicit local opt-in only for affected behavior with existing tools. Do not reinstall vcpkg, SDKs, emulators or toolchains to expand validation. Do not repeat passing tests without a new change or concrete finding.
- Do not create tags, replacement releases or signatures solely to verify. Inspect failures before rerunning. Documentation-only changes need consistency review, not builds.
- Use normal networking. Do not configure a proxy, including port 7890. Linux opt-in checks run on the Linux MCP host, through the Linux MCP server, on a Linux-native filesystem copy, never through local WSL, not even as a fallback (ArcForges-Design AD-0018, AD-0019); record the distribution, kernel and toolchain versions. Toolchains there are installed by the user. On a network failure, report the exact operation and stop.
- Use retained worktrees/branches and reviewed PRs. Coordinate CPU-heavy local work. Each verification host runs the CI-equivalent verification once per pushed head and reports its commit status, which `main` requires (AD-0020, [AGENTS.md](../AGENTS.md) Verification after the push); the pre-commit hook checks only staged whitespace.
- After merge, confirm the expected commit and required build/publication/deployment result, then fast-forward the clean primary checkout. Stop without another download/hash/install/runtime cycle.

Historical plans and evidence describe their original executions; they do not reinstate removed gates. Report untested runtime/platform coverage honestly. Deployment completion is not live acceptance evidence.
