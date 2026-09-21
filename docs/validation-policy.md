# Validation policy

The accepted [Design policy](https://github.com/ArcForges/ArcForges-Design/blob/47db6670a727317939b91245e8c0b288834acf99/docs/assurance/ci-and-local-validation-policy.md) replaces earlier mandatory runtime and publication verification during WP02.04.

- CI has no macOS runner, device/emulator, desktop GUI, browser E2E, live API, real inference/Workflow, installed-consumer or public-release installation/upgrade execution. This includes nested scripts and scheduled/manual workflows.
- Retain necessary Windows/Linux compilation, packaging, static checks, targeted offline units and non-duplicated security scans. Pure fixtures do not establish live runtime behavior.
- Build once. Keep dependency locks/checksums, signing, licence/provenance and one necessary identity/integrity check at each actual trust handoff. Do not download public packages or assets to repeat archive/hash/runtime checks.
- Runtime checks are explicit local opt-in only for affected behavior with existing tools. Do not reinstall vcpkg, SDKs, emulators or toolchains to expand validation. Do not repeat passing tests without a new change or concrete finding.
- Do not create tags, replacement releases or signatures solely to verify. Inspect failures before rerunning. Documentation-only changes need consistency review, not builds.
- Use normal networking. Do not configure a proxy, including port 7890, or invoke wsl.exe/WSL wrappers. On a network failure, report the exact operation and stop. Use a directly available WSL terminal only if needed.
- Use retained worktrees/branches and reviewed PRs. Coordinate CPU-heavy local work; hooks must not rebuild/test on every commit or push.
- After merge, confirm the expected commit and required build/publication/deployment result, then fast-forward the clean primary checkout. Stop without another download/hash/install/runtime cycle.

Historical plans and evidence describe their original executions; they do not reinstate removed gates. Report untested runtime/platform coverage honestly. Deployment completion is not live acceptance evidence.
