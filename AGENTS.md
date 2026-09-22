# Cloud repository instructions

Plan bounded changes before implementation. This repository owns the C# Native AOT Cloud service, its Docker image and its Cloudflare Container ingress Worker. Formal product designs live in the separate Design repository.

- Work in an isolated worktree. Do not edit adjacent repositories as part of a Cloud change.
- Keep repository documentation in English. Preserve AGPL-3.0-only and third-party notices.
- Consume exact published Contracts NuGet/npm/Maven packages. Never edit generated contracts here, copy sibling source, use submodules or add adjacent ProjectReferences.
- Keep the executable Native AOT compatible. Do not suppress trimming/AOT diagnostics to pass a build. Keep the final Linux image build; runtime execution is local opt-in.
- Commit NuGet/npm/Gradle locks and Gradle verification metadata; pin tools/base images/Actions. Dependency updates must pass locked restores and the relevant compilation and packaging checks.
- PR code must not receive deployment secrets. Main deployment promotes the sealed candidate image and Worker; never rebuild during publication.
- The current Hello is anonymous, bounded and stateless. Do not add authenticated/commercial/AI behavior implicitly.
- Keep the API route separate from Web's apex Custom Domain. Preserve binary gRPC-Web responses and status trailers.
- Run the checks in CONTRIBUTING.md. Distinguish unit, Docker, local Worker runtime, live Cloudflare and real browser evidence.
- Never read or print local credential stores, log tokens, commit secrets or request secret values in chat. Describe missing environment configuration explicitly.

## Required validation limits

Follow [validation policy](docs/validation-policy.md), which supersedes older runtime and release-test requirements. Never add or execute macOS CI, device/emulator/GUI/browser E2E CI, live service or inference CI, installed-consumer CI or public-download verification. Keep runtime checks explicit local opt-in. Do not repeat public archive/hash checks, passing tests or post-merge runtime cycles. Preserve lock/signature/licence/provenance checks at actual trust handoffs. Do not invoke wsl.exe, configure proxy 7890 or install toolchains solely for testing. Stop and report the exact failed network operation. Hooks do not rebuild/test on commit or push.

Dependency additions and upgrades follow [the enforced admission policy](docs/dependency-policy.md); update its input-bound review and retain the existing class and provenance gates.
