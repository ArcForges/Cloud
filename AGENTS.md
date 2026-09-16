# Cloud repository instructions

Plan bounded changes before implementation. This repository owns the C# Native AOT Cloud service, its Docker image and its Cloudflare Container ingress Worker. Formal product designs live in the separate Design repository.

- Work in an isolated worktree. Do not edit adjacent repositories as part of a Cloud change.
- Keep repository documentation in English. Preserve AGPL-3.0-only and third-party notices.
- Consume exact published Contracts NuGet/npm packages. Never edit generated contracts here, copy sibling source, use submodules or add adjacent ProjectReferences.
- Keep the executable Native AOT compatible. Do not suppress trimming/AOT diagnostics to pass a build. Test the actual final Linux image.
- Commit NuGet/npm locks and pin tools/base images/Actions. Dependency updates must pass locked restores and the same image/protocol checks.
- PR code must not receive deployment secrets. Main deployment promotes the tested candidate image and Worker; never rebuild during publication.
- The current Hello is anonymous, bounded and stateless. Do not add authenticated/commercial/AI behavior implicitly.
- Keep the API route separate from Web's apex Custom Domain. Preserve binary gRPC-Web responses and status trailers.
- Run the checks in CONTRIBUTING.md. Distinguish unit, Docker, local Worker runtime, live Cloudflare and real browser evidence.
- Never read or print local credential stores, log tokens, commit secrets or request secret values in chat. Describe missing environment configuration explicitly.
