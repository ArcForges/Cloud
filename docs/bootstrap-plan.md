# Cloud bootstrap plan

Status: implementation delivered in Cloud PR #1. The workflow records source, real image and Worker runtime checks separately from production acceptance. Live deployment requires the repository's Cloudflare credentials and a merge to main.

## Scope and evidence

Build an independently reproducible Hello service in C# 14 / .NET 10, publish a real Linux x64 Native AOT executable in a non-root Docker image, and run that image in Cloudflare Containers behind a small TypeScript Worker. Consume the already published `ArcForges.Contracts.PublicApi` package; never copy generated contracts or depend on adjacent source repositories. Keep the repository's AGPL-3.0-only license.

This is a public, stateless transport demonstration. It does not implement accounts, authentication, billing, PostgreSQL, AI, or the full Cloud product. No model calls or application secrets are needed. Deployment credentials are still required. Docker, CI, and production Cloudflare evidence must be reported separately.

## Collected inputs

- Cloud starts at `1e0c378` with only a license. Work happens on `codex/cloud-aot-containers` in `.worktree/aot-containers`.
- The local machine has SDK 10.0.401, runtime 10.0.12 and a working Linux x64 Docker daemon accessed through WSL.
- Contracts publishes `ArcForges.Contracts.PublicApi` and `@arcforges/api-client` at `1.0.0-ci.25.1`. Hello accepts a nonempty name, returns `Hello, <name>!`, and rejects an empty name with `INVALID_ARGUMENT`.
- The old repository's C# settings are reference material. Its JIT/SignalR architecture is not the architecture of this bootstrap.
- Web PR #5 prepares a real gRPC-Web call from `/cloud-hello/` to the same-origin `/api/arcforges.hello.v1.HelloService/SayHello`. It is not yet deployed.
- `arcforges.com` already uses the separate `arcforges-web` Worker Custom Domain. Cloud must use a route for `arcforges.com/api/*`, not replace that domain binding.
- Cloud has no GitHub deployment environment, variables or secrets yet. The user will provide the deployment token through GitHub, never through source or chat.

## Decisions

1. Pin SDK, NuGet, npm, Docker bases and GitHub Actions. Commit central NuGet versions and per-project locks plus the npm lock. Use TypeScript 7.0.2 and the existing Node 24 LTS line for Worker tooling.
2. Use ASP.NET Core's slim builder, generated gRPC bindings and gRPC-Web middleware with Native AOT. HTTP/1.1 gRPC-Web is the public Worker transport. Test native HTTP/2 gRPC directly against the same Docker image on a separate local port; do not claim the Worker path provides native gRPC.
3. Keep a narrow endpoint allowlist, body and message limits, deadlines, rate limiting, one fixed container instance, a short idle shutdown, no container internet access and no public administration endpoint. These bound the Hello deployment; they are not authentication or a hard account spending cap.
4. Stamp the same source revision into Worker metadata and the compiled executable. Readiness must prove the running container revision, not merely that a Worker deployment command succeeded. Poll readiness for bounded rollout time; do not hide failures with automatic redeploys or repeat side effects.
5. Build the Docker image once, test it, save it with the bundled Worker and checksums as a candidate artifact. Main deployment must load and promote that image, not rebuild it. Verify source identity and artifact hashes before publication. Publish a GitHub prerelease only after the live route passes the protocol checks.
6. PRs run source, unit, security, AOT image and real protocol integration checks without cloud secrets. Pushes to main deploy after the verification gate. Serialize deployments and reject obsolete commits. Missing credentials fail explicitly with setup guidance.
7. Add a solution, editor/Git settings, opt-in local hooks, formatting, security policy, contribution guidance, Dependabot, dependency review, CodeQL for C#/TypeScript/Actions, secret scanning, development/deployment/recovery documentation and issue/PR templates.

## Execution order

1. Implement the C# service, unit tests and a native gRPC consumer using the published package.
2. Implement the Worker boundary, tests and Dockerfile. Verify Linux Native AOT, both wire transports, error responses, resource boundaries and process restart locally.
3. Implement immutable candidate/deployment tooling and CI; validate the bundled Worker and actual image rather than a mock service.
4. Review the complete diff against this plan, run the required checks, configure non-secret GitHub settings and submit a PR.
5. Provide the precise token permissions and GitHub environment setup. Once configured and merged, inspect real deployment, revision readiness and SDK calls through `arcforges.com/api/*`.
6. After Cloud is healthy and Web's Hello page is merged, verify the browser round trip. Preserve the distinct evidence and document any remaining limitation.

## Closure conditions

- Clean locked restores; formatting, lint, types, unit tests, Docker AOT compilation and published-client integration pass.
- The final image runs as non-root and contains the native executable, not a .NET runtime deployment; its exact identity is preserved across CI jobs.
- Unknown routes and unsupported methods/content types fail before waking a container. Valid and invalid Hello calls preserve protobuf and gRPC status semantics.
- CI cannot publish ahead of required tests. PR code has no deployment secrets. Production only owns the API route.
- Public deployment evidence includes the deployed source identity and successful/invalid Hello requests. If credentials or merge are pending, report this as pending instead of completed.

## Implementation review

The bootstrap includes all scoped repository controls, the published-contract service, immutable candidate promotion, main-only deployment and recovery instructions. Local validation exercised the real Native AOT image with C# and TypeScript consumers, error statuses and restart recovery. Verification corrected cross-platform NuGet restore targets and Docker's ephemeral port reassignment on restart. Deployment readiness compares the compiled container revision with the Worker revision, and startup failures return a generic unavailable response.

GitHub's repository-scoped `cloudflare` environment and Account ID are configured, with only main allowed to deploy. Secret scanning, push protection, private vulnerability reporting and Dependabot security updates are enabled. Main requires the Actions `Verify` check and resolved conversations; no human approval count was added. The owner must still enter the scoped deployment token before main deployment. No live Cloudflare or browser success is inferred from local validation.

## Primary references

- [ASP.NET Core gRPC Native AOT](https://learn.microsoft.com/en-us/aspnet/core/grpc/native-aot?view=aspnetcore-10.0)
- [Cloudflare Containers setup](https://developers.cloudflare.com/containers/get-started/)
- [Container image management](https://developers.cloudflare.com/containers/guides/image-management/)
- [Container interface](https://developers.cloudflare.com/containers/reference/container-class/)
- [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/)
- [Routes and Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#interaction-with-routes)
