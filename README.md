# ArcForges Cloud

A C# 14 / .NET 10 Native AOT Hello service in a Linux x64 Docker image, hosted in Cloudflare Containers. A small TypeScript Worker routes the public binary gRPC-Web endpoint to the container. The repository is independently buildable and consumes published Contracts packages.

```text
Web / published TypeScript or Kotlin gRPC-Web client
  https://arcforges.com/api/arcforges.hello.v1.HelloService/SayHello
        → arcforges-cloud Worker (route /api/*)
        → fixed Cloudflare Container (HTTP/1.1 :8080)
        → generated gRPC service → Hello, ArcForges!
```

The separate `arcforges-web` Worker continues serving the website. This repository implements a bounded, anonymous Hello diagnostic. Accounts, D1 business transactions, AI integration and commercial APIs are future work; the previous monorepo is not a runtime/build dependency.

- [Development and local validation](docs/development.md)
- [Cloudflare setup, deployment and recovery](docs/deployment.md)
- [Bootstrap plan and acceptance scope](docs/bootstrap-plan.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## Quick start

Prerequisites: .NET SDK **10.0.401**, Node **24.21.0**, npm **11.19.0**, **JDK 17** (`JAVA_HOME`), and Docker with a Linux x64 daemon. Worker tooling uses TypeScript **7.0.2**. The Kotlin verification client uses published Contracts **1.0.0-ci.42.1**. The final image contains a real native executable and runtime OS dependencies, with no .NET runtime/JIT or JVM.

```sh
npm ci --ignore-scripts
npm run check
npm run check:dotnet
npm run check:kotlin
npm run candidate
```

Runtime checks such as `npm run test:container` and `npm run test:worker` are explicit local opt-in using existing tools, never CI or routine post-merge gates. See [validation policy](docs/validation-policy.md).

## Delivery

The existing checks enforce [project licence declarations](docs/licence-boundary.md)
across managed, npm and Gradle scopes, including the final Docker build.

PRs run locked restores, relevant offline units, C#/TS/Kotlin compilation, formatting, dependency audit/review, CodeQL, secret scanning and a Linux Native AOT image build. Candidate construction inspects image metadata and legal contents without launching the application. No PR deploys to Cloudflare.

Main promotes the same sealed image and Worker after successful checks. CI loads that image, checks its identity, pushes it to the registry, pins the remote digest and deploys the Worker. Provider completion creates a prerelease with the candidate and deployment record. No live RPC, health polling or public download verification runs automatically.

The `cloudflare` repository environment needs one account variable and one deployment secret. There is no extra enable switch and no application secret in this Hello increment. A missing credential fails main deployment explicitly; configure it before merging.

License: [AGPL-3.0-only](LICENSE). Third-party dependencies retain their own licenses; see [NOTICE](NOTICE).

[Build identity](docs/build-identity.md) describes compiled support metadata, independent version axes and the candidate metadata boundary.
