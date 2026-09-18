# ArcForges Cloud

A C# 14 / .NET 10 Native AOT Hello service in a Linux x64 Docker image, hosted in Cloudflare Containers. A small TypeScript Worker routes the public binary gRPC-Web endpoint to the container. The repository is independently buildable and consumes published Contracts packages.

```text
Web / published TypeScript or Kotlin gRPC-Web client
  https://arcforges.com/api/arcforges.hello.v1.HelloService/SayHello
        → arcforges-cloud Worker (route /api/*)
        → fixed Cloudflare Container (HTTP/1.1 :8080)
        → generated gRPC service → Hello, ArcForges!
```

The separate `arcforges-web` Worker continues serving the website. This repository implements a bounded, anonymous Hello diagnostic. Accounts, PostgreSQL, AI and commercial APIs are future work; the previous monorepo is not a runtime/build dependency.

- [Development and local validation](docs/development.md)
- [Cloudflare setup, deployment and recovery](docs/deployment.md)
- [Bootstrap plan and acceptance scope](docs/bootstrap-plan.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## Quick start

Prerequisites: .NET SDK **10.0.401**, Node **24.21.0**, npm **11.19.0**, **JDK 17** (`JAVA_HOME`), and Docker with a Linux x64 daemon. Worker tooling uses TypeScript **7.0.2**. The Kotlin verification client uses published Contracts **1.0.0-ci.36.1**. The final image contains a real native executable and runtime OS dependencies, with no .NET runtime/JIT or JVM.

```sh
npm ci --ignore-scripts
npm run check
npm run check:dotnet
npm run check:kotlin
npm run candidate
```

On Linux/WSL, also run `npm run test:worker` to verify the bundled Worker, Durable Object/Container binding and actual AOT service together. See the development guide for Windows/WSL setup.

## Delivery

The existing checks enforce [project licence declarations](docs/licence-boundary.md)
across managed, npm and Gradle scopes, including the final Docker build.

PRs run locked restores, C#/TS/Kotlin tests, formatting, dependency audit/review, CodeQL, secret scanning, real AOT image build, native gRPC and gRPC-Web consumers, restart recovery and local Worker/Container integration. No PR deploys to Cloudflare.

After merge, main builds and verifies a versioned candidate before deployment. CI loads that exact image, pushes it to Cloudflare's registry, pins the remote digest and uploads the already bundled Worker. Deployment succeeds only after the public API reports matching Worker/container source identities and the published client verifies success and error statuses. A GitHub prerelease then records the candidate and live evidence.

The `cloudflare` repository environment needs one account variable and one deployment secret. There is no extra enable switch and no application secret in this Hello increment. A missing credential fails main deployment explicitly; configure it before merging.

License: [AGPL-3.0-only](LICENSE). Third-party dependencies retain their own licenses; see [NOTICE](NOTICE).
