# ArcForges Cloud

The production Container runs the ArcForges center, `arcforges-center`, written in Go ([center](docs/center.md), [AD-0021](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0021-central-access-go-center.md)); today it serves the anonymous Hello, which queries Neon, and its health. A small TypeScript Worker preserves the public binary gRPC-Web endpoint and its deny-by-default route table, generated from the center's registrations. The image retains the C# 14 / .NET 10 Native AOT executable for the isolated proof environment and the Hello rollback until AF-CTR-09. The center consumes the published Contracts Go module and the C# host the NuGet packages of the same cohort. The same `arcforges-center` binary runs as a self-hosted center without the Worker.

```text
Web or published gRPC-Web client
  https://arcforges.com/api/arcforges.hello.v1.HelloService/SayHello
        → arcforges-cloud Worker (route /api/*)
        → fixed Cloudflare Container (HTTP/1.1 :8080, /app/arcforges-center)
        → ingress pipeline → generated Connect service → Hello, ArcForges!
```

The separate `arcforges-web` Worker continues serving the website. This repository implements a bounded, anonymous Hello diagnostic. Accounts, D1 business transactions, AI integration and commercial APIs are future work; the previous monorepo is not a runtime/build dependency.

- [Development and local validation](docs/development.md)
- [Cloudflare setup, deployment and recovery](docs/deployment.md)
- [Bootstrap plan and acceptance scope](docs/bootstrap-plan.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## Flagship role

Cloud is an active repository of the ArcForges flagship ([AD-0001](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0001-flagship-pivot.md)). It hosts the flagship cloud: accounts and sign-in, node enrollment, entitlements, commerce (Paddle and Google Play), the fleet relay, remote commands, push notifications, support and operator endpoints, built on the reused host, Worker ingress, deploy scripts and D1 storage layer ([architecture 01 §5](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/01-system-overview.md#5-repository-and-project-map), [architecture 10](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/10-cloud.md), [reuse classification](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/reuse/inventory-and-classification.md#3-cloud)). Modules the flagship does not need are retained and not composed. Work is scheduled in the [ArcForges/Plan delivery graph](https://github.com/ArcForges/Plan/blob/main/delivery-graph.json) and delivered serially under its [execution policy](https://github.com/ArcForges/Plan/blob/main/execution-policy.md); flagship surfaces deploy dark until production activation.

## Quick start

Prerequisites: .NET SDK **10.0.401**, Node **24.21.0**, npm **11.19.0**, Go **1.27.3** (`center/toolchain.json`; gcc on Linux for the race detector), and Docker with a Linux x64 daemon. Worker tooling uses TypeScript **7.0.2**. The final image contains a real native executable and runtime OS dependencies, with no .NET runtime/JIT or JVM.

```sh
npm ci --ignore-scripts
npm run check
npm run check:dotnet
python eng/center.py check
npm run candidate
```

Runtime checks such as `npm run test:container` and `npm run test:worker` are explicit local opt-in using existing tools, never CI or routine post-merge gates. See [validation policy](docs/validation-policy.md).

## Delivery

The existing checks enforce [project licence declarations](docs/licence-boundary.md)
across managed and npm scopes, including the final Docker build.

PRs run locked restores, relevant offline units, C#/TS/Go compilation, formatting, analyzers, the Go race detector and fuzz targets, dependency audit/review, CodeQL, secret scanning and a Linux image build ([engineering controls](docs/engineering-controls.md)): external PRs in hosted CI, and every PR on the owner's two hosts after the push, a Windows leg on native Windows and a Linux leg on native Linux whose statuses `main` requires (`eng/verify.py run-and-report`; dependency review and CodeQL stay hosted). Candidate construction inspects image metadata and legal contents without launching the application. No PR deploys to Cloudflare.

A main push builds the sealed candidate image and Worker and promotes them without re-running the PR checks. CI loads that image, checks its identity, pushes it to the registry, pins the remote digest and deploys the Worker. Provider completion creates a prerelease with the candidate and deployment record. No live RPC, health polling or public download verification runs automatically.

The `cloudflare` repository environment needs one account variable and one deployment secret. There is no extra enable switch and no application secret in this Hello increment. A missing credential fails main deployment explicitly; configure it before merging.

License: [AGPL-3.0-only](LICENSE). Third-party dependencies retain their own licenses; see [NOTICE](NOTICE).

[Build identity](docs/build-identity.md) describes compiled support metadata, independent version axes and the candidate metadata boundary.
