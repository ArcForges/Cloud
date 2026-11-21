# ArcForges Cloud

The release image runs the ArcForges Center, `arcforges-center`, written in Go. The same executable runs as a self-hosted Center without the Worker. It consumes the published Contracts Go module and uses a least-privilege PostgreSQL role for management state, command receipts, audit and signing keys. The TypeScript Worker exposes registered gRPC-Web routes and rejects unregistered methods. Deployment checks require a PostgreSQL migration receipt and verify that D1 bindings are absent before promotion. [Center](docs/center.md) · [PostgreSQL store](docs/postgres-store.md)

```text
Web or published gRPC-Web client
  https://arcforges.com/api/arcforges.hello.v1.HelloService/SayHello
        → arcforges-cloud Worker (route /api/*)
        → fixed Cloudflare Container (HTTP/1.1 :8080, /app/arcforges-center)
        → ingress pipeline → generated Connect service → Hello, ArcForges!
```

The separate `arcforges-web` Worker serves the website. The Hello endpoint is a diagnostic alongside the Center's management routes.

- [Development and local validation](docs/development.md)
- [Cloudflare setup, deployment and recovery](docs/deployment.md)
- [Bootstrap plan and acceptance scope](docs/bootstrap-plan.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## Flagship role

Cloud provides the Center side of account access, Node enrollment, authenticated management and operator checks. ArcForges Node retains local authorization and execution. The old C# Center and the original D1 deployment tools are preserved at their reviewed historical Git revision. The current repository verifies the applied migrations and retained inputs against that history. [Delivery graph](https://github.com/ArcForges/Plan/blob/main/delivery-graph.json) · [D1 history](docs/d1-physical-schema.md#migrations)

## Quick start

Use Node **26.13.1**, npm **12.2.2**, Go **1.27.4** and Docker with a Linux x64 daemon. The Linux Go race checks use gcc. Use .NET SDK **11.0.100** for the managed contract consumer and architecture checks. The release image contains the native Go executable and its operating system dependencies.

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

The main delivery workflow builds the sealed candidate image and Worker. Production deployment and external bootstrap authority are disabled in the current workflow. Public activation follows the explicit approval and deployment requirements in AFV2-PROD-01. [Delivery graph](https://github.com/ArcForges/Plan/blob/main/delivery-graph.json) · [Deployment](docs/deployment.md)

License: [AGPL-3.0-only](LICENSE). Third-party dependencies retain their own licenses; see [NOTICE](NOTICE).

[Build identity](docs/build-identity.md) describes compiled support metadata, independent version axes and the candidate metadata boundary.
