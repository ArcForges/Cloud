# Go Hello deployment proof

> **History.** This record describes the bounded Go Hello proof of 2026-10-27 (Cloud #110). AF-CTR-02 replaced it with the
> Go center: `hello-go/`, `eng/hello-go.py` and `/app/arcforges-hello-go` no longer exist, the Hello moved unchanged in
> behaviour into `center/internal/hello`, the bindings come from the published Contracts Go module instead of the NuGet
> descriptor, and `python eng/center.py check` replaces the check below. The successor is [center](center.md); the controls
> are in [engineering controls](engineering-controls.md).

This increment follows the verified C# / Neon deployment (PR #109, 0.1.0-ci.417.1).
It switches only the production Hello process to Go. It does not migrate the other Cloud modules,
D1, accounts, fleet, commerce, or the product architecture.

The Worker uses the existing public binary gRPC-Web route and the same runtime Neon secret.
ARCFORGES_HELLO_RUNTIME=go selects /app/arcforges-hello-go. The final image also retains the C#
Native AOT executable, which remains the image's default entrypoint and serves the isolated proof
environment. Setting the production runtime back to csharp through a reviewed main push is the
rollback; no database rollback is needed because Hello performs only read-only transactions.

## Contracts and runtime

Go 1.27.3 is pinned with official archive hashes. The Go module and sum file lock the driver,
transport, protobuf generator and security tooling. Generated protobuf and service bindings are
derived during checks/builds from the exact published ArcForges.Contracts.PublicApi
1.0.0-ci.287.1 NuGet package. Package SHA512, descriptor and schema SHA256 hashes are checked.
No sibling source or handwritten protobuf implementation is used, and the generated files remain
build artifacts. The existing Contracts Apache-2.0 licence/NOTICE and generator obligations are
preserved.

Connect handles binary gRPC-Web and gRPC; pgx executes the same bytea greeting in a read-only
transaction so NUL and Unicode remain compatible with the published C# client. The 256 UTF-16-unit
limit and existing status codes are retained. TLS verifies the certificate and host, channel
binding is required, the pool is capped at two and queries have bounded deadlines. Errors never
include PostgreSQL details and never produce a local-success fallback in enabled mode.

Health identifies runtime=go, nativeAot=false and helloBackend=neon-postgresql. The false Native AOT
field distinguishes this Go executable from .NET Native AOT; the Go executable is still compiled
native code. Build and artifact identities are embedded from the same candidate inputs.

## Verification

Run python eng/hello-go.py check after the locked .NET restore with Go 1.27.3 available on PATH.
The native-host and external-PR profiles add this check without removing any existing step:
locked modules, generation, gofmt, vet, offline protocol tests, govulncheck and a native build.
The final image gate requires and hashes both ELF executables and their complete legal files.

Live validation remains an explicit native-host operation after the guarded main deployment:
confirm the exact revision and Go/Neon health identity, then run the existing published C# Hello
client against the real Worker. Local protocol tests are not evidence of a live Neon connection.
