# Development and validation

## Layout

- `src/ArcForges.Cloud`: ASP.NET Core slim host, generated gRPC service implementation and source-generated health JSON.
- `src/ArcForges.Cloud.Modules.<Name>`: the nineteen module boundaries, one project per module, and `src/ArcForges.Cloud.Modules.Abstractions` with the shared boundary types. `src/ArcForges.Cloud.Storage.D1`: the named-plan binding mechanism. `storage/plans`: the reviewed plans, by owner. See [storage plans and module boundaries](storage-plans.md). The physical D1 schema, its typed exact adapters and the migration runner (`npm run check:physical`, opt-in `npm run test:d1:local`) are described in [D1 physical schema and migrations](d1-physical-schema.md).
- `tests/ArcForges.Cloud.Tests`: C# behavior tests using xUnit v3 and Microsoft.Testing.Platform.
- `tests/ArcForges.Cloud.Consumer`: separately referenced, published C# client verifying native HTTP/2 against the running image.
- `worker`: the Cloudflare Container class and API boundary; no AI harness or business database.
- `tests/worker`: isolated boundary tests. They are not live Container evidence.
- `tooling`: candidate construction, published TypeScript client checks and deployment.
- `Dockerfile`: digest-pinned SDK AOT builder and non-root chiseled runtime-dependencies image.

## Local checks

```sh
npm ci --ignore-scripts
npm run hooks
npm run check
npm run check:dotnet
npm run candidate
```

`candidate` builds the Linux Native AOT image, inspects its declared user/entry point/source label and extracts licence/provenance files from a stopped container. It never launches the application, restarts a service or runs RPC consumers. The build identity companion comes from the same independently resolved inputs supplied to compilation; it is not claimed as a runtime observation.

`test:container` and `test:worker` remain explicit local diagnostics for affected behavior when an existing native Docker/Linux environment is available. They reject CI execution. `test:artifact` is a separate local packaging investigation; normal source checks do not rebuild candidates for adversarial archive tests. Do not run these commands as routine PR or post-merge gates.

## Windows and WSL

Source checks work in Windows PowerShell. Use a native Docker CLI where available. No automatic WSL wrapper is supported. If a Linux environment is required, use a directly available WSL terminal; do not invoke wsl.exe, reinstall tools or introduce a proxy for validation. Hosted Linux compilation remains available without local Docker.

`npm run dev` uses source and the Dockerfile in an existing suitable local environment. It supplies complete source/build arguments from the checkout. It is an explicit development command, not a CI validation step. See [validation policy](validation-policy.md).

## Protocol and limits

| Boundary       | Behavior                                                                                                                                                              |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public API     | `POST /api/arcforges.hello.v1.HelloService/SayHello`; binary `application/grpc-web+proto` or `application/grpc-web`, media type case-insensitive, parameters accepted |
| Health         | `GET /api/healthz`, compiled source revision and Native AOT flag                                                                                                      |
| Name           | Nonempty, preserved verbatim; at most 256 UTF-16 code units                                                                                                           |
| Invalid input  | Empty: gRPC `INVALID_ARGUMENT`; too long: `RESOURCE_EXHAUSTED`                                                                                                        |
| Ingress        | 4096 body bytes; five-second body read; unsupported content encoding/type rejected                                                                                    |
| Deadline       | Smaller of caller `grpc-timeout` and ten seconds, including body read, startup and complete unary response; health fifteen seconds                                    |
| Deadline error | Malformed header: gRPC `INVALID_ARGUMENT`; expired budget: `DEADLINE_EXCEEDED`; caller abort: `CANCELED`. No retry.                                                   |
| Response       | Unary response buffered up to 8192 bytes, including gRPC-Web terminal status; stalled/oversized upstream responses cannot keep ingress open indefinitely              |
| Exposure       | Unknown path 404, unsupported verb 405, unsupported content type 415, oversized body 413                                                                              |
| Rate           | 60 requests/minute/IP/location, including health; not a global billing quota                                                                                          |
| Instance       | One fixed name, maximum one lite container, 60-second idle shutdown, no outbound internet                                                                             |
| Credentials    | Worker discards incoming cookies/authorization; Hello never uses an authenticated identity                                                                            |

The schema remains authoritative for the Hello example. Limits are explicit hosting constraints, not new product business rules. Do not use this anonymous diagnostic as an authenticated client/session template. Application/deadline errors use HTTP 200 with a gRPC-Web status frame. Boundary HTTP errors (404/405/413/415/429/503) are transport failures; clients must not treat them as protobuf success. ASP.NET can return the default protobuf media type `application/grpc-web`. Compression, JSON, base64 text and public native gRPC remain unsupported; port 8081 still provides native gRPC for direct integration.

Early rejection disposes any unread upload through `waitUntil`, capped at 4097 bytes and one second, then cancels it. This cleanup does not delay the error response, extend the RPC budget, or call a container. The immutable bundle is tested with `no_bundle`: source-mode Wrangler injects its own request-body draining middleware and can otherwise hide connection reuse failures.

## Tool updates

Central package versions and project locks must move together. Keep SDK/base-image patches aligned deliberately; a Dependabot SDK PR alone does not automatically update Docker. Review exact Contracts versions across C# and TypeScript together. Never disable locks or add broad checksum trust rules to fix CI. CI blocks compatibility or AOT regressions.
