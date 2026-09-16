# Development and validation

## Layout

- `src/ArcForges.Cloud`: ASP.NET Core slim host, generated gRPC service implementation and source-generated health JSON.
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
npm run test:worker
```

`candidate` builds Linux x64 Native AOT, runs the final image with a read-only filesystem and dropped capabilities, validates both published clients, checks `nativeAot: true`, restarts the container and retests. Docker allocates ephemeral localhost ports. The evidence is written to `artifacts/container-evidence.json`; candidate bytes and hashes are in `artifacts/candidate`.

The host binds HTTP/1.1 gRPC-Web/health to 8080 and native HTTP/2 gRPC to 8081. Only 8080 is forwarded through the public Worker. A direct development run with `dotnet run --project src/ArcForges.Cloud` is JIT and reports `nativeAot: false`; it does not satisfy the image acceptance gate.

`test:worker` runs Wrangler locally with the candidate bundle and a FROM-only image wrapper around the tested image. It does not compile source again. It verifies real Worker → Durable Object → Docker → gRPC-Web behavior. Cloudflare's Linux CI runner supports this without an account/token. The bundled Worker and image remain the publication inputs; the local wrapper is test-only.

## Windows and WSL

Source checks work in Windows PowerShell. If Docker is exposed only through `wsl -e docker`, set `$env:CLOUD_DOCKER_WSL = '1'` before `npm run candidate`. This affects the tooling's Docker invocation only; a native Docker Desktop CLI does not need it.

Wrangler currently rejects local Containers development on Windows. Run `npm run test:worker` in a Linux/WSL checkout with Linux Node and Docker, or use the mandatory Linux CI job. Do not reuse Windows `node_modules` in Linux; restore dependencies with `npm ci --ignore-scripts` in that checkout. Do not claim Windows router unit tests are Container binding verification.

`npm run dev` uses the source Worker and Dockerfile on Linux/WSL. The Dockerfile defaults to the development revision `local`; normal candidates inject the Git revision automatically. This development default is not accepted for deployment.

## Protocol and limits

| Boundary      | Behavior                                                                                   |
| ------------- | ------------------------------------------------------------------------------------------ |
| Public API    | `POST /api/arcforges.hello.v1.HelloService/SayHello`, binary `application/grpc-web+proto`  |
| Health        | `GET /api/healthz`, compiled source revision and Native AOT flag                           |
| Name          | Nonempty, preserved verbatim; at most 256 UTF-16 code units                                |
| Invalid input | Empty: gRPC `INVALID_ARGUMENT`; too long: `RESOURCE_EXHAUSTED`                             |
| Ingress       | 4096 body bytes; five-second body read; unsupported content encoding/type rejected         |
| Deadline      | Ten seconds for the internal RPC; fifteen-second container request/startup signal          |
| Exposure      | Unknown path 404, unsupported verb 405, unsupported content type 415, oversized body 413   |
| Rate          | 60 requests/minute/IP/location, including health; not a global billing quota               |
| Instance      | One fixed name, maximum one lite container, 60-second idle shutdown, no outbound internet  |
| Credentials   | Worker discards incoming cookies/authorization; Hello never uses an authenticated identity |

The schema remains authoritative for the Hello example. Limits are explicit hosting constraints, not new product business rules. Do not use this anonymous diagnostic as an authenticated client/session template.

## Tool updates

Central package versions and project locks must move together. Keep SDK/base-image patches aligned deliberately; a Dependabot SDK PR alone does not automatically update Docker. Exact Contracts version in C# and TypeScript must be reviewed together. CI blocks compatibility or AOT regressions.
