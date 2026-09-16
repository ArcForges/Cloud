# Development and validation

## Layout

- `src/ArcForges.Cloud`: ASP.NET Core slim host, generated gRPC service implementation and source-generated health JSON.
- `tests/ArcForges.Cloud.Tests`: C# behavior tests using xUnit v3 and Microsoft.Testing.Platform.
- `tests/ArcForges.Cloud.Consumer`: separately referenced, published C# client verifying native HTTP/2 against the running image.
- `tests/kotlin-consumer`: JVM verification application using the published Maven Central Connect-Kotlin client. No proto generation or sibling sources.
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
npm run check:kotlin
npm run candidate
npm run test:worker
```

Install JDK 17 and set `JAVA_HOME` before `check:kotlin`. The verification project uses Kotlin 2.4.20, JVM 17 bytecode and the checksum-pinned Gradle 9.7.1 wrapper. This does not change Mobile's toolchain. Maven Central is the only dependency repository for the application; strict locks and verification metadata are committed. C#, TypeScript and Kotlin consume Contracts `1.0.0-ci.36.1`.

`check:kotlin` builds the consumer and runs a local fault fixture for deadlines before response headers and during a stalled body. The fixture is not server evidence. `candidate` builds Linux x64 Native AOT, runs the final image with a read-only filesystem and dropped capabilities, validates all three published clients, checks `nativeAot: true`, restarts the container and retests, including Kotlin. Docker allocates ephemeral localhost ports. The evidence is written to `artifacts/container-evidence.json` and `artifacts/kotlin-*-evidence.json`; candidate bytes and hashes are in `artifacts/candidate`.

The host binds HTTP/1.1 gRPC-Web/health to 8080 and native HTTP/2 gRPC to 8081. Only 8080 is forwarded through the public Worker. A direct development run with `dotnet run --project src/ArcForges.Cloud` is JIT and reports `nativeAot: false`; it does not satisfy the image acceptance gate.

`test:worker` runs Wrangler locally with the candidate bundle and a FROM-only image wrapper around the tested image. It does not compile source again. TypeScript and Kotlin verify real Worker → Durable Object → Docker → gRPC-Web behavior through `/api`. Cloudflare's Linux CI runner supports this without an account/token. The bundled Worker and image remain the publication inputs; the local wrapper is test-only.

## Windows and WSL

Source checks work in Windows PowerShell. If Docker is exposed only through `wsl -e docker`, set `$env:CLOUD_DOCKER_WSL = '1'` before `npm run candidate`. This affects the tooling's Docker invocation only; a native Docker Desktop CLI does not need it.

Wrangler currently rejects local Containers development on Windows. Run `npm run test:worker` in a Linux/WSL checkout with Linux Node and Docker, or use the mandatory Linux CI job. Do not reuse Windows `node_modules` in Linux; restore dependencies with `npm ci --ignore-scripts` in that checkout. Do not claim Windows router unit tests are Container binding verification.

`npm run dev` uses the source Worker and Dockerfile on Linux/WSL. The Dockerfile defaults to the development revision `local`; normal candidates inject the Git revision automatically. This development default is not accepted for deployment.

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

## Kotlin and current live verification

Use Maven dependency `io.github.arcforges:contracts-connect-client:1.0.0-ci.36.1`, Connect-Kotlin OkHttp and Java-lite serialization 0.9.0, and explicitly select `NetworkProtocol.GRPC_WEB`. The production base URL is `https://arcforges.com/api`; direct local container tests use `http://127.0.0.1:<port>` without `/api`. Do not use the default Connect protocol against this ASP.NET gRPC service.

After `npm run check:kotlin`, run `npm run test:kotlin:live` to call the current deployed Hello without a deployment token. It records the observed deployed revision, checks Native AOT and Worker identity, then checks six real SDK calls: success, Unicode, whitespace, 256-character boundary, empty-name `INVALID_ARGUMENT`, and 257-character `RESOURCE_EXHAUSTED`. It also verifies request path, binary Content-Type, emitted timeout, response media type, and terminal statuses. There is no automatic RPC retry. `artifacts/kotlin-current-live-evidence.json` describes the running deployment, not unmerged changes. Main's separate `test:live` requires the newly deployed candidate revision and also tests normalized media types and deadline rejection.

This JVM client proves the same published transport works with Cloud. Android device, UI, lifecycle and network-security configuration remain Mobile acceptance work.

## Tool updates

Central package versions and project locks must move together. Keep SDK/base-image patches aligned deliberately; a Dependabot SDK PR alone does not automatically update Docker. Review exact Contracts versions across C#, TypeScript and Kotlin together. After a deliberate Kotlin dependency change, run `tests/kotlin-consumer/gradlew -p tests/kotlin-consumer --write-locks --write-verification-metadata sha256 resolveDependencies check installDist` with an empty `GRADLE_USER_HOME` under ignored `artifacts/`. A warm cache can omit plugin BOM metadata needed on fresh CI runners. Review the new coordinates/hashes, then rerun `npm run check:kotlin` with strict verification. Never disable locks or add broad checksum trust rules to fix CI. CI blocks compatibility or AOT regressions.
