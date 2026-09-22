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
```

Install JDK 17 and set `JAVA_HOME` before `check:kotlin`. The verification project uses Kotlin 2.4.20, JVM 17 bytecode and the checksum-pinned Gradle 9.7.1 wrapper. This does not change Mobile's toolchain. Maven Central is the only dependency repository for the application; strict locks and verification metadata are committed. C# and TypeScript consume Contracts `1.0.0-ci.74.1`; the Kotlin verification client independently pins `1.0.0-ci.42.1`. Package build numbers may differ while the declared Hello v1 schema and descriptor remain compatible.

`check:kotlin` compiles the consumer and prepares its distribution without executing it. The loopback deadline fixture is available only as an explicit local `deadlineTest` Gradle task and rejects CI. `candidate` builds the Linux Native AOT image, inspects its declared user/entry point/source label and extracts licence/provenance files from a stopped container. It never launches the application, restarts a service or runs RPC consumers. The build identity companion comes from the same independently resolved inputs supplied to compilation; it is not claimed as a runtime observation.

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

## Optional local Kotlin runtime diagnostics

Use Maven dependency `io.github.arcforges:contracts-connect-client:1.0.0-ci.42.1`, Connect-Kotlin OkHttp and Java-lite serialization 0.9.0, and explicitly select `NetworkProtocol.GRPC_WEB`. The production base URL is `https://arcforges.com/api`; direct local container tests use `http://127.0.0.1:<port>` without `/api`. Do not use the default Connect protocol against this ASP.NET gRPC service.

Only when the changed behavior needs a live local diagnostic, after `npm run check:kotlin`, explicitly run `npm run test:kotlin:live` to call the current deployed Hello without a deployment token. It records the observed deployed revision, checks Native AOT and Worker identity, then checks six real SDK calls: success, Unicode, whitespace, 256-character boundary, empty-name `INVALID_ARGUMENT`, and 257-character `RESOURCE_EXHAUSTED`. It also verifies request path, binary Content-Type, emitted timeout, response media type, and terminal statuses. There is no automatic RPC retry. `artifacts/kotlin-current-live-evidence.json` describes the running deployment, not unmerged changes. `test:live` is also local opt-in and never a CI or publication requirement.

This JVM client proves the same published transport works with Cloud. Android device, UI, lifecycle and network-security configuration remain Mobile acceptance work.

## Tool updates

Central package versions and project locks must move together. Keep SDK/base-image patches aligned deliberately; a Dependabot SDK PR alone does not automatically update Docker. Review exact Contracts versions across C#, TypeScript and Kotlin together. After a deliberate Kotlin dependency change, run `tests/kotlin-consumer/gradlew -p tests/kotlin-consumer --write-locks --write-verification-metadata sha256 resolveDependencies check installDist` with an empty `GRADLE_USER_HOME` under ignored `artifacts/`. A warm cache can omit plugin BOM metadata needed on fresh CI runners. Review the new coordinates/hashes, then rerun `npm run check:kotlin` with strict verification. Never disable locks or add broad checksum trust rules to fix CI. CI blocks compatibility or AOT regressions.

## Reproducible Java selection

CI selects the reviewed Temurin patch from `.java-version`, rather than a moving major-version selector. Keep the existing JVM bytecode target and strict Gradle locks/checksum verification. Local checks record the actual installed JDK; only the matching pinned hosted producer run establishes the candidate toolchain identity. Dependency resolution can be repeated with `--offline` after fetching the complete locked cache. An unavailable cache entry fails instead of silently downloading during that repeat.
