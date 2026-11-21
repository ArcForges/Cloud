# Development and validation

## Layout

- `center/` contains the Go Center, its registered routes and the PostgreSQL store. [Center](center.md) · [PostgreSQL store](postgres-store.md)
- `worker/` contains the Cloudflare Container adapter, ingress and generated route tables. `tests/worker/` contains the offline boundary and proof fixtures.
- `Cloud.slnx` contains exactly two managed verification projects. `tests/ArcForges.Cloud.Consumer` exercises the published NuGet client against a local Center or Worker in explicit runtime diagnostics. `tests/ArchitectureTests` checks repository architecture and policy.
- `tooling/` contains candidate construction, provenance verification and the guarded deployment entry points. `Dockerfile` builds `arcforges-center` with the pinned Go toolchain and packages it as the sole application executable in a digest-pinned, non-root runtime image.

## Local checks

```sh
npm ci --ignore-scripts
npm run check
npm run check:dotnet
python eng/center.py check
```

Choose the commands relevant to the change. The Linux leg runs `npm run candidate` in its native Docker Engine. The candidate builds the Go image and the Worker bundles, checks the image user, entry point and source label, and reads the licence and provenance files from a stopped container. Its build identity records the inputs resolved for compilation. Candidate acceptance inspects the sealed artifacts without runtime execution.

`test:container` and `test:worker` are local opt-in runtime diagnostics for an existing native Linux Docker environment. They refuse CI execution. The Linux verification leg runs `npm run test:artifact` as `worker-provenance` to compare locked Wrangler output with the approved Worker closure and exercise the verifier's rejection cases. The hosted candidate independently verifies its own output. [Validation policy](validation-policy.md)

## Windows and Linux

After a push, fetch the exact GitHub commit independently on the designated Windows workstation and native Linux host. Use an isolated worktree on each host's native filesystem. In Windows PowerShell and in the Linux host's SSH session, run the same command:

```sh
python eng/verify.py run-and-report
```

The verifier selects the host's own full leg and reports `arcforges/windows` or `arcforges/linux` on the tested commit. Native Linux also runs the scoped PostgreSQL integration and restore tests and builds the Go candidate. Use the pinned tools already installed on the hosts. Preserve the logs and `summary.json`, including genuine failures. GitHub requires both native success statuses and the applicable hosted checks for external PRs. WSL and Windows-mounted Linux checkouts are outside this profile. [Verification after the push](../AGENTS.md#verification-after-the-push-ad-0020)

`npm run dev` uses source and the Dockerfile in an existing suitable local environment. It supplies complete source/build arguments from the checkout. It is an explicit development command, not a CI validation step. See [validation policy](validation-policy.md).

## Historical Cloud source

The C# Center, generator, D1 migration CLI and managed executor proof are preserved at Cloud commit `9b8796eac760982d9814f371b820b736ddd945c4`. Use `npm run check:legacy-cloud-history` to verify its archive and the preserved migration, plan and test inputs. The current `check:generated` verifies frozen generated outputs, and the Go checks verify the generated Go route table. Dated evidence retains its original host, revision and scope. [D1 history](d1-physical-schema.md#migrations) · [Harness proofs](harness-proofs.md)

## Anonymous Hello protocol and limits

This example documents the anonymous Hello diagnostic. For the Center's registered management and account routes, see [Center](center.md).

| Boundary       | Behavior                                                                                                                                                              |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public API     | `POST /api/arcforges.hello.v1.HelloService/SayHello`; binary `application/grpc-web+proto` or `application/grpc-web`, media type case-insensitive, parameters accepted |
| Health         | `GET /api/healthz`, compiled source revision, `runtime=go` and `nativeAot=false`                                                                                      |
| Name           | Nonempty, preserved verbatim; at most 256 UTF-16 code units                                                                                                           |
| Invalid input  | Empty: gRPC `INVALID_ARGUMENT`; too long: `RESOURCE_EXHAUSTED`                                                                                                        |
| Ingress        | 4096 body bytes; five-second body read; unsupported content encoding/type rejected                                                                                    |
| Deadline       | Smaller of caller `grpc-timeout` and ten seconds, including body read, startup and complete unary response; health fifteen seconds                                    |
| Deadline error | Malformed header: gRPC `INVALID_ARGUMENT`; expired budget: `DEADLINE_EXCEEDED`; caller abort: `CANCELED`. No retry.                                                   |
| Response       | Unary response buffered up to 8192 bytes, including gRPC-Web terminal status; stalled/oversized upstream responses cannot keep ingress open indefinitely              |
| Exposure       | Unknown path 404, unsupported verb 405, unsupported content type 415, oversized body 413                                                                              |
| Rate           | 60 requests/minute/IP/location, including health; not a global billing quota                                                                                          |
| Instance       | One fixed name, maximum one lite container and 60-second idle shutdown                                                                                                |
| Credentials    | Worker discards incoming cookies/authorization; Hello never uses an authenticated identity                                                                            |

Use the published Hello schema and its binary gRPC-Web media types for this diagnostic. Application and deadline errors use HTTP 200 with a gRPC-Web status frame. Treat boundary HTTP errors (404/405/413/415/429/503) as transport failures. Port 8081 provides native gRPC for direct integration.

Early rejection disposes any unread upload through `waitUntil`, capped at 4097 bytes and one second, then cancels it. This cleanup does not delay the error response, extend the RPC budget, or call a container. The immutable bundle is tested with `no_bundle`: source-mode Wrangler injects its own request-body draining middleware and can otherwise hide connection reuse failures.

## Tool updates

Update managed dependency pins and per-project locks together. Review exact published contract versions for the Go module, independent NuGet consumer and Worker package. Keep the Go compiler and base-image digests explicitly pinned. Preserve the existing locked restores and checksum, licensing and provenance checks.
