# ArcForges center (Go)

The center is the Go service of [AD-0021](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0021-central-access-go-center.md):
one executable, `arcforges-center`, built from the `center/` Go module (`github.com/ArcForges/Cloud/center`). It replaces the
bounded Go Hello proof ([go-hello](go-hello.md), now history) and is the runtime the production Worker selects. AF-CTR-02 delivered
it in two parts:

- **Part A (this document):** the executable, the ingress compatibility with the Worker and the C# host, the explicit center
  mode, configuration, health, readiness, logs and metrics, the Worker's production table generated from the center's
  registrations, and the Go engineering controls ([engineering controls](engineering-controls.md)).
- **Part B ([PostgreSQL store](postgres-store.md)):** the store, its migrations and platform tables, the roles, the
  `migrate` and `admin` commands, the deployment's PostgreSQL step and runtime credential rotation, the acceptance environment
  and the recovery procedure.

The C# Native AOT host stays in the same image as its default entrypoint: setting `ARCFORGES_HELLO_RUNTIME=csharp` through a
reviewed main push is the Hello rollback (AD-0021 §15, until AF-CTR-09). The `proof` environment (proof.arcforges.com) runs the
Go center as the acceptance environment since part B.

## Layout

| Path                           | Contents                                                                                                                                                                                                                            |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `center/cmd/arcforges-center`  | The executable: `serve` (default), `migrate [apply\|status\|plan]`, `admin ensure-database`, `admin rotate-runtime-credential [--live-slot a\|b]`, `admin confirm-runtime-credential --slot a\|b`, `version`/`--build-info`, `help` |
| `center/cmd/center-gen`        | Development generator (never in the image): `worker-tables` writes `worker/tables/center-tables.generated.ts`                                                                                                                       |
| `center/internal/config`       | Environment configuration, refused when missing or invalid; the public base URL and database URL parsers                                                                                                                            |
| `center/internal/ingress`      | The admission pipeline: policy registry, framing, envelope reader, credential shapes, owner gate, refusals and their status                                                                                                         |
| `center/internal/correlation`  | Correlation identity and the strict W3C `traceparent` parser                                                                                                                                                                        |
| `center/internal/routes`       | The center's registrations: methods with policies, plain routes and the Worker's transport budgets                                                                                                                                  |
| `center/internal/workertables` | Rendering of the Worker's production table from the registrations                                                                                                                                                                   |
| `center/internal/hello`        | The anonymous Hello (`arcforges.hello.v1`), stateless or read from PostgreSQL                                                                                                                                                       |
| `center/internal/schema`       | The embedded migrations and the runtime role's grants ([PostgreSQL store](postgres-store.md))                                                                                                                                       |
| `center/internal/store`        | The runtime store: transactions, retries, sanitized errors; `store/migrate` is the migration runner                                                                                                                                 |
| `center/internal/platform`     | Command receipts, inbox, outbox and publisher, job leases, the audit chain and signing-key metadata                                                                                                                                 |
| `center/internal/provision`    | Database creation and the runtime credential rotation                                                                                                                                                                               |
| `center/internal/pgtest`       | Integration test support: an isolated database on a real PostgreSQL                                                                                                                                                                 |
| `center/internal/feature`      | The feature gate of AD-0021 §13a (a fail-closed stub until AF-CTR-03)                                                                                                                                                               |
| `center/internal/buildinfo`    | The compiled build identity and the health document                                                                                                                                                                                 |
| `center/internal/observe`      | JSON logging and request metrics                                                                                                                                                                                                    |
| `center/internal/server`       | Composition, listeners, readiness, metrics exposition and graceful shutdown                                                                                                                                                         |
| `center/tools`                 | A separate, never shipped module that pins staticcheck and govulncheck as Go `tool` dependencies                                                                                                                                    |

The bindings come from the published Contracts Go module `github.com/ArcForges/Contracts/go` at exactly `v1.0.0-ci.410.1`
(tag `go/v1.0.0-ci.410.1`, Contracts commit `7205743`, the cohort of the NuGet packages `1.0.0-ci.410.1`), fetched through the
public module proxy and verified by `go.sum` and the checksum database. No wire code is generated or written here.

## Request path

```text
client (published C# gRPC-Web client, Web)
  → arcforges-cloud Worker (/api/*; deny-by-default table from center-tables.generated.ts, edge limits, traceparent)
  → Cloudflare Container :8080 (/app/arcforges-center, official-hosted)
  → ingress pipeline (canonical path, policy, media type, credentials, body bound, envelope, correlation)
  → Connect handler (binary gRPC-Web or gRPC) → Hello → (Neon read-only transaction when enabled)

self-hosted client → arcforges-center serve (HTTP/1.1 + h2c on the configured address; the same pipeline and routes)
```

The Worker strips the `/api` prefix it owns; the center serves the method paths and `/healthz` at its root. A self-hosted center
that is published under a path prefix sits behind a proxy that removes it, exactly as the Worker does.

## Configuration

Every value is an environment variable. A missing or invalid value refuses to start with one JSON log line that names the
variable and never repeats its value.

| Variable                                | Default  | Rule                                                                                                                                                                                                                    |
| --------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ARCFORGES_CENTER_MODE`                 | none     | Required: `official-hosted` or `self-hosted` exactly                                                                                                                                                                    |
| `ARCFORGES_CENTER_PUBLIC_BASE_URL`      | none     | Required: canonical absolute `https` URL (lowercase host, optional port and path, no trailing slash, query, fragment or user); `http` only for a loopback host in self-hosted mode                                      |
| `ARCFORGES_CENTER_HTTP_ADDRESS`         | `:8080`  | HTTP/1.1 and h2c listener; `host:port` with an IP literal, `localhost` or no host                                                                                                                                       |
| `ARCFORGES_CENTER_GRPC_ADDRESS`         | `:8081`  | h2c-only listener; `off` disables it                                                                                                                                                                                    |
| `ARCFORGES_CENTER_ADMIN_ADDRESS`        | disabled | Readiness (`/readyz`) and metrics (`/metrics`); must be a loopback address in official-hosted mode                                                                                                                      |
| `ARCFORGES_CENTER_MAX_CONNECTIONS`      | `64`     | Concurrent connections per listener, 1 to 4096                                                                                                                                                                          |
| `ARCFORGES_CENTER_LOG_LEVEL`            | `info`   | `debug`, `info`, `warn` or `error`                                                                                                                                                                                      |
| `ARCFORGES_CENTER_METRICS_LOG_INTERVAL` | `1m`     | The periodic metrics log line; `0` disables it, otherwise 10 s to 1 h                                                                                                                                                   |
| `ARCFORGES_CENTER_PLAN_CONFIGURATION`   | none     | Official-hosted only: empty (production until AF-PROD-01: no gated feature) or `development-fixtures` (the acceptance environment); never `development-fixtures` in production (`tests/worker/proof-deploy.test.ts`)    |
| `ARCFORGES_NEON_HELLO`                  | disabled | `enabled` reads the Hello greeting from PostgreSQL: through the runtime role when `ARCFORGES_CENTER_DATABASE_URL` is set, otherwise through `NEON_DATABASE_URL`                                                         |
| `NEON_DATABASE_URL`                     | none     | With the Neon Hello and no store: a complete pooled Neon URL with `sslmode` and `channel_binding=require`; pool of two, exec query mode; `application_name` `arcforges-center` (the Go Hello sent `arcforges-go-hello`) |
| `ARCFORGES_CENTER_DATABASE_URL`         | none     | The runtime role's pooled URL of the store (a login role of the runtime group; [PostgreSQL store](postgres-store.md)); verified TLS with channel binding, except a loopback host of a self-hosted center                |
| `ARCFORGES_CENTER_DATABASE_MAX_CONNS`   | `4`      | Pool size of the runtime database, 1 to 32                                                                                                                                                                              |

The `migrate` and `admin` commands read their own variables (`ARCFORGES_CENTER_MIGRATION_DATABASE_URL`, the migration role's
direct URL; `ARCFORGES_CENTER_DATABASE_NAME`; `ARCFORGES_CENTER_RUNTIME_ROLE`; `ARCFORGES_CENTER_RUNTIME_SECRET_FILE`;
`ARCFORGES_CENTER_RUNTIME_POOLED_HOST`; `ARCFORGES_CENTER_MIGRATION_LOCK_TIMEOUT`); `serve` never reads them
([PostgreSQL store](postgres-store.md)). No URL of the official deployment is compiled
into a code path: `TestNoOfficialEndpointIsCompiledIn` fails if one appears, and health and every URL the center issues derive
from `ARCFORGES_CENTER_PUBLIC_BASE_URL`. The production deployment states its values in `wrangler.json`
(`ARCFORGES_CENTER_MODE=official-hosted`, `ARCFORGES_CENTER_PUBLIC_BASE_URL=https://arcforges.com/api`), which
`worker/foundation/cloud-container.ts` passes to the Container unchanged.

## Center mode and feature availability

The mode is explicit configuration (AD-0021 §13a); there is no default. `internal/feature` answers feature availability behind
the interface the plan resolver of AF-CTR-03 will implement:

| Mode              | Gated features (`center.nodes`, `center.execute`, `remote.view`, `remote.control`, `center.mcp`, `push`)  | Unknown key |
| ----------------- | --------------------------------------------------------------------------------------------------------- | ----------- |
| `official-hosted` | unavailable (`plan_configuration_missing`): no plan configuration exists yet, so nothing gated is enabled | unavailable |
| `self-hosted`     | available (`self_hosted_default`): the built-in default                                                   | unavailable |
| anything else     | the center does not start                                                                                 | —           |

Hello, health, readiness and metrics are not gated features. Availability is one more check after authentication, ownership,
authorization, AGENT/HUMAN separation, audit and resource controls and never replaces them.

## Self-hosted mode

```sh
cd center
go build -trimpath -o arcforges-center ./cmd/arcforges-center
ARCFORGES_CENTER_MODE=self-hosted \
ARCFORGES_CENTER_PUBLIC_BASE_URL=https://center.example.org \
ARCFORGES_CENTER_HTTP_ADDRESS=0.0.0.0:8080 \
ARCFORGES_CENTER_ADMIN_ADDRESS=127.0.0.1:9090 \
./arcforges-center serve
```

The same routes, pipeline and health document are served without the Worker. TLS is terminated by the operator's proxy;
`http` base URLs are accepted only for a loopback host. `python eng/center.py check` starts the built executable this way on an
ephemeral loopback port on both verification hosts, checks health and an `UNIMPLEMENTED` refusal, refuses a start without a mode,
and (on Linux) checks the graceful shutdown on `SIGTERM`.

## Ingress compatibility

The pipeline ports the host-side admission of the C# `IngressPipeline` (`src/ArcForges.Cloud/Ingress`) for the methods the
center serves, in the same order:

1. **Canonical target.** The raw request target must equal the decoded path: no percent-encoding, dot or empty segment, trailing
   slash, backslash or absolute-form target; otherwise plain `404`.
2. **Plain routes** (`/healthz`) go to their handler. A path shaped like `/package.Service/Method` is admitted below; any other
   path is plain `404`.
3. **Method.** Only `POST` (else plain `405`). A method without a registered policy is the trailers-only `UNIMPLEMENTED` refusal.
4. **Media.** Binary gRPC-Web (`application/grpc-web`, `application/grpc-web+proto`), as the C# host admitted, and binary gRPC
   (`application/grpc`, `application/grpc+proto`) for direct clients of a self-hosted center and the gRPC listener; no
   `content-encoding`, and `grpc-encoding` absent or `identity`. Anything else (JSON or text codecs, the Connect protocol) is plain
   `415`. Admitting native gRPC is the one widening against the C# host, which the Worker never reaches (it forwards gRPC-Web only).
5. **Credentials** of a `session` method: a bearer and a session cookie together are `UNAUTHENTICATED`; a bearer must be exactly
   one `Bearer` value of 16 to 4096 token characters and validate as a native bearer; a cookie (`__Host-af_session`, exactly once)
   needs exactly one `Origin` equal to the allowed origin (else `PERMISSION_DENIED`), a valid session and that session's
   `X-AF-CSRF` token (else `PERMISSION_DENIED`). A store that cannot be reached is `UNAVAILABLE dependency.unavailable`. No
   verifier is registered in part A, so every session method would be `UNAUTHENTICATED`; AF-CTR-03 registers them.
6. **Body bound.** A declared length over the method's bound is `RESOURCE_EXHAUSTED validation.invalid_request` before any byte is
   read; the reader stops at the bound for the others.
7. **Envelope** of a method that reads `RequestMeta` (workspace-scoped, or declared to carry one): exactly one data frame of the
   declared length, then the strict reader of `RequestMeta` (no repeated meta, workspace, generation or correlation id, `Id`
   values of exactly 16 nonzero bytes, no groups or truncation); anything else is `INVALID_ARGUMENT validation.invalid_request`.
   A workspace-scoped method then needs a workspace the caller owns (`PERMISSION_DENIED`) in the caller's recovery generation
   (`FAILED_PRECONDITION state.stale_generation`).
8. **Correlation.** One identity per call: the validated envelope value, else the trace id of the Worker's `traceparent` (strict
   W3C version 00, lowercase, nonzero ids, exactly one header), else a new UUID. A `traceparent` of another trace is not a parent.
   The identity is bound after every decision above and read by none of them; handlers return it in `ResponseMeta` (tag 4) and
   `ArcError` (tag 6).
9. Admitted replies carry `cache-control: no-store` and `x-content-type-options: nosniff`.

`center/internal/ingress` has a test for every rule, and the envelope reader and the `traceparent` parser are fuzz targets.

## ArcError and gRPC status

The design has no table from an `ArcError` category to a gRPC code, and neither the C# Cloud host nor DesktopPlatform's
LocalRpc keeps one: LocalRpc and the C# proof methods return a domain refusal as gRPC `OK` with the `ArcError` in the reply
message. The C# `IngressPipeline` produces a closed set of transport refusals, each a fixed pair of status and registry code. The
center ports both exactly (`center/internal/ingress/errors.go`, `TestTheRefusalTableIsTheHostTable`):

| Refusal (grpc-message)                | gRPC status             | ArcError category   | When                                                                         |
| ------------------------------------- | ----------------------- | ------------------- | ---------------------------------------------------------------------------- |
| `unimplemented`                       | 12 `UNIMPLEMENTED`      | — (not an ArcError) | a method-shaped path without a registered policy                             |
| `auth.unauthenticated`                | 16 `UNAUTHENTICATED`    | `AUTHENTICATION`    | missing, malformed, unknown or conflicting credential                        |
| `perm.resource_denied`                | 7 `PERMISSION_DENIED`   | `AUTHORIZATION`     | wrong Origin or CSRF token, or a workspace the caller does not own           |
| `validation.invalid_request`          | 3 `INVALID_ARGUMENT`    | `VALIDATION`        | malformed frame or envelope, including a malformed correlation id            |
| `validation.invalid_request`          | 8 `RESOURCE_EXHAUSTED`  | `VALIDATION`        | request body over the method's bound                                         |
| `state.stale_generation`              | 9 `FAILED_PRECONDITION` | `STATE`             | envelope recovery generation differs from the caller's session               |
| `dependency.unavailable`              | 14 `UNAVAILABLE`        | `EXECUTION`         | a credential store could not be reached                                      |
| any other `ArcError` (domain refusal) | 0 `OK`                  | its own category    | after admission: the `ArcError` in the reply, with the call's correlation id |

A transport refusal is trailers-only: to binary gRPC-Web it is HTTP 200 with one trailer frame, byte for byte the C# host's
(`grpc-status: N\r\ngrpc-message: <code>\r\n`, the message percent-encoded as .NET's `Uri.EscapeDataString`); to native gRPC it
is the trailers-only `HEADERS` of gRPC over HTTP/2. It has no reply message and therefore no correlation id. The Hello keeps its
own statuses: `INVALID_ARGUMENT` ("Name must not be empty."), `RESOURCE_EXHAUSTED` ("Name exceeds 256 UTF-16 code units."),
`UNAVAILABLE` ("Hello database unavailable."), `DEADLINE_EXCEEDED` and `CANCELED`. The Worker produces its own edge statuses
(`CANCELED`, `INVALID_ARGUMENT`, `DEADLINE_EXCEEDED`, `PERMISSION_DENIED`, `UNAVAILABLE`, `UNAUTHENTICATED`;
[cloud-ingress](cloud-ingress.md)). The Design records this mapping in a companion change of `contracts/errors.md`.

Signatures and request digests always cover the bytes as transmitted, never a re-encoding (AD-0021 §10): the Go and C# protobuf
encoders order `oneof` fields differently, so a verifier must never re-encode a decoded message.

## Worker table authority

The Worker's production method table, its health route and their transport budgets (`helloPath`, `healthPath`, `maxBodyBytes`,
`coldStartBudgetMs`, `streamLifetimeMs`, `healthRoute`, `productionRoutes`) are generated from the center's registrations
(`center/internal/routes`) into `worker/tables/center-tables.generated.ts`, together with the `ApiRoute` type. The center's
ingress registry is built from the same registrations, so a method cannot be served without its Worker row or the reverse; the
generator refuses a method without a budget, a budget without a method, a second plain route and a body bound other than the
Hello's. `python eng/center.py generate` writes the file; `TestCommittedWorkerTablesAreCurrent` (part of `go test`, both legs)
and `go run ./cmd/center-gen worker-tables -check` fail on any drift, the Go counterpart of `npm run check:generated`.

The proof environment stays C# until AF-CTR-09: its methods, the edge guard, the correlation and storage guards, the readiness
vocabulary and the wire limits are still generated from C# into `worker/tables/cloud-tables.generated.ts`, which imports the
`ApiRoute` type from the center's module. The C# `HelloModule` registration stays for the rollback host, and
`GeneratedTablesTests.TheGoCenterProductionTableEqualsTheCSharpRegistrations` checks that the Go module carries byte for byte
the production rows the C# generator wrote before the split, so switching the runtime changes no Worker behaviour. Both
generated modules are excluded from the WorkerAdapter literal check, which keeps refusing any business literal in the
hand-written Worker sources.

## Health, readiness, logs and metrics

`GET /healthz` returns the health document; it never touches a database:

```json
{
  "service": "arcforges-cloud",
  "revision": "<commit>[-dirty]",
  "nativeAot": false,
  "runtime": "go",
  "helloBackend": "stateless | postgresql-runtime | neon-postgresql",
  "artifact": { "id": "Cloud", "version": "0.1.0-ci.<run>.<attempt>" },
  "build": {
    "sourceCommit": "…",
    "dirty": false,
    "kind": "ci",
    "buildId": "…",
    "runId": "…",
    "runAttempt": 1,
    "pipelineRun": "…",
    "sourceDateEpoch": 0
  },
  "center": {
    "binary": "arcforges-center",
    "mode": "official-hosted",
    "publicBaseUrl": "https://…"
  }
}
```

Go is compiled native code but not .NET Native AOT, so `nativeAot` is false. The build identity is set with `-ldflags -X` from
the same inputs as the C# executable's (`tooling/build-identity.ts`), and the release tooling compares `artifact` and `build`
with the candidate. `arcforges-center version` prints the same document with `helloBackend` `not-probed` and no mode.

Readiness is separate from health. `GET /readyz` on the admin listener answers `200` with `{"status":"ready","components":{…}}`
when every configured database answers a ping within two seconds (`helloDatabase`, `database`) and the store's schema carries
every migration of this build exactly (`databaseSchema`), and `503` with `unavailable` otherwise. `GET /metrics` on the same
listener exposes the Prometheus text format: `arcforges_center_requests_total{method,code}`,
`arcforges_center_request_duration_seconds{method}` (histogram), `arcforges_center_refusals_total{code,category}` and the
database pool and schema metrics of the [PostgreSQL store](postgres-store.md#observability-and-alert-conditions). Labels are closed values: a registered method path or `plain`,
`unregistered`, `not_found`; a gRPC code name or `http_<status>`; a registry code and an `ArcError` category. The admin
listener is not configured in the hosted Container, so production adds no route; there the metrics reach the operator as the
periodic `metrics` log line, which the Container's logs carry.

Logs are JSON lines (`log/slog`) with `service=arcforges-center`. A request line holds the method label, the outcome code, the
duration, the correlation id of an admitted call and the refusal code and category; it never holds a header value, a credential,
a request or response body, a command line, output or file content. A configuration error names the variable only.

## Hosted deployment

`worker/foundation/cloud-container.ts` selects `/app/arcforges-center` when `ARCFORGES_HELLO_RUNTIME=go` and passes the center
mode, base URL and plan configuration, and the runtime role's URL (the Worker secret `ARCFORGES_CENTER_DATABASE_URL` that the
deployment rotates; [PostgreSQL store](postgres-store.md#deployment)). The Hello's own Neon secret reaches only the C# host or a
Go center without a store (`tooling/neon-runtime.ts`). The Dockerfile builds the
center with the pinned Go archive (`center/toolchain.json`, SHA-256 checked), `go mod verify`, `CGO_ENABLED=0`, `-trimpath`,
`-buildvcs=false` and the identity `-ldflags`, beside the C# executable, which stays the image's default entrypoint. The
candidate inspects both ELF members and their legal files without running them (`tooling/release-provenance.ts`).

Structural cost bounds of the production deployment, enforced by configuration:

| Bound               | Value                                                           | Where                                                                                                   |
| ------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Container instances | `max_instances: 1`, `instance_type: lite`                       | `wrangler.json` (checked by the candidate)                                                              |
| Idle stop           | `sleepAfter` 60 s                                               | generated `containerSleepAfter`                                                                         |
| Worker CPU          | `cpu_ms: 50`                                                    | `wrangler.json`                                                                                         |
| Public rate limit   | 60 requests per 60 s                                            | `HELLO_RATE_LIMITER` in `wrangler.json`                                                                 |
| Center connections  | 64 per listener                                                 | `ARCFORGES_CENTER_MAX_CONNECTIONS` default                                                              |
| Hello database      | pool of 2, 5 s statement timeout, 15 s call                     | `internal/config`, `internal/hello`                                                                     |
| Runtime database    | pool of 4 (1 to 32); login roles limited to 16 connections each | `ARCFORGES_CENTER_DATABASE_MAX_CONNS` default; [PostgreSQL store](postgres-store.md#connection-budgets) |

While a node is connected (AF-CTR-05 onward) the one instance stays running; that always-on worst case is one `lite` instance
per deployment, which AF-PLAT-01's budgets take as the bound.

## Verification

`python eng/center.py check` is the one entry point of both verification legs (`win-center`, `linux-center` in
`eng/verify_steps.py`) and of hosted CI for external PRs; [engineering controls](engineering-controls.md) lists every control,
its stage and its evidence. The published C# client's exchange is covered offline by the protocol tests of
`center/internal/server` (greeting, Unicode, NUL, empty and oversized names, statuses and trailers over gRPC and binary
gRPC-Web, and the probe's raw HTTP/1.1 exchange). Two local opt-in diagnostics (never CI, not gates) start the sealed candidate
image: `npm run test:container` runs `/app/arcforges-center` as the Container does (the mode and public base URL of
`wrangler.json`, a read-only filesystem, no capabilities, `no-new-privileges`, 256 MiB) and checks its build identity, the health
identity and `center` block, the published C# gRPC-Web probe, the published native gRPC Consumer and a clean stop on `SIGTERM`;
`npm run test:worker` runs the same executable behind the real Worker bundle.
