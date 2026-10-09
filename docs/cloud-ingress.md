# Cloud ingress pipeline

This document is the design, protocol and evidence record of the CLOUD.01 ingress and host pipeline (Design
WP-21.00). It states what the code implements, which checks run in hosted CI, which ran only as explicit local
opt-in, and what has not been observed. It does not claim any deployed result that the task record does not hold.

## Scope

WP-21.00 generalizes the Hello mechanics that the bootstrap proved at small scale into the one public boundary every
later business call crosses: Worker `/api` routing, and the C# Native AOT gRPC-Web, authentication and current-owner
pipeline behind it, in the real Container image.

| Part                       | What is implemented                                                                                                                                                                      | Where                                                                                      |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Worker method table        | Exact `/api/<package>.<Service>/<Method>` routes, deny by default; one entry per public method with its kind, authentication, bounds and Container instance                              | `worker/tables/cloud-tables.generated.ts` (generated), `worker/ingress/routes.ts` (lookup) |
| Worker admission           | Binary gRPC-Web only, no compression, no query, deadline and cancellation budget, bounded request body, rate limit, edge credential checks                                               | `worker/ingress/pipeline.ts`, `worker/ingress/edge-caller.ts`                              |
| Frame-guarded pass-through | A server stream is passed frame by frame and never buffered; a stream can never end without a gRPC status; deadline and cancellation reach the Container                                 | `worker/ingress/frames.ts`                                                                 |
| Host method policy         | Every public method declares kind, authentication, owner scope and body bound; a method without a policy is refused                                                                      | `src/ArcForges.Cloud/Ingress/RpcPolicy.cs`                                                 |
| Host admission pipeline    | Runs before the gRPC-Web adapter and any generated handler: framing, credential validation, exact Origin and CSRF, the current-owner gate                                                | `src/ArcForges.Cloud/Ingress/IngressPipeline.cs`                                           |
| Proof-only pipeline probe  | An authenticated workspace-scoped unary call, a timed server stream with a custom trailer and an observation of how the host saw its streams end; only in the isolated proof environment | `src/ArcForges.Cloud/Ingress/PipelineProbe.cs`, `worker/ingress/routes.ts` (`proofRoutes`) |
| Scenarios                  | Local cross-process and explicit opt-in deployed scenarios of the path                                                                                                                   | `eng/verification/pipeline-scenarios.ts`                                                   |

The production Worker and Container serve exactly one public method, the anonymous Hello `SayHello`, plus the plain
`/api/healthz`. No business module, identity store or bearer verifier exists yet: the pipeline is the mechanism they
register against (CLOUD.02, CLOUD.11, CLOUD.13, CLOUD.19), and a session method cannot be satisfied in production
until one of them provides a verifier. Nothing here adds authenticated, commercial or AI behavior.

## Request path

```text
client ── HTTPS ──> Worker  arcforges.com/api/*  (or the proof custom domain)
   1. exact method lookup in the route table (unknown path: 404, no Container wakes)
   2. admission: POST, binary gRPC-Web, identity encoding, no query, grpc-timeout, rate limit
   3. session methods: edge credential and Origin/CSRF-shape checks (UNAUTHENTICATED / PERMISSION_DENIED here, no Container wakes)
   4. bounded request body (one message), then a fresh private request built by the Worker
Worker ── Durable Object binding (the only path to the Container) ──> Container, Kestrel on 8080
   5. ingress pipeline: method policy, framing, credential, Origin, CSRF, current owner, body bound
   6. gRPC-Web adapter and the generated handler (or a stream handler)
Worker <── response: unary bounded and buffered, server stream frame by frame through the frame guard
```

The Container port is never published: `wrangler.json` declares no port or route for it, the only caller of the
Container binding for public requests is `handleApiRequest`, and it forwards only headers the Worker builds itself.
Everything under `/internal` and every unlisted path is answered by the Worker. A static test pins these facts.

## Worker rules

- **Method table.** `findRoute` returns a route only for an exact path; the proof-only probe methods exist only when
  `FOUNDATION_PROOF` is exactly `enabled`. The rows are generated, never hand-written: `tools/ArcForges.Cloud.Generation`
  reads the host's registrations (`HelloModule`, `PipelineProbe`) and the transport budgets in
  `src/ArcForges.Cloud/Generation/TransportBudgets.cs`, and writes `worker/tables/cloud-tables.generated.ts`. The
  generator refuses a registered method without a budget and a budget without a registered method. `npm run check:generated`
  and the C# test `GeneratedTablesTests` fail on any drift, and a C# test pins the production table to the single Hello method.
  The Worker's transport budgets and edge-guard names (the session cookie and the CSRF header) come from the same module.
- **Admission.** A non-POST is 405, a media type other than `application/grpc-web` or `application/grpc-web+proto` is
  415, `content-encoding` or a `grpc-encoding` other than identity is 415, a query string is 400, a request body over
  the method bound is 413 (declared or actual bytes), the compressed flag in the first frame is 415. A malformed
  `grpc-timeout` is `INVALID_ARGUMENT` and an expired budget is `DEADLINE_EXCEEDED`, both as trailers-only statuses.
- **Budget.** A unary call is capped at its route's `maxDurationMs` (ten seconds for the current methods) or the client's
  shorter `grpc-timeout`, minus the time spent reading the body; the remainder is forwarded to the host. A server stream
  lives at most its route's duration (or the client's shorter deadline). Client cancellation aborts the Container request.
- **Cold start.** A stream's Container start is bounded on its own (`coldStartBudgetMs`, fifteen seconds) so that a
  long stream lifetime never makes an unavailable Container wait that long; the call then fails with HTTP 503 (no retry guidance: the
  call may have reached a running Container that was slow to answer). There is no retry or replay of an application call.
- **Credentials.** Only a session method reads a credential. A bearer (`Authorization: Bearer`, 16 to 4096 token
  characters) is forwarded as given. A browser session needs the one `__Host-af_session` cookie (43 base64url
  characters), the exact configured `Origin` (`ALLOWED_ORIGIN`) and a well-formed `X-AF-CSRF` token, because every RPC is
  an unsafe request; the Worker forwards only that cookie, the Origin and the token. Both kinds together, a repeated or
  malformed cookie, or no configured origin is refused. The Worker cannot prove a session: the host validates it.
- **Reply.** Only `content-type`, `grpc-status`, `grpc-message` and the Worker's own headers (`cache-control: no-store`,
  `x-content-type-options`, the revision and build headers) are returned; cookies and any other Container header are
  dropped. A non-200 Container status is HTTP 503 with a fixed text, never the Container's body. When the Containers
  platform could not start the Container (its own plain-text 503, 500 or 429, which proves the request never reached the
  host), the 503 carries `Retry-After: 2`; any other non-200 status and any thrown error carries none, because the call
  may have been forwarded ([cloud-readiness](cloud-readiness.md)).

## The frame guard

`guardResponse` wraps a Container reply body and follows frame boundaries without copying. It enforces the frame bound,
the total bound and the data-frame count of a unary reply, and refuses an unknown flag and any byte after the trailer
frame. A stream ends in exactly one of these ways, and never as a silent end of data:

| Event                                                         | Result for the client                                                         |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| The host ends the reply after its status trailer              | A complete stream                                                             |
| The host ends the reply on a frame boundary without a trailer | An explicit `UNAVAILABLE` trailer from the Worker                             |
| The deadline or a cancellation fires on a frame boundary      | An explicit `DEADLINE_EXCEEDED` or `CANCELED` trailer, the Container released |
| Any of those inside a frame, a violation, or a source error   | The stream errors; the client observes a failed transfer, not end of data     |
| The client closes its response                                | The Container request is aborted and its body released                        |

The guard reads from the Container only as fast as the client reads (no read-ahead queue). A unary reply is read fully
through the same guard before any byte is returned, bounded by its route, so a failure still maps to an accurate status.

## Host rules

The pipeline runs in this order and stops at the first refusal, which is a trailers-only gRPC-Web status (HTTP 200 and
one trailer frame) with a stable message key; no plan, store write or business code has run when it is produced.

0. Before any routing the request target must be byte-for-byte canonical: no percent-encoding, dot segment, empty segment,
   trailing slash, backslash or absolute-form target (the decoded path must equal the raw one). Anything else is a plain 404.
   A canonical path must then be a declared plain route (`/healthz`, the browser session routes and the signed
   `/internal/foundation/v1/` prefix, each declared by its module) or a method path; any other path is a plain 404. Deny by default
   therefore does not depend on how a path looks, and endpoint routing never sees a variant (a trailing slash, another case) that the
   exact tables do not know. The Worker's table is exact for the same reason.
1. A path of the form `/package.Service/Method` is an RPC. The method must be POST (405) and must have a policy: an unregistered
   method (including every case variant) is `UNIMPLEMENTED` (`unimplemented`).
2. The media type must be binary gRPC-Web without a content or gRPC encoding (415).
3. Authentication per the policy. An anonymous method reads and validates no credential at all. A session method needs
   exactly one credential kind: a bearer validated by `IBearerTokenVerifier`, or the cookie validated by
   `IBrowserSessionVerifier` after the exact single `Origin` header matches `AllowedOrigin` and the session's own CSRF
   token verifies. Failures are `UNAUTHENTICATED` (`auth.unauthenticated`) or `PERMISSION_DENIED`
   (`perm.resource_denied`); the reply never says which check failed. A store failure is `UNAVAILABLE`
   (`dependency.unavailable`). Validation reads the authoritative store on every call, never renews idle expiry (a passive
   call or stream never extends a session) and keeps no positive cache.
4. The method's own body bound is set before any body byte is read.
5. For a workspace-scoped method the one request message is read (exactly one uncompressed frame within the bound) and
   its `RequestMeta` (field 1 of every generated request, wire registry 04) is read from the protobuf bytes without a
   per-method type: the addressed workspace must be present (`INVALID_ARGUMENT` otherwise), one of the workspaces the
   validated session owns (`PERMISSION_DENIED` otherwise) and, when the request states a recovery generation, equal to the
   session's (`FAILED_PRECONDITION`, `state.stale_generation`). The result is the `CurrentOwner` of the call, available to
   handlers with the `CallerContext`; handlers never re-derive authority from the request.
6. The call proceeds to the gRPC-Web adapter. A server stream has response buffering disabled.

`IBearerTokenVerifier` has no implementation yet: a bearer is refused as `UNAUTHENTICATED` until the identity module
provides one. The browser verifier over the guarded session plans exists only in the proof environment.

## Correlation (CLOUD.69)

One correlation identity per call (Design CR-01, CR-03, CR-06, HP-06) is accepted or created at the edge, joined to one
W3C `traceparent` from the Worker to the host, returned in the replies the host builds, and carried with a causation id
in the job wake message and the private job-slice call. It uses only fields the wire registry already defines
(`RequestMeta.correlationId` tag 3, `ResponseMeta.correlationId` tag 4, `ArcError.correlationId` tag 6) and the standard
`traceparent` request header between the Worker and the host. It adds no wire field, no client-visible header and no
contract meaning, and it is never an authorization input.

| Hop                    | What happens                                                                                                                                                                                                                                                                      | Where                                                                                    |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Client to Worker       | A route that declares `requestMeta` has the client's `RequestMeta.correlationId` read from the request message. Only a canonical `Id` (exactly 16 bytes, not all zero, stated once) is accepted; an absent value is created (`crypto.randomUUID`); a malformed one is refused.    | `worker/ingress/correlation.ts`, `worker/ingress/pipeline.ts`                            |
| Worker to host         | The Worker builds `traceparent: 00-<correlation id without hyphens>-<new span>-01`. A UUID is exactly the 128 bits of a trace id, so the identifier alone joins the hops. Nothing the client sent (its own `traceparent`, `tracestate`, `baggage`, request ids) is forwarded.     | `worker/ingress/pipeline.ts`                                                             |
| Host admission         | The pipeline reads the envelope strictly (`RequestEnvelopeReader`), validates the same `Id`, and binds a `CorrelationContext` to the call: the stated value, else the trace id of a strict single `traceparent`, else a new identity. The host's span is a child of the Worker's. | `src/ArcForges.Cloud/Ingress/Correlation.cs`, `IngressPipeline.cs`, `Caller.cs`          |
| Host replies           | `ResponseMeta.correlationId` and `ArcError.correlationId` are built from the call's context by `CorrelationReplies`; the proof probe's replies use them.                                                                                                                          | `Correlation.cs`, `PipelineProbe.cs`                                                     |
| Queue wake             | A wake message carries `correlationId` and `causationId` (the originating request, or the previous wake event of a continuation) as part of its closed key set. A wake queued before this change (no correlation) is still accepted and takes its own event id for both.          | `worker/foundation/queue.ts`, `types.ts`, `proof-routes.ts`                              |
| Private job-slice call | The consumer sends both identifiers inside the signed JSON body (`jobSliceBody`). The host's request is closed and requires both as canonical UUIDs; the slice carries them in its call context, echoes them and stores them in the `job.slice` outbox payload.                   | `worker/foundation/container-client.ts`, `FoundationOperations.cs`, `JobSliceService.cs` |

Rules the code and the tests pin:

- **Malformed is refused, never repaired.** A repeated field, an `Id` of 15 or 17 bytes, an all-zero `Id`, a wrong wire
  type, an `Id` that is text, or a truncated field is `INVALID_ARGUMENT` with the registered key
  `validation.invalid_request`, before any handler, plan or store write runs. The Worker refuses it before the Container
  wakes; the host refuses it when it reads the envelope, before the current-owner decision. A message the Worker cannot read
  as protobuf at all is passed on with a created identity and left to the host, whose reader is equally strict.
- **No authorization effect.** The decisions of the pipeline (credential, Origin, CSRF, session, current owner, recovery
  generation) never read the correlation. A test states six different identities (including none and values equal to the
  session id, the workspace id and a workspace the caller does not own) across eight admission cases and requires identical
  outcomes. Credential validation still comes first: an unauthenticated request with a malformed identity is
  `UNAUTHENTICATED`, exactly as with a valid one.
- **Method-declared.** Only a method that declares a `RequestMeta` has its body read for an identity: a workspace-scoped
  method always does, an account-scoped method opts in with `carriesRequestMeta`. The anonymous Hello request has no
  `RequestMeta` (its field 1 is the name), so it is never interpreted; its call still gets a trace.
- **No injection.** Every value that becomes a header, a log field or a message member is produced from 16 validated bytes
  or from the platform's random source, in canonical lowercase UUID or hex form. A client's own trace headers are dropped by
  the Worker; the host ignores any `traceparent` that is not exactly one strict W3C value (version 00, lowercase hex,
  nonzero ids) and never reflects one.
- **Where the identity is returned.** In `ResponseMeta` and `ArcError` of the replies the host builds. A refusal of the
  pipeline or the Worker itself is a trailers-only gRPC status with no message, which the wire registry treats as a
  transport failure without a fabricated result, so it carries no identity and no new header was added to carry one. The
  anonymous Hello reply has no `ResponseMeta` in its contract.
- **Trace flags.** The `01` trace flag only marks the trace as joinable; it states no sampling decision. Sampling and
  retention belong to the telemetry policy (PLT.50), not to this seam.
- **One seam.** `CorrelationContext` (host) and `worker/ingress/correlation.ts` (Worker) are what later hop owners reuse:
  the stream and publication owners (CLOUD.33 and the stream tasks) populate `Event.correlationId` from them, and provider
  owners (AIR.04) a provider request's correlation. Neither the realtime nor the provider hop exists here.

The proof probe shows the replies: every unary reply and every stream frame carries a `ResponseMeta` in field 10, and
`Whoami` with request field 10 set to 1 returns an acknowledged domain refusal (gRPC OK) with an `ArcError` in field 11
(`state.not_found`) that carries the identity.

## Static profile assets on the proof origin (CLOUD.71)

On the proof origin only, static assets answer the two Web profile shells (`/account/`, `/chat/`, with the Blazor WebAssembly framework at the root under base href `/`), the C# public Site (`/`, `/hello/`, `/cloud-hello/`, and its not-found page for any other path that no route owns), and the shared `/assets/*`, `/_framework/*`, `/favicon.svg` and `/robots.txt` (CLOUD.85 replaces the React bytes that CLOUD.71 served). Every route family of this document (`/api/*`, `/session/v1/*`, `/proof/v1/*`) is configured Worker-first, so no asset can shadow or answer them, and the pipeline's deny-by-default admission is unchanged: the assets add no method, policy or credential. The Site's policy never carries WebAssembly; each profile's policy carries the WebAssembly token, and the Site's policy is unset under `/account/*` and `/chat/*`. Production serves no assets. See [prf-07-foundation-proof](prf-07-foundation-proof.md#serving-the-built-web-profiles-cloud71) for the pinned release assets, their verification and what was and was not observed.

## Known limits

- **Revocation and a running stream.** A session and its owner are validated when a call is admitted, not again while a stream runs.
  A revocation therefore takes effect for a running stream only when it ends: at most five minutes by design (the route lifetime,
  `streamLifetimeMs`, 310 seconds with slack) and 60 seconds for the proof probe. Annex 10 asks for authority to be re-checked at
  least every 15 seconds on a stream; that periodic check belongs to the first real stream service (CLOUD.29, CLOUD.34), which owns the
  stream's frames, and it cannot be satisfied by this boundary alone. A call that already returned bytes cannot be recalled in any case.
- **Container sleep and long streams.** `sleepAfter` is 60 seconds and a stream may live longer. The locked `@cloudflare/containers`
  counts every proxied request until its response body ends and treats the Container as active meanwhile; a test pins that behavior
  (`container-classes.test.ts`) so a library upgrade cannot silently end open streams. It is not observed on the platform.
- **Frame guard memory.** The guard keeps one abort listener per stream and no per-read state; a test reads 200,000 frames and bounds the
  retained heap (the earlier design retained roughly 600 bytes per read).

## Adding a public method

A module appends its method in its own section, in two places that a test compares: its `RpcPolicy` in the module's
`RpcPolicies` (host) and its transport budget in `TransportBudgets.ByMethod`; its `ApiRoute` row is generated from the two
(`worker/tables/cloud-tables.generated.ts`). The policy states whether the request carries a `RequestMeta`
(`carriesRequestMeta` on the policy, always true for a workspace-scoped method; `requestMeta` on the generated route), and that
decides whether the correlation of a call is read from the body. A generated service mapped without a policy fails
`EveryMappedGrpcMethodHasAnIngressPolicyAndEveryPolicyHasAnEndpoint`. The host composition only lists modules
(RES-cloud-host-composition).

## Proof-only pipeline probe

The probe lets the deployed ingress be observed without a business service. `arcforges.proof.v1.PipelineProbe` is
registered only when the foundation proof is enabled; production does not contain it in the host or in the Worker table.
Its messages are hand-framed proof bytes, not Contracts records: the pinned generated surface carries no authenticated
unary or server-streaming method that fits, and no wire meaning is invented for product use. Requests carry the envelope
convention (field 1 is `RequestMeta`). Every reply the probe builds carries the call's correlation (see Correlation).

| Method        | Kind          | Reply                                                                                                                                                                                     |
| ------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Whoami`      | unary         | `1` session id, `2` user id, `3` current-owner workspace, `4` recovery generation                                                                                                         |
| `Stream`      | server stream | request fields `10` count (1 to 50) and `11` interval ms (0 to 2000, at most 30 seconds in all); frames `1` sequence and `2` 32 payload bytes; a final OK trailer with `x-af-probe: done` |
| `Observation` | unary         | counters `1` started, `2` completed, `3` canceled, `4` deadline exceeded streams of this host process                                                                                     |

## Running the checks

| Check                                                                | Command                                                               | Where it runs                                                      |
| -------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Worker pipeline, frame guard, routes and host agreement              | `npm test` (`tests/worker/ingress-*.test.ts`)                         | hosted CI and locally                                              |
| Host pipeline on the real Kestrel host and the real gRPC-Web adapter | `npm run check:dotnet` (`IngressPipelineTests`)                       | hosted CI and locally                                              |
| Linux Native AOT image (trim and AOT warnings as errors)             | `npm run candidate`                                                   | hosted CI (needs Docker)                                           |
| Real AOT host behind the real Worker modules in workerd, real HTTP   | `FOUNDATION_HOST_EXE=<host executable> npm run test:foundation:local` | explicit local opt-in only                                         |
| The same scenarios against the deployed proof environment            | `npm run test:foundation:live` (the `pipeline-*` rows)                | explicit local opt-in only, under the lease `RES-cloud-deployment` |

The `correlation-*` scenarios (CLOUD.69) run with them on both targets: `correlation-supplied`, `correlation-absent`,
`correlation-malformed`, `correlation-error-reply` and `correlation-queue-wake` (see Correlation validation below).

The `pipeline-*` scenarios run on both targets and write one evidence row each:

- `pipeline-unary`: an authenticated workspace-scoped call returns the session, the user and the current-owner
  workspace, with a status trailer, `no-store` and no `set-cookie`.
- `pipeline-refusals`: twelve refusals (no credential, wrong or missing Origin, no or wrong CSRF, malformed or unknown
  cookie, foreign workspace, no workspace, stale generation, a bearer without a verifier, a revoked session) each with its
  exact status and no message frame; an unknown method and an `/api/internal` path are 404.
- `pipeline-stream`: five frames at 500 ms intervals arrive in order, none lost, with the frames spread over the intervals
  (a buffering Worker would deliver them as one burst) and the custom trailer visible to the client.
- `pipeline-stream-cancel`: closing the client's response is observed by the host as a canceled stream, and the stream
  does not run to completion afterward.
- `pipeline-stream-deadline`: a 700 ms deadline ends the stream with `DEADLINE_EXCEEDED` after some frames, never silently.

## Validation actually performed

Offline and local results below were observed on the delivery's Windows 11 machine (ArcForges delivery worker
w-c20261005-cloud01) and are claimant-reported until independent review and hosted CI confirm them.

| Check                                          | Command                                                                                                                                                          | Observed                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Worker and tooling tests                       | `npm test`                                                                                                                                                       | 243 passed, 0 failed (67 more than the 176 of the PRF.07 delivery)                                                                                                                                                                                                                                                                                                                               |
| Dependency, licence, provenance, plan manifest | `npm run test:dependencies`, `node tooling/dependency-policy.ts`, `node tooling/project.ts licence`, `node tooling/project.ts provenance`, `npm run check:plans` | pass (receipt `cloud-01-r1`, profile `cloud-release-r23`)                                                                                                                                                                                                                                                                                                                                        |
| Real bundle against the release profile        | `node tooling/project.ts prepare-provenance-test` then `node --test tests/worker/release-provenance.test.ts`                                                     | 10 of 10 passed (bundle 183,693 bytes)                                                                                                                                                                                                                                                                                                                                                           |
| Formatting, lint, types                        | `prettier --check .`, `biome lint`, `tsc` for both projects                                                                                                      | clean                                                                                                                                                                                                                                                                                                                                                                                            |
| C# build, tests, format                        | `dotnet build` and `dotnet test` of `Cloud.slnx`, Release, under the build slot; `dotnet format --verify-no-changes`                                             | 0 warnings, 189 tests passed (30 new in `IngressPipelineTests`), format clean                                                                                                                                                                                                                                                                                                                    |
| Native AOT                                     | local `dotnet publish -r win-x64` with trim and AOT warnings as errors                                                                                           | linked, no diagnostics                                                                                                                                                                                                                                                                                                                                                                           |
| Cross-process local integration                | `npm run test:foundation:local` (all fourteen scenarios) against that AOT host                                                                                   | passed, including the five `pipeline-*` scenarios: the stream's five frames arrived at 31, 540, 1052, 1567 and 2082 ms (500 ms apart), closing the client was seen by the host 545 ms later, and a 700 ms deadline ended a stream with status 4 after four frames                                                                                                                                |
| Mutation checks                                | deliberate mutations of the Worker pipeline and the host pipeline                                                                                                | Worker: 16 of 17 killed (the survivor removes a duplicate of the unary size bound that the buffered read enforces again, an equivalent mutant); host: 19 of 19 killed, of which the four conditions mutated to a constant were re-run as non-constant mutants so that a compile error could not count as a kill. The other fifteen host mutants were not individually checked for compile errors |

Local integration uses the real Native AOT host process and workerd (Miniflare) with local D1, R2, Durable Object and Queue
emulation, a Node SQLite bridge standing in for D1, and real HTTP between workerd and the host for every request (an
external service binding, so that closing a response closes the connection as the platform's Container stub does). The harness's
earlier function-binding proxy collected every reply and did not propagate cancellation, which is why it was replaced.

### Correlation validation actually performed (CLOUD.69)

Claimant-reported (ArcForges delivery worker w-c20261005-cloud69, Windows 11, until independent review and the hosted exact-head
run confirm them):

| Check                                         | Command                                                                                                                          | Observed                                                                                                                                                                                                                                                        |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Host and architecture tests, format           | `dotnet build`, `dotnet test --solution` and `dotnet format --verify-no-changes` of `Cloud.slnx`, Release, under the build slot  | 0 warnings; 528 passed, 0 failed (the first run of the architecture gate needed a clean checkout and a fresh `npm run policy` naming report); format clean                                                                                                      |
| Worker tests and static checks                | `npm test`, `tsc` for both projects, `biome lint`, `prettier --check .`                                                          | all pass (the new file `tests/worker/ingress-correlation.test.ts` is in the explicit test list)                                                                                                                                                                 |
| Dependency review, provenance, release bundle | `node tooling/dependency-policy.ts`, `node tooling/project.ts provenance`, `node --test tests/worker/release-provenance.test.ts` | pass with receipt `cloud-69-r1`, profile `cloud-release-r27`, Worker bundle `fc790066839d420b24a9d3a888681742b4498610e17671539df4fe97b3268f92` (191,309 bytes, 102 inputs); no coordinate, integrity value, lock or closure entry changed                       |
| Mutation checks (Worker)                      | seven deliberate mutations of the Worker code, run against the Worker tests                                                      | 7 of 7 killed: no refusal of a malformed value, a repeated field accepted, no 16-byte check, no causation on a continuation, a client `traceparent` forwarded, no causation in the slice body, the origin request replaced by the correlation as the cause      |
| Native AOT                                    | local `dotnet publish -r win-x64` of the host                                                                                    | linked with trim and AOT warnings as errors, no diagnostics                                                                                                                                                                                                     |
| Cross-process local integration               | `FOUNDATION_HOST_EXE=<that executable> npm run test:foundation:local` (nineteen scenarios)                                       | all passed, including `correlation-supplied`, `correlation-absent`, `correlation-malformed` (five forms, each on Whoami and Stream), `correlation-error-reply` and `correlation-queue-wake` (a 120-item job finished by the queue wake alone, one host restart) |

The local run found one real defect before the first hosted run: the earlier `checkpoint-restart` scenario called the
private job-slice route without the identifiers the host now requires (HTTP 400); the scenario was corrected and the
nineteen scenarios then passed.

What a correlation scenario proves and what it does not:

- `correlation-supplied`, `correlation-absent`, `correlation-malformed` and `correlation-error-reply` observe the public
  binary gRPC-Web path through the real Worker modules and the real AOT host: the identity returned in `ResponseMeta`
  (unary reply and first stream frame) and in `ArcError` equals what the client stated, an absent one is a canonical new
  UUID per call, and each malformed form is `INVALID_ARGUMENT` with `validation.invalid_request`, no message frame and no
  handler (the probe's started-stream counter does not move).
- `correlation-queue-wake` starts a job with a stated chain identity and lets the queue wake run it to completion. The
  host's job-slice request is closed and requires both identifiers as canonical UUIDs, so a finished job proves the wake
  carried both through the consumer and the signed call. A direct slice call also shows the host echoing exactly the
  identifiers it was given, and a nil identity is refused. The identity stored in the outbox row is covered by the host
  tests; no public surface reads it back.
- The Worker and the host share the identity by the trace id of one `traceparent`: the Worker tests assert what the Worker
  builds and the host tests assert what the host binds from it. The local run exercises the two as separate processes. No
  external trace store exists, so "one connected trace" is established by identifier equality at each hop, not by a
  collected trace.

### Unobserved (CLOUD.01 and earlier)

- Anything on the deployed platform: the deployed `pipeline-*` scenarios have not been run by this document's author unless
  the task record says so. Provider behavior of the Durable Object stub's streaming, Cloudflare's own cancellation and
  trailer handling, and the production Container image executing are not observed here.
- The local run uses workerd (Miniflare) and a local HTTP connection to a win-x64 Native AOT host, not Cloudflare's Container
  platform and not the Linux image.
- A real generated server-streaming service is not exercised: the pinned Contracts packages carry none that fits, so the stream
  behavior is observed with the proof-only probe (hand-framed bytes). Package-consumer streaming tests belong to PRF.06 and CLOUD.29.
- No bearer verifier, no passkey or session issuance flow and no business module exists; the browser verifier is the proof
  session store over the plan bridge.
- Absence of a directly reachable Container port is established by configuration and by the static tests (no route, no
  published port, one binding caller), not by an external port scan.

### Unobserved (CLOUD.69)

- Correlation on the deployed platform: the `correlation-*` scenarios are part of the explicit opt-in deployed run
  (`npm run test:foundation:live`, lease `RES-cloud-deployment`), which this change did not perform. The deployed Worker,
  Container, Queue and Durable Object behavior with the new wake shape is not observed.
- Realtime and provider hops: they do not exist yet (`Event.correlationId` belongs to the publication and stream owners, a
  provider request identifier to the provider owners); the anonymous Hello reply has no `ResponseMeta`, and the pipeline's
  own trailers-only refusals have no message to carry the identity.
- The C# origin of PLT.48 that attaches a typed correlation to a generated request and the connected trace across owners
  are not exercised here.
- Host-side mutation checks were not run (each needs a full build); the host tests were reviewed against the Worker
  mutations only.
