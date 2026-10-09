# Harness foundation (HAR.40)

HAR.40 is the first Harness proof set under P2-021: the C# executor on D1, the thin `ai.internal` outbound adapter in the Cloud Worker and the Hello-agent slice ported to C#. It is a partial delivery of WP-52.00 (executor) and WP-43.00 (Workers AI adapter). The full run loop belongs to HAR.00 and the provider adapters to AIR.00; neither is complete here.

## Boundaries

- **C# decides.** Run state, admission, budget reservation, retry, idempotency, unknown-effect policy, pinned model and tariff checks, per-model rate admission and the Hello-agent flow live in `ArcForges.Cloud.Modules.Task` and `ArcForges.Cloud.Modules.Agent`. No business decision is made in TypeScript.
- **TypeScript is a thin adapter.** `worker/harness/run-alarm*.ts` holds only a Durable Object wake handle: it sends one signed wake to the C# endpoint with bounded retries and fails closed without the W2C key. `worker/ai/internal/*.ts` forwards the frozen request to the `env.AI` binding and streams the answer back unchanged. Neither keeps run state.
- **No Cloudflare Workflow holds run state** (P2-021 item 5). A Workflow may be considered later only as a stateless wake adapter, under a reviewed record.
- **Only the `env.AI` binding is reachable from the container.** The production `CloudContainer` registers exactly one outbound host, `ai.internal`. `enableInternet` stays `false`. The proof class keeps its storage and objects hosts only.

## Executor (`src/ArcForges.Cloud.Modules.Task/Harness/Executor`)

- **Run identity.** Each run carries the Cloud build identity and the Cloudflare Worker version identifier as separate fields, both bound into every dispatch intent. The Worker version is never replaced by the build identity.
- **Lease and fencing.** A claim takes a 60-second epoch lease (`TermMicros`), renewed every 20 seconds. Every durable write is a checked-in plan under `storage/plans/task/harness-executor-*` whose guard holds the fence: holder, epoch, recovery generation and an unexpired lease. A stale writer is rejected by the guard, not by a timing assumption.
- **Dispatch order.** A counted step reserves budget before dispatch. A dispatch intent is durable before the external call. The outcome and any yield are recorded under the fence.
- **Retries.** At most two pre-dispatch retries, each with a fresh attempt id. After a dispatch intent there is no retry. A dispatch intent without an outcome is recorded as an unknown effect on resume and is never dispatched again.
- **Step status.** `NotDispatched` means no external call was made by the step. An outcome that cannot be recorded after the call is `OutcomeNotRecorded` (the supplier was called, its result is kept as the answer kind when known, and the effect is reconciled as unknown on resume); it is never reported as `NotDispatched`.
- **Crash resume.** A reserved attempt with no dispatch intent is released. A dispatch intent with no outcome becomes `UnknownEffectRecorded`. Crash points are tested before and after each fenced write (claim, reserve, dispatch intent, outcome, yield).
- **Checkpoints.** A checkpoint is limited to 128 KiB (`CheckpointLimitBytes`), holds references only and never the raw prompt.
- **Durable counters.** `task_harness_budget` (migration 0025) keeps counted steps, subrequests, model calls and tool invocations, monotonic by trigger, so a restart or lease takeover never resets them.

### Cost controls

| Control                               | Value                                          | Source                                                                               |
| ------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------ |
| Lease and renewal                     | 60 s, renewed every 20 s                       | `HarnessPolicy` (`TermMicros`, `RenewIntervalMicros`)                                |
| Step guard                            | stop effects at 24,000 counted steps           | `EffectStepGuard`                                                                    |
| Hard step ceiling                     | 25,000; reconciliation reserve 1,000           | `HardStepCeiling`, `ReconciliationStepReserve`                                       |
| Subrequest stop                       | 900,000 of 1,000,000                           | `EffectSubrequestStop`, `SubrequestAllowance`                                        |
| Pre-dispatch retries                  | at most 2, fresh attempt id                    | `MaxPreDispatchRetries`                                                              |
| Model retries after possible dispatch | 0                                              | `MaxPreDispatchRetries` and the unknown-effect rule                                  |
| Hello model deadline                  | 90 s (current AI value, reconciled by record)  | `ModelDeadlineSeconds`                                                               |
| Loop deadline                         | 120 s, the P2-021 value for HAR.00             | `LoopDeadlineSeconds`                                                                |
| Model calls                           | default 16, hard 64                            | `DefaultModelCalls`, `HardModelCalls`                                                |
| Tool invocations                      | default 64, hard 256                           | `DefaultToolInvocations`, `HardToolInvocations`                                      |
| Tool parallelism                      | default 4, hard 8                              | `DefaultToolParallelism`, `HardToolParallelism`                                      |
| No progress                           | 3                                              | `NoProgressLimit`                                                                    |
| Output cap                            | 4,096 tokens                                   | `OutputTokenCap`                                                                     |
| Text input cap                        | 24,000 tokens                                  | `TextInputTokenCap`                                                                  |
| Tool count cap                        | 32                                             | `ToolCountCap`                                                                       |
| Context                               | 256 KiB default, 1 MiB hard; 200 and 500 items | `ContextBytesDefault`, `ContextBytesHard`, `ContextItemsDefault`, `ContextItemsHard` |
| Checkpoint                            | 128 KiB, references only                       | `CheckpointLimitBytes`                                                               |

The values are C# policy. A policy may narrow a bound and never enlarge it.

### Reviewed budget definition (HAR.40 validation (b)(1))

`BudgetDefinition` in `Domain/Budget.cs` is the reviewed C# definition of the counted classes. Every listed call is one counted step (`StepWeight`). A subrequest is counted for the classes that leave the executor (`SubrequestWeight`).

| Counted class   | Steps | Subrequests | Where it is charged                                                |
| --------------- | ----- | ----------- | ------------------------------------------------------------------ |
| `D1Call`        | 1     | 1           | every D1 statement (a read) or batch (a write) the executor issues |
| `OutboundFetch` | 1     | 1           | the outbound fetch of a model step, including `ai.internal`        |
| `ContainerCall` | 1     | 1           | the call that carries a wake into the container                    |
| `R2Operation`   | 1     | 1           | none today; any R2 call charges this class                         |
| `Retry`         | 1     | 0           | each pre-dispatch retry (a fresh attempt identity)                 |
| `WaitCycle`     | 1     | 0           | each wake delivery of a run                                        |

The charges are written in the same fenced batch as the call they pay for:

- **Model attempt** (reserved before dispatch): the state read, the reservation, the dispatch intent, the outbound fetch and the outcome, so 5 steps and 5 subrequests for the first attempt. A retry attempt is 5 steps and 4 subrequests (the retry class instead of the state read). A tool attempt is 4 steps and 4 subrequests (no outbound fetch).
- **Claim**: the claim batch and the two state reads of the claim sequence, 3 steps and 3 subrequests. A wake adds its wait cycle and container call and the open-attempt read of its resume (`WakeDelivery`, `ResumeRead`).
- **Renewal, checkpoint and yield**: one D1 batch each (1 step and 1 subrequest). A resumed outcome written on a wake is one D1 batch.
- **Alarm park** (HAR.40 alarm arming): before a run is parked with a timer, one fenced lease renewal reserves two outbound fetches, the arm and the best-effort cancel (`BudgetDefinition.AlarmReservation`), in the same batch as the renewal's own batch. The cancel can only follow a commit that did not happen, and no fenced write is left to charge it afterwards, so both calls are reserved before the arm. A reserved cancel that is not sent leaves the counters one subrequest higher, the conservative side. A refused reservation arms nothing and writes nothing further; a refused arm keeps its reserved charge.

Named limits: a read that is not followed by a fenced write (a refused claim, a refused effect) is not durable-counted. Every such refusal stops the slice or the wake at once and is bounded by the Durable Object alarm schedule (seven deliveries) and by the step guard, and the HAR.00 loop must stop on the first refusal the same way.

### Model and tariff pin (HAR.40 validation (f))

The pinned model and tariff snapshot is stored in `task_harness_budget` at the run's first claim and never changes (the table refuses an update of the pin). Every later dispatching claim and reservation must present the same pair: a claim under a different pair is refused before any lease is taken (`PinRefused`), and the reservation plan refuses it inside the database. The executor also refuses the pair before any reservation. A wake dispatches nothing and carries no pair, so it claims under the pair the run stores (`ClaimPinRule.InheritStored`); a run that never stored a pair has never been dispatched and is not claimed by a wake (`PinRefused`, nothing written).

### Wake

`HarnessRunAlarm` (Durable Object, one per run) holds only a wake handle. The C# route is `POST /internal/harness/v1/wake` (`HarnessWakeRoute.Path`). The route exists only when the host registers the wake port, so production maps nothing. The signed wake carries the workspace id, the run id, the Cloudflare Worker version identifier and the wake time (`HarnessWakeMessage`), and C# verifies it before it parses. A wake is delivered at most seven times: the first delivery, then one retry after each of 1, 2, 4, 8, 16 and 32 seconds (63 seconds in all, more than the 60-second lease term), then dropped; the alarm never holds run state across those attempts. A run whose live lease belongs to another holder is refused by the claim and answered 503, so the retry lands after that lease has expired and the wake claims the run instead of dropping it. A store that cannot settle the wake (`Stopped`) and a store read that is not served (`Unavailable`, a typed retryable reply with `Retry-After: 1`) are answered 503 as well; only a successful take is 200.

**Arming is delivered by HAR.40 at library level, and the proof environment binds the wake class.** The C# executor arms the run's wake before it parks a run with a timer (`HarnessExecutor.ParkWithTimerAsync`, the contracts 05 `wait` row). The order is fixed: the arm, through the `IHarnessAlarmPort` (declared in Abstractions, implemented by the Task module), comes first, and only then does the fenced commit record the waiting state and release the lease. The port is one closed JSON request per call to the outbound virtual host `harness.internal`: `POST /v1/schedule` with `{runId, wakeAtMs, workspaceId}`, or `POST /v1/cancel` with the run key `{runId, workspaceId}`. `HarnessAlarmClient` fails closed: anything other than the exact reply `{"scheduled":true}` with status 200, a transport failure, a timeout or a cancelled caller is a refusal.

- A refused arm does not park the run and writes nothing. The lease is left to its term, and the caller answers the typed retryable reply. A retry claims the run once that lease has expired.
- A waiting commit that did not commit after arming (refused, unavailable or stale) cancels the armed wake on a best-effort basis. A commit whose outcome is unknown keeps the wake armed: a stray wake is harmless under the fenced claim, while cancelling a wake of a run that did commit its waiting state would strand that run.
- A crash after arming and before the commit leaves a running run whose lease expires within 60 seconds. The armed wake retries for 63 seconds, which outlasts that lease, and the fenced claim then recovers the run. A crash after the commit leaves a waiting run that a later wake claims.
- The arming caller is the Hello-agent slice's `read_unavailable` exit (`HelloAgentSlice`). When a composition supplies the alarm port (the proof composition's foundation wake module registers it), a read that is not served parks the run through `ParkWithTimerAsync` with a wake one second later. The wake claims the run and settles it back to waiting, and it runs no model or tool step, so the greeting continues only when a later claim is made by the caller's own retry. No host route constructs the Hello-agent slice: the park is proven at library level by offline tests that construct the slice with the port, not by a deployed or proof route. A refused arm answers the same typed retryable reply (`read_unavailable`) and parks nothing; the lease is left to its term. A reserving renewal that does not commit answers `reserve_*` (nothing is armed or written). A waiting commit that does not happen after arming answers `release_refused` (or `release_unknown`, when the outcome is unknown, in which case the wake stays armed), the same reply as a failed release. Without the port the exit settles to waiting as before, so production is unchanged.

On the Worker, `worker/harness/run-alarm-core.ts` serves `harness.internal` (the handler is folded into the core, which keeps the write scope of the run alarm). It validates the closed shapes (the schedule shape by `parseSchedule`, the cancel shape by `parseRunRef`), the method, the path, the host, the query, the JSON content type and the body size before it reads the binding, and it calls `HARNESS_RUN_ALARM.getByName(<workspaceId>/<runId>)` with `schedule` or `cancel`. A missing binding is 503, a schedule the Durable Object refuses is 422, and a failed stub call is 502. The handler is registered on `FoundationContainer.outboundByHost` only; the production `CloudContainer` keeps exactly `ai.internal`. In the proof environment `env.proof` in `wrangler.json` binds `HARNESS_RUN_ALARM` with its migration `harness-run-alarm-v1`. The C# alarm port is registered only with the wake route, under `FOUNDATION_PROOF` (`HostModules.cs`), so production registers nothing new.

Scope of the delivery: the reserve, the arming order, the refusals, the cancel and the crash rows are tested offline (`HarnessAlarmArmingTests`, `HarnessAlarmClientTests`, and `tests/worker/run-alarm.test.ts`, which includes the handler refusals and the schedule, alarm and signed wake loop). The Hello-agent slice's `read_unavailable` exit is the arming caller at library level (tested in `HelloSliceTests`).

**Binding item not delivered (brief section 10, HAR.40 alarm arming, follow-up item 1).** The brief requires that a parked Hello run resumes even when the caller does not retry, tested end to end offline. That is not delivered. The wake settles the run to waiting only and runs no step. A continuation needs three things the code does not have: a stored greeting input (the executor persists no request content, so a wake has no name to continue with), a model dispatch under the wake, and a route. The coordinator has not decided how the input is stored, so this item is open and blocks approval of HAR.40 until that decision is recorded. The offline test `AParkedHelloRunResumesAndCompletesTheGreetingWithoutACallerRetry` states the required behaviour and is skipped until then. The other timers, including the 60-second waiting-timer reconcile of contracts 05, the approval and capacity waits, and the production executor's mapping, are HAR.00's. The live observation of a real alarm wake after a process restart is an operator step recorded as `liveNotRun` in [harness proofs](harness-proofs.md) (Proof 2).

## ai.internal (`worker/ai/internal`, `src/ArcForges.Cloud.Modules.Agent/Dispatch`)

- **Envelope.** C# sends one closed JSON envelope per call: version, model, the C#-supplied admitted-model set (at most 16), the body and response caps, and the frozen Workers AI request. The Worker reads only these fields.
- **Admission, fail closed.** The Worker refuses, before the binding is called:
  - a body over the 1 MiB hard ceiling (413), or over the C#-supplied body cap (413);
  - a model outside the C#-supplied admitted set (403);
  - a malformed or closed-shape violation (400), a wrong content type (415), a wrong host or path (404), a wrong method (405), a missing binding (503).
- **Forwarding.** The frozen request reaches `env.AI.run` unchanged. No request header and no token is forwarded. No Workers AI token exists in the container.
- **Answers.** A JSON answer or an SSE stream is returned unchanged within the C#-supplied response cap. An SSE stream over its cap is cut off mid-stream. A binding failure after the call is a 502 `ai.upstream_failed`, which C# treats as a possibly dispatched effect and never retries. C# never requests a stream: `ModelDispatchClient` refuses a request whose top-level `stream` member is present and not `false` (`stream_refused`) before any token is spent, and treats an answer whose media type is not `application/json` as `Unknown` (`response_media_type`), so a streamed answer can never be recorded as a refusal.
- **C# side.** `ModelDispatchClient` checks the snapshot before any dispatch. A changed, missing or unpinned model or tariff snapshot is refused before dispatch, and the refusal is recorded. The per-model token bucket (`ModelRateBuckets`) refuses an empty bucket before dispatch and spends no token on a refused admission.
- **Base address.** `ModelDispatchOptions` accepts exactly `http://ai.internal/`. Any other destination is refused.

## Hello-agent slice (`src/ArcForges.Cloud.Modules.Task/Harness/HelloSlice`)

The admission, request-tool, local `say_hello` tool and finish-greeting steps are ported to C# on the executor (`HelloAgentSlice`). The model calls keep the Hello deadline of 90 s (`BudgetPolicy.ModelDeadlineSeconds`), inside the 120 s loop ceiling. Every step uses the same reserve-before-dispatch, zero-retry-after-dispatch and unknown-effect rules as the executor, and the slice refuses a missing or changed pinned snapshot before any claim or dispatch.

The slice takes an optional `IHarnessAlarmPort` as its last constructor argument. Without it (production) a read that is not served releases the run to waiting; with it the run parks with a one-second wake (see Wake above). No host route or production composition constructs the slice yet; it is exercised by the offline tests.

## Architecture rules and dependencies

- The Cloud `wrangler.json` and `package.json` are hash-bound inputs. Their changes for this task are admitted by the successor receipt chain in `eng/policy/dependency-reviews/` (`har-40-r1.json`, then later successors), each naming its retained predecessor. The reviewer field names the independent reviewer at review time.
- The `EvaluatedRepositoryGate` contract map links the dispatch, wake and route members to their offline tests (`tests/ArcForges.Cloud.Tests/HarnessFoundation`).
- The GOV.10 successor architecture rules are in `tests/ArchitectureTests/AiHarness` (HAR.40 validation (d)). All 27 rules keep their names under the five WP-05 obligations and run over Cloud's C# projects, manifests and Worker sources. Each rule has a passing baseline fixture and at least one refusing fixture, and the real inputs of this checkout carry no finding outside the owned register `eng/policy/harness-architecture-exceptions.json`.
- That register holds five rows, each expiring 2027-03-31 (174 days after creation for the five rows created 2026-10-08; the cap is 180 days). The former row `HAR40-EX-6` (`layer-escape` on `tests/worker/harness-internal.test.ts`) is removed with that file: its constant-path loads now sit in `tests/worker/run-alarm.test.ts`, which `HAR40-EX-3` already admits. `HAR40-EX-1` is `wire-codec` on `src/ArcForges.Cloud/Ingress/PipelineProbe.cs`: the proof-only probe frames its replies with a private encoder because no generated Contracts message exists for its service, and it leaves the production path under CLOUD.84. `HAR40-EX-2` and `HAR40-EX-3` are `layer-escape` on two test files that load workerd-only modules through reviewed constant paths. `HAR40-EX-4` and `HAR40-EX-5` are `wire-codec` on the CLOUD.69 Worker correlation reader and its test-only frame encoder, which predate HAR.40 and are owned by CLOUD.69; the reader must be replaced by a reviewed generated reader before they expire.
- The AI policy suite is ported one-for-one (HAR.40 validation (d)). Its 84 fixtures (27 passing, 57 refusing) run as `HarnessArchitectureFixtures.AiFixtures()` with the AI rule, kind and name, applied to the Cloud layout. Its lexer suite (`PolicyLexerTests`, 7 tests), SPDX suite (`SpdxExpressionTests`, 4 tests: the two AI tests of `architecture.test.ts` and two further precedence and syntax tests), exceptions suite (`ArchitectureExceptionTests`, 7 tests), architecture suite (`HarnessArchitectureTests`) and repository suite (`HarnessRepositoryTests`, 3 tests) are ported with the same test names and outcomes. The naming suite is `NamingGateTests` (the pinned archive, the scanner on the Cloud tree, every forbidden term, and a failing scanner as a finding).
- The Worker TypeScript is read through the policy lexer (`PolicyLexer`): comments, strings, templates and regular expressions are opaque, and module declarations are read from tokens. Computed imports fail closed.
- `licence-allowlist` evaluates each locked licence and declared project licence as a real SPDX expression (`SpdxExpression`): AND binds tighter than OR, parentheses group, a WITH exception is always refused, and an operator or identifier outside the grammar is refused.
- The exceptions register (`eng/policy/harness-architecture-exceptions.json`) uses the AI exceptions schema. Each exception names one exact finding (rule, file and detail), an owner, a reason of substance, a creation date that is not in the future and a lifetime of at most 180 days; an expired, malformed, over-long or unused entry is itself a finding.
- Adaptations to Cloud's layout, each recorded so that a reviewer can see where the port differs from the AI policy. The Worker entry is `worker/index.ts`. The Workers AI adapter is the `worker/ai/internal` folder, and the Harness wake handle is `worker/harness`; the inference binding may be called only in the adapter. The store rules (D1, R2, KV, Hyperdrive, Queue types and bindings) apply to those adapter folders, because Cloud's own storage bridge holds D1 by design. A route is refused only when it exposes an internal path (`/internal...`) or covers every path (`/*`), because the Cloud API route `arcforges.com/api/*` is public by design. `@arcforges/proto` may be a development dependency of the root manifest; a Worker file that imports it must have it as a runtime dependency. The admitted Contracts packages are `@arcforges/proto`, `@arcforges/ai-internal` and `@arcforges/api-client`.
- Recorded limits, carried over from GOV.10: the rules match lexical tokens and C# syntax, not symbols, so aliasing and indirection are not seen; the task-result check is a syntactic heuristic (a call, or a name ending in task); the Worker rules see one module specifier per declaration; the wrangler audit covers the top level and each environment.
- The forbidden-term scan is the canonical scanner and policy of the NuGet package `ArcForges.Contracts.Validation` 1.0.0-ci.205.1 (`eng/policy/naming-candidate.json`, CON.23 identity, GOV.14 binding). The npm `@arcforges/proto` 1.0.0-ci.287.1 publication is provenance only. `tooling/project.ts naming` verifies the restored archive SHA512, the packaged source commit and both packaged SHA256 values before `python -I` runs the scanner.

### Rule catalogue

| Rule                       | Obligation | What it refuses                                                                                              |
| -------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------ |
| `layer-cycle`              | WP-05.00   | A cycle in the project graph or in the Worker import graph                                                   |
| `layer-entry`              | WP-05.00   | An import of the Worker entry (`worker/index.ts`) or of the host entry                                       |
| `layer-escape`             | WP-05.00   | A sibling or parent checkout, an absolute path, a URL, a test or a computed import reached from the Worker   |
| `layer-runtime-dependency` | WP-05.00   | A Node built-in or an undeclared package in the Worker, or an undeclared central package in a source project |
| `layer-product-reference`  | WP-05.00   | An ArcForges package other than the admitted Contracts packages and this repository's own projects           |
| `layer-business-authority` | WP-05.00   | A store type or store binding in an adapter, a Durable Object outside the run alarm, a module-to-module link |
| `layer-public-exposure`    | WP-05.00   | `workers_dev` or `preview_urls` enabled, or a route that exposes an internal path or covers every path       |
| `licence-declaration`      | WP-05.01   | A project or manifest without an SPDX identifier or boundary, and an inventory that drifts from the projects |
| `licence-boundary-set`     | WP-05.01   | An unenumerated Apache boundary, or an AGPL boundary whose licence is not AGPL-3.0-only                      |
| `licence-cross-boundary`   | WP-05.01   | An Apache-boundary project that references an AGPL project                                                   |
| `licence-allowlist`        | WP-05.01   | A locked or declared licence expression that the boundary does not allow, or LGPL outside development        |
| `naming-identity`          | WP-05.02   | A naming candidate that is not the pinned NuGet identity, the pinned digests, the publication or the pin     |
| `naming-scan`              | WP-05.02   | A naming scan report that is missing, failed or ran under another policy                                     |
| `wire-package`             | WP-05.03   | A wire pin that is floating, not registry-locked, or not a runtime dependency of a Worker that imports it    |
| `wire-import`              | WP-05.03   | A deep or build-output import of the generated package, or a file compiled outside its project               |
| `wire-source`              | WP-05.03   | A copied generated source, an authored schema, or protoc output authored in the repository                   |
| `wire-codec`               | WP-05.03   | A handwritten or alternative wire codec (C# primitives, a protobuf wire package, manual varint masks)        |
| `wire-schema`              | WP-05.03   | A codec call whose schema is not imported from the published package                                         |
| `wire-shadow`              | WP-05.03   | A local declaration that redefines a generated wire type or namespace                                        |
| `banned-reflection`        | WP-05.04   | Reflection emit, dynamic loading, `Reflect`, or prototype mutation                                           |
| `banned-dynamic-code`      | WP-05.04   | `eval`, `Function`, runtime compilation, `dynamic`, a code string in a timer, or a computed import           |
| `banned-blocking-wait`     | WP-05.04   | A sync-over-async wait, `Atomics.wait`, a `*Sync` host call, a clock busy-wait, or `XMLHttpRequest`          |
| `banned-provider-sdk`      | WP-05.04   | A provider SDK package, namespace, import or endpoint literal                                                |
| `banned-provider-call`     | WP-05.04   | The inference binding referenced or called outside the Workers AI adapter                                    |
| `banned-secret-logging`    | WP-05.04   | Logging of a secret-bearing or content-bearing value (`console`, `Console`, `Debug`, `Trace`, `Log`)         |
| `banned-float-money`       | WP-05.04   | A floating-point type or handling in a money, credit, price or amount value                                  |
| `banned-raw-memory`        | WP-05.04   | Unmanaged or unsafe memory, `SharedArrayBuffer`, `WebAssembly.Memory`, or non-wait `Atomics`                 |

## Still open

- HAR.00: the full Harness loop on this executor (turn loop, context assembly, tool proposals, the 120 s loop deadline and the rest of WP-52.00).
- AIR.00: the production admitted-model snapshot from POL.08 (HAR.40 uses a reviewed proof fixture only). Production dispatch is never released without it.
- The live Workers AI binding proof, the container capacity proof and the deployed crash-injection proof. These are operator runs (see [harness proofs](harness-proofs.md)).
- The AI-repository retirement documentation. It waits for the AI integration role to be claimed; no AI-repository file was changed.
- Retirement of the deployed `arcforges-ai-hello` Worker. It needs explicit user confirmation and is not performed by this task.
