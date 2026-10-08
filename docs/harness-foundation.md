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

The values are C# policy. A policy may narrow a bound and never enlarge it. The step-guard counted classes follow the reviewed C# budget definition in HAR.40 validation (b).

### Wake

`HarnessRunAlarm` (Durable Object, one per run) holds only a wake handle. The C# route is `POST /internal/harness/v1/wake` (`HarnessWakeRoute.Path`). The route exists only when the host registers the wake port, so production maps nothing. The signed wake carries the workspace id, the run id, the Cloudflare Worker version identifier and the wake time (`HarnessWakeMessage`), and C# verifies it before it parses. A failed wake is retried at most four times with 1, 2 and 4 second backoff, then dropped; the alarm never holds run state across those attempts.

## ai.internal (`worker/ai/internal`, `src/ArcForges.Cloud.Modules.Agent/Dispatch`)

- **Envelope.** C# sends one closed JSON envelope per call: version, model, the C#-supplied admitted-model set (at most 16), the body and response caps, and the frozen Workers AI request. The Worker reads only these fields.
- **Admission, fail closed.** The Worker refuses, before the binding is called:
  - a body over the 1 MiB hard ceiling (413), or over the C#-supplied body cap (413);
  - a model outside the C#-supplied admitted set (403);
  - a malformed or closed-shape violation (400), a wrong content type (415), a wrong host or path (404), a wrong method (405), a missing binding (503).
- **Forwarding.** The frozen request reaches `env.AI.run` unchanged. No request header and no token is forwarded. No Workers AI token exists in the container.
- **Answers.** A JSON answer or an SSE stream is returned unchanged within the C#-supplied response cap. An SSE stream over its cap is cut off mid-stream. A binding failure after the call is a 502 `ai.upstream_failed`, which C# treats as a possibly dispatched effect and never retries.
- **C# side.** `ModelDispatchClient` checks the snapshot before any dispatch. A changed, missing or unpinned model or tariff snapshot is refused before dispatch, and the refusal is recorded. The per-model token bucket (`ModelRateBuckets`) refuses an empty bucket before dispatch and spends no token on a refused admission.
- **Base address.** `ModelDispatchOptions` accepts exactly `http://ai.internal/`. Any other destination is refused.

## Hello-agent slice (`src/ArcForges.Cloud.Modules.Task/Harness/HelloSlice`)

The admission, request-tool, local `say_hello` tool and finish-greeting steps are ported to C# on the executor (`HelloAgentSlice`). The model calls keep the Hello deadline of 90 s (`BudgetPolicy.ModelDeadlineSeconds`), inside the 120 s loop ceiling. Every step uses the same reserve-before-dispatch, zero-retry-after-dispatch and unknown-effect rules as the executor, and the slice refuses a missing or changed pinned snapshot before any claim or dispatch.

## Architecture rules and dependencies

- The Cloud `wrangler.json` and `package.json` are hash-bound inputs. Their changes for this task are admitted by the successor receipt chain in `eng/policy/dependency-reviews/` (`har-40-r1.json`, then later successors), each naming its retained predecessor. The reviewer field names the independent reviewer at review time.
- The `EvaluatedRepositoryGate` contract map links the dispatch, wake and route members to their offline tests (`tests/ArcForges.Cloud.Tests/HarnessFoundation`).
- The GOV.10 successor architecture rules (the AI Harness rule set with its fixtures) are not part of this tree yet. They remain open under HAR.40 validation (d).

## Still open

- HAR.00: the full Harness loop on this executor (turn loop, context assembly, tool proposals, the 120 s loop deadline and the rest of WP-52.00).
- AIR.00: the production admitted-model snapshot from POL.08 (HAR.40 uses a reviewed proof fixture only). Production dispatch is never released without it.
- The live Workers AI binding proof, the container capacity proof and the deployed crash-injection proof. These are operator runs (see [harness proofs](harness-proofs.md)).
- The GOV.10 successor architecture port (validation (d)).
- The AI-repository retirement documentation. It waits for the AI integration role to be claimed; no AI-repository file was changed.
- Retirement of the deployed `arcforges-ai-hello` Worker. It needs explicit user confirmation and is not performed by this task.
