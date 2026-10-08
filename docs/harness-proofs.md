# Harness proofs (HAR.40)

These are the three early proofs of P2-021 item 5 and brief section 4.3: the Workers AI binding, executor crash injection and container capacity. Each is a local opt-in driver under `eng/verification`. None runs in CI (P2-017), and none reads a credential or a local credential store. Each writes one JSON record under `artifacts/harness-proof/`, which is ignored by Git and reproduced by the commands below.

## Rules for every record

- `realness` says what was measured: `node-fixture` (the adapter run against a labelled fixture binding), `dotnet-local` (the offline C# suites), `deployed-live` (a deployed resource was probed), or `not-run`.
- A check is `passed`, `failed` or `observed`. An observation has no pass criterion and never makes a proof pass; a proof with only observations is `not-run`.
- `liveNotRun` lists each measurement that needs a deployed Cloudflare resource and the operator step that takes it. Nothing in that list is claimed.
- Under `CI=true` or `GITHUB_ACTIONS=true` each driver refuses to run.

## Commands

```sh
# Fixture proof of the ai.internal adapter (node only, no build slot needed)
npm run test:harness:ai

# Offline C# crash injection and executor suites (CPU-heavy: run through the build slot, after a build)
python C:\MyFile\Projects\Plan\tools\delivery.py build-slot run --worker <worker> --task HAR.40 -- npm run test:harness:executor

# Container launch values, plus an optional live probe of a deployed proof Worker
npm run test:harness:capacity
HARNESS_CAPACITY_URL=https://<proof-origin> HARNESS_CAPACITY_PATH=/healthz HARNESS_CAPACITY_CONCURRENCY=4 npm run test:harness:capacity
```

The live probe sends no credential, requires an `https` origin with no query, fragment or userinfo, refuses redirects, and bounds each request by `HARNESS_CAPACITY_TIMEOUT_MS` (default 120000, at most 180000).

## Proof 1: Workers AI binding and the ai.internal adapter

Driver: `eng/verification/harness-proof-ai.ts`. Realness: `node-fixture`.

| Check                                       | What it establishes                                                                                                        |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `frozen-request-forwarded-unchanged`        | one binding call with the frozen request and the admitted model                                                            |
| `json-answer-returned-unchanged`            | the binding answer comes back unaltered                                                                                    |
| `adapter-overhead-json-answered-every-time` | 50 of 50 JSON calls answered 200; p50 and p95 adapter overhead (fixture, not Workers AI latency)                           |
| `sse-pass-through-byte-identical`           | an SSE answer is byte-identical (SHA-256 compared)                                                                         |
| `sse-first-byte-before-stream-end`          | the first byte arrives while the binding is still producing (pass-through, not buffered)                                   |
| `sse-over-response-cap-is-cut-off`          | a stream over the C#-supplied cap is cut off mid-stream                                                                    |
| `binding-429-is-one-502-never-retried`      | a binding failure is one 502 `ai.upstream_failed`, one binding call                                                        |
| five refusal checks                         | admitted-set (403), body cap (413), hard ceiling (413), host (404) and method (405) refusals, each with zero binding calls |

Live steps that remain operator runs (`liveNotRun`):

1. Workers AI binding latency on the deployed Worker: deploy the proof environment with the AI binding and time `ai.internal` calls.
2. gpt-oss tier and its requests-per-minute admission: observe the account tier. No tier is assumed here.
3. Real 429 semantics, including whether a rate-limited call was counted or dispatched: provoke the limit on the proof account and record the response. Until then a 429 is treated as a possibly dispatched effect.
4. SSE pass-through across the Cloudflare edge: stream one answer through the deployed Worker.

## Proof 2: executor crash injection

Driver: `eng/verification/harness-proof-executor.ts`. Realness: `dotnet-local`. It runs `HarnessCrashTests` and `HarnessExecutorTests` (34 tests, including the ten-row crash matrix at claim, reserve, dispatch intent, outcome and yield, each before and after its commit) against the SQLite oracle with the checked-in plans.

Live steps that remain operator runs (`liveNotRun`):

1. Cloudflare D1 fenced writes under a real lease: kill the Container between a dispatch intent and its outcome on the proof environment.
2. Durable Object alarm wake after a real process restart: observe `HarnessRunAlarm` on the proof environment.

## Proof 3: container capacity

Driver: `eng/verification/harness-proof-capacity.ts`. Realness: `not-run` unless `HARNESS_CAPACITY_URL` is set, then `deployed-live`.

Locally the driver records the `wrangler.json` container values beside the Design launch target (`standard-2`, four realm slots, ten-minute idle sleep; architecture/05 line 74). Those values are observations: the production `CloudContainer` is `lite` with `max_instances` 1, and the target is not applied yet.

With the probe URL set, the driver takes one cold request (run it after the container has slept), then a parallel burst, and records each status and latency. The burst check passes only when every request answers 2xx.

Live steps that remain operator runs (`liveNotRun`):

1. Cold start on the standard-2 image after the container has slept.
2. `max_instances` semantics and per-instance concurrency: compare the instance names served across the burst. Cloudflare does not document these values; CLOUD.71 observed `max_instances` 2 serving one of two named instances at a time, which is history and not this proof.
3. Sleep with an open stream: hold one streamed response open past `sleepAfter` on the proof environment.

## Evidence template

Each record has the same shape. Copy the structure when a result is reported in another place; do not edit a recorded result.

```json
{
  "schemaVersion": 1,
  "proof": "<ai-binding | executor-crash | container-capacity>",
  "task": "HAR.40",
  "status": "<passed | failed | not-run>",
  "realness": "<node-fixture | dotnet-local | deployed-live | not-run>",
  "generatedAt": "<ISO-8601 UTC>",
  "checks": [
    {
      "name": "<check name>",
      "status": "<passed | failed | observed>",
      "expected": "<criterion>",
      "observed": "<measured value>"
    }
  ],
  "liveNotRun": ["<operator step>"],
  "notes": ["<limit of this run>"],
  "environment": { "<key>": "<value>" }
}
```

Operator live runs use the same template with `realness` set to `deployed-live`, a `environment` entry naming the deployed Worker version identifier and the Cloud build identity, and the operator's own name in `notes`. The proof account and URL are not recorded.

## Local results recorded for this tree (2026-10-08)

| Proof                | Status  | Realness     | Result                                                                      |
| -------------------- | ------- | ------------ | --------------------------------------------------------------------------- |
| `ai-binding`         | passed  | node-fixture | 12 of 12 checks passed; overhead p50 0.195 ms and p95 0.703 ms (fixture)    |
| `executor-crash`     | passed  | dotnet-local | 34 of 34 crash and executor tests passed on the clean build                 |
| `container-capacity` | not-run | not-run      | configuration observed only (`lite`, `max_instances` 1); live steps not run |

The live steps above are open. None of these results is a Cloudflare provider result.
