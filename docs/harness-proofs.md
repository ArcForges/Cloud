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

Driver: `eng/verification/harness-proof-executor.ts`. Realness: `dotnet-local`. It runs `HarnessCrashTests` and `HarnessExecutorTests` (38 tests, including the ten-row crash matrix at claim, reserve, dispatch intent, outcome and yield, each before and after its commit) against the SQLite oracle with the checked-in plans.

Live steps that remain operator runs (`liveNotRun`):

1. Cloudflare D1 fenced writes under a real lease: kill the Container between a dispatch intent and its outcome on the proof environment.

Deferred to HAR.00 (a reviewed deferral, not an operator step for this proof):

2. Durable Object alarm wake after a real process restart. Nothing in HAR.40 arms `HarnessRunAlarm`: no Worker route calls `schedule`, and the proof environment (`env.proof` in `wrangler.json`) binds no `HarnessRunAlarm` (the production Worker binds `HARNESS_RUN_ALARM`, and nothing arms it). The C# wake route is mapped only under `FOUNDATION_PROOF`, so an alarm POST would be refused in production. The wake contract and its offline tests pass; the arming path, the proof binding and the live observation belong to HAR.00 ([harness foundation](harness-foundation.md), Wake).

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

## Local results recorded for this tree (2026-10-09)

Tree: `task/har-40` at code commit `af732b55970b1a7be7d70287fa1e99f6b9431f27` (tree `740ff1b8112d064b9645312d84d989e56d8530f9`). That commit is the last change to code, tests and the budget comment. The commit that records this section changes only this file after it. Every offline, proof and Native AOT result below was run at `af732b5`, through the workstation build slot unless stated otherwise. The Windows runs used the clean worktree with SDK 10.0.401 from `global.json` and Node v24.20.0. The WSL run used a Linux-native clone of the same commit (see the Native AOT records below). Each proof record is written under `artifacts/harness-proof/`, which Git ignores; the three records were regenerated by the run at `af732b5` (`generatedAt` 2026-10-09T02:53Z).

Earlier stamps in this section (`3725db0` and `7aaebd4`) are superseded. At `7aaebd4` the batch passed except `check:dotnet`, which failed on a stale naming report (RP-08) that the policy step refreshes, and `format:check`, which flagged this file. Both pass at `af732b5`.

### Proof records

| Proof                | Status  | Realness     | Result                                                                                                                                                                            |
| -------------------- | ------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ai-binding`         | passed  | node-fixture | 12 of 12 checks passed; 50 of 50 JSON calls answered 200; overhead p50 0.088 ms and p95 0.406 ms (fixture, not Workers AI latency); SSE first byte at 35.8 ms of 1,269.2 ms total |
| `executor-crash`     | passed  | dotnet-local | 2 of 2 checks passed; the filtered `dotnet test` (`HarnessCrashTests` and `HarnessExecutorTests`) reported 38 total, 38 succeeded, 0 failed, exit 0                               |
| `container-capacity` | not-run | not-run      | no probe URL set; two configuration observations (`CloudContainer` `lite`, `max_instances` 1; launch target not applied) and no pass; the live steps are not run                  |

The live steps above are open. None of these results is a Cloudflare provider result.

### Offline validation at af732b5 (Windows)

| Command                                                                                                                                       | Exit | Counts                                                                                                                                                                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run check:dotnet` (restore `--locked-mode`, Release build, test, format verify)                                                          | 0    | 1,365 total, 1,365 succeeded, 0 failed, 0 skipped across `ArcForges.Cloud.Tests` and `ArchitectureTests` (both `Passed`)                                                                                                                                              |
| `npm run check` (restore `ArchitectureTests --locked-mode`, `test:dependencies`, `check:plans`, `check:physical`, `policy`, then `toolchain`) | 1    | The first five steps passed: 18 of 18 dependency tests; 65 plans, no rewrites; 162 tables, 105 enums; 26 numbered migrations, 0 pending; `policy` 821 files, 0 exceptions, 0 findings. The sixth step, `toolchain`, stopped on the Node pin (see the Node gap below). |
| `node tooling/project.ts licence` (run separately after the stop)                                                                             | 0    | no findings printed                                                                                                                                                                                                                                                   |
| `node tooling/project.ts provenance` (run separately after the stop)                                                                          | 0    | no findings printed                                                                                                                                                                                                                                                   |
| `npm run format:check`                                                                                                                        | 0    | all matched files use Prettier code style                                                                                                                                                                                                                             |
| `npm run lint`                                                                                                                                | 0    | 399 files, no findings                                                                                                                                                                                                                                                |
| `npm run typecheck`                                                                                                                           | 0    | `tsconfig.json` and `tsconfig.worker.json`                                                                                                                                                                                                                            |
| `npm test`                                                                                                                                    | 0    | 777 tests, 777 passed, 0 failed, 0 skipped; includes the model-token test added at `af732b5`                                                                                                                                                                          |
| `npm run test:harness:ai`                                                                                                                     | 0    | `ai-binding` passed, 12 checks                                                                                                                                                                                                                                        |
| `npm run test:harness:executor`                                                                                                               | 0    | `executor-crash` passed, 2 checks                                                                                                                                                                                                                                     |
| `npm run test:harness:capacity`                                                                                                               | 0    | `container-capacity` not-run (no probe URL set)                                                                                                                                                                                                                       |

`npm run check` as a whole exits 1 on this machine, at the toolchain step only. The other steps were run as above, with the exit codes shown.

**Node gap.** The local runtime is Node v24.20.0. `package.json` (`engines`) and `.node-version` pin 24.21.0, and the toolchain step fails its pinned-version assertion (`tooling/project.ts`, `verifyToolchain`). This is a local environment gap, recorded as not run locally. Hosted CI is the authority for this gate (brief section 10), and no Node download was made for it.

### Native AOT publishes (P2-024)

| Target      | Machine                                                                                                         | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `win-x64`   | Windows 11 Pro for Workstations, clean worktree at `af732b5`, SDK 10.0.401                                      | `restore --locked-mode` exit 0; `publish -c Release -r win-x64` exit 0; `ArcForges.Cloud.exe`, 18,775,552 bytes; `--build-info` exit 0 reports `sourceCommit` `af732b5`, `dirty` false, kind `local`. Host run: `GET /healthz` 200 with `revision` `af732b5`; `SayHello` with name `World` 200, body `Hello, World!`, `grpc-status: 0`; empty name 200 with `grpc-status: 3` and `Name must not be empty.`; unknown method 200 with the trailer `grpc-status: 12` (`unimplemented`). The host stopped on SIGTERM. |
| `linux-x64` | WSL2 Debian GNU/Linux 13 (trixie), kernel 6.18.40.1-microsoft-standard-WSL2, Linux-native clone (`~/har40-fix`) | `publish -c Release -r linux-x64` exit 0 after the unlocked restore; `ArcForges.Cloud`, 18,506,840 bytes; `--build-info` exit 0 reports `sourceCommit` `af732b5`, `dirty` true (the uncommitted SDK adapter below). Host run: `GET /healthz` 200 with `revision` `af732b5-dirty`; `SayHello` with name `World` 200, body `Hello, World!`, `grpc-status: 0`. The host stopped on SIGTERM. The empty-name and unknown-method calls were not repeated on WSL in this record.                                         |

- The WSL toolchain was .NET SDK 10.0.400 with runtime 10.0.11, Debian clang and LLD 19.1.7. The clone was fetched from a git bundle of `task/har-40` at `af732b5`, then checked out at that commit with a clean tree before the adapter.
- Locked restore failed under SDK 10.0.400 with exit 1 (NU1004), the same cause as before: `Microsoft.NET.ILLink.Tasks` is requested as `[10.0.12, )` and resolves to 10.0.11, and `Microsoft.DotNet.ILCompiler` differs the same way. The committed lock files were not changed to match.
- Unlocked restore (the documented fallback) exited 0 only after a temporary `global.json` adapter that changed the SDK pin from 10.0.401 to 10.0.400. The adapter and the rewritten `packages.lock.json` files exist in the Linux clone only, and are not committed.
- The first win-x64 publish attempt in the batch failed with MSB3073: the Native AOT link step calls `vswhere.exe`, which was not on the batch `PATH`. The retry added the Visual Studio Installer directory (`C:\Program Files (x86)\Microsoft Visual Studio\Installer`) to `PATH` for that run only and exited 0. No project file changed.

### Decision: the root `@arcforges/proto` devDependency stays (ADP-07)

`@arcforges/proto` 1.0.0-ci.287.1 remains a root devDependency. No successor receipt was written, and no manifest or lock file changed. Reasons:

- The architecture rule `WirePackagePin` in `tests/ArchitectureTests/AiHarness/HarnessArchitectureRules.cs` requires an exact, registry-locked pin of the public wire package in the root manifest and its lock. Removing the entry would make the wire-package rule refuse.
- `@arcforges/api-client`, also a root devDependency, depends on `@arcforges/proto`, so its lock entry stays whatever the root says.
- No Worker or product source imports the package. `tests/worker/identity-structure.test.ts` reads its generated `dist/gen` files, and `tooling/licence-boundary.ts` names it.

A later change to the package is a separate admission, not part of HAR.40.

## Local candidate attempt (2026-10-09): environment limitation

Tree: `task/har-40` at `9b4b3b4b1b1015fb81673bf09d6356be8b03a173`, clean worktree. The run used `npm run candidate` through the build slot (`delivery.py build-slot run --worker w-deku-20261008-har-40 --task HAR.40`), with the docker launcher kept outside the repository (it forwards to `wsl -e docker`) on `PATH` for that run only.

| Attempt                                    | Result                                                                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| 1                                          | Not started. The slot started `npm` without a shell and Windows could not find it (WinError 2). No npm or docker process ran.         |
| 2 (the one retry, `npm.cmd run candidate`) | Reached the container image's NuGet restore and stalled. No package restore completed. The build was stopped after about 516 seconds. |

The stall: 29 timeout lines from the container's restore against `api.nuget.org`, either 100-second request timeouts or 60-second no-data timeouts. The failing packages were `Microsoft.NET.ILLink.Tasks` 10.0.12 (4 times), `Microsoft.DotNet.ILCompiler` 10.0.12, `ArcForges.Build.Policy` 1.0.0-ci.94.1, `Grpc.AspNetCore.Web` 2.84.0 (2 times), `ArcForges.Contracts.CloudInternal` 1.0.0-ci.287.1, and the `ArcForges.Contracts.PublicApi` package index.

This is classified as a local environment limitation. The host and a plain container reach nuget.org, but the container image's restore does not. No proxy, DNS or network change was made. No candidate manifest and no candidate image were produced; the stopped run left only the git-ignored `artifacts/candidate/legal-notices.json`. No container was left running. Per the 2026-10-09 HAR.40 local candidate adjudication (brief section 10), the hosted candidate job is the authority for the candidate.

Offline gates re-run at this HEAD after the stop:

| Command                              | Exit | Result                                             |
| ------------------------------------ | ---- | -------------------------------------------------- |
| `npm run policy`                     | 0    | `Cloud: pass; 821 files; 0 exceptions; 0 findings` |
| `node tooling/project.ts provenance` | 0    | no findings                                        |
