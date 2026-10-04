# PRF.07 Cloudflare foundation proof

This document is the design, protocol and evidence record of the PRF.07 foundation proof (Design
WP-06.04, VG-06 supporting evidence). It states what the code implements, which checks run in
hosted CI, which run only as explicit local opt-in, and what has not been observed. It does not
claim any live Cloudflare result.

## Scope

The proof exercises the selected Cloudflare mechanisms end to end with the existing Native AOT host,
without introducing product behavior:

| Mechanism                       | What the proof implements                                                                                                                                                                                                                                                             | Where                                                                          |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Private D1 named-plan binding   | `POST /internal/storage/v1/execute-plan` on the virtual host `storage.internal`: the generated Contracts `ExecutePlan` request and reply, a reviewed plan dictionary with one SHA-256 manifest identity, typed bind and result kinds, one atomic `D1Database.batch()` per plan        | `worker/storage/**`, `src/ArcForges.Cloud/Storage/**`                          |
| Rollback on guard failure       | the guard row pattern of the D1 profile: a false precondition violates a named `CHECK` and the whole batch rolls back; the failure is reported as `precondition`                                                                                                                      | plan SQL, `worker/proof-migrations/0001_foundation_probe.sql`                  |
| Exact 64-bit and decimal values | int64 and uint64 travel as canonical decimal strings, are bound with `CAST(? AS INTEGER)` and returned with `CAST(column AS TEXT)`; decimals are canonical text; no JavaScript `Number` conversion exists on the path                                                                 | generator rules, `worker/storage/**`, `Storage/D1Values.cs`                    |
| Session, CSRF and revoke        | opaque 256-bit session handle stored only as a SHA-256 hash, twelve-hour absolute and thirty-minute idle expiry, CSRF token derived from the session, exact Origin and `X-AF-CSRF` checks on the unsafe route, guarded revocation that every Container observes through primary reads | `src/ArcForges.Cloud/Foundation/**`                                            |
| Bounded checkpoint and restart  | a finite job of at most 100 items or 20 seconds per slice, claimed under a D1 lease with a monotonic fence, committed in one guarded batch with an inbox row, resumable after the Container is stopped                                                                                | `src/ArcForges.Cloud/Foundation/**`, `worker/foundation/**`                    |
| Durable Object                  | one `FoundationJobCoordinator` per job: duplicate-delivery admission by event id and single-flight slices                                                                                                                                                                             | `worker/foundation/**`                                                         |
| Queue                           | wake hints that reference a job id only; D1 stays the authority; retries and a dead-letter queue                                                                                                                                                                                      | `worker/foundation/**`, `wrangler.json`                                        |
| R2                              | private bucket facade on `objects.internal`: bounded signed PUT with server-verified SHA-256 and signed range GET                                                                                                                                                                     | `worker/foundation/**`                                                         |
| Private ingress                 | the Container reaches bindings only through outbound handlers on exact virtual hosts; ordinary Internet egress stays disabled                                                                                                                                                         | `worker/index.ts`, `worker/storage/handler.ts`, `worker/foundation/objects.ts` |

The proof is deployed only by the explicit `proof` Wrangler environment (Worker
`arcforges-cloud-proof`, its own D1 database, R2 bucket, queue and Container), reachable only at the
dedicated custom domain `proof.arcforges.com`; `workers.dev` and preview URLs stay disabled. The production
`arcforges-cloud` Worker keeps its anonymous Hello behavior: every proof route is refused there
unless the `FOUNDATION_PROOF` variable is `enabled`.

Everything here is a proof of mechanisms. The probe tables are `probe_*` tables of the isolated proof
database; product modules own their tables and numbered migrations under RES-cloud-d1-migrations. The
proof does not implement a passkey ceremony, the WP-22 identity flows, the full object-grant ports of
contracts 05 section 9, the EventFeed and RunStream Durable Objects, Cron or Workflows.

## Protocol

### Private request signing

Every private request between the Container and the Worker handlers, in either direction, carries the
headers of contracts 05 section 2: `X-AF-Key-Id`, `X-AF-Time` (UTC epoch seconds), `X-AF-Nonce`
(unpadded base64url of 128 random bits), `X-AF-Request-Id` (lowercase UUID) and `X-AF-Signature`.

The signature is the unpadded base64url HMAC-SHA256 of the UTF-8 text

```text
METHOD LF exact-encoded-path-and-query LF time LF nonce LF request-id LF lowercase-hex-sha256-of-body
```

with LF separators and no trailing LF. The body hash of a byte transfer is the declared
`X-AF-Content-SHA256` value, so the signature is verified before any byte is accepted. Keys are
direction specific: `c2w` (Container to Worker) and `w2c` (Worker to Container). Each endpoint holds a
current and an optional previous 256-bit key and its pinned key identifiers. A verifier checks the
header shapes, rejects a time skew above 60 seconds, selects the key by identifier, compares the
signature in constant time and only then reads the body. Every refusal is the same empty HTTP 401, so
the reply never reveals which check failed. A nonce replay ledger is not implemented in this proof;
the outbound handler path and the exact route allowlist are the primary boundary and the signature is
defense in depth.

### Storage

`POST http://storage.internal/internal/storage/v1/execute-plan`, `application/json`, at most 256 KiB.
The body is the generated `ExecutePlanRequest`; the reply is HTTP 200 with the generated
`ExecutePlanResponse`, success or typed failure. The Worker accepts a request only when, in this order:

1. the signature is valid and the body parses as a strict `ExecutePlanRequest`;
2. the signed request id equals the body request id;
3. the plan id and version exist and the manifest hash equals the Worker dictionary hash
   (otherwise `invalidPlan`);
4. the recovery generation equals the active one (otherwise `staleGeneration`);
5. the deadline lies in the future and at most ten seconds ahead (an expired deadline is
   `unavailable` and nothing ran);
6. the argument arrays match the plan statement by statement: counts, kinds, nullability, exact
   integer ranges, canonical decimals, and every `scope` argument equals the request owner scope.

A write plan runs as one atomic batch and returns no rows; its change count is the sum of the batch
statement changes. A read plan runs one statement and returns at most `maxRows` rows. A deadline that
expires during a write is `unknownOutcome` and the caller must read the receipt, never resend under a
new command id. A violated named guard is `precondition`; any other SQLite constraint is `constraint`.

### Plans

`src/ArcForges.Cloud/Storage/Plans/<owner>/<name>.sql` are the reviewed plans. A header declares
`plan`, `version`, `access` and `maxRows`; each `-- statement:` block declares `params=` and `returns=`
kinds (`int64 uint64 decimal text bytes bool scope`, a trailing `?` marks a nullable value). The
generator `node eng/verification/storage-plans.ts` validates the files and writes
`worker/storage/plans.generated.ts` and `src/ArcForges.Cloud/Storage/PlanManifest.g.cs`; `--check` is
part of `npm run check`. It refuses comments, several statements in one block, DDL, `PRAGMA`,
`RETURNING`, named placeholders, an int64 argument that is not wrapped as `CAST(? AS INTEGER)` and any
other argument that is.

## Resource names (binding plan)

Names reserved for the proof environment (RES-cloud-deployment and RES-cloud-leased-singletons). Each
has exactly one owner, this task, and later module tasks use their own names.

| Kind            | Name                                                                                                                                                                                                                                                   |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Worker          | `arcforges-cloud-proof` (Wrangler environment `proof`)                                                                                                                                                                                                 |
| D1              | binding `DB`, database `arcforges-proof-business`                                                                                                                                                                                                      |
| R2              | binding `OBJECTS`, bucket `arcforges-proof-objects`, key `realm/<realm>/workspace/<workspace>/diagnostic/<resource>/<sha256>`                                                                                                                          |
| Queue           | binding `WAKE_QUEUE`, queue `arcforges-proof-wake`, dead-letter queue `arcforges-proof-wake-dlq`                                                                                                                                                       |
| Durable Objects | `CloudContainer` (the unchanged production Container controller), `FoundationContainer` (its proof-environment subclass, which alone registers the outbound hosts and the environment hook) and `FoundationJobCoordinator`; no alarm namespace is used |
| Ingress         | custom domain `proof.arcforges.com` of `arcforges-cloud-proof` only (`wrangler.json` `env.proof.routes`); `workers_dev` and `preview_urls` are `false`; the production route `arcforges.com/api/*` and the Web apex Custom Domain are not referenced   |
| Virtual hosts   | `storage.internal`, `objects.internal`                                                                                                                                                                                                                 |

## Behavior

### Sessions, CSRF and revocation

`GET /session/v1/bootstrap` and `POST /session/v1/logout` are the two routes of the Contracts browser-session
exception schema (`BrowserBootstrapResponse`, `BrowserSessionProjection`, `BrowserReceipt`, all generated).

- The cookie is `__Host-af_session`, holding a random 256-bit handle. Only its SHA-256 is stored.
- A session ends at twelve hours absolute, thirty minutes idle (renewed only by the explicit bootstrap, never
  past the absolute limit), on revocation, or when its recovery generation differs from the configured one.
- The CSRF token is the HMAC of the session's handle hash under a deployment secret, so it needs no storage.
  The anonymous bootstrap token is a different value that never verifies on the unsafe route.
- Logout needs the exact configured `Origin`, a valid session cookie and `X-AF-CSRF`, all checked before any
  write. A safe GET may omit `Origin`, but a present one must match exactly.
- Revocation is one guarded batch (session row, outbox row). Any Container reads the primary through the same
  plans, so a revoked session is refused everywhere on the next read. A second logout is `unauthenticated`.
- Session issue exists only as the proof route `session/issue` because the WP-22 ceremonies are not part of
  this task; it returns the only copy of the handle.

### Bounded checkpoint and restart

A job has at most 1,000 items. One slice handles at most 100 items or 20 seconds (always at least one item),
claims a 60-second D1 lease with a monotonic fence, and commits items, cursor, running sum, inbox row and
outbox row in one guarded batch that also releases the lease. A stale holder fails the fence guard, a repeated
event id fails the inbox key, and a restarted Container resumes from the stored cursor. Item amounts are
exact checked int64 values (`(n + 1) * 4611686018427`, each below 2^53 within the 1,000-item limit); the running
sum passes 2^53 from the 63rd item on, so the stored uint64 sum and checksum are exact only if the whole path is
exact, and they are compared with a sum computed independently. The `exact` route covers single values above 2^53.

The Queue message carries only the job id, scope and a fresh event id. The Durable Object admits an event once and
allows one slice in flight per job; it is a disposable projection, so losing it can only cause a safe re-check.

## Pipeline order (BR-06 item 9)

The existing workflow runs the offline and build parts of this task on every pull request and every main build, not
once: the plan and Worker tests, the C# tests, the dependency, licence and provenance gates, and the Native AOT image
and Worker bundle build. The foundation scenarios against a running host and Worker, and the live proof, are local
opt-in and never run in CI. Its order is unchanged:
`Source` (Linux and Windows: locked restores, `npm run check` including the plan-manifest check, the Worker vectors,
the dependency, licence and provenance gates, format, lint and typecheck; the Linux job also runs `npm run check:dotnet`
with the C# tests and the format check) and `Dependency audit and repository checks` (including the secret scan), then
`Native AOT image and Worker build` (the Linux Native AOT image with `IlcTreatWarningsAsErrors` and
`ILLinkTreatWarningsAsErrors`, so any trim or AOT diagnostic fails the build, plus the sealed Worker bundle and its legal
inspection), then `Verify`. Only a successful main build deploys. It deploys the default Worker and the production Hello container: the
default Container class is unchanged (no outbound interception, no environment hook, pinned by
`tests/worker/container-classes.test.ts`), the default configuration is unchanged, and the Worker bundle is larger
(61,990 bytes in Hello, 168,129 bytes now) because it now contains the dormant foundation modules, which answer nothing without
`FOUNDATION_PROOF=enabled`. The image likewise contains the dormant host module. The proof environment is never
deployed by a push or a pull request; it is deployed only by the manually dispatched jobs described
under Deploying below, and no CI job connects to the deployed service.

## Running the checks

| Check                                                                                    | Command                                                                     | Where it runs                                                                              |
| ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Plan manifest, Worker vectors and tests                                                  | `npm run check`                                                             | hosted CI and locally                                                                      |
| C# build, tests, format                                                                  | `npm run check:dotnet`                                                      | hosted CI and locally                                                                      |
| Linux Native AOT image and sealed Worker candidate                                       | `npm run candidate`                                                         | hosted CI (needs Docker)                                                                   |
| Local cross-process integration (real host, workerd with local D1/R2/DO/Queue emulation) | `FOUNDATION_HOST_EXE=<host executable> npm run test:foundation:local`       | explicit local opt-in only                                                                 |
| Proof token access, resources and deployment                                             | dispatch of `CI` on `main` with `proof` = `access`, `provision` or `deploy` | manually dispatched CI jobs in the `cloudflare` environment, never on push or pull request |
| Live scenarios against the deployed proof environment                                    | `npm run test:foundation:live`                                              | explicit local opt-in only, under the lease `RES-cloud-deployment`                         |

### Deploying and exercising the proof environment

The deployment runs in CI, so that the Cloudflare token and the proof secrets never leave GitHub Actions and
Cloudflare. Nothing is deployed by a push or a pull request.

1. **Dispatch** the `CI` workflow on `main` with the input `proof`:
   - `access` runs `npm run access:proof` (job `Proof Cloudflare access and resources`, `cloudflare` environment):
     read probes of the token's Workers Scripts, D1, R2, Queues and `arcforges.com` zone permissions, printed as
     `PASS` / `FAIL` / `INFO` lines of capability names and HTTP statuses only.
   - `provision` adds `npm run provision:proof`: idempotent creation, after a lookup by exact name, of the D1
     database `arcforges-proof-business`, the R2 bucket `arcforges-proof-objects` and the queues
     `arcforges-proof-wake` and `arcforges-proof-wake-dlq`. Nothing else is created, changed or deleted.
   - `deploy` runs both and then, in the job `Deploy Cloudflare proof environment`, consumes the sealed candidate of the
     same run: pushes the sealed image, applies the proof migration to the proof database, deploys
     `--env proof` with `--containers-rollout immediate` and a configuration generated at deploy time (the real D1
     database id, the registry image digest, the revision), and attaches the custom domain `proof.arcforges.com`.
2. **Secrets.** `HMAC_C2W_SECRET`, `HMAC_W2C_SECRET` and `CSRF_SECRET` are 256-bit random values generated inside the
   deploy step, written to a runner-local file that Wrangler uploads with the Worker version (`--secrets-file`), and
   removed immediately. They are never printed, committed or stored elsewhere, and a redeploy rotates them. There is
   no operator token: see Operator access below.
   Before the domain is attached the job stops if a DNS record for `proof.arcforges.com` exists (or the zone, domain or
   DNS lookup cannot be read) unless the domain already serves the proof Worker, so an existing record or service is
   never taken over.
3. **Receipts, not tests.** After the deployment the job reads provider metadata only: `workers.dev` and preview URLs are
   disabled (an absent field counts as not disabled) for the proof Worker, the custom domain `proof.arcforges.com` serves `arcforges-cloud-proof`, the production route
   `arcforges.com/api/*` still serves `arcforges-cloud` and no route of the zone serves the proof Worker. The job
   writes `proof-deployment.json` (revision, version, image digest, hostname, database id, receipts; no secret) as the
   artifact `proof-evidence-<run>-<attempt>`. No request is sent to the deployed service by CI.
4. **Live scenarios** (explicit local opt-in, once, under the lease): hold
   `python tools/delivery.py claim RES-cloud-deployment --worker W --task PRF.07` only for the run, then
   `npm run test:foundation:live` (default target `https://proof.arcforges.com`; `PROOF_BASE_URL` overrides it) and
   release the lease immediately. The run writes `artifacts/foundation-live-evidence.json`; it never records a secret.

### Operator access

The proof surface (`/proof/v1/*`) lets its caller drive the D1, R2, Queue and Container paths, so it is gated, but the
person or agent who runs the live scenarios must not need a shared secret. The Worker therefore trusts an Ed25519
**public key** (`PROOF_OPERATOR_VERIFIER`, a plain variable of `env.proof`, committed in `wrangler.json`) and each
operator request carries a signature:

```text
Authorization: AF-Operator t=<UTC epoch seconds>,n=<unpadded base64url of 128 random bits>,s=<unpadded base64url Ed25519 signature>
signed text:   AF-OPERATOR-V2 LF METHOD LF host LF exact-path LF t LF n LF lowercase-hex-sha256-of-body
```

The Worker reads the bounded body, verifies the signature over its hash, rejects a time skew above 60 seconds and
answers every refusal with the same empty HTTP 401. The private key is generated by
`npm run operator:proof -- init` into `~/.arcforges/proof-operator/ed25519-private.pem` (or
`PROOF_OPERATOR_KEY_FILE`), is never printed, committed or uploaded, and is used only by
`eng/verification/proof-operator.ts` to sign. Only the public key is printed. A new key means a new public key in
`wrangler.json` and a redeploy. The signature binds the host, so a request signed for another origin is refused. It has no nonce store, so a captured request can be replayed within the skew
window, which the operator surface tolerates because TLS protects the transport and every operation is a proof
operation on the isolated proof database. The browser-session routes (`/session/v1/*`) need no operator credential: the
bootstrap is anonymous and the session round trip starts from `session/issue`, an operator operation, so the PRF.08
session and CSRF round trip is run with the same local signing key and without any human handling a secret.

The scenario file `eng/verification/foundation-scenarios.ts` runs exact `int64`, `uint64` and `decimal` values through
the operator JSON surface, not gRPC-Web: the deployed proof environment exposes no generated gRPC-Web service that
carries those primitives (the Hello service carries strings), so the PRF.05 exact-value gRPC-Web scenarios have no
method to call there until a service that carries them exists.

### R2 facade: what "mismatch rejection" means

A PUT whose bytes do not hash to the declared (and signed) SHA-256, or whose length differs from the declared length,
is answered 422 and stores nothing, whether or not the key already exists. The first live run found that the
conditional write (`etagDoesNotMatch: "*"`) returns without evaluating R2's own checksum when the key exists, so a
mismatching body was answered 200 `existing`; the facade therefore reads the bounded body (one part, 8 MiB), verifies
length and hash itself and only then writes. The scenario checks both an existing key and a fresh key and reports the
status of each. The offline fake models the same conditional-first behavior, with a test that fails on the old facade.

### Live evidence and the Hello ingress

`npm run test:foundation:live` runs every scenario even when one fails and writes
`artifacts/foundation-live-evidence.json` (one row per scenario with its detail, error text and elapsed time) before it
reports a failure. It also observes the existing anonymous Hello ingress on the proof origin (`/api/healthz` and a
hand-framed `SayHello`), which only shows that the same Worker serves `/api` next to the proof surface. The proof
exposes no generated gRPC-Web service that carries int64, uint64 and decimal values: that needs a new Contracts service
and published packages, so PRF.05's exact-value gRPC-Web scenario is not served here.

### Blocked egress

The proof Container keeps Internet access disabled (`enableInternet = false`); its only outbound paths are the interception
hosts `storage.internal` and `objects.internal`. The operator operation `egress/probe` makes the host attempt a harmless
`HEAD` to `http://example.com/` and to the literal address `http://1.1.1.1/` (no body, no redirect, response body never
read, 8 second limit each) and reports only host, outcome and elapsed time.

**What blocked means on this platform.** The first live probe showed that Cloudflare does not refuse the connection: the
hostname attempt timed out after the whole window (8,002 ms) and the literal address was accepted and dropped within about
1 ms (`reached_then_failed`), while the allowed control path answered in the same call. The accepted criterion is therefore
**no HTTP response at all** (no status line of any code, including a 520 from a proxy), not "connection refused". The
scenario `egress-blocked` passes only when every attempt got no response (`connection_failed`, `timeout` and
`reached_then_failed` all count), both a hostname and a literal address were attempted, and the control path, the host's
storage readiness through the interception, answered in the same call, so a broken probe cannot pass vacuously. Any status
line, a failed control or fewer than two attempts fails it. The platform's own accept-then-drop behavior is the reason a
peer that accepts and then closes counts as no response here; the limits of that criterion are that it cannot distinguish a
silent drop from a very slow open route (the elapsed times are recorded, and the hostname attempt is seen to use its whole
window) and that it proves the absence of an answer, not the mechanism. A timeout is not required to use the whole window, so a slow open route can false-pass; a peer that answers with something other than HTTP (a banner or a TLS alert) is also "no response" here, since only a status line counts as an answer. The C# tests run the real HTTP stack and host route
against a closed port, a silent listener, peers that accept and then close or reset, and answering servers with status 200,
404 and 520 (all answering cases fail), and a failed control. Production does not serve the operation.

### Rollout and instance limits of the live run

After a deployment a Container instance that was started before the rollout finished can still run the previous image (the
first run after the second deployment answered a new operation with 404 from the old host). The live runner therefore first
waits, for at most three minutes, until both the Worker revision header and the Hello instance's health revision equal the
expected revision (the checked-out commit, or `PROOF_EXPECTED_REVISION`); that instance is only a signal that the platform now
starts the new image. It then stops the foundation instance (the stop must succeed) and restarts it with a readiness call whose
reply carries the host's own compiled revision, which must equal the expected one; the exact-value and egress scenarios run
against that foundation instance. The proof environment (and only it) allows two Container instances, because the Hello
`/api` instance and the foundation instance are separate Durable Object instances of one class and contended for the single
slot with `max_instances: 1`; production keeps one instance. The Hello scenario retries thrown errors within its 150 second deadline; each request is bounded by the remaining time, so it cannot overrun the deadline by an iteration.

## Not claimed

- No live Cloudflare result of any kind: no deployed D1, R2, Queue, Durable Object or Container behavior, no outbound
  handler interception, no blocked-egress or public-denial proof on a real deployment, no provider limits.
- The outbound handlers use plain HTTP to the two virtual hosts inside the platform; HTTPS interception (HP-01) needs the
  Cloudflare CA to be installed in the image and is not configured here.
- No nonce replay ledger, passkey ceremony, WP-22 identity flow, object grants of contracts 05 section 9, EventFeed or
  RunStream Durable Object, Cron, Workflow or alarm.
- SQLite is not D1: the offline plan vectors prove the SQL, constraints and batch rollback, not Cloudflare's network
  path or primary-read behavior.
- Replay protection is partial. Signature, a 60 second skew window, key selection and the exact route check exist;
  the 120 second nonce store with exact-retry replay, the route-audience allowlist and the key-overlap purge of
  contracts 05 section 2 do not.
- The R2 facade (`/internal/objects/v1/probe/...`) and `worker/proof-migrations/0001_foundation_probe.sql` are
  proof-only. They are not the CON.15 job-object ports and are not part of the global D1 migration sequence.
- The CI proof jobs (`access`, `provision`, `deploy`) are exercised offline only (fake Cloudflare API, configuration
  and secret generation); their first run on the real account is recorded in the ledger, not here.
- The proof environment binds `FoundationContainer`; its container start path with outbound interception has not been
  observed on Cloudflare. The production class does not register any.

## Validation actually performed

All results below were observed on the claimant's Windows 11 machine (ArcForges delivery worker w-c20261002-prf07) and
are claimant-reported until the independent review and hosted CI confirm them. Nothing here is a live Cloudflare result.

| Check                                   | Command                                                                                                      | Observed                                                                                                                                     |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Worker and tooling tests                | `npm test`                                                                                                   | 176 tests passed, 0 failed                                                                                                                   |
| Dependency policy                       | `npm run test:dependencies`, `node tooling/dependency-policy.ts`                                             | 18 passed; policy and receipt `prf-07-r1` verify                                                                                             |
| Licence, provenance                     | `node tooling/project.ts licence`, `node tooling/project.ts provenance`                                      | pass                                                                                                                                         |
| Real bundle against the release profile | `node tooling/project.ts prepare-provenance-test` then `node --test tests/worker/release-provenance.test.ts` | 10 of 10 passed (bundle 168129 bytes)                                                                                                        |
| Plan generator drift                    | `npm run check:plans`                                                                                        | 19 plans, manifest hash matches the generated TS and C#                                                                                      |
| Formatting, lint, types                 | `prettier --check .`, `biome lint`, `tsc` for both projects                                                  | clean                                                                                                                                        |
| C# build and tests                      | `dotnet build` and `dotnet test` of `Cloud.slnx`, Release, under the build slot                              | 0 warnings, 159 tests passed                                                                                                                 |
| Cross-process local integration         | `npm run test:foundation:local`                                                                              | readiness, exact values, guard rollback, session/CSRF/revoke, R2 objects, checkpoint restart (one host restart) and public denial all passed |
| Native AOT                              | local `dotnet publish` for win-x64                                                                           | linked and ran in the local integration run above                                                                                            |
| Mutation checks                         | 13 deliberate mutations of the C# host                                                                       | 13 of 13 caught by the tests                                                                                                                 |

Local integration uses the real Native AOT host process and workerd (Miniflare) with local D1, R2, Durable Object and
Queue emulation, and a Node SQLite bridge standing in for D1.

### Unobserved

- Any deployed Cloudflare behavior: D1, R2, Queue, Durable Object, Container, outbound handlers, blocked egress,
  public-surface denial, provider limits. `npm run test:foundation:live` has not been run against a deployment as of this document.
- The Linux Native AOT image and the Docker build (no Docker here); they are exercised only by hosted CI.
- The local Node and npm are newer than the pinned toolchain; the pinned toolchain check runs only in hosted CI.
- SQLite and workerd are emulation, not the provider.

### What the live evidence needs

The deployed proof environment (dispatch `CI` with `proof` = `deploy`, see above), the operator key file on the
workstation that runs the scenarios, and the `RES-cloud-deployment` lease for that run. Until the scenarios have run
against the deployment and their evidence is recorded, PRF.07 cannot be complete.
