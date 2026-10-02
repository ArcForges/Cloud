# PRF.07 Cloudflare foundation proof

This document is the design, protocol and evidence record of the PRF.07 foundation proof (Design
WP-06.04, VG-06 supporting evidence). It states what the code implements, which checks run in
hosted CI, which run only as explicit local opt-in, and what has not been observed. It does not
claim any live Cloudflare result.

## Scope

The proof exercises the selected Cloudflare mechanisms end to end with the existing Native AOT host,
without introducing product behavior:

| Mechanism                       | What the proof implements                                                                                                                                                                                                                                                             | Where                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Private D1 named-plan binding   | `POST /internal/storage/v1/execute-plan` on the virtual host `storage.internal`: the generated Contracts `ExecutePlan` request and reply, a reviewed plan dictionary with one SHA-256 manifest identity, typed bind and result kinds, one atomic `D1Database.batch()` per plan        | `worker/storage/**`, `src/ArcForges.Cloud/Storage/**`         |
| Rollback on guard failure       | the guard row pattern of the D1 profile: a false precondition violates a named `CHECK` and the whole batch rolls back; the failure is reported as `precondition`                                                                                                                      | plan SQL, `worker/proof-migrations/0001_foundation_probe.sql` |
| Exact 64-bit and decimal values | int64 and uint64 travel as canonical decimal strings, are bound with `CAST(? AS INTEGER)` and returned with `CAST(column AS TEXT)`; decimals are canonical text; no JavaScript `Number` conversion exists on the path                                                                 | generator rules, `worker/storage/**`, `Storage/D1Values.cs`   |
| Session, CSRF and revoke        | opaque 256-bit session handle stored only as a SHA-256 hash, twelve-hour absolute and thirty-minute idle expiry, CSRF token derived from the session, exact Origin and `X-AF-CSRF` checks on the unsafe route, guarded revocation that every Container observes through primary reads | `src/ArcForges.Cloud/Foundation/**`                           |
| Bounded checkpoint and restart  | a finite job of at most 100 items or 20 seconds per slice, claimed under a D1 lease with a monotonic fence, committed in one guarded batch with an inbox row, resumable after the Container is stopped                                                                                | `src/ArcForges.Cloud/Foundation/**`, `worker/foundation/**`   |
| Durable Object                  | one `FoundationJobCoordinator` per job: duplicate-delivery admission by event id and single-flight slices                                                                                                                                                                             | `worker/foundation/**`                                        |
| Queue                           | wake hints that reference a job id only; D1 stays the authority; retries and a dead-letter queue                                                                                                                                                                                      | `worker/foundation/**`, `wrangler.json`                       |
| R2                              | private bucket facade on `objects.internal`: bounded signed PUT with server-verified SHA-256 and signed range GET                                                                                                                                                                     | `worker/foundation/**`                                        |
| Private ingress                 | the Container reaches bindings only through outbound handlers on exact virtual hosts; ordinary Internet egress stays disabled                                                                                                                                                         | `worker/index.ts`, `worker/foundation/outbound.ts`            |

The proof is deployed only by the explicit `proof` Wrangler environment (Worker
`arcforges-cloud-proof`, its own D1 database, R2 bucket, queue and Container). The production
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

| Kind            | Name                                                                                                                          |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Worker          | `arcforges-cloud-proof` (Wrangler environment `proof`)                                                                        |
| D1              | binding `DB`, database `arcforges-proof-business`                                                                             |
| R2              | binding `OBJECTS`, bucket `arcforges-proof-objects`, key `realm/<realm>/workspace/<workspace>/diagnostic/<resource>/<sha256>` |
| Queue           | binding `WAKE_QUEUE`, queue `arcforges-proof-wake`, dead-letter queue `arcforges-proof-wake-dlq`                              |
| Durable Objects | `CloudContainer` (Container controller) and `FoundationJobCoordinator`; no alarm namespace is used                            |
| Virtual hosts   | `storage.internal`, `objects.internal`                                                                                        |

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
exact checked int64 values above 2^53 and the stored sum is compared with a sum computed independently.

The Queue message carries only the job id, scope and a fresh event id. The Durable Object admits an event once and
allows one slice in flight per job; it is a disposable projection, so losing it can only cause a safe re-check.

## Pipeline order (BR-06 item 9)

The existing workflow runs this proof on every pull request and every main build, not once. Its order is unchanged:
`Source` (Linux and Windows: locked restores, `npm run check` including the plan-manifest check, the Worker vectors,
the dependency, licence and provenance gates, format, lint and typecheck; the Linux job also runs `npm run check:dotnet`
with the C# tests and the format check) and `Dependency audit and repository checks` (including the secret scan), then
`Native AOT image and Worker build` (the Linux Native AOT image with `IlcTreatWarningsAsErrors` and
`ILLinkTreatWarningsAsErrors`, so any trim or AOT diagnostic fails the build, plus the sealed Worker bundle and its legal
inspection), then `Verify`. Only a successful main build deploys, and it deploys the production Hello Worker exactly as
before: the proof environment is never deployed by CI and CI never connects to a live service.

## Running the checks

| Check                                                                                    | Command                                                               | Where it runs                                                                            |
| ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Plan manifest, Worker vectors and tests                                                  | `npm run check`                                                       | hosted CI and locally                                                                    |
| C# build, tests, format                                                                  | `npm run check:dotnet`                                                | hosted CI and locally                                                                    |
| Linux Native AOT image and sealed Worker candidate                                       | `npm run candidate`                                                   | hosted CI (needs Docker)                                                                 |
| Local cross-process integration (real host, workerd with local D1/R2/DO/Queue emulation) | `FOUNDATION_HOST_EXE=<host executable> npm run test:foundation:local` | explicit local opt-in only                                                               |
| Deployed proof environment                                                               | `npm run deploy:proof`, then `npm run test:foundation:live`           | explicit local opt-in only, needs Cloudflare access and the lease `RES-cloud-deployment` |

### Deploying and exercising the proof environment

This is the live part. It was not run by the author of this change because it needs interactive Cloudflare
account access that does not exist in the authoring environment.

1. One-time account setup by the account owner: create the D1 database `arcforges-proof-business`, the R2 bucket
   `arcforges-proof-objects` and the queues `arcforges-proof-wake` and `arcforges-proof-wake-dlq`, and an API token
   with Workers Scripts, Containers, D1, R2 and Queues edit rights for that account.
2. Export `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` for the local session, and the secrets
   `PROOF_OPERATOR_TOKEN`, `PROOF_HMAC_C2W_SECRET`, `PROOF_HMAC_W2C_SECRET` and `PROOF_CSRF_SECRET` (each at least 32
   random bytes encoded as unpadded base64url, the operator token any 32 to 256 URL-safe characters). Optionally set
   `PROOF_D1_DATABASE_ID`.
3. Build the sealed candidate (`npm run candidate`, needs Docker), then hold the lease
   `python tools/delivery.py claim RES-cloud-deployment --worker W --task PRF.07` for the live run only.
4. `npm run deploy:proof` pushes the sealed image, applies the proof migration, sets the four Worker secrets and deploys
   `--env proof`. Set `PROOF_BASE_URL` to the resulting `workers.dev` origin and run `npm run test:foundation:live`.
5. Release the lease immediately. The run writes `artifacts/foundation-live-evidence.json`; it never records a secret.

## Not claimed

- No live Cloudflare result of any kind: no deployed D1, R2, Queue, Durable Object or Container behavior, no outbound
  handler interception, no blocked-egress or public-denial proof on a real deployment, no provider limits.
- The outbound handlers use plain HTTP to the two virtual hosts inside the platform; HTTPS interception (HP-01) needs the
  Cloudflare CA to be installed in the image and is not configured here.
- No nonce replay ledger, passkey ceremony, WP-22 identity flow, object grants of contracts 05 section 9, EventFeed or
  RunStream Durable Object, Cron, Workflow or alarm.
- SQLite is not D1: the offline plan vectors prove the SQL, constraints and batch rollback, not Cloudflare's network
  path or primary-read behavior.

## Validation actually performed

This section is completed with exact commands, commits, run identifiers and results when the
evidence exists. Until then nothing in it is claimed.
