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

## Validation actually performed

This section is completed with exact commands, commits, run identifiers and results when the
evidence exists. Until then nothing in it is claimed.
