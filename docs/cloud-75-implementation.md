# CLOUD.75 production realm authority

The shared `IRealmAuthorityPort` resolves a required deployment authentication epoch and a real persisted Platform recovery epoch. The single shared contract lives in `Abstractions/Platform/RealmAuthorityPort.cs`; Identity, PAT and session consumers use that contract rather than a user revision or a proof-mode constant.

The ordered delivery is: implement the closed typed contracts and Platform-owned named read; bind required configuration through the real lazy host adapter; run actual owner/read/configuration/lifecycle tests; rebase onto the accepted integration predecessor, regenerate the manifest and seal an immutable successor from actual artifact inputs; obtain independent exact-head review, passing applicable CI and fenced delivery; then wire the delivered producer into its consumers. No new module project, package, schema column, table or public route is introduced.

## Configuration and composition

The host registers `RealmAuthorityModule` explicitly and serves no route through it. Security authority resolution captures these required environment values once, lazily:

- `AF_REALM_ID`: one canonical lowercase non-nil GUID in D form.
- `AF_AUTH_EPOCH`: one canonical positive signed 64-bit decimal integer.
- `AF_RECOVERY_GENERATION`: one canonical nonnegative signed 64-bit decimal integer.

Missing or invalid values refuse before storage access. Health and anonymous bootstrap requests remain available because registration neither reads these values nor resolves the executor. Configuration never defaults to a proof realm, epoch 1 or generation 0. A later environment change cannot silently replace the identity of an already initialized process; a correctly configured deployment must replace the process.

The adapter builds the Platform owner's `ModulePlanPortFactory` from the required expected generation, the actual `IPlanExecutor` and `TimeProvider`. It does not reuse `FoundationOptions` or replace another module's factory. An unavailable executor is a typed refusal. Production signed Worker transport and Worker-to-Container environment activation remain CLOUD.21-owned; this implementation is composed and testable without pretending that the default host already has that transport activated.

## Persisted current authority

`RecoveryEpochReader` seals its own `ModuleDescriptor.Create("Platform", "platform")` and executes only `platform.recovery-current`. This read selects at most one row by exact realm primary key and returns realm, generation, state and revision from `platform_recovery_epoch` with exact int64 encoding. It never writes or switches realm.

Each call rereads storage. The result must contain exactly one correctly typed row, the requested realm, a nonnegative generation, a positive revision and a known recovery state. Only current/open state 4 is usable; fenced, restoring and reconciling states refuse. The host additionally requires the stored generation to equal the configured expected generation. A newer persisted generation is a stale deployment refusal, never automatically adopted.

Unavailable or unknown read outcomes retry at most three times with 50 ms and 100 ms backoff. Each attempt has an eight-second deadline. Caller cancellation propagates before reads, during reads, after acknowledgement and during backoff. Stale generation, malformed rows, rejected plans and closed recovery states do not retry. Failed reads never become missing rows.

The snapshot includes the actual recovery revision for subsequent request-specific fencing. A successful read alone does not make a later security mutation atomic with a recovery-state change. Security family consumers use the actual Platform-owned sealed current-epoch guard participant described below, under their reviewed registered family plan. Identity cannot manufacture a foreign Platform role. Full restore acceptance and real provider/network behavior remain separately deferred until the corresponding transport and restore producers are available.

## Validation evidence and pending checks

The locked npm installation audited zero vulnerabilities, and full solution locked restore passed. Three offline tests run the real production Worker executor and exact SQL over all numbered migrations in SQLite: closed plan ownership/boundedness, realm/current-state and maximum int64 changes, and twelve concurrent side-effect-free reads. All three passed without skips. SQLite is not a provider deployment, provider authentication proof or OS isolation proof.

At source checkpoint `830e834c3ee2987e1acd7527c5812b97cfc527ac`, all 31 managed authority tests passed without skips. They drive the actual registered host adapter, actual `RecoveryEpochReader`, `ModulePlanPortFactory` and production Worker executor through the existing SQLite bridge. Only unavailable transport/error injection and the clock for fast deadline verification use fakes. They cover required configuration, current/version changes, wrong realm, missing/corrupt rows, closed states, generation mismatch, concurrency, bounded retry, deadline and cancellation. The first build diagnosed mandatory xUnit caller-cancellation wiring; the test source was corrected without disabling the analyzer before this successful run.

Before delivery, the owner will record actual managed results, exact immutable artifact/admission successors, independent review, current-head CI and the real publication/deployment receipt. CLOUD.21 owns real signed transport and configured production activation; restore acceptance belongs to the recovery/restore delivery owner. No mocked result is evidence of real deployment or whole-system acceptance.

## Atomic recovery contribution

`IRealmAuthorityFamilyPort.PrepareAsync` resolves the real configured authority afresh, then asks the exact shared `ModuleFamilyPortFactory` to issue one opaque `PlatformRecoveryFamilyGuard`. The caller supplies only family, plan and owner scope. The registered role must be exactly platform/guard/authorization/recovery-current with the closed non-null command/realm/int64 generation/state/revision shape. The configured generation must equal the shared factory generation; missing shared activation refuses lazily rather than using a private or proof issuer.

The immutable capability binds the shared issuer identity, exact family/plan/scope/generation and actual realm/current-open state 4/captured positive recovery revision. `WriteAsync` accepts this separate Storage-owned capability and validates every contribution before receipt preflight. Generic business Platform contributions, receipt/outbox/archive/release authority and caller SQL remain rejected. Changed persisted recovery state, generation, realm or revision refuses the guard in the same Worker transaction as all mutations and tail effects. Configured AuthEpoch-only rollover is a CLOUD.21 stale-container drain/configuration obligation; no nonexistent D1 AuthEpoch predicate is claimed.

Production uses the generated closed catalogue. An internal constructor copies and freezes the entire nested fixture catalogue for ordinary component tests; there is no public custom-plan API. A test-owned future enrollment consumer inserts the actual generated Platform recovery predicate before the unchanged actual enrollment statements. The real issuer, composer, plan argument validation and Worker batch execute over all SQLite migrations, with a separately owner-issued Workspace contribution. Old registered enrollment plans and their production SQL are unchanged. This is actual component atomicity evidence for the consumer contract, not a deployed security route or provider D1 acceptance.

Guard cases exercise cross-issuer, forged, duplicate, missing, wrong-scope, wrong-plan, stale generation, unavailable activation, wrong role/shape, cancellation and caller-mutated catalogue inputs. SQLite cases cover all non-open states, generation/revision/realm transitions after prepare, same-command fresh reread/replay, eight concurrent writers and late-tail unknown failure with receipt reconciliation and no mutation retry. The offline oracle directly checks every affected owner/tail table for rollback; its unclassified trigger error is correctly reported as UnknownOutcome, never as safely retryable success.

Final ordinary component verification before immutable seal: 330 managed cases passed, zero skipped, including the real future-consumer rollback/replay/concurrency cases, all new issuer/copy/cross-plan cases, existing Identity/family regressions and lazy host/authority components. The first expanded run exposed a missing pre-existing Consumer assembly required by BuildMetadataTests; an actual locked Consumer build completed with zero warnings/errors, then the bounded expanded retry passed. Three actual Worker read cases, full TypeScript typecheck, owned strict lint and full owned formatter passed. No test failure was suppressed and no fake component replaced production behavior.

## Scope and correspondence successor

The first full 751-case Worker check exposed the new bounded read's missing owner-scope parameter. The producer now uses params=scope and the reader signs the canonical realm as both OwnerScope and argument; the existing generator/gate is unchanged. Wrong signed realm scope is refused by the actual production WorkerPlanExecutor before HTTP dispatch, and the real Worker oracle separately refuses it. The regenerated65-plan manifest is68a94e039b2c10bbf92b388734ac3ddb2a911da524c442861c0262ef9a0d962b. All12 focused Worker read/generator cases and273 relevant managed Identity/family/authority/Platform regression cases passed, zero skipped, including the real guarded future-consumer rollback cases. Three new public family port/result methods now have exact RP-10 correspondence to actual capability and closed-result tests; the architecture engine was not changed.

A separate existing commerce10ms test returned the intentional pre-dispatch408 under full parallel load rather than its assumed post-dispatch504. One isolated justified diagnostic rerun passed; the same case also passed the actual hosted run. Runtime classification and foreign test source remain unchanged. The initialr47/cloud75r1 seal remains immutable history; the scope/correspondence correction requires a new reservedr48/cloud75r2 actual artifact/input successor and fresh CI before delivery.

CLOUD.21 transport activation consumes the same internal lazy ConfiguredRealmOptionsCapture as authority resolution. Capture/TryGetConfigured performs no database/executor lookup, freezes required canonical values once, and never adopts changed environment values. All32 actual RealmAuthority tests passed after this minimum composition bridge; owned formatter passed. Fresh full CI remains required.
