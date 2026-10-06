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

The snapshot includes the actual recovery revision for subsequent request-specific fencing. A successful read alone does not make a later security mutation atomic with a recovery-state change. Security family consumers require an actual Platform-owned sealed current-epoch guard participant under their reviewed family plan; its follow-up owner is CLOUD.75/Cloud integration coordination. Identity cannot manufacture a foreign Platform role. Full restore acceptance and real provider/network behavior remain separately deferred until the corresponding transport and restore producers are available.

## Validation evidence and pending checks

The locked npm installation audited zero vulnerabilities, and full solution locked restore passed. Three offline tests run the real production Worker executor and exact SQL over all numbered migrations in SQLite: closed plan ownership/boundedness, realm/current-state and maximum int64 changes, and twelve concurrent side-effect-free reads. All three passed without skips. SQLite is not a provider deployment, provider authentication proof or OS isolation proof.

At source checkpoint `830e834c3ee2987e1acd7527c5812b97cfc527ac`, all 31 managed authority tests passed without skips. They drive the actual registered host adapter, actual `RecoveryEpochReader`, `ModulePlanPortFactory` and production Worker executor through the existing SQLite bridge. Only unavailable transport/error injection and the clock for fast deadline verification use fakes. They cover required configuration, current/version changes, wrong realm, missing/corrupt rows, closed states, generation mismatch, concurrency, bounded retry, deadline and cancellation. The first build diagnosed mandatory xUnit caller-cancellation wiring; the test source was corrected without disabling the analyzer before this successful run.

Before delivery, the owner will record actual managed results, exact immutable artifact/admission successors, independent review, current-head CI and the real publication/deployment receipt. CLOUD.21 owns real signed transport and configured production activation; restore acceptance belongs to the recovery/restore delivery owner. No mocked result is evidence of real deployment or whole-system acceptance.
