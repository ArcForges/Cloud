# Entitlement resolver

The Entitlement module (`src/ArcForges.Cloud.Modules.Entitlement`) resolves immutable grants and revocations, service terms and a versioned definition set into one entitlement snapshot per workspace (COM.05, WP-42.04). The resolver lives in the `Resolver` folder, with its layers as namespaces: `Resolver.Domain` (records, definitions, the pure resolver), `Resolver.Application` (the grant interface, the service and the ports) and `Resolver.Infrastructure` (the canonical stored form of a snapshot). Every type is `internal`; the module's own `Register` entry point lists the service and nothing is reachable from the network (no route, no method policy).

## What it guarantees

- **Deterministic.** `EntitlementResolver.Resolve(records, definitions, asOf)` is a pure function. It reads no clock, no store and no randomness, and it iterates only sorted, immutable inputs, so the order of the input records never changes the result. Instants are whole UTC microseconds (`UtcMicros`); an interval is closed at its start and exclusive at its end.
- **Rebuildable.** The snapshot version is itself a function of the records: the number of distinct effective changes across every instant at which a known record could change meaning, up to the evaluated instant. A snapshot is therefore independent of how often it was evaluated, and `EntitlementService.VerifyRebuildAsync` rebuilds it from the records alone at the instant it was computed and compares it in full, version and validity included. A difference is reported as `Mismatch` (a defect) and nothing is overwritten; `DefinitionsChanged` separates a snapshot computed under another definitions version.
- **Definitions changes raise the version.** Each activation of a definitions version after the first is a recorded input (`DefinitionsActivation`) and raises the version exactly once, even when the new definitions happen to produce equal content, because the earlier definitions are not part of the record set. The service records the activation the first time it sees different active definitions; a record set whose last activation is not the definitions being applied is refused.
- **Same-instant facts resolve by a total order.** Of workspace status facts recorded at one instant, the more restrictive status wins, then a cancelled renewal over a continuing one, then no pending purchase over a pending one; the later instant always wins. A store's row order never matters. Of several revocations of one grant the earliest effective one applies, so a later duplicate never resurrects a grant. Equal quota or allowance priorities are decided by grant identifier.
- **A refresh never lowers a stored version.** A derived version below the stored one means a record was admitted with a creation time before the stored computation; the service reports `InvalidHistory` and writes nothing. Owner admissions of terms, status facts and feature releases (COM.11 and the others) must stamp the authoritative time as their creation time.
- **Knowledge time.** At an instant only records created, recorded or released at or before it are known. A grant issued late with an earlier start never rewrites what was served before, and a late revocation takes effect when it is recorded (TM-01).
- **A reason for every entry.** Each capability, quota, allowance and feature carries one of `Available`, `NoEntitlement`, `SubscriptionExpired`, `PaymentGrace`, `TemporarilyRestricted`, `WorkspaceSuspended`, `FeatureUnavailable`. `QuotaExceeded` is in the vocabulary (ES-02) but is never assigned by the resolver: it is a usage fact owned by quota admission, and the snapshot is derived from grants and terms only.
- **Fail closed.** A record set the resolver cannot interpret (repeated identifiers, a foreign workspace, an orphan revocation, a revocation older than its grant, an interval that ends before it starts, an undefined enum value, more than 2000 records) throws `ResolverInputException`; the service turns it into `InvalidHistory`, produces no snapshot and writes nothing.

## Resolution rules

Service state is driven by paid-through (EN-05): the effective service intervals are `[max(starts_at, authorized_at), ends_at)` after term actions, merged where they overlap or abut. The state is `None`, `Pending`, `Active`, `CancelScheduled` (auto-renew off, still entitled), `Grace` (after paid-through, before the term's grace end), `Ended` or `Suspended`. A provider status string is not an input. A self-host service grant counts only in a self-host realm, and an official term only in an official realm (SV-04).

| Kind               | Combination rule                                                                                                                                                                                         |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Capability         | A valid sourced grant AND, for a capability whose definition requires it, an active paid term and no restriction. Suspension and an unreleased feature gate come first. No grant stands in for the term. |
| Quota              | Per definition: sum (base plus add-ons), maximum, or priority replace. The contributing grants are listed, so the limit is explainable.                                                                  |
| Allowance          | At most one selection by priority then grant identifier (no duplicate issuance); granted only during an active paid term. The capacity account itself is a later task.                                   |
| Consumable balance | Not a grant kind. It is a Commerce ledger projection and never resolver arithmetic.                                                                                                                      |

Which capabilities need a paid term, which quotas combine how, and which feature gates apply are data in the definitions the `IEntitlementDefinitionSource` port supplies (the activated configuration revision); no capability key or commercial figure is compiled into the resolver.

## The grant interface

`EntitlementService.IssueGrantAsync` and `RevokeGrantAsync` are the only way in (EO-03). Admission requires a closed source and kind, a source reference naming the originating transaction or audited action, a reason for administrative, compensation and migration grants, bounded values, and a window that ends after it starts. A replay with the same source reference is a no-op; a different grant under a used reference is a conflict. A revocation names one exact grant and the snapshot version the caller decided against, and a stale version writes nothing. Records and the snapshot that reflects them commit in one call to `IEntitlementStore.CommitAsync`, guarded by a per-workspace revision, so two writers never derive a snapshot from a history the other has already changed.

## Time

All evaluation uses the injected `TimeProvider` (one authoritative source, EN-08). **Single-clock assumption:** the module registers `TimeProvider.System` for each replica, and because the effective time never moves backwards past a stored computation, one replica whose clock runs ahead moves a workspace forward for every other replica. The composition must therefore supply one authoritative time source (or bound the accepted skew before it admits writes); the resolver does not. The effective time never moves backwards past a stored computation, so a clock that steps back neither rewinds a snapshot nor backdates a record.

A new record of a workspace is admitted at an instant strictly after the stored computation (at least one microsecond later), so no two admissions share an instant and the derived version, which counts changes across instants, can neither collapse nor fall because two records arrived together.

## Limits

- **Replay cost.** Every issue, revoke, refresh and expired read replays all points against all records (about 1.2 s for 1,700 records in Release on a development machine). History is bounded at 2000 records and there is no compaction path: a workspace at the bound returns `InvalidHistory` permanently until a compaction design exists.
- **The store port carries grants, revocations and activations only.** Terms, status facts and feature releases are appended by their owners; until those admissions extend the port or share the unit of work, a snapshot read from a store they appended to is stale until the next refresh and `VerifyRebuildAsync` reports a difference.

## Not covered here

- **Persistence.** `IEntitlementStore` has no production implementation: the D1 tables, named plans and migrations belong to the migration and plan tasks (CLOUD.03 and the storage plan owner). The tests use an in-memory store that implements the port's contract; it proves the resolver's logic and proves nothing about D1.
- **Service terms, status facts and feature releases** are read as records. Their owner admissions (COM.11 for terms, trust and safety for status, configuration for releases) are later tasks.
- **Distribution, quota and usage, credits, capacity and operator operations** are COM.06, COM.07, COM.08, COM.12 and COM.13.
- **The Commerce grant port has no owning task yet.** `IssueGrant`/`RevokeGrant` for Commerce (EO-03) need a type in the shared Abstractions project; the service is internal to the Entitlement project today.
- **The grant row has no reason column.** GR-05 requires a reason for administrative grants; the model carries it on `Grant.Reason` and the schema mapping is the persistence task's decision.
