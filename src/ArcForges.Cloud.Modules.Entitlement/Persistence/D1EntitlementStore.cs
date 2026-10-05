// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;

/// <summary>The named plans of the Entitlement owner (<c>storage/plans/entitlement</c>); the only strings this module hands to the plan port.</summary>
internal static class EntitlementPlans
{
    public const string Commit = "entitlement.commit";
    public const string RevisionLoad = "entitlement.revision-load";
    public const string SnapshotLoad = "entitlement.snapshot-load";
    public const string GrantsLoad = "entitlement.grants-load";
    public const string RevocationsLoad = "entitlement.revocations-load";
    public const string TermsLoad = "entitlement.terms-load";
    public const string TermActionsLoad = "entitlement.term-actions-load";
    public const string StatusFactsLoad = "entitlement.status-facts-load";
    public const string ActivationsLoad = "entitlement.activations-load";
    public const string FeatureReleasesLoad = "entitlement.feature-releases-load";
    public const string FeatureReleaseGet = "entitlement.feature-release-get";
    public const string FeatureReleaseAppend = "entitlement.feature-release-append";
}

/// <summary>
/// The production <see cref="IEntitlementStore"/>: the Entitlement module's own persistence over D1, written only against the
/// Abstractions plan port (a module reaches storage through named plans and nothing else). One commit appends the records and replaces
/// the snapshot together with the owner receipt, the change-archive record and one notification outbox row in one guarded batch, under
/// the workspace's <c>entitlement_revision</c> row: a stale writer's guard is false and nothing commits (the first commit of a workspace
/// creates the row, and a concurrent first commit fails its guard). The command identity of a commit is derived from its content, so a
/// repeat after an unknown outcome is recognised by its receipt and never applied twice.
/// </summary>
internal sealed class D1EntitlementStore(IModulePlanPort plans) : IEntitlementStore
{
    /// <summary>Most records of one kind a single commit may carry; far above any admission and far below the 64 KiB change record and 256 KiB request bounds.</summary>
    public const int MaxAppendPerKind = 100;

    /// <summary>How long a replay of a commit is answered from its receipt.</summary>
    public static readonly long ReceiptRetentionMicros = 7L * 86_400_000_000;

    /// <summary>Rows per keyset page (the bound of the load plans). A page cursor starts at the smallest signed 64-bit value, never at zero: an instant may be zero.</summary>
    private const int PageSize = 100;
    private const int LoadAttempts = 3;
    private const string GlobalScope = "entitlement.global";
    private const string Actor = "entitlement-module";
    private const string Operation = "entitlement.commit";
    private const string EventType = "entitlement.snapshot.changed";
    private const string AggregateKind = "entitlement.snapshot";

    public async ValueTask<EntitlementState> LoadAsync(string workspaceId, CancellationToken cancellationToken)
    {
        var scope = RequireWorkspace(workspaceId);
        for (var attempt = 0; attempt < LoadAttempts; attempt++)
        {
            var revision = await ReadRevisionAsync(scope, cancellationToken).ConfigureAwait(false);
            var snapshot = await ReadSnapshotAsync(scope, cancellationToken).ConfigureAwait(false);
            var budget = new Budget();
            var grants = await Pages(EntitlementPlans.GrantsLoad, scope, [PlanValue.FromInt64(0), PlanValue.FromInt64(long.MinValue), PlanValue.FromText("")], budget,
                row => EntitlementRowCodec.ReadGrant(scope, row), row => [row[1], row[6], row[0]], cancellationToken).ConfigureAwait(false);
            var revocations = await Pages(EntitlementPlans.RevocationsLoad, scope, [PlanValue.FromInt64(long.MinValue), PlanValue.FromText("")], budget,
                EntitlementRowCodec.ReadRevocation, row => [row[5], row[0]], cancellationToken).ConfigureAwait(false);
            var terms = await Pages(EntitlementPlans.TermsLoad, scope, [PlanValue.FromInt64(long.MinValue), PlanValue.FromText("")], budget,
                EntitlementRowCodec.ReadTerm, row => [row[2], row[0]], cancellationToken).ConfigureAwait(false);
            var actions = await Pages(EntitlementPlans.TermActionsLoad, scope, [PlanValue.FromInt64(long.MinValue), PlanValue.FromText("")], budget,
                EntitlementRowCodec.ReadTermAction, row => [row[4], row[0]], cancellationToken).ConfigureAwait(false);
            var facts = await Pages(EntitlementPlans.StatusFactsLoad, scope, [PlanValue.FromInt64(long.MinValue), PlanValue.FromText("")], budget,
                EntitlementRowCodec.ReadStatusFact, row => [row[1], row[0]], cancellationToken).ConfigureAwait(false);
            var activations = await Pages(EntitlementPlans.ActivationsLoad, scope, [PlanValue.FromInt64(long.MinValue)], budget,
                EntitlementRowCodec.ReadActivation, row => [row[1]], cancellationToken).ConfigureAwait(false);
            var releases = await Pages(EntitlementPlans.FeatureReleasesLoad, scope, [PlanValue.FromText("")], budget,
                EntitlementRowCodec.ReadRelease, row => [row[0]], cancellationToken, scoped: false).ConfigureAwait(false);

            // Every commit of the workspace advances the revision in the same batch as its rows, so a read that saw one revision before and after
            // all its pages saw one consistent history; otherwise a commit landed in between and the read starts again.
            if (await ReadRevisionAsync(scope, cancellationToken).ConfigureAwait(false) != revision) continue;
            var records = new EntitlementRecordSet(scope, grants, revocations, terms, actions, facts, releases, activations);
            return new EntitlementState(records, snapshot, revision);
        }

        throw new EntitlementStoreException(EntitlementStoreFailure.Unavailable, "The workspace changed during every attempt to read it.");
    }

    public async ValueTask<CommitOutcome> CommitAsync(
        string workspaceId, long expectedRevision, EntitlementAppend append, EntitlementSnapshot snapshot, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(append);
        ArgumentNullException.ThrowIfNull(snapshot);
        var scope = RequireWorkspace(workspaceId);
        if (expectedRevision < 0 || expectedRevision == long.MaxValue) throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        if (snapshot.WorkspaceId != workspaceId) throw new ArgumentException("The snapshot belongs to another workspace.", nameof(snapshot));
        if (append.Grants.Length > MaxAppendPerKind || append.Revocations.Length > MaxAppendPerKind || append.Terms.Length > MaxAppendPerKind
            || append.TermActions.Length > MaxAppendPerKind || append.Activations.Length > MaxAppendPerKind || append.StatusFacts.Length > MaxAppendPerKind)
        {
            throw new ArgumentException("A commit carries at most " + MaxAppendPerKind + " records of one kind.", nameof(append));
        }

        foreach (var grant in append.Grants)
        {
            if (grant.WorkspaceId != workspaceId) throw new ArgumentException("A grant belongs to another workspace.", nameof(append));
        }

        RequireWellFormed(append);
        var columns = SnapshotMapper.ToColumns(snapshot);
        var newRevision = expectedRevision + 1;
        var grants = EntitlementRowCodec.GrantsJson(append.Grants);
        var revocations = EntitlementRowCodec.RevocationsJson(append.Revocations);
        var terms = EntitlementRowCodec.TermsJson(append.Terms);
        var actions = EntitlementRowCodec.TermActionsJson(append.TermActions);
        var activations = EntitlementRowCodec.ActivationsJson(append.Activations);
        var facts = EntitlementRowCodec.StatusFactsJson(append.StatusFacts);

        // The identity of the command is the content: the same commit under the same revision is the same command, whatever the attempt.
        var hash = Hash(scope, expectedRevision, grants, revocations, terms, actions, activations, facts, columns);
        var commandId = IdOf(hash, "command");
        var workspace = Guid.ParseExact(scope, "D");
        var command = PlanValue.FromText(commandId.ToString("D"));
        var owner = new IReadOnlyList<PlanValue>[]
        {
            [command, PlanValue.FromText(scope), PlanValue.FromInt64(expectedRevision)],
            [PlanValue.FromText(scope), PlanValue.FromInt64(newRevision), PlanValue.FromInt64(snapshot.ComputedAt.Value), PlanValue.FromInt64(expectedRevision)],
            [PlanValue.FromText(scope), PlanValue.FromText(grants)],
            [PlanValue.FromText(revocations)],
            [PlanValue.FromText(scope), PlanValue.FromText(terms)],
            [PlanValue.FromText(actions)],
            [PlanValue.FromText(scope), PlanValue.FromText(activations)],
            [PlanValue.FromText(scope), PlanValue.FromText(facts)],
            [PlanValue.FromText(scope), PlanValue.FromInt64(columns.Version), PlanValue.FromInt64(columns.ComputedAt), PlanValue.FromInt64(columns.ValidUntil ?? -1),
                PlanValue.FromText(columns.Capabilities), PlanValue.FromText(columns.Quotas), PlanValue.FromText(columns.Features)],
        };
        var result = Json(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("revision", newRevision);
            writer.WriteNumber("entitlementVersion", columns.Version);
            writer.WriteEndObject();
        });
        // The receipt is stamped with the instant the snapshot was computed for (a receipt needs a positive instant; only an instant at the
        // Unix epoch itself, which a real clock never reports, is lifted to the first microsecond).
        var created = Math.Max(snapshot.ComputedAt.Value, 1);
        var commit = new ModuleCommit(
            commandId, workspace, Actor, Operation, hash, result, newRevision, created, created + ReceiptRetentionMicros,
            [new ModuleOutboxEvent(IdOf(hash, "outbox"), AggregateKind, workspace, newRevision, EventType, result, workspace, commandId, null)],
            1, ChangeRecord(scope, newRevision, columns.Version, append));
        var outcome = await plans.WriteAsync(new ModulePlanWrite(EntitlementPlans.Commit, scope, owner, commit), cancellationToken).ConfigureAwait(false);
        return outcome.Status switch
        {
            ModulePlanStatus.Succeeded or ModulePlanStatus.Replayed => CommitOutcome.Committed,
            ModulePlanStatus.GuardRefused => CommitOutcome.RevisionConflict,
            ModulePlanStatus.UnknownOutcome => CommitOutcome.UnknownOutcome,
            ModulePlanStatus.Unavailable or ModulePlanStatus.StaleGeneration => throw new EntitlementStoreException(EntitlementStoreFailure.Unavailable, "The commit was not executed: " + outcome.Status + "."),
            _ => throw new EntitlementStoreException(EntitlementStoreFailure.Defect, "The commit was refused: " + outcome.Status + "."),
        };
    }

    public async ValueTask<FeatureReleaseOutcome> AppendFeatureReleaseAsync(FeatureReleaseFact release, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(release);
        if (!InputRules.IsKey(release.Feature)) throw new ArgumentException("A feature release names a malformed feature.", nameof(release));
        if (release.ReleasedAt.Value <= 0) throw new ArgumentException("A feature release has a positive instant.", nameof(release));
        // The owner scope of a feature release is the feature itself, which the Worker checks against the scope argument of the plan.
        var scope = release.Feature;
        var outcome = await plans.WriteAsync(new ModulePlanWrite(EntitlementPlans.FeatureReleaseAppend, scope,
            [[PlanValue.FromText(release.Feature), PlanValue.FromInt64(release.ReleasedAt.Value)]], null), cancellationToken).ConfigureAwait(false);
        switch (outcome.Status)
        {
            case ModulePlanStatus.Succeeded:
                return FeatureReleaseOutcome.Released;
            case ModulePlanStatus.ConstraintRefused:
                // The feature already has a release: the same instant is a replay, any other is a conflict. Nothing was written either way.
                var existing = await plans.ReadAsync(new ModulePlanRead(EntitlementPlans.FeatureReleaseGet, scope, [PlanValue.FromText(scope)]), cancellationToken)
                    .ConfigureAwait(false);
                Require(existing, "read the feature release");
                if (existing.Rows.Count != 1 || existing.Rows[0].Count != 1) throw EntitlementRowCodec.Defect("A feature release constraint failed but no release exists.");
                return existing.Rows[0][0].AsInt64() == release.ReleasedAt.Value ? FeatureReleaseOutcome.AlreadyReleased : FeatureReleaseOutcome.Conflict;
            case ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome or ModulePlanStatus.StaleGeneration:
                throw new EntitlementStoreException(EntitlementStoreFailure.Unavailable, "The feature release was not confirmed: " + outcome.Status + ".");
            default:
                throw new EntitlementStoreException(EntitlementStoreFailure.Defect, "The feature release was refused: " + outcome.Status + ".");
        }
    }

    /// <summary>Text with an unpaired surrogate would be replaced on the way to D1 and the stored row would differ from the record the caller holds, so it is refused here.</summary>
    private static void RequireWellFormed(EntitlementAppend append)
    {
        var texts = append.Grants.SelectMany(g => new[] { g.GrantId, g.Subject, g.SourceRef, g.IssuedByActor, g.Reason, (g.Value as AllowanceValue)?.CapacityPlanRef })
            .Concat(append.Revocations.SelectMany(r => new[] { r.RevocationId, r.GrantId, r.ReasonCode, r.IssuedByActor }))
            .Concat(append.Terms.SelectMany(r => new[] { r.Fact.TermId, r.RealmId, r.SubscriptionRef, r.PeriodRef, r.SupersedesId, r.OfferId, r.OfferSnapshotId }))
            .Concat(append.TermActions.SelectMany(r => new[] { r.ActionId, r.SourceRef, r.Fact.TermId, r.ReplacementTermId }))
            .Concat(append.Activations.Select(a => a.Version))
            .Concat(append.StatusFacts.SelectMany(f => new[] { f.FactId, f.SourceRef }));
        if (texts.Any(text => text is not null && !Utf16.IsWellFormed(text))) throw new ArgumentException("A record holds text with an unpaired surrogate.", nameof(append));
    }

    private async Task<long> ReadRevisionAsync(string scope, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new ModulePlanRead(EntitlementPlans.RevisionLoad, scope, [PlanValue.FromText(scope)]), cancellationToken).ConfigureAwait(false);
        Require(outcome, "read the revision");
        if (outcome.Rows.Count == 0) return 0;
        if (outcome.Rows.Count != 1 || outcome.Rows[0].Count != 1) throw EntitlementRowCodec.Defect("The revision answer is malformed.");
        var revision = outcome.Rows[0][0].AsInt64();
        return revision >= 0 ? revision : throw EntitlementRowCodec.Defect("A stored revision is negative.");
    }

    private async Task<EntitlementSnapshot?> ReadSnapshotAsync(string scope, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new ModulePlanRead(EntitlementPlans.SnapshotLoad, scope, [PlanValue.FromText(scope)]), cancellationToken).ConfigureAwait(false);
        Require(outcome, "read the snapshot");
        if (outcome.Rows.Count == 0) return null;
        if (outcome.Rows.Count != 1 || outcome.Rows[0].Count != 6) throw EntitlementRowCodec.Defect("The snapshot answer is malformed.");
        var row = outcome.Rows[0];
        return SnapshotMapper.FromColumns(scope, new SnapshotColumns(row[0].AsInt64(), row[1].AsInt64(), row[2].AsOptionalInt64(), row[3].AsText(), row[4].AsText(), row[5].AsText()));
    }

    /// <summary>
    /// Reads one record kind in keyset pages: each page asks for the rows after the last one it returned, in the plan's own order, so no row
    /// is skipped or repeated. A history past the resolver's bound stops the read; the resolver then refuses the oversized set as invalid.
    /// </summary>
    private async Task<ImmutableArray<T>> Pages<T>(
        string planId, string scope, PlanValue[] start, Budget budget, Func<IReadOnlyList<PlanValue>, T> read,
        Func<IReadOnlyList<PlanValue>, PlanValue[]> cursorOf, CancellationToken cancellationToken, bool scoped = true)
    {
        var items = ImmutableArray.CreateBuilder<T>();
        var cursor = start;
        while (true)
        {
            // The global feature release table has no workspace: its reads are called under the one global scope.
            var owner = scoped ? scope : GlobalScope;
            var arguments = new[] { PlanValue.FromText(owner) }.Concat(cursor).ToArray();
            var outcome = await plans.ReadAsync(new ModulePlanRead(planId, owner, arguments), cancellationToken).ConfigureAwait(false);
            Require(outcome, "read " + planId);
            foreach (var row in outcome.Rows) items.Add(read(row));
            budget.Used += outcome.Rows.Count;
            if (outcome.Rows.Count < PageSize || budget.Used > InputRules.MaxRecords) return items.ToImmutable();
            cursor = cursorOf(outcome.Rows[^1]);
        }
    }

    private static void Require(ModulePlanOutcome outcome, string what)
    {
        switch (outcome.Status)
        {
            case ModulePlanStatus.Succeeded:
                return;
            case ModulePlanStatus.Unavailable or ModulePlanStatus.StaleGeneration:
                throw new EntitlementStoreException(EntitlementStoreFailure.Unavailable, "Could not " + what + ": " + outcome.Status + ".");
            default:
                throw new EntitlementStoreException(EntitlementStoreFailure.Defect, "Could not " + what + ": " + outcome.Status + ".");
        }
    }

    /// <summary>Entitlement identifiers of the physical schema are canonical lower-case UUID text; the resolver accepts any token, so the store is where the stricter shape is enforced.</summary>
    private static string RequireWorkspace(string workspaceId)
    {
        ArgumentNullException.ThrowIfNull(workspaceId);
        if (workspaceId.Length != 36 || !Guid.TryParseExact(workspaceId, "D", out var parsed) || parsed == Guid.Empty
            || !string.Equals(parsed.ToString("D"), workspaceId, StringComparison.Ordinal))
        {
            throw new ArgumentException("A workspace identifier is a canonical lower-case UUID.", nameof(workspaceId));
        }

        return workspaceId;
    }

    private static string Hash(string scope, long expectedRevision, params object[] parts)
    {
        var text = new StringBuilder(scope).Append('\n').Append(expectedRevision.ToString(CultureInfo.InvariantCulture));
        foreach (var part in parts)
        {
            text.Append('\n').Append(part is SnapshotColumns c
                ? string.Join('\n', c.Version.ToString(CultureInfo.InvariantCulture), c.ComputedAt.ToString(CultureInfo.InvariantCulture),
                    c.ValidUntil?.ToString(CultureInfo.InvariantCulture) ?? "-", c.Capabilities, c.Quotas, c.Features)
                : (string)part);
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }

    /// <summary>A stable identifier derived from the content hash and a purpose, in the canonical UUID form every <c>id</c> column requires.</summary>
    private static Guid IdOf(string hash, string purpose)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(purpose + ":" + hash));
        var id = new byte[16];
        Array.Copy(bytes, id, 16);
        id[7] = (byte)((id[7] & 0x0F) | 0x50);
        id[8] = (byte)((id[8] & 0x3F) | 0x80);
        return new Guid(id, bigEndian: true);
    }

    private static string ChangeRecord(string scope, long revision, long version, EntitlementAppend append) => Json(writer =>
    {
        writer.WriteStartObject();
        writer.WriteString("workspaceId", scope);
        writer.WriteNumber("revision", revision);
        writer.WriteNumber("entitlementVersion", version);
        List(writer, "grants", append.Grants.Select(grant => grant.GrantId));
        List(writer, "revocations", append.Revocations.Select(revocation => revocation.RevocationId));
        List(writer, "terms", append.Terms.Select(term => term.Fact.TermId));
        List(writer, "termActions", append.TermActions.Select(action => action.ActionId));
        List(writer, "activations", append.Activations.Select(activation => activation.Version));
        List(writer, "statusFacts", append.StatusFacts.Select(fact => fact.FactId));
        writer.WriteEndObject();
    });

    private static void List(Utf8JsonWriter writer, string name, IEnumerable<string> values)
    {
        writer.WriteStartArray(name);
        foreach (var value in values) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }

    private static string Json(Action<Utf8JsonWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer)) write(writer);
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private sealed class Budget
    {
        public int Used { get; set; }
    }
}
