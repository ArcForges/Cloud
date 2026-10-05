// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Application;

internal enum RebuildStatus
{
    /// <summary>The snapshot rebuilt from the records alone equals the stored snapshot exactly, version included.</summary>
    Equal,

    /// <summary>The rebuild differs under the same definitions. This is a defect, never a refresh (EN-02).</summary>
    Mismatch,

    /// <summary>The active definitions are not the ones the stored snapshot was computed under; a refresh records their activation.</summary>
    DefinitionsChanged,

    /// <summary>No snapshot is stored yet.</summary>
    NoSnapshot,
}

internal sealed record RebuildReport(string WorkspaceId, RebuildStatus Status, EntitlementSnapshot? Stored, EntitlementSnapshot? Rebuilt, ImmutableArray<string> Differences);

/// <summary>
/// The single reader and writer of grants, revocations and snapshots (MB-04). Time comes only from the injected <see cref="TimeProvider"/>
/// and never moves backwards past a stored computation (EN-08, RF-02); the snapshot and the records that justify it commit atomically
/// through the store port; and every refusal is a typed result. It holds no state of its own, so any replica produces the same answer
/// provided every replica reads the one authoritative time source: a replica whose clock runs ahead can move a workspace's stored
/// computation forward for every other replica, and the composition is responsible for supplying one source (see the docs).
/// </summary>
internal sealed class EntitlementService(
    IEntitlementStore store, IEntitlementDefinitionSource definitions, IEntitlementIdSource ids, TimeProvider clock)
{
    private const int Attempts = 4;
    private const string UnknownDetail = "The store could not tell whether the commit happened; send the same request again.";

    /// <summary>The current snapshot. A stored snapshot is returned while its validity holds; otherwise it is recomputed and stored.</summary>
    public async ValueTask<EntitlementResult<EntitlementSnapshot>> ReadAsync(string workspaceId, CancellationToken cancellationToken)
    {
        if (!InputRules.IsIdentifier(workspaceId)) return EntitlementResult<EntitlementSnapshot>.Failure(EntitlementError.InvalidRequest, "The workspace identifier is malformed.");
        var state = await store.LoadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        var now = Now(state);
        if (state.Snapshot is { } stored && stored.Content.DefinitionsVersion == definitions.Current().Version
            && (stored.ValidUntil is not { } validUntil || now < validUntil))
        {
            return EntitlementResult<EntitlementSnapshot>.Success(stored);
        }

        return await RefreshAsync(workspaceId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Recomputes the snapshot at the authoritative instant and stores it when it differs. This is what the validity sweeper calls.</summary>
    public async ValueTask<EntitlementResult<EntitlementSnapshot>> RefreshAsync(string workspaceId, CancellationToken cancellationToken)
    {
        if (!InputRules.IsIdentifier(workspaceId)) return EntitlementResult<EntitlementSnapshot>.Failure(EntitlementError.InvalidRequest, "The workspace identifier is malformed.");
        for (var attempt = 0; attempt < Attempts; attempt++)
        {
            var state = await store.LoadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
            var needsActivation = NeedsActivation(state.Records);
            var now = needsActivation ? WriteNow(state) : Now(state);
            var (records, activations) = WithActivation(state.Records, now);
            var snapshot = Seal(state, records, now, out var failure);
            if (snapshot is null) return EntitlementResult<EntitlementSnapshot>.Failure(EntitlementError.InvalidHistory, failure!);

            // An unchanged workspace is not rewritten at every later instant: only a different effect, validity or definitions activation is.
            if (activations.IsEmpty && state.Snapshot is { } stored && stored.Version == snapshot.Version
                && stored.Content.SameEffectAs(snapshot.Content) && stored.ValidUntil == snapshot.ValidUntil)
            {
                return EntitlementResult<EntitlementSnapshot>.Success(stored);
            }

            var append = new EntitlementAppend([], [], activations);
            var outcome = await store.CommitAsync(workspaceId, state.Revision, append, snapshot, cancellationToken).ConfigureAwait(false);
            if (outcome == CommitOutcome.Committed) return EntitlementResult<EntitlementSnapshot>.Success(snapshot);
            if (outcome == CommitOutcome.UnknownOutcome) return EntitlementResult<EntitlementSnapshot>.Failure(EntitlementError.OutcomeUnknown, UnknownDetail);
        }

        return EntitlementResult<EntitlementSnapshot>.Failure(EntitlementError.ConcurrentUpdate, "The workspace changed concurrently on every attempt.");
    }

    /// <summary>Issues a grant through the published grant interface (EO-03) and commits it atomically with the snapshot that reflects it.</summary>
    public async ValueTask<EntitlementResult<Grant>> IssueGrantAsync(IssueGrantRequest request, CancellationToken cancellationToken)
    {
        var refusal = GrantAdmission.Validate(request);
        if (refusal is not null) return EntitlementResult<Grant>.Failure(EntitlementError.InvalidRequest, refusal);
        for (var attempt = 0; attempt < Attempts; attempt++)
        {
            var state = await store.LoadAsync(request.WorkspaceId, cancellationToken).ConfigureAwait(false);
            var existing = state.Records.Grants.FirstOrDefault(grant => grant.Source == request.Source && grant.SourceRef == request.SourceRef);
            if (existing is not null)
            {
                return GrantAdmission.IsSameIssuance(existing, request)
                    ? EntitlementResult<Grant>.Success(existing, duplicate: true)
                    : EntitlementResult<Grant>.Failure(EntitlementError.Conflict, "The source reference was already used for a different grant.");
            }

            var now = WriteNow(state);
            var grant = new Grant(ids.NewId(), request.WorkspaceId, request.Kind, request.Subject, request.Value, request.Source, request.SourceRef,
                request.EffectiveFrom, request.EffectiveUntil, request.IssuedByActor, now, request.Reason);
            var (withActivation, activations) = WithActivation(state.Records, now);
            var records = withActivation with { Grants = withActivation.Grants.Add(grant) };
            var snapshot = Seal(state, records, now, out var failure);
            if (snapshot is null) return EntitlementResult<Grant>.Failure(EntitlementError.InvalidHistory, failure!);
            var append = new EntitlementAppend([grant], [], activations);
            var outcome = await store.CommitAsync(request.WorkspaceId, state.Revision, append, snapshot, cancellationToken).ConfigureAwait(false);
            if (outcome == CommitOutcome.Committed) return EntitlementResult<Grant>.Success(grant);
            if (outcome == CommitOutcome.UnknownOutcome) return EntitlementResult<Grant>.Failure(EntitlementError.OutcomeUnknown, UnknownDetail);
        }

        return EntitlementResult<Grant>.Failure(EntitlementError.ConcurrentUpdate, "The workspace changed concurrently on every attempt.");
    }

    /// <summary>
    /// Revokes one exact grant. The caller names the snapshot version it decided against; a different stored version is a stale decision
    /// and nothing is written. A replay of the same revocation writes nothing: without an explicit effective instant, any earlier
    /// revocation of the grant with the same reason code is the same revocation.
    /// </summary>
    public async ValueTask<EntitlementResult<Revocation>> RevokeGrantAsync(RevokeGrantRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!InputRules.IsIdentifier(request.WorkspaceId) || !InputRules.IsIdentifier(request.GrantId) || !InputRules.IsKey(request.ReasonCode)
            || !InputRules.IsActor(request.IssuedByActor))
        {
            return EntitlementResult<Revocation>.Failure(EntitlementError.InvalidRequest, "The revocation names a malformed workspace, grant, reason code or actor.");
        }

        for (var attempt = 0; attempt < Attempts; attempt++)
        {
            var state = await store.LoadAsync(request.WorkspaceId, cancellationToken).ConfigureAwait(false);
            var grant = state.Records.Grants.FirstOrDefault(candidate => candidate.GrantId == request.GrantId);
            if (grant is null) return EntitlementResult<Revocation>.Failure(EntitlementError.UnknownGrant, "No such grant exists in this workspace.");
            if ((state.Snapshot?.Version ?? 0) != request.ExpectedSnapshotVersion)
            {
                return EntitlementResult<Revocation>.Failure(EntitlementError.StaleVersion, "The entitlement version changed since the caller decided.");
            }

            var now = WriteNow(state);
            var existing = state.Records.Revocations.FirstOrDefault(revocation => revocation.GrantId == request.GrantId
                && revocation.ReasonCode == request.ReasonCode && (request.EffectiveFrom is not { } wanted || revocation.EffectiveFrom == wanted));
            if (existing is not null) return EntitlementResult<Revocation>.Success(existing, duplicate: true);
            var revocation = new Revocation(ids.NewId(), request.GrantId, request.ReasonCode, request.EffectiveFrom ?? now, request.IssuedByActor, now);
            var (withActivation, activations) = WithActivation(state.Records, now);
            var records = withActivation with { Revocations = withActivation.Revocations.Add(revocation) };
            var snapshot = Seal(state, records, now, out var failure);
            if (snapshot is null) return EntitlementResult<Revocation>.Failure(EntitlementError.InvalidHistory, failure!);
            var outcome = await store.CommitAsync(request.WorkspaceId, state.Revision, new EntitlementAppend([], [revocation], activations), snapshot, cancellationToken)
                .ConfigureAwait(false);
            if (outcome == CommitOutcome.Committed) return EntitlementResult<Revocation>.Success(revocation);
            if (outcome == CommitOutcome.UnknownOutcome) return EntitlementResult<Revocation>.Failure(EntitlementError.OutcomeUnknown, UnknownDetail);
        }

        return EntitlementResult<Revocation>.Failure(EntitlementError.ConcurrentUpdate, "The workspace changed concurrently on every attempt.");
    }

    /// <summary>
    /// Rebuilds the snapshot from the records alone, at the instant the stored one was computed, and compares them in full. A difference
    /// is a defect, not a refresh (EN-02): it is reported and nothing is overwritten. Note that a snapshot read from a store that other
    /// owners appended terms or facts to without refreshing reports a difference too, until the next refresh.
    /// </summary>
    public async ValueTask<RebuildReport> VerifyRebuildAsync(string workspaceId, CancellationToken cancellationToken)
    {
        var state = await store.LoadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        if (state.Snapshot is not { } stored) return new RebuildReport(workspaceId, RebuildStatus.NoSnapshot, null, null, []);
        var current = definitions.Current();
        if (!state.Records.Activations.IsEmpty && RecordSetValidator.LastActivation(state.Records).Version != current.Version)
        {
            return new RebuildReport(workspaceId, RebuildStatus.DefinitionsChanged, stored, null, []);
        }

        var rebuilt = EntitlementResolver.Resolve(state.Records, current, stored.ComputedAt);
        if (rebuilt.SameAs(stored)) return new RebuildReport(workspaceId, RebuildStatus.Equal, stored, rebuilt, []);
        var status = rebuilt.Content.DefinitionsVersion != stored.Content.DefinitionsVersion ? RebuildStatus.DefinitionsChanged : RebuildStatus.Mismatch;
        return new RebuildReport(workspaceId, status, stored, rebuilt, Differences(stored, rebuilt));
    }

    private UtcMicros Now(EntitlementState state)
    {
        var now = UtcMicros.FromDateTimeOffset(clock.GetUtcNow());
        return state.Snapshot is { } stored ? UtcMicros.Max(now, stored.ComputedAt) : now;
    }

    /// <summary>
    /// The instant a new record is admitted at: strictly after the stored computation, so no two admissions of one workspace share an
    /// instant and the version, which counts changes across instants, can never collapse or fall because two records arrived together.
    /// </summary>
    private UtcMicros WriteNow(EntitlementState state)
    {
        var now = UtcMicros.FromDateTimeOffset(clock.GetUtcNow());
        return state.Snapshot is { } stored ? UtcMicros.Max(now, new UtcMicros(stored.ComputedAt.Value + 1)) : now;
    }

    private bool NeedsActivation(EntitlementRecordSet records) =>
        records.Activations.IsEmpty || RecordSetValidator.LastActivation(records).Version != definitions.Current().Version;

    /// <summary>Records the activation of the active definitions when the last activation names another version (the first one counts for nothing).</summary>
    private (EntitlementRecordSet Records, ImmutableArray<DefinitionsActivation> Added) WithActivation(EntitlementRecordSet records, UtcMicros now)
    {
        var version = definitions.Current().Version;
        if (!records.Activations.IsEmpty && RecordSetValidator.LastActivation(records).Version == version) return (records, []);
        var added = new DefinitionsActivation(version, now);
        return (records with { Activations = records.Activations.Add(added) }, [added]);
    }

    /// <summary>
    /// Resolves the new snapshot and refuses one whose derived version fell below the stored version: that can only mean a record was
    /// admitted with a creation time before the stored computation, which would let a client's cached newer version outlive the truth.
    /// Owner admissions of terms, facts and releases must stamp the authoritative time.
    /// </summary>
    private EntitlementSnapshot? Seal(EntitlementState state, EntitlementRecordSet records, UtcMicros now, out string? failure)
    {
        try
        {
            failure = null;
            var snapshot = EntitlementResolver.Resolve(records, definitions.Current(), now);
            if (state.Snapshot is { } stored && snapshot.Version < stored.Version)
            {
                failure = "The derived entitlement version fell below the stored version: a record was admitted with a creation time before the stored computation.";
                return null;
            }

            return snapshot;
        }
        catch (ResolverInputException exception)
        {
            failure = exception.Message;
            return null;
        }
    }

    private static ImmutableArray<string> Differences(EntitlementSnapshot stored, EntitlementSnapshot rebuilt)
    {
        var lines = new List<string>();
        if (stored.Version != rebuilt.Version) lines.Add("version: " + stored.Version + " != " + rebuilt.Version);
        if (stored.ComputedAt != rebuilt.ComputedAt) lines.Add("computedAt differs");
        if (stored.Content.ValidUntil != rebuilt.Content.ValidUntil) lines.Add("validUntil differs");
        var left = stored.Content.Canonical().Split('\n');
        var right = rebuilt.Content.Canonical().Split('\n');
        lines.AddRange(left.Except(right, StringComparer.Ordinal).Select(line => "stored only: " + line));
        lines.AddRange(right.Except(left, StringComparer.Ordinal).Select(line => "rebuilt only: " + line));
        return [.. lines];
    }
}
