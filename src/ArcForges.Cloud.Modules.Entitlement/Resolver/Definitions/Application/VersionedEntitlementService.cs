// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;

/// <summary>Production async definition composition. Each call captures immutable facts; the pure existing engine is unchanged.</summary>
internal sealed class VersionedEntitlementService(IEntitlementStore store, ICurrentResolverDefinitionSource definitions,
    IResolverDefinitionPort profiles, IRealmAuthorityPort? realm, IModuleFamilyPort families,
    IResolverConfigurationParticipant? configuration, IRealmAuthorityFamilyPort? recovery, IEntitlementIdSource ids, TimeProvider clock)
{
    internal sealed record GrantAttempt(EntitlementGrantPortAdapter Adapter, CurrentResolverDefinitions Definitions, RealmAuthoritySnapshot Authority);
    internal async Task<GrantAttempt> GrantAdapterAsync(CancellationToken cancellationToken)
    {
        var captured = await CaptureAsync(cancellationToken).ConfigureAwait(false);
        return new(new(Engine(captured.Definitions)), captured.Definitions, captured.Authority);
    }
    internal async Task CompleteGrantAsync(GrantAttempt attempt, CancellationToken cancellationToken)
    {
        var status = await definitions.RevalidateAsync(attempt.Definitions, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (status != ResolverDefinitionStatus.Succeeded) throw Unavailable();
        await RequireSameRealmAsync(attempt.Authority, cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask<EntitlementResult<EntitlementSnapshot>> ReadAsync(string workspaceId, bool refresh, CancellationToken cancellationToken)
    {
        if (!InputRules.IsIdentifier(workspaceId)) return EntitlementResult<EntitlementSnapshot>.Failure(EntitlementError.InvalidRequest, "The workspace identifier is malformed.");
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var captured = await CaptureAsync(cancellationToken).ConfigureAwait(false);
            var result = refresh
                ? await Engine(captured.Definitions).RefreshAsync(workspaceId, cancellationToken).ConfigureAwait(false)
                : await Engine(captured.Definitions).ReadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!result.Succeeded) return result;
            var status = await definitions.RevalidateAsync(captured.Definitions, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await RequireSameRealmAsync(captured.Authority, cancellationToken).ConfigureAwait(false);
            if (status == ResolverDefinitionStatus.Succeeded) return result;
            if (status != ResolverDefinitionStatus.Stale) throw Unavailable();
        }
        return EntitlementResult<EntitlementSnapshot>.Failure(EntitlementError.ConcurrentUpdate, "The current definitions changed during every read attempt.");
    }

    internal async ValueTask<RebuildReport> VerifyRebuildAsync(string workspaceId, CancellationToken cancellationToken)
    {
        if (!InputRules.IsIdentifier(workspaceId)) throw new ArgumentException("The workspace identifier is malformed.", nameof(workspaceId));
        if (realm is null) throw Unavailable();
        var authority = await realm.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (authority.Snapshot is not { } current) throw Unavailable();
        var state = await store.LoadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (state.Snapshot is not { } snapshot)
        {
            await RequireSameRealmAsync(current, cancellationToken).ConfigureAwait(false);
            return new(workspaceId, RebuildStatus.NoSnapshot, null, null, []);
        }
        var retained = await profiles.ReadAsync(current.RealmId, snapshot.Content.DefinitionsVersion, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (retained.Status != ResolverDefinitionStatus.Succeeded || retained.Value is not { } profile) throw Unavailable();
        var rebuilt = EntitlementResolver.Resolve(state.Records, ResolverDefinitionValidator.ToDefinitions(profile.Profile, profile.RealmKind), snapshot.ComputedAt);
        await RequireSameRealmAsync(current, cancellationToken).ConfigureAwait(false);
        return rebuilt.SameAs(snapshot)
            ? new(workspaceId, RebuildStatus.Equal, snapshot, rebuilt, [])
            : new(workspaceId, RebuildStatus.Mismatch, snapshot, rebuilt, ["The stored snapshot differs from its retained immutable definitions and history."]);
    }

    private sealed record Capture(CurrentResolverDefinitions Definitions, RealmAuthoritySnapshot Authority);
    private async Task<Capture> CaptureAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realm is null) throw Unavailable();
        var authority = await realm.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (authority.Snapshot is not { } current) throw Unavailable();
        var read = await definitions.ReadAsync(current.RealmId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (read.Status != ResolverDefinitionStatus.Succeeded || read.Value is not { } captured) throw Unavailable();
        if (captured.Configuration.RealmId != current.RealmId) throw new EntitlementStoreException(EntitlementStoreFailure.Defect, "The current definitions name another realm.");
        await RequireSameRealmAsync(current, cancellationToken).ConfigureAwait(false);
        return new(captured, current);
    }
    private async Task RequireSameRealmAsync(RealmAuthoritySnapshot expected, CancellationToken cancellationToken)
    {
        if (realm is null) throw Unavailable();
        var reopened = await realm.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (reopened.Snapshot != expected) throw Unavailable();
    }
    private EntitlementService Engine(CurrentResolverDefinitions captured)
        => new(new CurrentDefinitionEntitlementStore(store, families, configuration, recovery, definitions, captured),
            new CapturedDefinitions(ResolverDefinitionValidator.ToDefinitions(captured.Definitions.Profile, captured.Configuration.RealmKind)), ids, clock);
    private sealed class CapturedDefinitions(EntitlementDefinitions value) : IEntitlementDefinitionSource
    {
        public EntitlementDefinitions Current() => value;
    }
    private static EntitlementStoreException Unavailable() => new(EntitlementStoreFailure.Unavailable, "Current definition authority is unavailable.");
}

/// <summary>The public grant port selects the async production source, never a synchronous fixture registry.</summary>
internal sealed class VersionedEntitlementGrantPortAdapter(VersionedEntitlementService service) : IEntitlementGrantPort
{
    public async ValueTask<EntitlementPortResult<EntitlementGrantRecord>> IssueGrantAsync(IssueGrantCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        if (!EntitlementGrantPortAdapter.ValidBoundary(command)) return new(EntitlementPortStatus.InvalidRequest, null, "The grant request is malformed.");
        try
        {
            var attempt = await service.GrantAdapterAsync(cancellationToken).ConfigureAwait(false);
            var result = await attempt.Adapter.IssueGrantAsync(command, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await service.CompleteGrantAsync(attempt, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (EntitlementStoreException error) when (error.Failure == EntitlementStoreFailure.Unavailable)
        { cancellationToken.ThrowIfCancellationRequested(); return new(EntitlementPortStatus.Unavailable, null, "Current definition authority is unavailable."); }
    }
    public async ValueTask<EntitlementPortResult<EntitlementRevocationRecord>> RevokeGrantAsync(RevokeGrantCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        if (!EntitlementGrantPortAdapter.ValidBoundary(command)) return new(EntitlementPortStatus.InvalidRequest, null, "The revocation request is malformed.");
        try
        {
            var attempt = await service.GrantAdapterAsync(cancellationToken).ConfigureAwait(false);
            var result = await attempt.Adapter.RevokeGrantAsync(command, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await service.CompleteGrantAsync(attempt, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (EntitlementStoreException error) when (error.Failure == EntitlementStoreFailure.Unavailable)
        { cancellationToken.ThrowIfCancellationRequested(); return new(EntitlementPortStatus.Unavailable, null, "Current definition authority is unavailable."); }
    }
}
