// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Application;

internal sealed class QuotaPeriodSource(IQuotaPeriodStore store, IQuotaDefinitionPort profiles,
    IQuotaApprovedConfigurationSource? configurations, IQuotaDefinitionValidator validator, TimeProvider clock) : IQuotaPeriodSource
{
    public async Task<QuotaPeriodResult> ReadAsync(Guid realmId, Guid workspaceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty || workspaceId == Guid.Empty) return new(QuotaDefinitionStatus.Invalid);
        if (configurations is null) return new(QuotaDefinitionStatus.Unavailable);
        var source = await configurations.ReadCurrentAsync(realmId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (source.Status != QuotaDefinitionStatus.Succeeded || source.Value is not { } current) return new(source.Status == QuotaDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : source.Status);
        if (current.RealmId != realmId || current.ConfigurationRevisionId == Guid.Empty || current.RealmKind is not ("official" or "selfHosted")
            || current.ResolverDefinitions.IsDefault || current.ResolverDefinitions.Length > QuotaDefinitionValidator.MaximumDefinitions
            || current.ResolverDefinitions.Any(d => d is null) || current.ArtifactProfile != QuotaDefinitionValidator.ProfileName
            || !Hash(current.DocumentHash) || !Hash(current.ArtifactHash) || current.VerifiedLength is < 2 or > QuotaDefinitionValidator.MaximumBytes
            || !QuotaDefinitionValidator.Version(current.DefinitionsVersion) || !QuotaDefinitionValidator.Version(current.ArtifactId)
            || !QuotaDefinitionValidator.Version(current.PublisherRef)) return new(QuotaDefinitionStatus.Defect);
        var stored = await store.ReadAsync(realmId, workspaceId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (stored.Status != QuotaDefinitionStatus.Succeeded || stored.Value is not { } value) return new(stored.Status == QuotaDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : stored.Status);
        var snapshot = value.Snapshot;
        if (value.Revision <= 0 || snapshot.Version <= 0 || snapshot.WorkspaceId != workspaceId.ToString("D")) return new(QuotaDefinitionStatus.Defect);
        if (snapshot.Content.DefinitionsVersion != current.DefinitionsVersion) return new(QuotaDefinitionStatus.Stale);
        var profile = await profiles.ReadAsync(realmId, current.DefinitionsVersion, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (profile.Status != QuotaDefinitionStatus.Succeeded || profile.Value is not { } immutable) return new(profile.Status == QuotaDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : profile.Status);
        if (immutable.RealmId != realmId || immutable.ArtifactId != current.ArtifactId || immutable.ArtifactHash != current.ArtifactHash
            || immutable.ArtifactLength != current.VerifiedLength || immutable.Profile.Hash != current.ArtifactHash) return new(QuotaDefinitionStatus.Stale);
        var semantics = validator.Validate(immutable.Profile.CanonicalBytes, current.DefinitionsVersion, current.ResolverDefinitions, cancellationToken);
        if (semantics.Status != QuotaDefinitionStatus.Succeeded || semantics.Profile is not { } definitions) return new(QuotaDefinitionStatus.Defect);
        // Current configuration is reopened after persistence and artifact validation; an old approved revision never authorizes new work.
        var rechecked = await configurations.ReadCurrentAsync(realmId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (rechecked.Status != QuotaDefinitionStatus.Succeeded || rechecked.Value is not { } latest) return new(rechecked.Status == QuotaDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : rechecked.Status);
        if (latest.RealmId != realmId || latest.ConfigurationRevisionId != current.ConfigurationRevisionId || latest.DocumentHash != current.DocumentHash
            || latest.ArtifactHash != current.ArtifactHash || latest.ArtifactId != current.ArtifactId || latest.DefinitionsVersion != current.DefinitionsVersion
            || latest.RealmKind != current.RealmKind || latest.ArtifactProfile != current.ArtifactProfile || latest.VerifiedLength != current.VerifiedLength
            || latest.PublisherRef != current.PublisherRef || latest.ResolverDefinitions.IsDefault || !latest.ResolverDefinitions.SequenceEqual(current.ResolverDefinitions)) return new(QuotaDefinitionStatus.Stale);
        var now = checked((clock.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
        cancellationToken.ThrowIfCancellationRequested();
        if (snapshot.ComputedAt.Value > now || snapshot.ValidUntil is { } valid && now >= valid.Value) return new(QuotaDefinitionStatus.Stale);
        var selection = QuotaPeriodSelector.Select(realmId, workspaceId, current.RealmKind, value.Terms, value.Actions, now);
        if (selection.Status != QuotaDefinitionStatus.Succeeded) return new(selection.Status);
        if (snapshot.Content.Service.PaidTermActive != (selection.Selected is not null)) return new(QuotaDefinitionStatus.Stale);
        var quotas = snapshot.Content.Quotas;
        if (quotas.IsDefault || quotas.Length != definitions.Definitions.Length || quotas.Select(q => q.Key).Distinct(StringComparer.Ordinal).Count() != quotas.Length
            || !quotas.Select(q => q.Key).Order(StringComparer.Ordinal).SequenceEqual(definitions.Definitions.Select(d => d.Key).Order(StringComparer.Ordinal))) return new(QuotaDefinitionStatus.Defect);
        var resolved = ImmutableArray.CreateBuilder<QuotaResolvedDefinition>(quotas.Length);
        foreach (var definition in definitions.Definitions)
        {
            var quota = quotas.Single(q => q.Key == definition.Key);
            if (quota.Limit < 0 || !Enum.IsDefined(quota.Reason)) return new(QuotaDefinitionStatus.Defect);
            var reason = (QuotaResolvedReason)quota.Reason;
            var period = definition.Mode == QuotaDefinitionMode.EntitlementPeriod ? selection.Selected?.PeriodKey : null;
            if (definition.Mode == QuotaDefinitionMode.EntitlementPeriod && period is null && reason == QuotaResolvedReason.Available)
                reason = snapshot.Content.Service.State == ServiceState.Grace ? QuotaResolvedReason.PaymentGrace : QuotaResolvedReason.NoEntitlement;
            resolved.Add(new(definition, quota.Limit, reason, period));
        }
        var until = snapshot.ValidUntil?.Value;
        if (selection.NextBoundaryMicros is { } boundary && (until is null || boundary < until)) until = boundary;
        cancellationToken.ThrowIfCancellationRequested();
        return new(QuotaDefinitionStatus.Succeeded, new(realmId, workspaceId, current, value.Revision, snapshot.Version,
            value.SnapshotHash, snapshot.ComputedAt.Value, now, until, snapshot.Content.Service.PaidTermActive, selection.Selected,
            resolved.MoveToImmutable(), value.Terms, value.Actions));
    }
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
