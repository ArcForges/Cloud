// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;

/// <summary>Composes the existing Entitlement writer with one actual current Config read capability in the same batch.</summary>
internal sealed class CurrentDefinitionEntitlementStore(IEntitlementStore reads, IModuleFamilyPort families,
    IResolverConfigurationParticipant? configuration, IRealmAuthorityFamilyPort? recovery,
    ICurrentResolverDefinitionSource source, CurrentResolverDefinitions captured) : IEntitlementStore
{
    internal const string Family = "entitlement-definition-resolution";
    internal const string Plan = "commit-current";
    private static readonly string[] RecordKeys = ["a-revision", "b-grants", "c-revocations", "d-terms", "e-actions", "f-activations", "g-facts", "h-snapshot"];

    public async ValueTask<EntitlementState> LoadAsync(string workspaceId, CancellationToken cancellationToken)
    {
        var value = await reads.LoadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return value;
    }

    public async ValueTask<CommitOutcome> CommitAsync(string workspaceId, long expectedRevision, EntitlementAppend append,
        EntitlementSnapshot snapshot, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (configuration is null || recovery is null || reads is not IEntitlementPreparedStore writer) throw Unavailable();
        var current = await source.RevalidateAsync(captured, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (current == ResolverDefinitionStatus.Stale) return CommitOutcome.RevisionConflict;
        if (current != ResolverDefinitionStatus.Succeeded) throw Unavailable();
        var prepared = writer.Prepare(workspaceId, expectedRevision, append, snapshot);
        var commit = prepared.Commit!;
        var generation = await recovery.PrepareAsync(Family, Plan, prepared.OwnerScope, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (generation.Contribution is null || generation.Snapshot is not { } epoch || epoch.RealmId != captured.Configuration.RealmId) throw Unavailable();
        var identity = new ModuleCommandIdentity(commit.CommandId, commit.WorkspaceId, commit.ActorRef, commit.Operation, commit.RequestHash);
        var guard = await configuration.PrepareCurrentAsync(new(captured.Configuration, Family, Plan, prepared.OwnerScope, identity), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (guard.Status is ResolverDefinitionStatus.Stale or ResolverDefinitionStatus.Conflict) return CommitOutcome.RevisionConflict;
        if (guard.Status != ResolverDefinitionStatus.Succeeded) throw Unavailable();
        if (guard.Contribution is null) throw new EntitlementStoreException(EntitlementStoreFailure.Defect, "The current Config guard is missing.");
        var association = captured.Configuration;
        var contributions = new List<ModuleFamilyContribution>
        {
            new("entitlement", "revision", "workspace-revision", prepared.OwnerArguments[0].Skip(1).ToArray()),
            new("entitlement", "policy", "resolver-profile",
                [PlanValue.FromText(association.RealmId.ToString("D")), PlanValue.FromText(association.DefinitionsVersion),
                 PlanValue.FromBytes(Convert.FromHexString(association.ArtifactHash)), PlanValue.FromText(association.ArtifactId),
                 PlanValue.FromBytes(Convert.FromHexString(association.ArtifactHash)), PlanValue.FromInt64(association.VerifiedLength),
                 PlanValue.FromInt64(association.RealmKind == "official" ? 1 : 2)]),
        };
        for (var index = 0; index < RecordKeys.Length; index++)
            contributions.Add(new("entitlement", "record", RecordKeys[index], prepared.OwnerArguments[index + 1]));
        var outcome = await families.WriteAsync(new(Family, Plan, prepared.OwnerScope, contributions, commit, [generation.Contribution, guard.Contribution]), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return writer.Classify(outcome);
    }

    public ValueTask<FeatureReleaseOutcome> AppendFeatureReleaseAsync(FeatureReleaseFact release, CancellationToken cancellationToken)
        => reads.AppendFeatureReleaseAsync(release, cancellationToken);
    private static EntitlementStoreException Unavailable() => new(EntitlementStoreFailure.Unavailable, "Current definition authority is unavailable.");
}
