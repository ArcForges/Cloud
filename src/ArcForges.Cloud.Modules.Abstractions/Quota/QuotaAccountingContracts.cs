// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules;

/// <summary>Captured unit-artifact association to reopen through the actual Config owner.
/// This neutral projection avoids a dependency on the quota-profile implementation;
/// constructing it neither validates the artifact nor grants authority.</summary>
public sealed class QuotaConfigurationAssociation
{
    public QuotaConfigurationAssociation(Guid realmId, Guid configurationRevisionId, string documentHash,
        string realmKind, string definitionsVersion, string artifactId, string artifactProfile,
        string artifactHash, int verifiedLength, string publisherRef,
        IEnumerable<ResolverQuotaDefinition> resolverDefinitions)
    {
        RealmId = realmId; ConfigurationRevisionId = configurationRevisionId; DocumentHash = documentHash;
        RealmKind = realmKind; DefinitionsVersion = definitionsVersion; ArtifactId = artifactId;
        ArtifactProfile = artifactProfile; ArtifactHash = artifactHash; VerifiedLength = verifiedLength;
        PublisherRef = publisherRef;
        ArgumentNullException.ThrowIfNull(resolverDefinitions);
        ResolverDefinitions = resolverDefinitions.Take(65).ToImmutableArray();
        if (ResolverDefinitions.Length > 64)
            throw new ArgumentException("The resolver association exceeds its bounded definition set.", nameof(resolverDefinitions));
    }
    public Guid RealmId { get; }
    public Guid ConfigurationRevisionId { get; }
    public string DocumentHash { get; }
    public string RealmKind { get; }
    public string DefinitionsVersion { get; }
    public string ArtifactId { get; }
    public string ArtifactProfile { get; }
    public string ArtifactHash { get; }
    public int VerifiedLength { get; }
    public string PublisherRef { get; }
    public ImmutableArray<ResolverQuotaDefinition> ResolverDefinitions { get; }
}

/// <summary>The two independently approved artifacts must belong to the same actual current
/// Configuration revision, document, realm and definitions version. These observations do
/// not grant operation permission; the current session and Workspace owners seal it separately.</summary>
public sealed record QuotaConfigurationGuardRequest(QuotaConfigurationAssociation QuotaConfiguration,
    ApprovedResolverConfiguration ResolverConfiguration, string FamilyId, string PlanId,
    string OwnerScope, ModuleCommandIdentity Command);

/// <summary>Only Config's actual issuing factory can seal the read predicate. A status or a
/// caller-constructed association is never a substitute for the opaque contribution.</summary>
public sealed record QuotaConfigurationGuardResult(ResolverDefinitionStatus Status,
    IModuleFamilyContributionSet? Contribution = null);

/// <summary>Reopens current signed approval and exact materialized full/unit associations,
/// then seals Config's current-head read for the closed quota-accounting publication/admission
/// plan and canonical workspace scope. No foreign SQL, descriptor or proof flag crosses it.</summary>
public interface IQuotaConfigurationParticipant
{
    Task<QuotaConfigurationGuardResult> PrepareCurrentAsync(QuotaConfigurationGuardRequest request,
        CancellationToken cancellationToken);
}
