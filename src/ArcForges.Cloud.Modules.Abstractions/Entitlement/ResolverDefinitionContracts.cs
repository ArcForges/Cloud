// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules;

public enum ResolverDefinitionCombination { Sum, Max, PriorityReplace }
public enum ResolverDefinitionStatus { Succeeded, Replayed, NotFound, Invalid, Conflict, Stale, Denied, Unavailable, UnknownOutcome, ReusedIdentifier, ReceiptExpired, Defect }

public sealed record ResolverCapabilityDefinition(string Key, bool RequiresPaidTerm, string? FeatureGate);
public sealed record ResolverQuotaDefinition(string Key, ResolverDefinitionCombination Combination);
public sealed record ResolverAllowanceDefinition(string Key);

/// <summary>Complete defensively captured canonical owner definitions. Validation does not grant approval.</summary>
public sealed class ResolverDefinitionProfile
{
    private readonly byte[] canonicalBytes;
    public ResolverDefinitionProfile(string definitionsVersion, string hash, ReadOnlyMemory<byte> canonicalBytes,
        IEnumerable<ResolverCapabilityDefinition> capabilities, IEnumerable<ResolverQuotaDefinition> quotas,
        IEnumerable<ResolverAllowanceDefinition> allowances)
    {
        DefinitionsVersion = definitionsVersion;
        Hash = hash;
        this.canonicalBytes = canonicalBytes.ToArray();
        Capabilities = capabilities.ToImmutableArray();
        Quotas = quotas.ToImmutableArray();
        Allowances = allowances.ToImmutableArray();
    }
    public string DefinitionsVersion { get; }
    public string Hash { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonicalBytes.ToArray();
    public ImmutableArray<ResolverCapabilityDefinition> Capabilities { get; }
    public ImmutableArray<ResolverQuotaDefinition> Quotas { get; }
    public ImmutableArray<ResolverAllowanceDefinition> Allowances { get; }
}

public sealed record ResolverDefinitionValidationResult(ResolverDefinitionStatus Status, ResolverDefinitionProfile? Profile = null);
public interface IResolverDefinitionValidator
{
    ResolverDefinitionValidationResult Validate(ReadOnlyMemory<byte> canonicalBytes, string definitionsVersion, CancellationToken cancellationToken);
}

/// <summary>Actual signed Config association. Bytes are reopened separately; caller construction confers no authority.</summary>
public sealed record ApprovedResolverConfiguration(Guid RealmId, Guid ConfigurationRevisionId, string DocumentHash,
    string RealmKind, string DefinitionsVersion, string ArtifactId, string ArtifactProfile, string ArtifactHash,
    int VerifiedLength, string PublisherRef);
public sealed record ResolverConfigurationResult(ResolverDefinitionStatus Status, ApprovedResolverConfiguration? Value = null);
public interface IResolverApprovedConfigurationSource
{
    Task<ResolverConfigurationResult> ReadCurrentAsync(Guid realmId, CancellationToken cancellationToken);
    Task<ResolverConfigurationResult> ReadHistoricalAsync(Guid realmId, Guid configurationRevisionId, string documentHash, CancellationToken cancellationToken);
}

public sealed class ResolverDefinitionArtifactResult
{
    private readonly byte[] bytes;
    public ResolverDefinitionArtifactResult(ResolverDefinitionStatus status, ReadOnlyMemory<byte> bytes = default)
    {
        Status = status;
        this.bytes = bytes.ToArray();
    }
    public ResolverDefinitionStatus Status { get; }
    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();
}
public interface IResolverDefinitionArtifactPort
{
    Task<ResolverDefinitionArtifactResult> ReadAsync(string artifactId, string profile, string hash, CancellationToken cancellationToken);
}

public sealed record ResolverDefinitionPublishRequest(Guid CommandId, Guid RealmId, Guid ConfigurationRevisionId, string DocumentHash, string PublisherRef);
/// <summary>First accepted provenance is immutable even when a later approved Config reuses this exact artifact.</summary>
public sealed record StoredResolverDefinitionProfile(Guid RealmId, ResolverDefinitionProfile Profile, string ArtifactId,
    string ArtifactHash, int ArtifactLength, Guid FirstConfigurationRevisionId, string FirstDocumentHash,
    string RealmKind, string PublisherRef, long CreatedAtMicros);
public sealed record ResolverDefinitionResult(ResolverDefinitionStatus Status, StoredResolverDefinitionProfile? Value = null);
public interface IResolverDefinitionPort
{
    Task<ResolverDefinitionResult> PublishAsync(ResolverDefinitionPublishRequest request, CancellationToken cancellationToken);
    Task<ResolverDefinitionResult> ReadAsync(Guid realmId, string definitionsVersion, CancellationToken cancellationToken);
}

/// <summary>One current head plus exact stored definitions, captured per operation. Revalidate after awaits and seal before writes.</summary>
public sealed record CurrentResolverDefinitions(ApprovedResolverConfiguration Configuration, StoredResolverDefinitionProfile Definitions);
public sealed record CurrentResolverDefinitionResult(ResolverDefinitionStatus Status, CurrentResolverDefinitions? Value = null);
public interface ICurrentResolverDefinitionSource
{
    Task<CurrentResolverDefinitionResult> ReadAsync(Guid realmId, CancellationToken cancellationToken);
    Task<ResolverDefinitionStatus> RevalidateAsync(CurrentResolverDefinitions captured, CancellationToken cancellationToken);
}

/// <summary>Config owner seals an exact current-head read guard for the closed resolution family and current command scope.</summary>
public sealed record ResolverDefinitionGuardRequest(ApprovedResolverConfiguration Configuration, string FamilyId, string PlanId,
    string OwnerScope, ModuleCommandIdentity Command);
public sealed record ResolverDefinitionGuardResult(ResolverDefinitionStatus Status, IModuleFamilyContributionSet? Contribution = null);
public interface IResolverConfigurationParticipant
{
    Task<ResolverDefinitionGuardResult> PrepareCurrentAsync(ResolverDefinitionGuardRequest request, CancellationToken cancellationToken);
}
