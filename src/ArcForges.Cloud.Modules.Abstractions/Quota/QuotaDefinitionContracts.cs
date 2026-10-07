// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules;

public enum QuotaDefinitionCombination { Sum, Max, PriorityReplace }
public enum QuotaDefinitionUnit { Bytes, Microseconds, Samples, Count }
public enum QuotaDefinitionMode { Gauge, EntitlementPeriod }
public enum QuotaDefinitionStatus { Succeeded, Replayed, NotFound, Invalid, Conflict, Stale, Denied, Unavailable, UnknownOutcome, ReusedIdentifier, ReceiptExpired, Defect }

/// <summary>The resolver's exact key/combination; neither a limit nor permission.</summary>
public sealed record QuotaResolverDefinition(string Key, QuotaDefinitionCombination Combination);
public sealed record QuotaSemanticDefinition(string Key, QuotaDefinitionCombination Combination, QuotaDefinitionUnit Unit, QuotaDefinitionMode Mode);

/// <summary>Complete canonical owner bytes. Both input and output buffers are copied; descriptors are immutable.</summary>
public sealed class QuotaSemanticProfile
{
    private readonly byte[] canonicalBytes;
    public QuotaSemanticProfile(string definitionsVersion, string hash, ReadOnlyMemory<byte> canonicalBytes, IEnumerable<QuotaSemanticDefinition> definitions)
    {
        DefinitionsVersion = definitionsVersion;
        Hash = hash;
        this.canonicalBytes = canonicalBytes.ToArray();
        Definitions = definitions.ToImmutableArray();
    }

    public string DefinitionsVersion { get; }
    public string Hash { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonicalBytes.ToArray();
    public ImmutableArray<QuotaSemanticDefinition> Definitions { get; }
}

public sealed record QuotaDefinitionValidationResult(QuotaDefinitionStatus Status, QuotaSemanticProfile? Profile = null);

public sealed record QuotaResolverDefinitionSet(string DefinitionsVersion, string RealmKind, ImmutableArray<QuotaResolverDefinition> Quotas);
public sealed record QuotaResolverDefinitionResult(QuotaDefinitionStatus Status, QuotaResolverDefinitionSet? Value = null);

/// <summary>Independent actual resolver definition facts for one realm/version. Never derive these expectations from the candidate semantic profile.</summary>
public interface IQuotaResolverDefinitionSource
{
    Task<QuotaResolverDefinitionResult> ReadAsync(Guid realmId, string definitionsVersion, CancellationToken cancellationToken);
}

/// <summary>Pure complete semantic validation against the exact resolver definition set. Successful validation is not approval.</summary>
public interface IQuotaDefinitionValidator
{
    QuotaDefinitionValidationResult Validate(ReadOnlyMemory<byte> canonicalBytes, string definitionsVersion,
        IReadOnlyList<QuotaResolverDefinition> resolverDefinitions, CancellationToken cancellationToken);
}

/// <summary>Bounded owner conflict detection against accepted stable key meanings and same-version profile bytes.
/// Successful compatibility is an observation; it confers no approval and cannot replace atomic publication guards.</summary>
public interface IQuotaDefinitionCompatibilityPort
{
    Task<QuotaDefinitionStatus> CheckAsync(Guid realmId, QuotaSemanticProfile profile, CancellationToken cancellationToken);
}

/// <summary>Facts returned only by the real signed Configuration owner. RealmKind is the exact official/selfHosted document value.
/// The immutable artifact tuple and resolver definitions are distinct from the artifact bytes and confer no caller authority.</summary>
public sealed class ApprovedQuotaConfiguration
{
    public ApprovedQuotaConfiguration(Guid realmId, Guid configurationRevisionId, string documentHash, string artifactId,
        string artifactProfile, string artifactHash, int verifiedLength, string definitionsVersion, string realmKind,
        string publisherRef, IEnumerable<QuotaResolverDefinition> resolverDefinitions)
    {
        RealmId = realmId;
        ConfigurationRevisionId = configurationRevisionId;
        DocumentHash = documentHash;
        ArtifactId = artifactId;
        ArtifactProfile = artifactProfile;
        ArtifactHash = artifactHash;
        VerifiedLength = verifiedLength;
        DefinitionsVersion = definitionsVersion;
        RealmKind = realmKind;
        PublisherRef = publisherRef;
        ResolverDefinitions = resolverDefinitions.ToImmutableArray();
    }

    public Guid RealmId { get; }
    public Guid ConfigurationRevisionId { get; }
    public string DocumentHash { get; }
    public string ArtifactId { get; }
    public string ArtifactProfile { get; }
    public string ArtifactHash { get; }
    public int VerifiedLength { get; }
    public string DefinitionsVersion { get; }
    public string RealmKind { get; }
    public string PublisherRef { get; }
    public ImmutableArray<QuotaResolverDefinition> ResolverDefinitions { get; }
}

public sealed record QuotaConfigurationResult(QuotaDefinitionStatus Status, ApprovedQuotaConfiguration? Value = null);

/// <summary>Server-only real Config authority; current and exact historical approved associations. A hash alone never approves a profile.</summary>
public interface IQuotaApprovedConfigurationSource
{
    Task<QuotaConfigurationResult> ReadCurrentAsync(Guid realmId, CancellationToken cancellationToken);
    Task<QuotaConfigurationResult> ReadHistoricalAsync(Guid realmId, Guid configurationRevisionId, string documentHash, CancellationToken cancellationToken);
}

/// <summary>Reopens a bounded exact artifact independently from approval. A Config adapter delegates to its real artifact store.</summary>
public interface IQuotaDefinitionArtifactPort
{
    Task<QuotaDefinitionArtifactResult> ReadAsync(string artifactId, string profile, string hash, CancellationToken cancellationToken);
}

public sealed class QuotaDefinitionArtifactResult
{
    private readonly byte[] bytes;
    public QuotaDefinitionArtifactResult(QuotaDefinitionStatus status, ReadOnlyMemory<byte> bytes = default)
    {
        Status = status;
        this.bytes = bytes.ToArray();
    }
    public QuotaDefinitionStatus Status { get; }
    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();
}

public sealed record QuotaDefinitionPublishRequest(Guid CommandId, Guid RealmId, Guid ConfigurationRevisionId, string DocumentHash, string PublisherRef);
public sealed record StoredQuotaSemanticProfile(Guid RealmId, QuotaSemanticProfile Profile, string ArtifactId, string ArtifactHash, int ArtifactLength, long CreatedAtMicros);
public sealed record QuotaDefinitionResult(QuotaDefinitionStatus Status, StoredQuotaSemanticProfile? Value = null);

/// <summary>Trusted materialization of a real approved artifact, with indexed immutable meanings and durable exact command replay.</summary>
public interface IQuotaDefinitionPort
{
    Task<QuotaDefinitionResult> PublishAsync(QuotaDefinitionPublishRequest request, CancellationToken cancellationToken);
    Task<QuotaDefinitionResult> ReadAsync(Guid realmId, string definitionsVersion, CancellationToken cancellationToken);
}
