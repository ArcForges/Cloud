// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

/// <summary>
/// A record set or definition set that the resolver refuses to interpret. The resolver fails closed: it never produces a snapshot
/// from inconsistent history, because a guess would be an entitlement nobody can explain.
/// </summary>
internal sealed class ResolverInputException(string message) : Exception(message);

/// <summary>Bounds and shape rules every record the resolver reads must satisfy. The same rules guard grant admission.</summary>
internal static class InputRules
{
    /// <summary>A hard bound on the history of one workspace the resolver replays, so that evaluation cost stays bounded.</summary>
    public const int MaxRecords = 2000;

    /// <summary>The largest quota limit of one grant. With <see cref="MaxRecords"/> it keeps every checked sum inside a signed 64-bit integer.</summary>
    public const long MaxQuotaLimit = 100_000_000_000_000;

    public static bool IsIdentifier(string? value) => IsToken(value, 64, allowSlash: false, allowUpper: true);

    public static bool IsKey(string? value) => IsToken(value, 128, allowSlash: false, allowUpper: false);

    public static bool IsOpaqueReference(string? value) => IsToken(value, 128, allowSlash: false, allowUpper: true);

    private static bool IsToken(string? value, int maxLength, bool allowSlash, bool allowUpper)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maxLength) return false;
        foreach (var c in value)
        {
            var ok = c is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-' or ':'
                || (allowUpper && c is >= 'A' and <= 'Z') || (allowSlash && c == '/');
            if (!ok) return false;
        }

        return true;
    }

    public static bool IsActor(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 128 && !value.Any(char.IsControl);

    public static bool IsReason(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
}

internal static class RecordSetValidator
{
    public static void Validate(EntitlementRecordSet records, EntitlementDefinitions definitions)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(definitions);
        ValidateDefinitions(definitions);
        if (!InputRules.IsIdentifier(records.WorkspaceId)) throw new ResolverInputException("The workspace identifier is malformed.");
        if (records.Count > InputRules.MaxRecords) throw new ResolverInputException("The record history exceeds the replay bound.");

        var grants = new Dictionary<string, Grant>(StringComparer.Ordinal);
        foreach (var grant in records.Grants)
        {
            if (!InputRules.IsIdentifier(grant.GrantId) || !grants.TryAdd(grant.GrantId, grant)) throw new ResolverInputException("A grant identifier is malformed or repeated.");
            if (grant.WorkspaceId != records.WorkspaceId) throw new ResolverInputException("A grant belongs to another workspace: " + grant.GrantId);
            if (!Enum.IsDefined(grant.Kind) || !Enum.IsDefined(grant.Source)) throw new ResolverInputException("A grant has an unknown kind or source: " + grant.GrantId);
            if (!InputRules.IsKey(grant.Subject)) throw new ResolverInputException("A grant subject is malformed: " + grant.GrantId);
            if (grant.SourceRef is not null && !InputRules.IsOpaqueReference(grant.SourceRef)) throw new ResolverInputException("A grant source reference is malformed: " + grant.GrantId);
            if (!InputRules.IsActor(grant.IssuedByActor)) throw new ResolverInputException("A grant has no issuing actor: " + grant.GrantId);
            if (grant.EffectiveUntil is { } until && until <= grant.EffectiveFrom) throw new ResolverInputException("A grant ends before it starts: " + grant.GrantId);
            ValidateValue(grant);
        }

        var revocations = new HashSet<string>(StringComparer.Ordinal);
        foreach (var revocation in records.Revocations)
        {
            if (!InputRules.IsIdentifier(revocation.RevocationId) || !revocations.Add(revocation.RevocationId)) throw new ResolverInputException("A revocation identifier is malformed or repeated.");
            if (!grants.TryGetValue(revocation.GrantId, out var grant)) throw new ResolverInputException("A revocation names no known grant: " + revocation.RevocationId);
            if (!InputRules.IsKey(revocation.ReasonCode) || !InputRules.IsActor(revocation.IssuedByActor)) throw new ResolverInputException("A revocation lacks a reason code or actor: " + revocation.RevocationId);
            if (revocation.CreatedAt < grant.CreatedAt) throw new ResolverInputException("A revocation predates its grant: " + revocation.RevocationId);
        }

        var terms = new Dictionary<string, ServiceTermFact>(StringComparer.Ordinal);
        foreach (var term in records.Terms)
        {
            if (!InputRules.IsIdentifier(term.TermId) || !terms.TryAdd(term.TermId, term)) throw new ResolverInputException("A service term identifier is malformed or repeated.");
            if (!Enum.IsDefined(term.Kind)) throw new ResolverInputException("A service term has an unknown kind: " + term.TermId);
            if (term.EndsAt <= term.StartsAt) throw new ResolverInputException("A service term ends before it starts: " + term.TermId);
            if (term.GraceEndsAt is { } grace && grace < term.EndsAt) throw new ResolverInputException("A service term grace ends before the term: " + term.TermId);
        }

        foreach (var action in records.TermActions)
        {
            if (!Enum.IsDefined(action.Kind)) throw new ResolverInputException("A term action has an unknown kind.");
            if (!terms.TryGetValue(action.TermId, out var term)) throw new ResolverInputException("A term action names no known term: " + action.TermId);
            if (action.RecordedAt < term.CreatedAt) throw new ResolverInputException("A term action predates its term: " + action.TermId);
        }

        foreach (var fact in records.StatusFacts)
        {
            if (!Enum.IsDefined(fact.Status)) throw new ResolverInputException("A workspace status fact has an unknown status.");
        }

        foreach (var release in records.FeatureReleases)
        {
            if (!InputRules.IsKey(release.Feature)) throw new ResolverInputException("A feature release names a malformed feature.");
        }

        var activations = new HashSet<(string, long)>();
        foreach (var activation in records.Activations)
        {
            if (!InputRules.IsOpaqueReference(activation.Version) || !activations.Add((activation.Version, activation.ActivatedAt.Value)))
            {
                throw new ResolverInputException("A definitions activation is malformed or repeated.");
            }
        }

        // When activations are recorded, the definitions being applied must be the ones activated last: a snapshot is never derived under
        // definitions whose activation, and therefore whose version change, no record shows.
        if (!records.Activations.IsEmpty && LastActivation(records).Version != definitions.Version)
        {
            throw new ResolverInputException("The definitions version being applied has no recorded activation.");
        }
    }

    /// <summary>The activation in force: the latest by instant, then by version, a total order.</summary>
    public static DefinitionsActivation LastActivation(EntitlementRecordSet records) =>
        records.Activations.OrderBy(activation => activation.ActivatedAt).ThenBy(activation => activation.Version, StringComparer.Ordinal).Last();

    private static void ValidateValue(Grant grant)
    {
        var ok = grant.Kind switch
        {
            GrantKind.Capability => grant.Value is CapabilityValue,
            GrantKind.Quota => grant.Value is QuotaValue { Limit: >= 0 and <= InputRules.MaxQuotaLimit, Priority: >= 0 },
            GrantKind.Allowance => grant.Value is AllowanceValue { Priority: >= 0 } allowance && InputRules.IsIdentifier(allowance.CapacityPlanRef),
            _ => false,
        };
        if (!ok) throw new ResolverInputException("A grant value does not match its kind: " + grant.GrantId);
    }

    private static void ValidateDefinitions(EntitlementDefinitions definitions)
    {
        if (!InputRules.IsOpaqueReference(definitions.Version)) throw new ResolverInputException("The definitions version is malformed.");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var capability in definitions.Capabilities)
        {
            if (!InputRules.IsKey(capability.Key) || !keys.Add("capability:" + capability.Key)) throw new ResolverInputException("A capability definition is malformed or repeated.");
            if (capability.FeatureGate is not null && !InputRules.IsKey(capability.FeatureGate)) throw new ResolverInputException("A capability feature gate is malformed.");
        }

        foreach (var quota in definitions.Quotas)
        {
            if (!InputRules.IsKey(quota.Key) || !Enum.IsDefined(quota.Combination) || !keys.Add("quota:" + quota.Key)) throw new ResolverInputException("A quota definition is malformed or repeated.");
        }

        foreach (var allowance in definitions.Allowances)
        {
            if (!InputRules.IsKey(allowance.Key) || !keys.Add("allowance:" + allowance.Key)) throw new ResolverInputException("An allowance definition is malformed or repeated.");
        }
    }
}
