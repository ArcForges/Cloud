// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>A fresh authority and its opaque, scope-bound Platform guard, or a closed refusal.</summary>
public sealed class RealmAuthorityFamilyResult
{
    private RealmAuthorityFamilyResult(RealmAuthoritySnapshot? snapshot, IModuleFamilyContributionSet? contribution, RealmAuthorityFailure? failure)
    {
        Snapshot = snapshot;
        Contribution = contribution;
        Failure = failure;
    }

    public RealmAuthoritySnapshot? Snapshot { get; }

    public IModuleFamilyContributionSet? Contribution { get; }

    public RealmAuthorityFailure? Failure { get; }

    public static RealmAuthorityFamilyResult Available(RealmAuthoritySnapshot snapshot, IModuleFamilyContributionSet contribution) =>
        new(snapshot ?? throw new ArgumentNullException(nameof(snapshot)), contribution ?? throw new ArgumentNullException(nameof(contribution)), null);

    public static RealmAuthorityFamilyResult Refused(RealmAuthorityFailure failure) => new(null, null, failure);
}

/// <summary>Prepares real current recovery authority for one registered transaction; callers supply neither authority facts nor SQL.</summary>
public interface IRealmAuthorityFamilyPort
{
    Task<RealmAuthorityFamilyResult> PrepareAsync(string familyId, string planId, string ownerScope, CancellationToken cancellationToken);
}
