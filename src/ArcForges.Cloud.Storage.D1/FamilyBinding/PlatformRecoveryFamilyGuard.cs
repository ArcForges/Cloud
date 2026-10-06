// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.SharedFamilies;

namespace ArcForges.Cloud.Storage.FamilyBinding;

/// <summary>Storage-only authority for the single registered recovery predicate. It grants no platform mutation or tail authority.</summary>
internal sealed class PlatformRecoveryFamilyGuard : IModuleFamilyContributionSet
{
    private readonly object issuer;
    private readonly string familyId;
    private readonly string planId;
    private readonly string ownerScope;
    private readonly ulong generation;
    private readonly FamilyContribution contribution;

    internal PlatformRecoveryFamilyGuard(object issuer, string familyId, string planId, string ownerScope, RealmAuthoritySnapshot snapshot)
    {
        this.issuer = issuer;
        this.familyId = familyId;
        this.planId = planId;
        this.ownerScope = ownerScope;
        generation = checked((ulong)snapshot.RecoveryGeneration);
        contribution = new FamilyContribution(FamilyModule.Platform, FamilyClass.Authorization, "recovery-current",
            Array.AsReadOnly(new[] { D1Values.Text(snapshot.RealmId.ToString("D")), D1Values.Int64(snapshot.RecoveryGeneration), D1Values.Int64(4), D1Values.Int64(snapshot.RecoveryRevision) }));
    }

    internal FamilyContribution For(object expectedIssuer, ModuleFamilyWrite write, ulong expectedGeneration)
    {
        if (!ReferenceEquals(issuer, expectedIssuer) || familyId != write.FamilyId || planId != write.PlanId
            || ownerScope != write.OwnerScope || generation != expectedGeneration)
            throw new InvalidOperationException("The recovery contribution capability is not valid for this factory, plan and scope.");
        return contribution;
    }
}
