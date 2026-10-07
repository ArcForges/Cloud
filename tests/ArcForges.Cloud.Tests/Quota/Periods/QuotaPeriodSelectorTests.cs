// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.QuotaPeriods;

public sealed class QuotaPeriodSelectorTests
{
    private static readonly Guid Realm = Guid.NewGuid();
    private static readonly Guid Workspace = Guid.NewGuid();
    private static QuotaServiceTerm Term(int id, long priority = 0, QuotaServiceTermKind kind = QuotaServiceTermKind.Pass) => new(
        Guid.Parse($"00000000-0000-4000-8000-{id:000000000000}"), Realm, Workspace, kind, "actual-period-" + id, 10, 100, 20, priority, 5);
    private static QuotaPeriodSelection Select(ImmutableArray<QuotaServiceTerm> terms, long now = 30, ImmutableArray<QuotaServiceTermAction> actions = default, string realmKind = "official")
        => QuotaPeriodSelector.Select(Realm, Workspace, realmKind, terms, actions.IsDefault ? [] : actions, now);

    [Fact]
    public void EligibilityUsesPaidOriginalIntervalActualAuthorizationAndKnownRowsWithoutGrace()
    {
        var term = Term(1);
        Assert.Null(Select([term], 19).Selected);
        Assert.Equal(20, Select([term], 19).NextBoundaryMicros);
        Assert.Equal(term.TermId, Select([term], 20).Selected!.Term.TermId);
        Assert.Null(Select([term], 100).Selected);
        Assert.Null(Select([term], 200).Selected);
        Assert.Null(Select([term with { CreatedAtMicros = 40 }]).Selected);
        Assert.Equal(40, Select([term with { CreatedAtMicros = 40 }]).NextBoundaryMicros);
    }

    [Fact]
    public void PinnedPriorityIncludesNegativeValuesAndHasStableIdTieBreaking()
    {
        var a = Term(1, -4); var b = Term(2, -3);
        Assert.Equal(b.TermId, Select([a, b]).Selected!.Term.TermId);
        Assert.Equal(a.TermId, Select([b with { SelectionPriority = -4 }, a]).Selected!.Term.TermId);
        Assert.Equal(a.TermId, Select([a, b with { SelectionPriority = -4 }]).Selected!.Term.TermId);
    }

    [Fact]
    public void RevokeAndSupersedeTruncateAtEffectiveTimeOnlyAfterKnowledgeWithoutChangingIdentity()
    {
        var a = Term(1); var b = Term(2, 5) with { StartsAtMicros = 50, AuthorizedAtMicros = 50 };
        var action = new QuotaServiceTermAction(Guid.NewGuid(), a.TermId, QuotaTermActionKind.Supersede, 50, 40, "actual-source", b.TermId);
        var original = Select([a, b], 30).Selected!;
        Assert.Equal(original.PeriodKey, Select([a, b], 45, [action]).Selected!.PeriodKey);
        Assert.Equal(50, Select([a, b], 45, [action]).Selected!.EligibleUntilMicros);
        Assert.Equal(b.TermId, Select([a, b], 50, [action]).Selected!.Term.TermId);
        var late = new QuotaServiceTermAction(Guid.NewGuid(), a.TermId, QuotaTermActionKind.Revoke, 25, 40, "late-source", null);
        Assert.Equal(a.TermId, Select([a], 30, [late]).Selected!.Term.TermId);
        Assert.Null(Select([a], 40, [late]).Selected);
    }

    [Fact]
    public void AThenBThenAReturnsSameOpaquePeriodWhileDistinctTermAndOriginalIntervalNeverAlias()
    {
        var a = Term(1); var b = Term(2, 5) with { StartsAtMicros = 40, EndsAtMicros = 60, AuthorizedAtMicros = 40 };
        var before = Select([a, b], 30).Selected!;
        Assert.Equal(b.TermId, Select([a, b], 50).Selected!.Term.TermId);
        Assert.Equal(before.PeriodKey, Select([a, b], 70).Selected!.PeriodKey);
        Assert.NotEqual(before.PeriodKey, QuotaPeriodSelector.PeriodKey(a with { TermId = b.TermId }));
        Assert.NotEqual(before.PeriodKey, QuotaPeriodSelector.PeriodKey(a with { EndsAtMicros = 101 }));
        Assert.NotEqual(before.PeriodKey, QuotaPeriodSelector.PeriodKey(a with { PeriodRef = "other" }));
        Assert.StartsWith("term:", before.PeriodKey); Assert.Equal(69, before.PeriodKey.Length);
    }

    [Fact]
    public void ExactRealmKindExcludesForeignTermKindsRatherThanManufacturingSubscriptionPeriod()
    {
        var official = Term(1, 100); var self = Term(2, -100, QuotaServiceTermKind.SelfHostGrant);
        Assert.Equal(official.TermId, Select([self, official]).Selected!.Term.TermId);
        Assert.Equal(self.TermId, Select([official, self], realmKind: "selfHosted").Selected!.Term.TermId);
        Assert.Null(Select([official], realmKind: "selfHosted").Selected);
    }

    [Fact]
    public void CorruptCrossOwnerAndUnboundedHistoriesFailClosed()
    {
        var a = Term(1);
        foreach (var term in new[] { a with { RealmId = Guid.NewGuid() }, a with { WorkspaceId = Guid.NewGuid() }, a with { EndsAtMicros = 10 },
            a with { Kind = (QuotaServiceTermKind)99 }, a with { PeriodRef = "\ud800" } })
            Assert.Equal(QuotaDefinitionStatus.Defect, Select([term]).Status);
        Assert.Equal(QuotaDefinitionStatus.Defect, Select([a, a]).Status);
        var action = new QuotaServiceTermAction(Guid.NewGuid(), a.TermId, QuotaTermActionKind.Supersede, 50, 40, "source", Guid.NewGuid());
        Assert.Equal(QuotaDefinitionStatus.Defect, Select([a], actions: [action]).Status);
        Assert.Equal(QuotaDefinitionStatus.Defect, Select([a], actions: [action with { Kind = QuotaTermActionKind.Revoke }]).Status);
        Assert.Equal(QuotaDefinitionStatus.Defect, Select([a], actions: [action with { Kind = QuotaTermActionKind.Revoke, ReplacementTermId = null, RecordedAtMicros = 4 }]).Status);
        Assert.Equal(QuotaDefinitionStatus.Defect, Select(Enumerable.Repeat(a, 2001).ToImmutableArray()).Status);
        Assert.Equal(QuotaDefinitionStatus.Defect, Select([a], realmKind: "unknown").Status);
    }
}
