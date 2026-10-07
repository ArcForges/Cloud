// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.ResolverDefinitionAuthority;

/// <summary>The early neutral contract is not the Config owner implementation. These tests
/// exercise its actual defensive capture and the real registered factory's capability
/// refusal; they do not substitute a successful participant or claim signed approval.</summary>
public sealed class QuotaConfigurationContractTests
{
    [Fact]
    public void AssociationCapturesBoundedResolverFactsWithoutPendingQuotaImplementation()
    {
        var original = new ResolverQuotaDefinition("storage", ResolverDefinitionCombination.Sum);
        var caller = new[] { original };
        var association = Association(caller);
        caller[0] = new("other", ResolverDefinitionCombination.Max);
        Assert.Equal(original, Assert.Single(association.ResolverDefinitions));
        var enumerated = 0;
        IEnumerable<ResolverQuotaDefinition> Unbounded()
        { while (true) { enumerated++; yield return original; } }
        Assert.Throws<ArgumentException>(() => Association(Unbounded()));
        Assert.Equal(65, enumerated);
        Assert.Throws<ArgumentNullException>(() => Association(null!));
        var member = Assert.Single(typeof(IQuotaConfigurationParticipant).GetMethods());
        Assert.Equal("PrepareCurrentAsync", member.Name);
        Assert.Equal(typeof(Task<QuotaConfigurationGuardResult>), member.ReturnType);
        Assert.Equal(new[] { typeof(QuotaConfigurationGuardRequest), typeof(CancellationToken) }, member.GetParameters().Select(p => p.ParameterType));
    }

    [Fact]
    public async Task ConstructedAssociationsAndSuccessStatusCannotAuthorizeAnActualScopedWriter()
    {
        using var bridge = new SqliteBridgeExecutor();
        var family = new ModuleFamilyPortFactory(bridge, bridge.Generation, TimeProvider.System).For(EntitlementModule.Instance.Descriptor);
        var realm = Guid.NewGuid(); var revision = Guid.NewGuid(); var workspace = Guid.NewGuid();
        var full = new ApprovedResolverConfiguration(realm, revision, new('a', 64), "official", "v1", "artifact:full", "profile", new('b', 64), 100, "publisher");
        var command = new ModuleCommandIdentity(Guid.NewGuid(), workspace, "actor", "operation", new('c', 64));
        var request = new QuotaConfigurationGuardRequest(Association([]), full,
            "entitlement-definition-resolution", "families.entitlement-definition-resolution.commit-current", workspace.ToString("D"), command);
        // Even a deliberately caller-constructed Success and an implementation of the
        // marker interface cannot become an owner-issued capability at the real boundary.
        var forged = new QuotaConfigurationGuardResult(ResolverDefinitionStatus.Succeeded, new CallerCapability());
        var commit = new ModuleCommit(command.CommandId, workspace, command.ActorRef, command.Operation, command.RequestHash,
            "{}", 1, 1, 2, [], 1, "{}");
        var calls = bridge.Calls;
        await Assert.ThrowsAsync<InvalidOperationException>(() => family.WriteAsync(new(request.FamilyId, request.PlanId,
            request.OwnerScope, [], commit, [forged.Contribution!]), T.Ct));
        Assert.Equal(calls, bridge.Calls);
    }

    private static QuotaConfigurationAssociation Association(IEnumerable<ResolverQuotaDefinition> definitions)
        => new(Guid.NewGuid(), Guid.NewGuid(), new('a', 64), "official", "v1", "artifact:unit", "unit-profile", new('b', 64), 100, "publisher", definitions);
    private sealed class CallerCapability : IModuleFamilyContributionSet;
}
