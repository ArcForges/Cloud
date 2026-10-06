// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

public sealed class ModuleFamilyContributionFailureTests
{
    private const string Family = "account-enrollment";
    private const string Plan = "families.account-enrollment.create-user";

    [Theory]
    [InlineData("unknown-family")]
    [InlineData("unknown-plan")]
    [InlineData("foreign-owner")]
    [InlineData("platform-tail")]
    [InlineData("unknown-class")]
    [InlineData("unknown-key")]
    [InlineData("duplicate")]
    [InlineData("argument-count")]
    [InlineData("null-list")]
    [InlineData("null-entry")]
    [InlineData("null-arguments")]
    public void ActualKnownContributionValidationHasOnlyClosedRejectedFailure(string failure)
    {
        var executor = new ScriptedExecutor();
        var port = new ModuleFamilyPortFactory(executor, 1, TimeProvider.System).For(ModuleDescriptor.Create("Identity", "identity"));
        var valid = new ModuleFamilyContribution("identity", "revision", "user",
            [PlanValue.FromText(Guid.NewGuid().ToString("D")), PlanValue.FromText(Guid.NewGuid().ToString("D")), PlanValue.FromInt64(0)]);
        IReadOnlyList<ModuleFamilyContribution> contributions = failure switch
        {
            "foreign-owner" => [valid with { Owner = "device" }],
            "platform-tail" => [valid with { Owner = "platform", Class = "record", Key = "a-receipt" }],
            "unknown-class" => [valid with { Class = "sql" }],
            "unknown-key" => [valid with { Key = "unknown" }],
            "duplicate" => [valid, valid],
            "argument-count" => [valid with { Arguments = [] }],
            "null-list" => null!,
            "null-entry" => [null!],
            "null-arguments" => [valid with { Arguments = null! }],
            _ => [valid],
        };
        var error = Assert.Throws<ModuleFamilyContributionException>(() => port.Contribute(
            failure == "unknown-family" ? "unknown" : Family, failure == "unknown-plan" ? "unknown" : Plan, contributions));
        Assert.Equal(ModuleFamilyContributionFailure.Rejected, error.Failure);
        Assert.Equal("Module family contribution refused.", error.Message);
        Assert.Null(error.InnerException);
        Assert.Empty(executor.Calls);
    }

    [Fact]
    public void UnexpectedCollectionFailureIsNotHiddenAsAValidationOrAvailabilityError()
    {
        var executor = new ScriptedExecutor();
        var port = new ModuleFamilyPortFactory(executor, 1, TimeProvider.System).For(ModuleDescriptor.Create("Identity", "identity"));
        Assert.Throws<NotSupportedException>(() => port.Contribute(Family, Plan, new BrokenCollection()));
        Assert.Empty(executor.Calls);
    }

    [Fact]
    public void ActualGenericFactoryStillCannotMintPrivilegedPlatformAuthority()
    {
        var executor = new ScriptedExecutor();
        var port = new ModuleFamilyPortFactory(executor, 1, TimeProvider.System).For(ModuleDescriptor.Create("Platform", "platform"));
        Assert.Equal(ModuleFamilyContributionFailure.Rejected, Assert.Throws<ModuleFamilyContributionException>(
            () => port.Contribute(Family, Plan, [])).Failure);
        Assert.Throws<ArgumentOutOfRangeException>(() => new ModuleFamilyContributionException((ModuleFamilyContributionFailure)99));
        Assert.Empty(executor.Calls);
    }

    private sealed class BrokenCollection : IReadOnlyList<ModuleFamilyContribution>
    {
        public int Count => 1;
        public ModuleFamilyContribution this[int index] => throw new NotSupportedException();
        public IEnumerator<ModuleFamilyContribution> GetEnumerator() => throw new NotSupportedException();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
