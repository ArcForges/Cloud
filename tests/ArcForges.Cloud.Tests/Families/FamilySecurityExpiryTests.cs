// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

public sealed class FamilySecurityExpiryTests
{
    private static FamilySecurityExpiry Metadata(FamilySecurityExpiryProfile profile = FamilySecurityExpiryProfile.NativeSession,
        string table = "identity_session", string[]? columns = null, int index = 3) => new(profile, table, columns ?? ["expires_at", "access_expires_at"], index);

    private static FamilyPlanDefinition Plan(FamilySecurityExpiry? expiry, FamilyModule module = FamilyModule.Identity, FamilyPhase phase = FamilyPhase.Guard,
        FamilyClass kind = FamilyClass.Authorization, string key = "actor-current", string family = "session-lifecycle", string name = "expiry") => new(
            new PlanDefinition("families." + family + "." + name, 1, PlanAccess.Write, 0,
                [new([new(PlanKind.Text), new(PlanKind.Text), new(PlanKind.Text), new(PlanKind.Int64)], null), new([], null), new([new(PlanKind.Text)], null)]), family,
            [new(module, phase, kind, key, expiry), new(FamilyModule.Identity, FamilyPhase.Mutation, FamilyClass.Record, "owner"),
                new(FamilyModule.Platform, FamilyPhase.Release, FamilyClass.Release, "release")]);

    private static IReadOnlyList<string> Problems(FamilyPlanDefinition plan) => FamilyPlanVerifier.Problems(plan,
        new FamilyDefinition(plan.Family, "Expiry component", "CLOUD.78", [new(FamilyModule.Identity, true, null)]));

    [Fact]
    public void TheRegisteredMetadataAndFinalTypedServerInstantAreAccepted()
        => Assert.Empty(Problems(Plan(Metadata())));

    [Fact]
    public void CallerOwnedColumnArraysCannotChangeCapturedMetadata()
    {
        var borrowed = new[] { "expires_at", "access_expires_at" };
        var metadata = Metadata(columns: borrowed);
        borrowed[1] = "idle_expires_at";
        Assert.Equal("access_expires_at", metadata.Columns[1]);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)metadata.Columns)[0] = "forged");
        Assert.Empty(Problems(Plan(metadata)));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(4)]
    public void AServerInstantCannotAliasAnotherParameterOrEscapeTheStatement(int index)
        => Assert.Contains(Problems(Plan(Metadata(index: index))), problem => problem.Contains("final nonnullable int64", StringComparison.Ordinal));

    [Fact]
    public void UnknownProfilesForeignTablesIncompleteAndReorderedSetsAreRefused()
    {
        foreach (var metadata in new[] { Metadata((FamilySecurityExpiryProfile)int.MaxValue), Metadata(table: "device_device"),
            Metadata(columns: ["expires_at"]), Metadata(columns: ["access_expires_at", "expires_at"]), Metadata(columns: ["expires_at", "expires_at"]) })
            Assert.Contains(Problems(Plan(metadata)), problem => problem.Contains("closed profile", StringComparison.Ordinal));
    }

    [Fact]
    public void ARegisteredProfileCannotMoveToAnotherFamilyKeyModuleOrClass()
    {
        foreach (var plan in new[] { Plan(Metadata(), family: "unknown-family"), Plan(Metadata(), key: "unbound"),
            Plan(Metadata(), module: FamilyModule.Device), Plan(Metadata(), kind: FamilyClass.Policy), Plan(Metadata(), phase: FamilyPhase.Mutation) })
            Assert.NotEmpty(Problems(plan));
    }

    [Fact]
    public void TheSecurityBuilderPreservesScalarOrderAndRejectsNegativeServerObservations()
    {
        var contribution = FamilyGuards.SecurityAuthorization("actor-current", [D1Values.Text("session")], [D1Values.Text("user")], 123);
        Assert.Equal(FamilyModule.Identity, contribution.Module);
        Assert.Equal(new[] { D1Values.Text("session"), D1Values.Text("user"), D1Values.Int64(123) }, contribution.Arguments);
        Assert.Throws<FamilyViolationException>(() => FamilyGuards.SecurityAuthorization("actor-current", [D1Values.Text("session")], [D1Values.Text("user")], -1));
    }

    [Fact]
    public void PendingLifetimeAndDueDeadlinesCannotMoveToArbitraryPlansOrTakeAFakeClock()
    {
        var pending = new FamilySecurityExpiry(FamilySecurityExpiryProfile.PendingChallenge, "identity_step_up_challenge", ["expires_at"], 3);
        Assert.Empty(Problems(Plan(pending, key: "challenge-pending", family: "account-security", name: "step-up-prove-native")));
        Assert.NotEmpty(Problems(Plan(pending, key: "challenge-pending", family: "account-security")));
        var due = new FamilySecurityExpiry(FamilySecurityExpiryProfile.DeletionGraceDue, "identity_account_deletion", ["grace_ends_at"], null);
        Assert.Empty(Problems(Plan(due, key: "deletion-due", family: "account-security", name: "begin-deletion-purge")));
        Assert.NotEmpty(Problems(Plan(due, key: "deletion-due", family: "account-security")));
        Assert.NotEmpty(Problems(Plan(new(FamilySecurityExpiryProfile.DeletionGraceDue, "identity_account_deletion", ["grace_ends_at"], 3),
            key: "deletion-due", family: "account-security", name: "begin-deletion-purge")));
        Assert.Equal(2, FamilyGuards.SecurityDueAuthorization("deletion-due", [D1Values.Text("deletion")], [D1Values.Int64(1)]).Arguments.Count);
    }
}
