// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.SharedFamilies;

/// <summary>The typed arguments of the five guard primitives: exactly the parameter order the generator expands, and nothing a guard could not mean.</summary>
public sealed class FamilyGuardArgumentTests
{
    private static readonly D1Scalar[] By = [D1Values.Text("key-1")];

    private static FamilyViolation Refusal(Action action) => Assert.Throws<FamilyViolationException>(action).Violation;

    private static string[] Shape(FamilyContribution contribution) => contribution.Arguments.Select(argument => argument switch
    {
        D1ScalarD1TextValue => "text",
        D1ScalarD1Int64Value => "int64",
        D1ScalarD1BytesValue => "bytes",
        D1ScalarD1NullValue => "null",
        _ => argument.GetType().Name,
    }).ToArray();

    [Fact]
    public void EachPrimitiveBuildsItsArgumentsInTheGeneratedParameterOrder()
    {
        var authorization = FamilyGuards.Authorization(FamilyModule.Workspace, "owner", By, [D1Values.Text("user"), D1Values.Int64(1)]);
        Assert.Equal((FamilyClass.Authorization, FamilyModule.Workspace, "owner"), (authorization.Class, authorization.Module, authorization.Key));
        Assert.Equal(["text", "text", "int64"], Shape(authorization));
        Assert.Equal(["text", "text", "int64", "int64"], Shape(FamilyGuards.Authorization(FamilyModule.Workspace, "owner", By, [D1Values.Text("user"), D1Values.Int64(1)], 5)));
        Assert.Equal(FamilyClass.Policy, FamilyGuards.Policy(FamilyModule.Configuration, "p", By, [D1Values.Int64(1)]).Class);
        Assert.Equal(["text", "int64"], Shape(FamilyGuards.Revision(FamilyModule.Entitlement, "r", By, 7)));
        Assert.Equal(["text", "int64", "int64", "int64"], Shape(FamilyGuards.Balance(FamilyModule.Entitlement, "b", By, 3, [D1Values.Int64(10), D1Values.Int64(2)])));
        var lease = FamilyGuards.Lease(FamilyModule.Platform, "l", By, "container-a", 5, 1_000_000);
        Assert.Equal(["text", "text", "int64", "int64"], Shape(lease));
        Assert.Equal("container-a", FamilyFixture.Text(lease.Arguments[1]));
        Assert.Equal(5, FamilyFixture.Int(lease.Arguments[2]));
        Assert.Equal(1_000_000, FamilyFixture.Int(lease.Arguments[3]));
    }

    [Fact]
    public void AFreshnessInstantFollowsTheMatchValuesAndComesLast()
    {
        var guard = FamilyGuards.Authorization(FamilyModule.Workspace, "owner", By, [D1Values.Text("user")], 42);
        Assert.Equal(42, FamilyFixture.Int(guard.Arguments[^1]));
        Assert.Equal("user", FamilyFixture.Text(guard.Arguments[1]));
    }

    [Fact]
    public void AGuardNoCallerCouldMeanIsRefused()
    {
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Revision(FamilyModule.Entitlement, "r", By, -1)));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Revision(FamilyModule.Entitlement, "r", [], 1)));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Revision(FamilyModule.Entitlement, "", By, 1)));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Balance(FamilyModule.Entitlement, "b", By, -1, [D1Values.Int64(1)])));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Balance(FamilyModule.Entitlement, "b", By, 1, [])));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Authorization(FamilyModule.Workspace, "a", By, [])));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Authorization(FamilyModule.Workspace, "a", By, [D1Values.Int64(1)], -5)));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Policy(FamilyModule.Policy, "p", By, [])));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Lease(FamilyModule.Platform, "l", By, "", 1, 1)));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Lease(FamilyModule.Platform, "l", By, "h", -1, 1)));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Lease(FamilyModule.Platform, "l", By, "h", 1, -1)));
        Assert.Throws<ArgumentNullException>(() => FamilyGuards.Lease(FamilyModule.Platform, "l", By, null!, 1, 1));
        Assert.Throws<ArgumentNullException>(() => FamilyGuards.Revision(FamilyModule.Entitlement, null!, By, 1));
    }

    [Fact]
    public void AMutationIsABucketReservationOrRecordNeverAGuardClass()
    {
        Assert.Equal(FamilyClass.Bucket, FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Bucket, "q", [D1Values.Int64(1)]).Class);
        Assert.Equal(FamilyClass.Reservation, FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Reservation, "q", []).Class);
        Assert.Equal(FamilyClass.Record, FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Record, "q", [D1Values.Int64(1)]).Class);
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Revision, "q", [])));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Release, "q", [])));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Record, "", [])));
    }

    [Fact]
    public void TheBuildersProduceTheFixturePlansExactArgumentKinds()
    {
        // Every contribution of the fixture, built only through the typed primitives, satisfies the generated statement it is sealed against.
        var call = FamilyFixture.Unit().Seal();
        for (var index = 0; index < call.Arguments.Length; index++) Assert.Equal(call.Plan.Statements[index].Params.Count, call.Arguments[index].Length);
    }

    [Fact]
    public void AContributionKeepsACopyOfItsArguments()
    {
        var arguments = new List<D1Scalar> { D1Values.Int64(1) };
        var contribution = FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Record, "q", arguments);
        arguments.Add(D1Values.Int64(2));
        Assert.Single(contribution.Arguments);
    }
}
