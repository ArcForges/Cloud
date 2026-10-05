// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// The published grant port (EO-03) as Commerce, the operator path and the refund path see it: primitives in, primitives out, idempotent by
/// source reference, a stale version refused, the GR-05 reason required for operator sources, and no Entitlement type across the boundary.
/// </summary>
public sealed class GrantPortContractTests
{
    private static readonly DateTimeOffset From = DateTimeOffset.UnixEpoch.AddDays(1);

    private static IssueGrantCommand Command(
        string reference = "order-1", EntitlementGrantSource source = EntitlementGrantSource.Subscription, string? reason = null,
        EntitlementGrantTerms? terms = null, EntitlementGrantKind kind = EntitlementGrantKind.Capability, string subject = "cloud.sync") =>
        new(EntitlementHarness.Workspace, kind, subject, terms ?? new CapabilityGrantTerms(), source, reference, From, null, "commerce", reason);

    private static (IEntitlementGrantPort Port, EntitlementHarness Harness) Create()
    {
        var harness = new EntitlementHarness().At(100);
        return (new EntitlementGrantPortAdapter(harness.Service), harness);
    }

    [Fact]
    public async Task AGrantIsIssuedWithItsSnapshotAndReportedAsPrimitives()
    {
        var (port, harness) = Create();

        var result = await port.IssueGrantAsync(Command(), T.Ct);

        Assert.Equal(EntitlementPortStatus.Succeeded, result.Status);
        var grant = result.Value!;
        Assert.Equal(EntitlementHarness.Workspace, grant.WorkspaceId);
        Assert.Equal(EntitlementGrantKind.Capability, grant.Kind);
        Assert.Equal(EntitlementGrantSource.Subscription, grant.Source);
        Assert.Equal("order-1", grant.SourceRef);
        Assert.Equal(From, grant.EffectiveFrom);
        Assert.Null(grant.Reason);
        Assert.Single(harness.Store.Records(EntitlementHarness.Workspace).Grants);
        Assert.Equal(1, harness.Store.CommitCount);
    }

    [Fact]
    public async Task AReplayBySourceReferenceIsAnIdempotentNoOpAndADifferentGrantUnderTheReferenceIsAConflict()
    {
        var (port, harness) = Create();
        var first = await port.IssueGrantAsync(Command(), T.Ct);

        var replay = await port.IssueGrantAsync(Command(), T.Ct);
        var conflict = await port.IssueGrantAsync(Command(subject: "cloud.ai"), T.Ct);

        Assert.Equal(EntitlementPortStatus.Duplicate, replay.Status);
        Assert.Equal(first.Value, replay.Value);
        Assert.Equal(EntitlementPortStatus.Conflict, conflict.Status);
        Assert.Null(conflict.Value);
        Assert.Equal(1, harness.Store.CommitCount);
        Assert.Single(harness.Store.Records(EntitlementHarness.Workspace).Grants);
    }

    [Theory]
    [InlineData(EntitlementGrantSource.AdminGrant)]
    [InlineData(EntitlementGrantSource.Compensation)]
    [InlineData(EntitlementGrantSource.Migration)]
    public async Task AnOperatorCompensationOrMigrationGrantRequiresAReasonAndCarriesIt(EntitlementGrantSource source)
    {
        var (port, harness) = Create();

        foreach (var missing in new string?[] { null, "", "  " })
        {
            var refused = await port.IssueGrantAsync(Command(source: source, reason: missing), T.Ct);
            Assert.Equal(EntitlementPortStatus.InvalidRequest, refused.Status);
        }

        Assert.Equal(0, harness.Store.CommitCount);
        var accepted = await port.IssueGrantAsync(Command(source: source, reason: "operator action for ticket 42"), T.Ct);
        Assert.Equal(EntitlementPortStatus.Succeeded, accepted.Status);
        Assert.Equal("operator action for ticket 42", accepted.Value!.Reason);
        Assert.Equal("operator action for ticket 42", harness.Store.Records(EntitlementHarness.Workspace).Grants.Single().Reason);
    }

    [Fact]
    public async Task AReasonIsBoundedAndAnOrdinarySourceNeedsNone()
    {
        var (port, harness) = Create();

        Assert.Equal(EntitlementPortStatus.InvalidRequest, (await port.IssueGrantAsync(Command(source: EntitlementGrantSource.AdminGrant, reason: new string('x', 513)), T.Ct)).Status);
        Assert.Equal(EntitlementPortStatus.InvalidRequest, (await port.IssueGrantAsync(Command(source: EntitlementGrantSource.AdminGrant, reason: "a\u0007b"), T.Ct)).Status);
        Assert.Equal(EntitlementPortStatus.Succeeded, (await port.IssueGrantAsync(Command(source: EntitlementGrantSource.AdminGrant, reason: new string('x', 512)), T.Ct)).Status);
        Assert.Equal(EntitlementPortStatus.Succeeded, (await port.IssueGrantAsync(Command("order-9", EntitlementGrantSource.PurchasedCredit), T.Ct)).Status);
        Assert.Equal(2, harness.Store.CommitCount);
    }

    [Fact]
    public async Task QuotaAndAllowanceTermsCrossThePortAndComeBackUnchanged()
    {
        var (port, _) = Create();

        var quota = await port.IssueGrantAsync(Command("order-q", EntitlementGrantSource.StorageAddOn, terms: new QuotaGrantTerms(5_000_000_000, 3), kind: EntitlementGrantKind.Quota, subject: "cloud.storage.bytes"), T.Ct);
        var allowance = await port.IssueGrantAsync(Command("order-a", terms: new AllowanceGrantTerms("plan-1", 7), kind: EntitlementGrantKind.Allowance, subject: "ai.capacity"), T.Ct);

        Assert.Equal(new QuotaGrantTerms(5_000_000_000, 3), quota.Value!.Terms);
        Assert.Equal(new AllowanceGrantTerms("plan-1", 7), allowance.Value!.Terms);
        Assert.Equal(EntitlementGrantSource.StorageAddOn, quota.Value.Source);
    }

    [Fact]
    public async Task AMalformedRequestIsRefusedBeforeAnyStoreCallAndNeverCoerced()
    {
        var (port, harness) = Create();
        var malformed = new[]
        {
            Command() with { Terms = null! },
            Command() with { SourceRef = null! },
            Command() with { Source = (EntitlementGrantSource)99 },
            Command() with { Kind = (EntitlementGrantKind)99 },
            Command() with { EffectiveFrom = From.AddTicks(1) },
            Command() with { EffectiveUntil = From.AddTicks(5) },
            Command() with { EffectiveUntil = From },
            Command() with { Subject = "Not A Key" },
            Command() with { WorkspaceId = "bad id" },
            Command() with { IssuedByActor = "" },
            Command(terms: new QuotaGrantTerms(-1), kind: EntitlementGrantKind.Quota, subject: "cloud.storage.bytes"),
            Command(terms: new CapabilityGrantTerms(), kind: EntitlementGrantKind.Quota, subject: "cloud.storage.bytes"),
        };

        foreach (var command in malformed)
        {
            var result = await port.IssueGrantAsync(command, T.Ct);
            Assert.Equal(EntitlementPortStatus.InvalidRequest, result.Status);
            Assert.Null(result.Value);
            Assert.False(result.Succeeded);
        }

        Assert.Equal(0, harness.Store.CommitCount);
    }

    [Fact]
    public async Task ARevocationNamesOneGrantGuardsTheVersionAndReplaysAsANoOp()
    {
        var (port, harness) = Create();
        var grant = (await port.IssueGrantAsync(Command(), T.Ct)).Value!;
        var version = (await harness.Read()).Version;

        var stale = await port.RevokeGrantAsync(new RevokeGrantCommand(EntitlementHarness.Workspace, grant.GrantId, "refund", null, "operator", version + 1), T.Ct);
        Assert.Equal(EntitlementPortStatus.StaleVersion, stale.Status);
        Assert.Empty(harness.Store.Records(EntitlementHarness.Workspace).Revocations);

        var unknown = await port.RevokeGrantAsync(new RevokeGrantCommand(EntitlementHarness.Workspace, "nope", "refund", null, "operator", version), T.Ct);
        Assert.Equal(EntitlementPortStatus.UnknownGrant, unknown.Status);

        var revoked = await port.RevokeGrantAsync(new RevokeGrantCommand(EntitlementHarness.Workspace, grant.GrantId, "refund", null, "operator", version), T.Ct);
        Assert.Equal(EntitlementPortStatus.Succeeded, revoked.Status);
        Assert.Equal(grant.GrantId, revoked.Value!.GrantId);
        var commits = harness.Store.CommitCount;

        var replay = await port.RevokeGrantAsync(new RevokeGrantCommand(EntitlementHarness.Workspace, grant.GrantId, "refund", null, "operator", (await harness.Read()).Version), T.Ct);
        Assert.Equal(EntitlementPortStatus.Duplicate, replay.Status);
        Assert.Equal(revoked.Value, replay.Value);
        Assert.Equal(commits, harness.Store.CommitCount);
    }

    [Fact]
    public async Task ASubMicrosecondRevocationInstantAndAMalformedRevocationAreRefused()
    {
        var (port, harness) = Create();
        var grant = (await port.IssueGrantAsync(Command(), T.Ct)).Value!;
        var version = (await harness.Read()).Version;

        var fine = await port.RevokeGrantAsync(new RevokeGrantCommand(EntitlementHarness.Workspace, grant.GrantId, "refund", From.AddTicks(1), "operator", version), T.Ct);
        var bad = await port.RevokeGrantAsync(new RevokeGrantCommand(EntitlementHarness.Workspace, grant.GrantId, "Not A Code", null, "operator", version), T.Ct);

        Assert.Equal(EntitlementPortStatus.InvalidRequest, fine.Status);
        Assert.Equal(EntitlementPortStatus.InvalidRequest, bad.Status);
        Assert.Empty(harness.Store.Records(EntitlementHarness.Workspace).Revocations);
    }

    [Fact]
    public async Task AStoreThatCannotBeReachedIsATypedStatusAnUnknownOutcomeIsNeverReportedAsSuccessAndADefectIsNotHidden()
    {
        var harness = new EntitlementHarness().At(100);
        var store = new ScriptedStore(harness.Store);
        var port = new EntitlementGrantPortAdapter(new EntitlementService(store, harness.Definitions, new SequentialIds(), harness.Clock));

        store.LoadFailure = new EntitlementStoreException(EntitlementStoreFailure.Unavailable, "overloaded");
        Assert.Equal(EntitlementPortStatus.Unavailable, (await port.IssueGrantAsync(Command(), T.Ct)).Status);
        Assert.Equal(EntitlementPortStatus.Unavailable, (await port.RevokeGrantAsync(new RevokeGrantCommand(EntitlementHarness.Workspace, "g", "refund", null, "operator", 0), T.Ct)).Status);

        store.LoadFailure = null;
        store.CommitOverride = CommitOutcome.UnknownOutcome;
        var unknown = await port.IssueGrantAsync(Command(), T.Ct);
        Assert.Equal(EntitlementPortStatus.OutcomeUnknown, unknown.Status);
        Assert.False(unknown.Succeeded);

        store.CommitOverride = null;
        store.LoadFailure = new EntitlementStoreException(EntitlementStoreFailure.Defect, "corrupt");
        await Assert.ThrowsAsync<EntitlementStoreException>(async () => await port.IssueGrantAsync(Command(), T.Ct));
    }

    [Fact]
    public void NoEntitlementTypeCrossesThePublishedPort()
    {
        var abstractions = typeof(IEntitlementGrantPort).Assembly;
        Assert.Equal("ArcForges.Cloud.Modules.Abstractions", abstractions.GetName().Name);
        var entitlement = typeof(EntitlementGrantPortAdapter).Assembly;
        foreach (var type in abstractions.GetExportedTypes())
        {
            foreach (var used in PublicSignatureTypes(type))
            {
                Assert.NotEqual(entitlement, used.Assembly);
                Assert.True(used.Assembly == abstractions || used.Assembly == typeof(object).Assembly || used.Assembly.GetName().Name is "System.Runtime" or "System.Collections" or "System.Collections.Immutable"
                    or "Microsoft.Extensions.DependencyInjection.Abstractions" or "Microsoft.AspNetCore.Routing",
                    type.FullName + " exposes " + used.FullName + " of " + used.Assembly.GetName().Name);
            }
        }

        Assert.False(typeof(EntitlementGrantPortAdapter).IsPublic);
        Assert.Contains(typeof(IEntitlementGrantPort), typeof(EntitlementGrantPortAdapter).GetInterfaces());
    }

    private static IEnumerable<Type> PublicSignatureTypes(Type type)
    {
        const BindingFlags all = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        var seen = new List<Type>();
        void Add(Type candidate)
        {
            if (candidate.IsGenericType) foreach (var argument in candidate.GetGenericArguments()) Add(argument);
            if (candidate.HasElementType) Add(candidate.GetElementType()!);
            seen.Add(candidate.IsGenericType ? candidate.GetGenericTypeDefinition() : candidate);
        }

        if (type.BaseType is { } baseType) Add(baseType);
        foreach (var contract in type.GetInterfaces()) Add(contract);
        foreach (var property in type.GetProperties(all)) Add(property.PropertyType);
        foreach (var field in type.GetFields(all)) Add(field.FieldType);
        foreach (var method in type.GetMethods(all).Concat<MethodBase>(type.GetConstructors(all)))
        {
            foreach (var parameter in method.GetParameters()) Add(parameter.ParameterType);
            if (method is MethodInfo info) Add(info.ReturnType);
        }

        return seen;
    }

    /// <summary>A store that delegates to the in-memory store and can fail or answer as scripted.</summary>
    private sealed class ScriptedStore(IEntitlementStore inner) : IEntitlementStore
    {
        public Exception? LoadFailure { get; set; }

        public CommitOutcome? CommitOverride { get; set; }

        public ValueTask<EntitlementState> LoadAsync(string workspaceId, CancellationToken cancellationToken) =>
            LoadFailure is { } failure ? throw failure : inner.LoadAsync(workspaceId, cancellationToken);

        public ValueTask<CommitOutcome> CommitAsync(string workspaceId, long expectedRevision, EntitlementAppend append, EntitlementSnapshot snapshot, CancellationToken cancellationToken) =>
            CommitOverride is { } outcome ? ValueTask.FromResult(outcome) : inner.CommitAsync(workspaceId, expectedRevision, append, snapshot, cancellationToken);

        public ValueTask<FeatureReleaseOutcome> AppendFeatureReleaseAsync(FeatureReleaseFact release, CancellationToken cancellationToken) =>
            inner.AppendFeatureReleaseAsync(release, cancellationToken);
    }
}
