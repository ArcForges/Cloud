// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using static ArcForges.Cloud.Tests.Entitlement.Fixtures;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>Clock determinism against an injected time source (EN-07, EN-08), the stored form, the module listing and source-level guards.</summary>
public sealed partial class ClockAndStructureTests
{
    [Fact]
    public async Task TwoReplicasAtTheSameInstantProduceTheSameSnapshot()
    {
        var one = new EntitlementHarness().At(0);
        await one.Issue(Capability("cloud.sync", 0, null, "s1"));
        await one.AddTerm(Term("t1", 0, 30 * Day));
        var first = await one.At(Day).Refresh();

        var replica = new EntitlementService(one.Store, one.Definitions, new SequentialIds(), new SettableTimeProvider(DateTimeOffset.UnixEpoch.AddSeconds(Day)));
        var second = await replica.ReadAsync(EntitlementHarness.Workspace, CancellationToken.None);
        Assert.True(first.SameAs(second.Value!));
    }

    [Fact]
    public async Task AClockThatMovesBackwardsNeverRewindsAStoredComputationOrBackdatesARecord()
    {
        var h = new EntitlementHarness().At(10 * Day);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        var stored = await h.Refresh();
        h.At(5 * Day);
        var after = await h.Refresh();
        Assert.Equal(stored.ComputedAt, after.ComputedAt);
        var grant = await h.Issue(Capability("cloud.web_continuity", 0, null, "s2"));
        // Admitted strictly after the stored computation (one microsecond), never at the rolled-back clock's earlier instant.
        Assert.True(grant.CreatedAt > T(10 * Day) && grant.CreatedAt.Value <= T(10 * Day).Value + 10);
        await h.AssertRebuildEqual();
    }

    [Fact]
    public void AnIntervalEndsExactlyAtItsExclusiveEndToTheMicrosecond()
    {
        var definitions = Definitions();
        var grant = new Grant("g1", "ws1", GrantKind.Capability, "cloud.sync", new CapabilityValue(), GrantSource.Subscription, "s1", T(0), null, "commerce", T(0));
        var term = new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(100), null, T(0), T(0));
        var records = EntitlementRecordSet.Empty("ws1") with { Grants = [grant], Terms = [term] };
        Assert.True(EntitlementResolver.Resolve(records, definitions, new UtcMicros(100 * 1_000_000 - 1)).Content.Capabilities.Single(c => c.Key == "cloud.sync").Granted);
        Assert.False(EntitlementResolver.Resolve(records, definitions, new UtcMicros(100 * 1_000_000)).Content.Capabilities.Single(c => c.Key == "cloud.sync").Granted);
    }

    [Fact]
    public void InstantsKeepMicrosecondPrecisionAndFloorBeforeTheEpoch()
    {
        var instant = DateTimeOffset.UnixEpoch.AddTicks(1_234_567);
        Assert.Equal(123_456, UtcMicros.FromDateTimeOffset(instant).Value);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddTicks(1_234_560), UtcMicros.FromDateTimeOffset(instant).ToDateTimeOffset());
        Assert.Equal(-1, UtcMicros.FromDateTimeOffset(DateTimeOffset.UnixEpoch.AddTicks(-1)).Value);
        Assert.Equal(-1, UtcMicros.FromDateTimeOffset(DateTimeOffset.UnixEpoch.AddTicks(-10)).Value);
        Assert.Equal(-2, UtcMicros.FromDateTimeOffset(DateTimeOffset.UnixEpoch.AddTicks(-11)).Value);
        Assert.Equal(0, UtcMicros.FromDateTimeOffset(new DateTimeOffset(1970, 1, 1, 2, 0, 0, TimeSpan.FromHours(2))).Value);
    }

    [Fact]
    public async Task TheStoredFormIsCanonicalAndAMalformedStoredValueIsRefused()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        await h.AddTerm(Term("t1", 0, 30 * Day));
        var snapshot = await h.At(Day).Refresh();
        var json = SnapshotCodec.Serialize(snapshot);
        Assert.Equal(json, SnapshotCodec.Serialize(SnapshotCodec.Deserialize(json)));
        Assert.Throws<FormatException>(() => SnapshotCodec.Deserialize(json[..^5]));
        Assert.Throws<FormatException>(() => SnapshotCodec.Deserialize(json.Replace("\"Available\"", "\"0\"", StringComparison.Ordinal)));
        Assert.Throws<FormatException>(() => SnapshotCodec.Deserialize(json.Replace("\"Available\"", "\"Sometimes\"", StringComparison.Ordinal)));
        Assert.Throws<FormatException>(() => SnapshotCodec.Deserialize(json.Replace("\"version\"", "\"versions\"", StringComparison.Ordinal)));
        Assert.Throws<FormatException>(() => SnapshotCodec.Deserialize("[]"));
    }

    [Fact]
    public void TheModuleListsTheResolverAndItNeedsItsPortsBeforeAnythingCanAskForIt()
    {
        var services = new ServiceCollection();
        ((IModuleBoundary)EntitlementModule.Instance).Register(services);
        using (var provider = services.BuildServiceProvider())
        {
            Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<EntitlementService>());
        }

        services.AddSingleton<IEntitlementStore>(new InMemoryEntitlementStore());
        services.AddSingleton<IEntitlementDefinitionSource>(new FixedDefinitions(Definitions()));
        services.AddSingleton<IEntitlementIdSource>(new SequentialIds());
        using var composed = services.BuildServiceProvider();
        Assert.NotNull(composed.GetRequiredService<EntitlementService>());
    }

    [Fact]
    public void NoResolverSourceReadsAnAmbientClockOrRandomnessOrUsesBinaryFloatingPoint()
    {
        var root = FindRoot();
        var sources = Directory.GetFiles(Path.Combine(root, "src", "ArcForges.Cloud.Modules.Entitlement", "Resolver"), "*.cs", SearchOption.AllDirectories);
        Assert.NotEmpty(sources);
        var forbidden = new[]
        {
            "DateTime.Now", "DateTime.UtcNow", "DateTimeOffset.Now", "DateTimeOffset.UtcNow", "TimeProvider.System", "Environment.TickCount",
            "Stopwatch", "Random", "Guid.NewGuid", "DateTime.Today",
        };
        foreach (var path in sources)
        {
            var code = string.Join('\n', File.ReadAllLines(path).Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal)));
            foreach (var token in forbidden) Assert.False(code.Contains(token, StringComparison.Ordinal), path + " uses " + token);
            Assert.False(BinaryFloat().IsMatch(code), path + " uses binary floating point");
            var readsTime = code.Contains("GetUtcNow", StringComparison.Ordinal);
            Assert.Equal(Path.GetFileName(path) == "EntitlementService.cs", readsTime);
        }
    }

    [Fact]
    public void TheResolverNamesNoProviderAndHardCodesNoCommercialFigureOrCapability()
    {
        var root = FindRoot();
        var sources = Directory.GetFiles(Path.Combine(root, "src", "ArcForges.Cloud.Modules.Entitlement", "Resolver"), "*.cs", SearchOption.AllDirectories);
        foreach (var path in sources)
        {
            var code = File.ReadAllText(path);
            foreach (var token in new[] { "Paddle", "Payoneer", "Stripe", "cloud.sync", "cloud.ai", "cloud.storage", "isPro", "IsPro" })
            {
                Assert.False(code.Contains(token, StringComparison.Ordinal), path + " names " + token);
            }
        }
    }

    [GeneratedRegex(@"\b(float|double|decimal)\b", RegexOptions.CultureInvariant)]
    private static partial Regex BinaryFloat();

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Cloud.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("The Cloud repository root was not found.");
    }
}
