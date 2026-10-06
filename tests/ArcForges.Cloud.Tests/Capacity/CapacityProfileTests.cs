// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Capacity;
using Xunit;

namespace ArcForges.Cloud.Tests.CapacityTests;

public sealed class CapacityProfileTests
{
    private static readonly Guid Realm = Guid.Parse("20000000-0000-0000-0000-000000000001");
    internal static CapacityProfile Selected() => new("launch-capacity.v1", Realm, "standard-2", 4, 600, 8000, 10000,
        new(64, 16, 32, 8, 2), CapacityProfileCodec.SelectedAccount, CapacityProfileCodec.SelectedRealm, [60, 70, 80, 90], new('a', 64), new('b', 64));
    private static string Hash(string json) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    [Fact]
    public void ExactApprovedProfilePreservesLargeUInt64ValuesAndSeparateControlReserve()
    {
        var json = CapacityProfileCodec.Encode(Selected());
        Assert.Contains("\"r2Bytes\":\"21474836480000\"", json);
        Assert.Contains("\"vectors\":2000000", json);
        Assert.True(CapacityProfileCodec.TryDecode(json, Hash(json), Realm, CapacityProfileCodec.SelectedRealm, out var profile));
        Assert.Equal(21474836480000UL, profile!.RealmBudgets.R2Bytes);
        Assert.Equal(new CapacityConcurrency(64, 16, 32, 8, 2), profile.PerInstance);
    }
    [Theory]
    [InlineData("\"instanceType\":\"standard-2\"", "\"instanceType\":\"lite\"")]
    [InlineData("\"instanceSlots\":4", "\"instanceSlots\":5")]
    [InlineData("\"sleepAfterSeconds\":600", "\"sleepAfterSeconds\":0")]
    [InlineData("\"controlSlots\":2", "\"controlSlots\":0")]
    [InlineData("\"queuedCalls\":32", "\"queuedCalls\":32000")]
    [InlineData("\"readinessTimeoutMs\":8000", "\"readinessTimeoutMs\":10001")]
    [InlineData("[60,70,80,90]", "[60,70,80]")]
    [InlineData("\"21474836480000\"", "21474836480000")]
    [InlineData("\"21474836480000\"", "\"021474836480000\"")]
    [InlineData("\"21474836480000\"", "\"18446744073709551616\"")]
    [InlineData("\"vectors\":2000000", "\"vectors\":-1")]
    [InlineData("\"instanceSlots\":4", "\"instanceSlots\":4,\"instanceSlots\":4")]
    [InlineData("\"instanceSlots\":4", "\"instanceSlots\":4,\"perAccountContainers\":true")]
    public void AlteredUnsafeOrAmbiguousProfileIsRefusedEvenWithMatchingArtifactHash(string oldValue, string replacement)
    {
        var json = CapacityProfileCodec.Encode(Selected());
        Assert.Contains(oldValue, json);
        json = json.Replace(oldValue, replacement, StringComparison.Ordinal);
        Assert.False(CapacityProfileCodec.TryDecode(json, Hash(json), Realm, CapacityProfileCodec.SelectedRealm, out _));
    }
    [Fact]
    public void WrongTrustHandoffRealmProviderCeilingOrBytesCannotActivateProfile()
    {
        var json = CapacityProfileCodec.Encode(Selected());
        Assert.False(CapacityProfileCodec.TryDecode(json, new('0', 64), Realm, CapacityProfileCodec.SelectedRealm, out _));
        Assert.False(CapacityProfileCodec.TryDecode(json, Hash(json), Guid.NewGuid(), CapacityProfileCodec.SelectedRealm, out _));
        Assert.False(CapacityProfileCodec.TryDecode(json, Hash(json), Realm, CapacityProfileCodec.SelectedRealm with { Namespaces = 3999 }, out _));
        Assert.False(CapacityProfileCodec.TryDecode(json + " ", Hash(json), Realm, CapacityProfileCodec.SelectedRealm, out _));
    }
}
