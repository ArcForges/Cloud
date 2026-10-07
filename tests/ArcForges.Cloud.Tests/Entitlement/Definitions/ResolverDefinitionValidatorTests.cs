// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.ResolverDefinitionAuthority;

public sealed class ResolverDefinitionValidatorTests
{
    private static readonly ResolverDefinitionValidator Validator = new();
    private const string Canonical = "{\"allowances\":[{\"key\":\"ai\"}],\"capabilities\":[{\"featureGate\":\"released\",\"key\":\"agent\",\"requiresPaidTerm\":true},{\"featureGate\":null,\"key\":\"local\",\"requiresPaidTerm\":false}],\"definitionsVersion\":\"v1\",\"quotas\":[{\"combination\":\"Sum\",\"key\":\"bytes\"},{\"combination\":\"Max\",\"key\":\"devices\"},{\"combination\":\"PriorityReplace\",\"key\":\"support\"}],\"schemaVersion\":\"entitlement.resolver-definitions.v1\"}";

    [Fact]
    public void CompleteDefinitionsPreserveDistinctOwnerSemanticsAndDefensiveCopies()
    {
        var bytes = Encoding.UTF8.GetBytes(Canonical);
        var result = Validator.Validate(bytes, "v1", TestContext.Current.CancellationToken);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, result.Status);
        var profile = Assert.IsType<ResolverDefinitionProfile>(result.Profile);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), profile.Hash);
        bytes[0] = 0;
        var escapedCopy = profile.CanonicalBytes.ToArray();
        escapedCopy[0] = 0;
        Assert.Equal(Canonical, Encoding.UTF8.GetString(profile.CanonicalBytes.Span));
        var official = ResolverDefinitionValidator.ToDefinitions(profile, "official");
        var selfHosted = ResolverDefinitionValidator.ToDefinitions(profile, "selfHosted");
        Assert.False(official.IsSelfHostRealm);
        Assert.True(selfHosted.IsSelfHostRealm);
        Assert.Equal("released", official.Capabilities[0].FeatureGate);
        Assert.True(official.Capabilities[0].RequiresPaidTerm);
        Assert.False(official.Capabilities[1].RequiresPaidTerm);
        Assert.Single(official.Allowances);
        Assert.Equal(3, official.Quotas.Length);
        Assert.Throws<ArcForges.Cloud.Modules.Entitlement.Resolver.Domain.ResolverInputException>(() => ResolverDefinitionValidator.ToDefinitions(profile, "unknown"));
    }

    [Theory]
    [InlineData("\"Sum\"", "0")]
    [InlineData("\"Sum\"", "\"sum\"")]
    [InlineData("\"requiresPaidTerm\":true", "\"requiresPaidTerm\":\"true\"")]
    [InlineData("\"featureGate\":null", "\"featureGate\":\"UPPER\"")]
    [InlineData("\"key\":\"devices\"", "\"key\":\"bytes\"")]
    [InlineData("\"key\":\"agent\"", "\"key\":\"agent\",\"key\":\"local\"")]
    [InlineData("\"key\":\"ai\"", "\"extra\":true,\"key\":\"ai\"")]
    [InlineData("\"definitionsVersion\":\"v1\"", "\"definitionsVersion\":\"v2\"")]
    [InlineData("\"capabilities\":", "\"capabilities\": ")]
    public void MalformedOrAmbiguousOwnerArtifactsNeverYieldDefinitions(string from, string to)
    {
        var result = Validator.Validate(Encoding.UTF8.GetBytes(Canonical.Replace(from, to, StringComparison.Ordinal)), "v1", TestContext.Current.CancellationToken);
        Assert.Equal(ResolverDefinitionStatus.Invalid, result.Status);
        Assert.Null(result.Profile);
    }

    [Fact]
    public void BoundsAndStrictUtf8RefuseBeforeAnyPartialProfileEscapes()
    {
        Assert.Equal(ResolverDefinitionStatus.Invalid, Validator.Validate(new byte[65537], "v1", TestContext.Current.CancellationToken).Status);
        Assert.Equal(ResolverDefinitionStatus.Invalid, Validator.Validate(new byte[] { 0xC0, 0xAF }, "v1", TestContext.Current.CancellationToken).Status);
        var entries = Enumerable.Range(0, 65).Select(i => new ResolverAllowanceDefinition("k" + i.ToString("D2", System.Globalization.CultureInfo.InvariantCulture)));
        var tooMany = ResolverDefinitionValidator.Encode("v1", [], [], entries);
        Assert.Equal(ResolverDefinitionStatus.Invalid, Validator.Validate(tooMany, "v1", TestContext.Current.CancellationToken).Status);
        Assert.Equal(ResolverDefinitionStatus.Invalid, Validator.Validate(Encoding.UTF8.GetBytes(Canonical), "invalid/version", TestContext.Current.CancellationToken).Status);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => Validator.Validate(Encoding.UTF8.GetBytes(Canonical), "v1", cancellation.Token));
    }
}
