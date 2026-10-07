// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.QuotaDefinitions;

public sealed class QuotaDefinitionValidatorTests
{
    private const string Canonical = """{"definitions":[{"combination":"Sum","key":"storage.bytes","mode":"Gauge","unit":"bytes"}],"definitionsVersion":"v1","schemaVersion":"entitlement.quota-definitions.v1"}""";
    private static QuotaResolverDefinition[] Resolver() => [new("storage.bytes", QuotaDefinitionCombination.Sum)];
    private static QuotaDefinitionValidationResult Validate(string value, IReadOnlyList<QuotaResolverDefinition>? expected = null)
        => new QuotaDefinitionValidator().Validate(Encoding.UTF8.GetBytes(value), "v1", expected ?? Resolver(), TestContext.Current.CancellationToken);

    [Fact]
    public void CompleteCanonicalArtifactRetainsExactOwnerSemanticsAndDefensiveBuffers()
    {
        var bytes = Encoding.UTF8.GetBytes(Canonical);
        var result = new QuotaDefinitionValidator().Validate(bytes, "v1", Resolver(), TestContext.Current.CancellationToken);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, result.Status);
        var profile = Assert.IsType<QuotaSemanticProfile>(result.Profile);
        bytes[0] = 0;
        var returned = profile.CanonicalBytes.ToArray(); returned[0] = 0;
        Assert.Equal(Canonical, Encoding.UTF8.GetString(profile.CanonicalBytes.Span));
        var definition = Assert.Single(profile.Definitions);
        Assert.Equal(QuotaDefinitionMode.Gauge, definition.Mode);
        Assert.Equal(QuotaDefinitionUnit.Bytes, definition.Unit);
        Assert.Equal(QuotaDefinitionCombination.Sum, definition.Combination);
        Assert.Equal("v1", profile.DefinitionsVersion);
    }

    [Theory]
    [InlineData("\"bytes\"", "\"tokens\"")]
    [InlineData("\"Gauge\"", "\"Month\"")]
    [InlineData("\"Sum\"", "\"sum\"")]
    [InlineData("\"Sum\"", "\"Max\"")]
    [InlineData("\"storage.bytes\"", "\"Storage.bytes\"")]
    [InlineData("\"v1\"", "\"v2\"")]
    [InlineData("\"unit\":\"bytes\"", "\"unit\":\"bytes\",\"unit\":\"bytes\"")]
    [InlineData("\"mode\":\"Gauge\"", "\"mode\":\"Gauge\",\"approved\":true")]
    [InlineData("\"definitionsVersion\":\"v1\"", "\"definitionsVersion\":\"v1\",\"calendar\":\"monthly\"")]
    public void UnknownChangedOrDuplicateSemanticsNeverValidate(string oldValue, string replacement)
    {
        var result = Validate(Canonical.Replace(oldValue, replacement, StringComparison.Ordinal));
        Assert.Equal(QuotaDefinitionStatus.Invalid, result.Status);
        Assert.Null(result.Profile);
    }

    [Fact]
    public void ExactResolverMembershipCombinationAndCanonicalBytesAreRequired()
    {
        Assert.Equal(QuotaDefinitionStatus.Invalid, Validate(Canonical, []).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, Validate(Canonical, [.. Resolver(), new("absent", QuotaDefinitionCombination.Max)]).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, Validate(Canonical, [.. Resolver(), .. Resolver()]).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, Validate(Canonical, [new("storage.bytes", QuotaDefinitionCombination.PriorityReplace)]).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, Validate(Canonical + "\n").Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, Validate(Canonical.Replace("\"combination\":\"Sum\",\"key\":\"storage.bytes\"",
            "\"key\":\"storage.bytes\",\"combination\":\"Sum\"", StringComparison.Ordinal)).Status);
    }

    [Fact]
    public void BoundedArtifactsStrictEncodingAndCancellationRefuse()
    {
        var validator = new QuotaDefinitionValidator();
        Assert.Equal(QuotaDefinitionStatus.Invalid, validator.Validate(new byte[65537], "v1", Resolver(), TestContext.Current.CancellationToken).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, validator.Validate(new byte[] { 255, 255 }, "v1", Resolver(), TestContext.Current.CancellationToken).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, validator.Validate(Encoding.UTF8.GetBytes(Canonical), "\ud800", Resolver(), TestContext.Current.CancellationToken).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, validator.Validate(Encoding.UTF8.GetBytes(Canonical), "v1",
            Enumerable.Range(0, 65).Select(i => new QuotaResolverDefinition("q" + i, QuotaDefinitionCombination.Sum)).ToArray(), TestContext.Current.CancellationToken).Status);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        Assert.Throws<OperationCanceledException>(() => validator.Validate(Encoding.UTF8.GetBytes(Canonical), "v1", Resolver(), cancel.Token));
    }

    [Fact]
    public void ApprovedAssociationCopiesExpectedResolverSetAndRetainsActualRealmFact()
    {
        var expected = Resolver();
        var association = new ApprovedQuotaConfiguration(Guid.NewGuid(), Guid.NewGuid(), new('a', 64), "artifact-1",
            QuotaDefinitionValidator.ProfileName, new('b', 64), Encoding.UTF8.GetByteCount(Canonical), "v1", "selfHosted", "configuration-owner", expected);
        expected[0] = new("forged", QuotaDefinitionCombination.Max);
        Assert.Equal("storage.bytes", Assert.Single(association.ResolverDefinitions).Key);
        Assert.Equal("selfHosted", association.RealmKind);
    }
}
