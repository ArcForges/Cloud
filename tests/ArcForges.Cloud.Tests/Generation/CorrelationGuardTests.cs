// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.Cloud.Generation;
using ArcForges.Cloud.Ingress;
using ArcForges.Contracts.Foundation.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Generation;

/// <summary>
/// CLOUD.84 S34(3): the correlation guards the Worker applies are declared in C# and generated. The declared identity shape must accept
/// exactly the identities the host accepts, and the declared field numbers must be the Contracts field numbers the host reads.
/// </summary>
public sealed class CorrelationGuardTests
{
    [Theory]
    [InlineData("4bf92f35-77b3-4da6-a3ce-929d0e0e4736", true)]
    [InlineData("4BF92F35-77B3-4DA6-A3CE-929D0E0E4736", false)]
    [InlineData("00000000-0000-0000-0000-000000000000", false)]
    [InlineData("4bf92f3577b34da6a3ce929d0e0e4736", false)]
    [InlineData("{4bf92f35-77b3-4da6-a3ce-929d0e0e4736}", false)]
    [InlineData(" 4bf92f35-77b3-4da6-a3ce-929d0e0e4736", false)]
    [InlineData("4bf92f35-77b3-4da6-a3ce-929d0e0e473", false)]
    [InlineData("4bf92f35-77b3-4da6-a3ce-929d0e0e47360", false)]
    [InlineData("4bf92f35-77b3-4da6-a3ce-929d0e0e4736\n", false)]
    [InlineData("", false)]
    public void TheDeclaredShapeAcceptsExactlyWhatTheHostAccepts(string text, bool valid)
    {
        // The Worker applies the pattern as JavaScript does, where $ matches only at the end of the input: \z gives .NET the same meaning.
        var declared = Regex.IsMatch(text, CorrelationGuards.UuidPattern + @"\z") && text != CorrelationGuards.NilUuid;
        Assert.Equal(valid, declared);
        Assert.Equal(valid, CorrelationContext.IsValidId(text));
    }

    [Fact]
    public void TheDeclaredFieldNumbersAreTheContractsFieldNumbers()
    {
        Assert.Equal(RequestMeta.CorrelationIdFieldNumber, CorrelationGuards.CorrelationIdField);
        Assert.Equal(Id.ValueFieldNumber, CorrelationGuards.IdValueField);
        Assert.Equal(16, CorrelationGuards.IdByteLength);
        Assert.Equal("00", CorrelationGuards.TraceparentVersion);
        Assert.Equal("01", CorrelationGuards.TraceparentFlags);
    }

    [Fact]
    public void TheGeneratedWorkerTableCarriesTheSameGuards()
    {
        var correlation = ArcForges.Cloud.Tools.Generation.HostReader.Read().Correlation;
        Assert.Equal(CorrelationGuards.UuidPattern, correlation.UuidPattern);
        Assert.Equal(CorrelationGuards.NilUuid, correlation.NilUuid);
        Assert.Equal(CorrelationGuards.RequestMetaField, correlation.RequestMetaField);
        Assert.Equal(CorrelationGuards.CorrelationIdField, correlation.CorrelationIdField);
        Assert.Equal(CorrelationGuards.IdValueField, correlation.IdValueField);
        Assert.Equal(CorrelationGuards.IdByteLength, correlation.IdByteLength);
    }
}
