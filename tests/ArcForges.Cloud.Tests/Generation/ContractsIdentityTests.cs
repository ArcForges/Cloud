// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Tools.Generation;
using Xunit;

namespace ArcForges.Cloud.Tests.Generation;

/// <summary>CLOUD.84 S33(3)(a): the committed Contracts identity is the restored package's source.json, byte for byte.</summary>
public sealed class ContractsIdentityTests
{
    [Fact]
    public void CommittedIdentityIsByteEqualToTheEmbeddedRestoredContractsSource()
    {
        var committed = File.ReadAllBytes(Path.Combine(T.RepoRoot().FullName, "eng/generated/contracts-identity.json"));
        var embedded = ContractsIdentity.Read(typeof(HelloEndpoint).Assembly);
        Assert.True(committed.AsSpan().SequenceEqual(embedded), "eng/generated/contracts-identity.json differs from the restored source.json.");
    }
}
