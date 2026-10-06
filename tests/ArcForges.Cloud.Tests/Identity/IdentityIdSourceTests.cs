// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Persistence;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

public sealed class IdentityIdSourceTests
{
    [Fact]
    public void LargeConcurrentDrawHasCanonicalVersionAndVariantAndNoDuplicates()
    {
        var source = new IdentityIdSource();
        var values = new System.Collections.Concurrent.ConcurrentBag<string>();
        Parallel.For(0, 20_000, _ => values.Add(source.NewId()));
        Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
        foreach (var value in values)
        {
            Assert.True(Guid.TryParseExact(value, "D", out _));
            Assert.Equal(value.ToLowerInvariant(), value);
            Assert.Equal('4', value[14]);
            Assert.Contains(value[19], "89ab");
        }
    }
}
