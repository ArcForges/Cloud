// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// The production identifier source: every identifier is a canonical lower-case version 4 UUID with the RFC 9562 variant, accepted by
/// the model's identifier types, never repeated in a large sample and not ordered or stepped like a counter or a clock.
/// </summary>
public sealed class RandomIdentityIdSourceTests
{
    private const int Draws = 100_000;

    [Fact]
    public void EveryIdentifierIsACanonicalVersionFourUuidTheModelAccepts()
    {
        var source = new RandomIdentityIdSource();
        for (var i = 0; i < 1_000; i++)
        {
            var id = source.NewId();
            Assert.True(IdentifierText.IsCanonical(id), id);
            Assert.Equal('4', id[14]);
            Assert.Contains(id[19], "89ab");
            Assert.Equal(id, Guid.ParseExact(id, "D").ToString("D"));
            Assert.Equal(id, UserId.Parse(id).Value);
        }
    }

    [Fact]
    public void AHundredThousandDrawsNeverRepeat()
    {
        var source = new RandomIdentityIdSource();
        var seen = new HashSet<string>(Draws, StringComparer.Ordinal);
        for (var i = 0; i < Draws; i++) Assert.True(seen.Add(source.NewId()), "an identifier repeated");
    }

    [Fact]
    public void IdentifiersAreNeitherOrderedNorSteppedLikeACounter()
    {
        var source = new RandomIdentityIdSource();
        var ids = Enumerable.Range(0, 1_000).Select(_ => source.NewId()).ToArray();

        // A counter or a clock-based identifier is (nearly) sorted; independent random draws are sorted in about half of the neighbour pairs.
        var ascending = ids.Zip(ids.Skip(1)).Count(pair => string.CompareOrdinal(pair.First, pair.Second) < 0);
        Assert.InRange(ascending, 400, 600);

        // The last twelve hex digits of neighbours never differ by one constant step.
        var tails = ids.Select(id => long.Parse(id[24..], NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToArray();
        var steps = tails.Zip(tails.Skip(1)).Select(pair => pair.Second - pair.First).Distinct().Count();
        Assert.True(steps > 990, "the identifiers step like a counter");

        // Every random nibble position takes every hex digit across the sample (the version nibble is the only fixed one).
        for (var position = 0; position < 36; position++)
        {
            if (position is 8 or 13 or 14 or 18 or 23 or 19) continue;
            Assert.Equal(16, ids.Select(id => id[position]).Distinct().Count());
        }
    }

    [Fact]
    public void TwoSourcesDoNotShareASequence()
    {
        var first = Enumerable.Range(0, 100).Select(_ => new RandomIdentityIdSource().NewId()).ToHashSet(StringComparer.Ordinal);
        var second = Enumerable.Range(0, 100).Select(_ => new RandomIdentityIdSource().NewId());
        Assert.DoesNotContain(second, first.Contains);
    }
}
