// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Cloud.Storage.Physical;
using Xunit;

namespace ArcForges.Cloud.Tests.Physical;

/// <summary>Sort keys, FTS5 scope-first expressions and the compatible-rollback rule against the vector files the SQLite oracle also runs.</summary>
public sealed class SortKeyAndFtsTests
{
    private static JsonElement Load(string name) =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "tests", "ArcForges.Cloud.Tests", "Vectors", name))).RootElement;

    [Fact]
    public void SortKeysEqualTheSharedVectorsAndAreStrictlyAscendingAsUnsignedBytes()
    {
        var vectors = Load("physical-order-bytes.json");
        Check(vectors.GetProperty("uint64"), value => ExactOrderBytes.FromUint64(ulong.Parse(value, CultureInfo.InvariantCulture)));
        Check(vectors.GetProperty("int64"), value => ExactOrderBytes.FromInt64(long.Parse(value, CultureInfo.InvariantCulture)));
        Check(vectors.GetProperty("decimal"), value => ExactOrderBytes.FromDecimal(decimal.Parse(value, NumberStyles.Float, CultureInfo.InvariantCulture)));

        static void Check(JsonElement list, Func<string, byte[]> encode)
        {
            byte[]? previous = null;
            foreach (var entry in list.EnumerateArray())
            {
                var key = encode(entry.GetProperty("value").GetString()!);
                Assert.Equal(entry.GetProperty("orderHex").GetString(), Convert.ToHexStringLower(key));
                if (previous is not null) Assert.True(ExactOrderBytes.Compare(previous, key) < 0, entry.GetProperty("value").GetString());
                previous = key;
            }
        }
    }

    [Fact]
    public void ADecimalOutsideThePhysicalDomainHasNoSortKey()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ExactOrderBytes.FromDecimal(1.0000000001m));
        Assert.Throws<ArgumentOutOfRangeException>(() => ExactOrderBytes.FromDecimal(12345678901234567890123456789m));
        Assert.Equal(ExactOrderBytes.DecimalLength, ExactOrderBytes.FromDecimal(0m).Length);
        Assert.Equal(ExactOrderBytes.Uint64Length, ExactOrderBytes.FromUint64(0).Length);
    }

    [Fact]
    public void TheScopeKeyIsOneAlphanumericWordOfTheWorkspaceAndTheProduct()
    {
        var workspace = Guid.Parse("0198a7c0-1c3e-7d4a-9b1f-00000000000a");
        Assert.Equal("0198a7c01c3e7d4a9b1f00000000000axarcscope", Fts5Scope.Word(workspace, "arcscope"));
        Assert.True(Fts5Scope.IsWord(Fts5Scope.Word(workspace, "companion")));
        Assert.Throws<PhysicalValueException>(() => Fts5Scope.Word(Guid.Empty, "arcscope"));
        Assert.Throws<PhysicalValueException>(() => Fts5Scope.Word(workspace, "arcnotes"));
        Assert.False(Fts5Scope.IsWord("0198A7C01C3E7D4A9B1F00000000000AXARCSCOPE"));
        Assert.False(Fts5Scope.IsWord("short"));
    }

    [Fact]
    public void EveryQueryVectorProducesExactlyTheSharedMatchExpression()
    {
        var vectors = Load("physical-fts5.json");
        var count = 0;
        foreach (var query in vectors.GetProperty("queries").EnumerateArray())
        {
            var prefix = query.TryGetProperty("prefix", out var flag) && flag.GetBoolean();
            Assert.Equal(query.GetProperty("match").GetString(), Fts5Query.Match(query.GetProperty("scopeWord").GetString()!, query.GetProperty("input").GetString()!, prefix));
            count++;
        }

        Assert.True(count >= 16);
    }

    [Fact]
    public void EveryRefusalVectorIsRefused()
    {
        foreach (var refusal in Load("physical-fts5.json").GetProperty("refusals").EnumerateArray())
            Assert.Throws<Fts5QueryException>(() => Fts5Query.Match(refusal.GetProperty("scopeWord").GetString()!, refusal.GetProperty("input").GetString()!));
    }

    [Fact]
    public void AQuoteInTheTextIsEscapedAndNeverClosesAPhrase()
    {
        var scope = Fts5Scope.Word(Guid.Parse("0198a7c0-1c3e-7d4a-9b1f-00000000000a"), "arcscope");
        var match = Fts5Query.Match(scope, "a\"b");
        Assert.EndsWith("(\"a\"\"b\")", match, StringComparison.Ordinal);
        Assert.StartsWith("scope_key : \"" + scope + "\" AND {title body} : (", match, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRollbackRuleEqualsTheSharedVectors()
    {
        var count = 0;
        foreach (var entry in Load("physical-compatibility.json").GetProperty("cases").EnumerateArray())
        {
            var state = entry.GetProperty("state");
            var result = SchemaCompatibility.Check(
                new SchemaState(state.GetProperty("schemaVersion").GetInt64(), state.GetProperty("readHorizon").GetInt64(), state.GetProperty("writeHorizon").GetInt64()),
                entry.GetProperty("application").GetInt64());
            var expected = entry.GetProperty("expected");
            Assert.Equal(expected.GetProperty("canRead").GetBoolean(), result.CanRead);
            Assert.Equal(expected.GetProperty("canWrite").GetBoolean(), result.CanWrite);
            Assert.Equal(expected.GetProperty("reason").GetString(), result.Reason);
            count++;
        }

        Assert.True(count > 20);
    }
}
