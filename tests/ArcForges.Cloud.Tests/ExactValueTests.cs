// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.RegularExpressions;
using ArcForges.Cloud.Storage;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed partial class ExactValueTests
{
    [Theory]
    [InlineData("0", 0L)]
    [InlineData("-9223372036854775808", long.MinValue)]
    [InlineData("9223372036854775807", long.MaxValue)]
    [InlineData("9007199254740993", 9007199254740993L)]
    [InlineData("-9007199254740993", -9007199254740993L)]
    public void Int64IsExactAtTheBoundariesAndBeyondTwoToTheFiftyThree(string text, long expected)
    {
        Assert.True(D1Values.TryParseInt64(text, out var value));
        Assert.Equal(expected, value);
        Assert.True(D1Values.TryGetInt64(D1Values.Int64(expected), out var again));
        Assert.Equal(expected, again);
        Assert.Equal(text, ((ArcForges.Contracts.CloudInternal.Storage.V1.D1ScalarD1Int64Value)D1Values.Int64(expected)).Value.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("-")]
    [InlineData("+1")]
    [InlineData("01")]
    [InlineData("-0")]
    [InlineData("1.0")]
    [InlineData("1e3")]
    [InlineData(" 1")]
    [InlineData("1 ")]
    [InlineData("٣")]
    [InlineData("9223372036854775808")]
    [InlineData("-9223372036854775809")]
    [InlineData("123456789012345678901")]
    public void Int64RefusesEveryNonCanonicalOrOutOfRangeText(string text) => Assert.False(D1Values.TryParseInt64(text, out _));

    [Theory]
    [InlineData("0", 0UL)]
    [InlineData("18446744073709551615", ulong.MaxValue)]
    [InlineData("9223372036854775808", 9223372036854775808UL)]
    public void Uint64IsExact(string text, ulong expected)
    {
        Assert.True(D1Values.TryParseUint64(text, out var value));
        Assert.Equal(expected, value);
        Assert.True(D1Values.TryGetUint64(D1Values.Uint64(expected), out var again));
        Assert.Equal(expected, again);
    }

    [Theory]
    [InlineData("")]
    [InlineData("-1")]
    [InlineData("-0")]
    [InlineData("00")]
    [InlineData("1.0")]
    [InlineData("18446744073709551616")]
    [InlineData("+1")]
    public void Uint64RefusesEveryNonCanonicalOrOutOfRangeText(string text) => Assert.False(D1Values.TryParseUint64(text, out _));

    [Theory]
    [InlineData("0")]
    [InlineData("-1234567890123456789.123456789")]
    [InlineData("9999999999999999999.999999999")]
    [InlineData("0.000000001")]
    [InlineData("-0.000000001")]
    [InlineData("123456789012345678901234567")]
    [InlineData("1.5")]
    public void CanonicalDecimalsRoundTripExactly(string text)
    {
        Assert.True(D1Values.TryParseDecimal(text, out var value));
        Assert.Equal(text, D1Values.FormatDecimal(value));
        Assert.True(D1Values.TryGetDecimal(D1Values.Decimal(value), out var again));
        Assert.Equal(value, again);
    }

    [Theory]
    [InlineData("")]
    [InlineData("-")]
    [InlineData("-0")]
    [InlineData("-0.0")]
    [InlineData("00.5")]
    [InlineData("+1")]
    [InlineData("1e3")]
    [InlineData("1.")]
    [InlineData(".5")]
    [InlineData("1.50")]
    [InlineData("1.0000000001")]
    [InlineData("12345678901234567890123456789")]
    [InlineData("1,5")]
    [InlineData(" 1")]
    public void DecimalRefusesEveryNonCanonicalText(string text) => Assert.False(D1Values.TryParseDecimal(text, out _));

    [Fact]
    public void FormattingStripsTrailingZerosAndNeverRoundsOutsideTheDomain()
    {
        Assert.Equal("1.1", D1Values.FormatDecimal(1.10m));
        Assert.Equal("0", D1Values.FormatDecimal(0.000m));
        Assert.Equal("0", D1Values.FormatDecimal(-0.0m));
        Assert.Throws<ArgumentOutOfRangeException>(() => D1Values.FormatDecimal(0.0000000001m));
        Assert.Throws<ArgumentOutOfRangeException>(() => D1Values.FormatDecimal(decimal.MaxValue));
    }

    [Fact]
    public void ParsingAndFormattingDoNotDependOnTheCurrentCulture()
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("de-DE");
            Assert.True(D1Values.TryParseDecimal("-1234.5", out var value));
            Assert.Equal("-1234.5", D1Values.FormatDecimal(value));
            Assert.True(D1Values.TryParseInt64("-9223372036854775808", out var signed));
            Assert.Equal("-9223372036854775808", ((ArcForges.Contracts.CloudInternal.Storage.V1.D1ScalarD1Int64Value)D1Values.Int64(signed)).Value.Value);
            Assert.False(D1Values.TryParseDecimal("1,5", out _));
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    [Fact]
    public void ScalarReadersRefuseTheWrongAlternative()
    {
        Assert.False(D1Values.TryGetInt64(D1Values.Uint64(1), out _));
        Assert.False(D1Values.TryGetUint64(D1Values.Int64(1), out _));
        Assert.False(D1Values.TryGetDecimal(D1Values.Text("1"), out _));
        Assert.False(D1Values.TryGetText(D1Values.Int64(1), out _));
        Assert.False(D1Values.TryGetBytes(D1Values.Text("AA"), out _));
        Assert.False(D1Values.TryGetBool(D1Values.Int64(1), out _));
        Assert.False(D1Values.TryGetInt64(null, out _));
        Assert.True(D1Values.IsNull(D1Values.Null()));
        Assert.False(D1Values.IsNull(D1Values.Text("")));
        Assert.True(D1Values.TryGetBytes(D1Values.Bytes([0, 255, 16]), out var bytes));
        Assert.Equal(new byte[] { 0, 255, 16 }, bytes);
        Assert.True(D1Values.TryGetBool(D1Values.Bool(true), out var flag) && flag);
    }

    [Fact]
    public void PlanManifestMatchesAnIndependentRecomputationFromThePlanFiles()
    {
        var directory = Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud", "Storage", "Plans");
        var lines = new List<(string Id, int Version, string Line)>();
        foreach (var file in Directory.GetFiles(directory, "*.sql", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file).Replace("\r\n", "\n", StringComparison.Ordinal).TrimEnd() + "\n";
            var id = Regex.Match(text, @"^-- plan: (\S+)", RegexOptions.Multiline).Groups[1].Value;
            var version = int.Parse(Regex.Match(text, @"^-- version: (\d+)", RegexOptions.Multiline).Groups[1].Value, CultureInfo.InvariantCulture);
            lines.Add((id, version, $"{id}@{version}:{T.Sha256Hex(text)}"));
        }

        var joined = string.Join('\n', lines.OrderBy(l => l.Id, StringComparer.Ordinal).ThenBy(l => l.Version).Select(l => l.Line)) + "\n";
        Assert.Equal(T.Sha256Hex(joined), PlanManifest.Hash);
        Assert.Equal(lines.Count, PlanManifest.All.Count);
        Assert.Equal(lines.Select(l => l.Id).Order(StringComparer.Ordinal), PlanManifest.All.Select(p => p.Id).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void EveryPlanDefinitionMatchesItsSqlPlaceholdersAndExactCasts()
    {
        var directory = Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud", "Storage", "Plans");
        foreach (var plan in PlanManifest.All)
        {
            var file = Directory.GetFiles(directory, plan.Id[(plan.Id.IndexOf('.', StringComparison.Ordinal) + 1)..] + ".sql", SearchOption.AllDirectories).Single();
            var blocks = Regex.Split(File.ReadAllText(file).Replace("\r\n", "\n", StringComparison.Ordinal), @"^-- statement:.*\n", RegexOptions.Multiline).Skip(1).ToArray();
            Assert.Equal(blocks.Length, plan.Statements.Count);
            for (var index = 0; index < blocks.Length; index++)
            {
                var sql = QuoteLiteral().Replace(blocks[index], "''");
                var placeholders = sql.Count(c => c == '?');
                Assert.Equal(placeholders, plan.Statements[index].Params.Count);
                var casts = CastPlaceholder().Matches(sql).Count;
                Assert.Equal(casts, plan.Statements[index].Params.Count(p => p.Kind == PlanKind.Int64));
            }

            Assert.Equal(plan.Access == PlanAccess.Read, plan.Statements.Any(s => s.Returns is not null));
        }

        Assert.Equal(PlanManifest.All.Count, PlanManifest.All.Select(p => p.Id).Distinct().Count());
    }

    [GeneratedRegex("'(?:[^']|'')*'")]
    private static partial Regex QuoteLiteral();

    [GeneratedRegex(@"CAST\(\?\s+AS\s+INTEGER\)")]
    private static partial Regex CastPlaceholder();
}
