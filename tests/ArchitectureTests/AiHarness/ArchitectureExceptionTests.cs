// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>The owned, expiring exceptions suite (exceptions.test.ts, HAR.40 validation (d)), ported one-for-one.</summary>
public sealed class ArchitectureExceptionTests
{
    private static readonly string Root = CloudRepository.FindRoot();

    private static readonly DateOnly Today = new(2026, 10, 4);

    private static readonly HarnessFinding Finding = new("banned-reflection", "src/x.ts", "Reflect entry point");

    private static JsonObject Entry(params (string Key, string Value)[] overrides)
    {
        var entry = new JsonObject
        {
            ["id"] = "AI-EX-1",
            ["rule"] = "banned-reflection",
            ["file"] = "src/x.ts",
            ["detail"] = "Reflect entry point",
            ["owner"] = "AI architecture owner",
            ["reason"] = "Bounded migration of a reviewed legacy adapter",
            ["created"] = "2026-10-01",
            ["expires"] = "2026-12-01",
        };
        foreach (var (key, value) in overrides) entry[key] = value;
        return entry;
    }

    private static JsonDocument Document(params JsonNode?[] exceptions) =>
        JsonDocument.Parse(new JsonObject { ["schemaVersion"] = 1, ["exceptions"] = new JsonArray(exceptions) }.ToJsonString());

    private static IEnumerable<string> Rules(ExceptionResult result) => result.Problems.Select(problem => problem.Rule);

    [Fact]
    public void ShipsAValidRegisterThatNamesOnlyFindingsOfThisCheckout()
    {
        var sources = HarnessArchitecture.ReadSources(Root);
        var register = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, ArchitectureExceptions.RegisterPath)));
        var result = WorkerAdapter.WorkerLiteralScan.ApplyRegister(sources, register.RootElement, DateOnly.FromDateTime(DateTime.UtcNow));
        Assert.Empty(result.Problems);
        register.Dispose();
    }

    [Fact]
    public void SuppressesExactlyTheNamedFindingWhileValid()
    {
        using var document = Document(Entry());
        var other = Finding with { File = "src/y.ts" };
        var result = ArchitectureExceptions.Apply([Finding, other], document.RootElement, Today);
        Assert.Equal(new[] { other }, result.Remaining);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public void StopsSuppressingAndReportsAnExpiredException()
    {
        using var document = Document(Entry());
        var result = ArchitectureExceptions.Apply([Finding], document.RootElement, new DateOnly(2026, 12, 2));
        Assert.Equal(new[] { Finding }, result.Remaining);
        Assert.Equal(new[] { "exception-expired" }, Rules(result));
    }

    [Fact]
    public void ReportsAnExceptionThatNoLongerMatchesAFinding()
    {
        using var document = Document(Entry());
        var result = ArchitectureExceptions.Apply([], document.RootElement, Today);
        Assert.Equal(new[] { "exception-unused" }, Rules(result));
    }

    [Fact]
    public void BoundsTheLifetime()
    {
        using var long_ = Document(Entry(("expires", "2027-12-01")));
        Assert.Contains("exception-lifetime", Rules(ArchitectureExceptions.Apply([Finding], long_.RootElement, Today)));
        Assert.Equal(180, ArchitectureExceptions.MaxExceptionDays);
        using var zero = Document(Entry(("expires", "2026-10-01")));
        Assert.Contains("exception-lifetime", Rules(ArchitectureExceptions.Apply([Finding], zero.RootElement, Today)));
    }

    [Fact]
    public void RejectsACreationDateInTheFutureWhichWouldDefeatTheLifetimeCap()
    {
        using var document = Document(Entry(("created", "2027-01-01"), ("expires", "2027-03-01")));
        var result = ArchitectureExceptions.Apply([Finding], document.RootElement, Today);
        Assert.Contains("exception-invalid", Rules(result));
    }

    [Fact]
    public void RejectsMalformedDocumentsAndEntries()
    {
        Assert.Equal(new[] { "exception-invalid" }, Rules(ArchitectureExceptions.Apply([], null, Today)));

        using (var wrongVersion = JsonDocument.Parse("{ \"schemaVersion\": 2, \"exceptions\": [] }"))
        {
            Assert.Equal(new[] { "exception-invalid" }, Rules(ArchitectureExceptions.Apply([], wrongVersion.RootElement, Today)));
        }

        using (var extraKey = JsonDocument.Parse("{ \"schemaVersion\": 1, \"exceptions\": [], \"extra\": 1 }"))
        {
            Assert.Equal(new[] { "exception-invalid" }, Rules(ArchitectureExceptions.Apply([], extraKey.RootElement, Today)));
        }

        var bad = new[]
        {
            Entry(("owner", string.Empty)),
            Entry(("reason", "short")),
            Entry(("rule", "no-such-rule")),
            Entry(("expires", "tomorrow")),
            WithExtraField(Entry()),
        };
        foreach (var entry in bad)
        {
            using var document = Document(entry);
            Assert.Contains("exception-invalid", Rules(ArchitectureExceptions.Apply([Finding], document.RootElement, Today)));
        }

        using var duplicate = Document(Entry(), Entry());
        Assert.Contains("exception-invalid", Rules(ArchitectureExceptions.Apply([Finding], duplicate.RootElement, Today)));
    }

    private static JsonObject WithExtraField(JsonObject entry)
    {
        entry["extra"] = "field";
        return entry;
    }
}
