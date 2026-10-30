// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Text.Json.Nodes;
using Xunit;
using Xunit.Sdk;
using Xunit.v3;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// The parity corpus of the Go resolver (AF-CTR-03 part B, F1/N2). The Go center ports this module's resolver line for line and
/// replays <c>center/internal/entitlement/testdata/csharp-resolver-vectors.json</c> in <c>TestResolverParityWithEveryCSharpVector</c>.
/// <see cref="TheCommittedVectorsAreWhatTheSuitesProduce"/> runs every row of the resolver-facing suites under the recorder
/// (<see cref="ResolverVectors"/>) and compares what they produce with the committed file, so a change to a suite, a fixture or the
/// resolver that is not followed by a rewritten corpus fails here instead of leaving the Go port unchecked. To rewrite the corpus:
/// <c>ARCFORGES_UPDATE_RESOLVER_VECTORS=1 dotnet test --project tests/ArcForges.Cloud.Tests -c Release --filter-class
/// ArcForges.Cloud.Tests.Entitlement.ResolverVectorsTests</c>, then <c>npx prettier --write
/// center/internal/entitlement/testdata/csharp-resolver-vectors.json</c> (the file is compared as data, not as text).
/// </summary>
public sealed class ResolverVectorsTests
{
    /// <summary>The resolver-facing suites: every row of these classes is covered.</summary>
    private static readonly Type[] Covered =
    [
        typeof(ResolverBehaviorTests),
        typeof(ReviewHardeningTests),
        typeof(RebuildEquivalenceTests),
        typeof(GrantInterfaceTests),
        typeof(ClockAndStructureTests),
        typeof(GrantPortContractTests),
    ];

    /// <summary>
    /// Rows that may record no vector, each with the reason. A row that records one anyway fails the run (a stale exclusion), and a
    /// row without a vector that is not listed here fails it too.
    /// </summary>
    private static readonly Dictionary<string, string> Excluded = new(StringComparer.Ordinal)
    {
        ["ClockAndStructureTests.InstantsKeepMicrosecondPrecisionAndFloorBeforeTheEpoch"] = "pure instant conversion; the Go Micros type has its own test",
        ["ClockAndStructureTests.TheModuleListsTheResolverAndItNeedsItsPortsBeforeAnythingCanAskForIt"] = "C# dependency injection of the module; nothing to port",
        ["ClockAndStructureTests.NoResolverSourceReadsAnAmbientClockOrRandomnessOrUsesBinaryFloatingPoint"] = "C# source scan; the Go package has its own scan test",
        ["ClockAndStructureTests.TheResolverNamesNoProviderAndHardCodesNoCommercialFigureOrCapability"] = "C# source scan; the Go package has its own scan test",
        ["GrantInterfaceTests.InputRulesAcceptOnlyBoundedOpaqueTokens"] = "InputRules predicates are ported with a hand-written table test",
        ["GrantInterfaceTests.AMalformedWorkspaceIdentifierIsRefusedBeforeAnyRead"] = "refused by the service before any resolver or admission call",
        ["GrantInterfaceTests.ARevocationNamesAnExactGrantInItsOwnWorkspace"] = "every revocation refusal (unknown grant, stale version, malformed) precedes any resolver call; the Go service tests port them",
        ["GrantPortContractTests.AMalformedRequestIsRefusedBeforeAnyStoreCallAndNeverCoerced"] = "refused by the port adapter's own well-formedness rules before the service; no resolver or admission call",
        ["GrantPortContractTests.AStoreThatCannotBeReachedIsATypedStatusAnUnknownOutcomeIsNeverReportedAsSuccessAndADefectIsNotHidden"] = "a store fault ahead of any resolver call; the Go store tests port the typed outcomes",
        ["GrantPortContractTests.NoEntitlementTypeCrossesThePublishedPort"] = "a reflection check of the C# port types; nothing to port",
    };

    private const string UpdateVariable = "ARCFORGES_UPDATE_RESOLVER_VECTORS";

    [Fact]
    public async Task TheCommittedVectorsAreWhatTheSuitesProduce()
    {
        var recorded = new List<(string Row, IReadOnlyList<object> Vectors)>();
        foreach (var (name, run) in await Rows())
        {
            var row = new Row(name);
            using (ResolverVectors.Begin(row))
            {
                try
                {
                    await run();
                }
                catch (Exception exception)
                {
                    throw new InvalidOperationException("The row " + name + " failed under the recorder: " + exception.Message, exception);
                }
            }

            recorded.Add((name, row.Vectors));
        }

        var silent = recorded.Where(row => row.Vectors.Count == 0 && !Excluded.ContainsKey(row.Row)).Select(row => row.Row).ToArray();
        Assert.True(silent.Length == 0, "Rows of the resolver suites without a vector (record one or list the row as excluded with a reason): " + string.Join(", ", silent));
        var stale = recorded.Where(row => row.Vectors.Count > 0 && Excluded.ContainsKey(row.Row)).Select(row => row.Row).ToArray();
        Assert.True(stale.Length == 0, "Rows listed as excluded that record vectors: " + string.Join(", ", stale));
        var unknown = Excluded.Keys.Where(name => !recorded.Any(row => row.Row == name)).ToArray();
        Assert.True(unknown.Length == 0, "Excluded rows that no suite has: " + string.Join(", ", unknown));

        var actual = VectorJson.Write(recorded, Excluded);
        var path = CorpusPath();
        if (Environment.GetEnvironmentVariable(UpdateVariable) == "1")
        {
            await File.WriteAllTextAsync(path, actual + "\n", T.Ct);
            return;
        }

        Assert.True(File.Exists(path), "The corpus is missing: rewrite it with " + UpdateVariable + "=1.");
        var expected = JsonNode.Parse(await File.ReadAllTextAsync(path, T.Ct))!;
        var produced = JsonNode.Parse(actual)!;
        if (!JsonNode.DeepEquals(expected, produced)) Assert.Fail("The committed corpus differs from what the suites produce. " + Describe(expected, produced) + " Rewrite it with " + UpdateVariable + "=1, then run prettier on the file.");
    }

    [Fact]
    public void EveryResolverCallOfACoveredSuiteGoesThroughTheRecorder()
    {
        var directory = Path.Combine(FindRoot(), "tests", "ArcForges.Cloud.Tests", "Entitlement");
        foreach (var type in Covered)
        {
            var code = File.ReadAllText(Path.Combine(directory, type.Name + ".cs"));
            Assert.False(code.Contains("EntitlementResolver.Resolve(", StringComparison.Ordinal), type.Name + " calls the resolver directly; use ResolverVectors.Resolve.");
            Assert.False(code.Contains("GrantAdmission.Validate(", StringComparison.Ordinal), type.Name + " calls grant admission directly; use ResolverVectors.Admit.");
        }
    }

    /// <summary>The rows of a theory: its inline data and the static members its member data names (methods without arguments or properties).</summary>
    private static IEnumerable<object?[]> TheoryRows(Type type, MethodInfo method)
    {
        foreach (var inline in method.GetCustomAttributes<InlineDataAttribute>())
        {
            foreach (var row in inline.GetData(method, new DisposalTracker()).AsTask().GetAwaiter().GetResult()) yield return row.GetData();
        }

        foreach (var member in method.GetCustomAttributes<MemberDataAttribute>())
        {
            var source = (member.MemberType ?? type).GetMember(member.MemberName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static).Single();
            var data = source switch
            {
                MethodInfo producer => producer.Invoke(null, member.Arguments),
                PropertyInfo property => property.GetValue(null),
                FieldInfo field => field.GetValue(null),
                _ => throw new InvalidOperationException("Unsupported member data source."),
            };
            foreach (var item in (System.Collections.IEnumerable)data!)
            {
                yield return item switch
                {
                    ITheoryDataRow row => row.GetData(),
                    object?[] values => values,
                    _ => [item],
                };
            }
        }
    }

    private static async Task<List<(string Name, Func<Task> Run)>> Rows()
    {
        var rows = new List<(string, Func<Task>)>();
        foreach (var type in Covered)
        {
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).OrderBy(m => m.Name, StringComparer.Ordinal))
            {
                var baseName = type.Name + "." + method.Name;
                if (method.GetCustomAttribute<TheoryAttribute>() is not null)
                {
                    var found = 0;
                    foreach (var arguments in TheoryRows(type, method))
                    {
                        rows.Add((baseName + "(" + string.Join(",", arguments.Select(argument => Convert.ToString(argument, System.Globalization.CultureInfo.InvariantCulture))) + ")", () => Invoke(type, method, arguments)));
                        found++;
                    }

                    Assert.True(found > 0, baseName + " is a theory without rows.");
                }
                else if (method.GetCustomAttribute<FactAttribute>() is not null)
                {
                    rows.Add((baseName, () => Invoke(type, method, [])));
                }
            }
        }

        return rows;
    }

    private static async Task Invoke(Type type, MethodInfo method, object?[] arguments)
    {
        var instance = Activator.CreateInstance(type)!;
        try
        {
            switch (method.Invoke(instance, arguments))
            {
                case Task task:
                    await task;
                    break;
                case ValueTask valueTask:
                    await valueTask;
                    break;
            }
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
        }
    }

    private static string Describe(JsonNode expected, JsonNode produced)
    {
        var committed = Rows(expected["rows"]);
        var now = Rows(produced["rows"]);
        var lines = new List<string>();
        foreach (var (name, counts) in now)
        {
            if (!committed.TryGetValue(name, out var before)) lines.Add("new row " + name);
            else if (before != counts) lines.Add("row " + name + ": " + before + " -> " + counts);
        }

        lines.AddRange(committed.Keys.Where(name => !now.ContainsKey(name)).Select(name => "removed row " + name));
        var ids = (expected["resolver"]?.AsArray().Count ?? 0, produced["resolver"]?.AsArray().Count ?? 0, expected["admission"]?.AsArray().Count ?? 0, produced["admission"]?.AsArray().Count ?? 0);
        return "Resolver vectors " + ids.Item1 + " -> " + ids.Item2 + ", admission vectors " + ids.Item3 + " -> " + ids.Item4 + ". " + string.Join("; ", lines.Take(12));
    }

    private static Dictionary<string, string> Rows(JsonNode? node) =>
        node is JsonObject rows ? rows.ToDictionary(pair => pair.Key, pair => pair.Value!.ToJsonString(), StringComparer.Ordinal) : [];

    private static string CorpusPath() => Path.Combine(FindRoot(), "center", "internal", "entitlement", "testdata", "csharp-resolver-vectors.json");

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Cloud.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("The Cloud repository root was not found.");
    }
}
