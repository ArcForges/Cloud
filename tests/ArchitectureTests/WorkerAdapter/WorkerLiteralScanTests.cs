// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Cloud.ArchitectureTests.AiHarness;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.WorkerAdapter;

/// <summary>
/// The fixtures and the repository checks of the WorkerAdapter literal check (CLOUD.84 S43). Every fixture is a small source with its exact
/// expected findings, so an unlisted literal fails and a listed or structural one passes. The repository check applies the shared register to
/// the real tree, so an unregistered finding and an unused register row both fail.
/// </summary>
public sealed class WorkerLiteralScanTests
{
    private static readonly string Root = CloudRepository.FindRoot();

    private static readonly DateOnly Today = DateOnly.FromDateTime(DateTime.UtcNow);

    /// <summary>One fixture: a file, its source and the findings the scan must report, as (rule, detail) pairs; empty means it passes.</summary>
    public sealed record Fixture(string Name, string File, string Source, (string Rule, string Detail)[] Expected);

    /// <summary>The both-ways fixtures: refusals and passes, the protocol list and the generated exclusion.</summary>
    public static readonly IReadOnlyList<Fixture> Fixtures =
    [
        new("a declared budget is refused", "worker/a.ts", "export const maxFrameBytes = 65536;\n",
            [(WorkerLiteralScan.BudgetRule, "maxFrameBytes")]),
        new("a class field budget is refused", "worker/a.ts", "class C {\n  override sleepAfter = \"60s\";\n}\n",
            [(WorkerLiteralScan.BudgetRule, "sleepAfter")]),
        new("a declared identifier regex is refused", "worker/a.ts",
            "const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;\n",
            [(WorkerLiteralScan.IdentifierRule, "uuid")]),
        new("an inline identifier regex is refused under its function", "worker/a.ts",
            "export function f(value: string) {\n  return /^[1-9][0-9]{0,8}$/u.test(value);\n}\n",
            [(WorkerLiteralScan.IdentifierRule, "f")]),
        new("a digest string is refused", "worker/a.ts",
            "const emptyHash = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";\n",
            [(WorkerLiteralScan.IdentifierRule, "emptyHash")]),
        new("an inline timer budget is refused under its function", "worker/a.ts",
            "export function f() {\n  setTimeout(() => g(), 5000);\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("an inline delay budget is refused under its function", "worker/a.ts",
            "export function f(message: M) {\n  message.retry({ delaySeconds: 60 });\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("a length comparison of four or more is refused", "worker/a.ts",
            "export function f(raw: Uint8Array | null) {\n  return raw?.length !== 32;\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("a fixed-size byte array is refused", "worker/a.ts", "export function f() {\n  return new Uint8Array(16);\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("a renamed budget is refused (CLOUD.84 S43 review fix)", "worker/a.ts", "const bound = 4096;\n",
            [(WorkerLiteralScan.BudgetRule, "bound")]),
        new("the reviewer's probe export const bound = 4096 is refused (S45)", "worker/a.ts", "export const bound = 4096;\n",
            [(WorkerLiteralScan.BudgetRule, "bound")]),
        new("the reviewer's probe return 65536 is refused (S45)", "worker/a.ts", "export function ceiling() {\n  return 65536;\n}\n",
            [(WorkerLiteralScan.BudgetRule, "ceiling")]),
        new("the reviewer's probe byteLength > 8192 is refused (S45)", "worker/a.ts",
            "export function guard(buf: Uint8Array) {\n  if (buf.byteLength > 8192) throw new Error(\"too large\");\n}\n",
            [(WorkerLiteralScan.BudgetRule, "guard")]),
        new("a quota named with no limit word is refused", "worker/a.ts", "export const quota = 100;\nexport const threshold = 1000;\n",
            [(WorkerLiteralScan.BudgetRule, "quota"), (WorkerLiteralScan.BudgetRule, "threshold")]),
        new("a divided budget is refused on its dividend", "worker/a.ts", "export const cap = 65536 / 1;\n",
            [(WorkerLiteralScan.BudgetRule, "cap")]),
        new("a bare comparison is refused under its function (CLOUD.84 S43 review fix)", "worker/a.ts",
            "export function f(buf: Uint8Array) {\n  if (buf.byteLength > 4096) throw new Error(\"too large\");\n  return buf.byteLength;\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("a comparison returned as a value is refused under its function", "worker/a.ts",
            "export function f(buf: Uint8Array) {\n  return buf.byteLength > 4096;\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("a literal return is refused under its function (CLOUD.84 S43 review fix)", "worker/a.ts",
            "export function defaultCap() {\n  return 4096;\n}\n",
            [(WorkerLiteralScan.BudgetRule, "defaultCap")]),
        new("a numeric string holding a budget is refused", "worker/a.ts", "const quotaText = \"4096\";\n",
            [(WorkerLiteralScan.BudgetRule, "quotaText")]),
        new("a destructured default is refused under its name", "worker/a.ts",
            "export function f(opts: Options) {\n  const { cap = 4096 } = opts;\n  return cap;\n}\n",
            [(WorkerLiteralScan.BudgetRule, "cap")]),
        new("an object property budget is refused under its function", "worker/a.ts",
            "export function f(store: Store) {\n  store.put({ maxBytes: 4096 });\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("an assigned budget is refused under its function", "worker/a.ts",
            "let limit: number;\nexport function f() {\n  limit = 4096;\n  return limit;\n}\n",
            [(WorkerLiteralScan.BudgetRule, "f")]),
        new("comparisons of zero and one pass", "worker/a.ts",
            "export function f(count: number) {\n  if (count === 0 || count > 1) return 1;\n  return 0;\n}\n", []),
        new("an admitted key list is refused", "worker/a.ts", "const envelopeKeys = \"admittedModels,maxBodyBytes\";\n",
            [(WorkerLiteralScan.AdmissionRule, "envelopeKeys")]),
        new("an RPC method path is refused", "worker/a.ts", "const helloMethod = \"/arcforges.hello.v1.HelloService/SayHello\";\n",
            [(WorkerLiteralScan.MethodTableRule, "helloMethod")]),
        new("a SQL statement is refused", "worker/a.ts", "const statement = \"SELECT id FROM plans\";\n",
            [(WorkerLiteralScan.PlanAuthorityRule, "statement")]),
        new("zero, one and structural literals pass", "worker/a.ts",
            "export const retries = 0;\nexport const aiEnvelopeVersion = 1;\nexport function f(text: string) {\n  return Number(text.padEnd(3, \"0\").slice(0, 3)) + new Uint8Array(text.length / 2).length;\n}\n",
            []),
        new("short length checks pass", "worker/a.ts", "export function f(bytes: Uint8Array) {\n  return bytes.length < 2 || bytes.length === 3;\n}\n", []),
        new("a number that names no limit is refused: the rule is structural, not name-gated", "worker/a.ts", "const label = 7;\n",
            [(WorkerLiteralScan.BudgetRule, "label")]),
        new("a timer with a named budget passes", "worker/a.ts", "export function f(ms: number) {\n  setTimeout(() => g(), ms);\n}\n", []),
        new("a regex without an identifier shape passes", "worker/a.ts", "const pattern = /checksum|digest/iu;\n", []),
        new("the generated module is not read", "worker/tables/cloud-tables.generated.ts", "export const maxFrameBytes = 65536;\n", []),
        new("a file outside the worker is not read", "src/a.ts", "export const maxFrameBytes = 65536;\n", []),
        new("a protocol constant named by the list passes", "worker/ingress/errors.ts", "export const grpcStatus = {\n  unavailable: 14,\n} as const;\n", []),
        new("the same constant in another file is refused", "worker/ingress/other.ts", "export const grpcStatus = {\n  unavailable: 14,\n} as const;\n",
            [(WorkerLiteralScan.BudgetRule, "grpcStatus")]),
        new("a renamed protocol constant is refused", "worker/ingress/pipeline.ts", "const units2 = {\n  H: 3600000,\n};\n",
            [(WorkerLiteralScan.BudgetRule, "units2")]),
        new("an inline readiness term is refused under its function", "worker/readiness/a.ts",
            "export function f() {\n  return \"unavailable\";\n}\n",
            [(WorkerLiteralScan.ReadinessRule, "f")]),
        new("a declared readiness term is refused", "worker/readiness/a.ts", "const fallback = \"misconfigured\";\n",
            [(WorkerLiteralScan.ReadinessRule, "fallback")]),
        new("a readiness term outside the readiness module is not read as readiness", "worker/storage/a.ts",
            "export function f() {\n  return \"unavailable\";\n}\n", []),
        new("a readiness-named declaration is refused", "worker/a.ts", "const readinessLabel = \"label\";\n",
            [(WorkerLiteralScan.ReadinessRule, "readinessLabel")]),
        new("a correlation constant is refused", "worker/a.ts", "const traceparentFlags = \"01\";\n",
            [(WorkerLiteralScan.CorrelationRule, "traceparentFlags")]),
        new("a readiness term named through the generated object passes", "worker/a.ts",
            "import { readinessTerms } from \"./tables.ts\";\nexport function f() {\n  return readinessTerms.unavailable;\n}\n", []),
        new("a string that only contains a readiness term passes", "worker/a.ts", "export const label = \"unavailableSoon\";\n", []),
    ];

    public static IEnumerable<object[]> FixtureCases() => Fixtures.Select(fixture => new object[] { fixture.Name });

    [Theory]
    [MemberData(nameof(FixtureCases))]
    public void EveryFixtureYieldsItsExactFindings(string name)
    {
        var fixture = Fixtures.Single(item => item.Name == name);
        var findings = WorkerLiteralScan.Audit(new Dictionary<string, string> { [fixture.File] = fixture.Source });
        var actual = findings.Select(finding => (finding.Rule, finding.Detail)).OrderBy(pair => pair.Rule, StringComparer.Ordinal).ThenBy(pair => pair.Detail, StringComparer.Ordinal).ToArray();
        var expected = fixture.Expected.OrderBy(pair => pair.Rule, StringComparer.Ordinal).ThenBy(pair => pair.Detail, StringComparer.Ordinal).ToArray();
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void EveryRuleOfTheCheckHasARefusedFixture()
    {
        var refused = Fixtures.Where(fixture => fixture.Expected.Length > 0).SelectMany(fixture => fixture.Expected.Select(pair => pair.Rule)).ToHashSet(StringComparer.Ordinal);
        Assert.True(refused.SetEquals(new[]
        {
            WorkerLiteralScan.BudgetRule, WorkerLiteralScan.IdentifierRule, WorkerLiteralScan.AdmissionRule, WorkerLiteralScan.MethodTableRule,
            WorkerLiteralScan.PlanAuthorityRule, WorkerLiteralScan.ReadinessRule, WorkerLiteralScan.CorrelationRule,
        }), "A rule of the check has no refused fixture.");
        Assert.Equal(WorkerLiteralScan.Rules.Count, WorkerLiteralScan.Rules.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void ReadinessTermsMatchTheGeneratedVocabulary()
    {
        // The readinessTerms object of the generated module names every term of the readiness vocabulary, keyed by itself. The check's list is
        // pinned to it, so a term that the generator adds is refused in the Worker until the check knows it too.
        var generated = File.ReadAllText(Path.Combine(Root, WorkerLiteralScan.GeneratedTablesPath));
        var block = System.Text.RegularExpressions.Regex.Match(generated, @"export const readinessTerms = \{(?<body>[\s\S]*?)\} as const;");
        Assert.True(block.Success, "The generated module has no readinessTerms object.");
        var entries = System.Text.RegularExpressions.Regex.Matches(block.Groups["body"].Value, @"^\s+([A-Za-z][A-Za-z0-9_]*): ""([^""]+)"",$",
            System.Text.RegularExpressions.RegexOptions.Multiline).Select(match => (Key: match.Groups[1].Value, Value: match.Groups[2].Value)).ToList();
        Assert.NotEmpty(entries);
        Assert.All(entries, entry => Assert.Equal(entry.Key, entry.Value));
        Assert.True(WorkerLiteralScan.ReadinessTerms.SetEquals(entries.Select(entry => entry.Value)),
            "The check's readiness terms differ from the generated vocabulary.");
    }

    [Fact]
    public void TheWorkerRepositoryHoldsNoBusinessLiteralOutsideTheNamedLists()
    {
        // The real tree: every finding is an owned register row (HAR.00 carve-out or CLOUD.05 D16) or a closed protocol row, and every row
        // names a real finding. The failure lists each unexempt literal with its value and line, so a classification is read from it.
        var sources = HarnessArchitecture.ReadSources(Root);
        using var register = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, ArchitectureExceptions.RegisterPath)));
        var result = WorkerLiteralScan.ApplyRegister(sources, register.RootElement, Today);
        var unexempt = WorkerLiteralScan.Literals(sources).Where(literal => !WorkerLiteralScan.IsExempt(literal))
            .Select(literal => $"{literal.Rule} {literal.File} {literal.Symbol} {literal.Value} L{literal.Line}");
        Assert.True(result.Problems.Count == 0 && result.Remaining.Count == 0,
            "Unregistered worker literals: " + string.Join("; ", result.Remaining.Select(finding => $"{finding.Rule} {finding.File} {finding.Detail}"))
            + ". Register problems: " + string.Join("; ", result.Problems.Select(problem => $"{problem.Rule} {problem.Detail}"))
            + ". Unexempt literals: " + string.Join("; ", unexempt));
    }

    [Fact]
    public void EveryNumberRowIsNamedByAStandardAndUsedByTheTree()
    {
        // A closed row must name the external standard that fixes its values, and must match a real literal: a row that matches nothing is stale.
        var sources = HarnessArchitecture.ReadSources(Root);
        var literals = WorkerLiteralScan.Literals(sources);
        foreach (var row in WorkerLiteralScan.NumberRows)
        {
            Assert.False(string.IsNullOrWhiteSpace(row.Source), "A number row has no source note: " + row.File + " " + row.Symbol);
            Assert.True(sources.TryGetValue(row.File, out var text), "The number row names a file outside the tree: " + row.File);
            Assert.True(row.Symbol == "<module>" || text!.Contains(row.Symbol, StringComparison.Ordinal), "The number row names a symbol outside its file: " + row.Symbol);
            foreach (var value in row.Values)
            {
                Assert.True(literals.Any(literal => literal.Rule == WorkerLiteralScan.BudgetRule && literal.File == row.File && literal.Symbol == row.Symbol && literal.Value == value),
                    $"The number row {row.File} {row.Symbol} {value} matches no literal (a stale row).");
            }
        }
    }

    [Fact]
    public void EveryShapeRowIsNamedByAStandardAndUsedByTheTree()
    {
        var sources = HarnessArchitecture.ReadSources(Root);
        var findings = WorkerLiteralScan.Literals(sources);
        foreach (var row in WorkerLiteralScan.ShapeRows)
        {
            Assert.False(string.IsNullOrWhiteSpace(row.Source), "A shape row has no source note: " + row.File + " " + row.Symbol);
            Assert.True(findings.Any(literal => literal.Rule == row.Rule && literal.File == row.File && literal.Symbol == row.Symbol),
                $"The shape row {row.File} {row.Symbol} {row.Rule} matches no finding (a stale row).");
        }
    }

    [Fact]
    public void NumberRowsAreClosedToTheirValues()
    {
        // A row exempts only the values it lists: a different value in the same symbol is still a finding, and so is the same value elsewhere.
        foreach (var row in WorkerLiteralScan.NumberRows)
        {
            var listed = row.Values[0];
            Assert.True(WorkerLiteralScan.IsExempt(new WorkerLiteralScan.Literal(WorkerLiteralScan.BudgetRule, row.File, row.Symbol, listed, 1)));
            Assert.False(WorkerLiteralScan.IsExempt(new WorkerLiteralScan.Literal(WorkerLiteralScan.BudgetRule, row.File, row.Symbol, "987654321", 1)));
            Assert.False(WorkerLiteralScan.IsExempt(new WorkerLiteralScan.Literal(WorkerLiteralScan.BudgetRule, "worker/elsewhere.ts", row.Symbol, listed, 1)));
        }
    }

    [Fact]
    public void EveryProtocolConstantNamedByTheListExistsInItsFile()
    {
        var sources = HarnessArchitecture.ReadSources(Root);
        foreach (var row in WorkerLiteralScan.ShapeRows)
        {
            Assert.True(sources.TryGetValue(row.File, out var text), "The shape list names a file outside the tree: " + row.File);
            Assert.Matches(@"\b(?:const|let|var|function)\s+" + System.Text.RegularExpressions.Regex.Escape(row.Symbol) + @"\b", text!);
        }
    }

    [Fact]
    public void TheCheckReadsEveryWorkerSourceExceptTheGeneratedOutputs()
    {
        Assert.True(WorkerLiteralScan.IsScanned("worker/index.ts"));
        Assert.True(WorkerLiteralScan.IsScanned("worker/foundation/objects.ts"));
        Assert.False(WorkerLiteralScan.IsScanned("worker/tables/cloud-tables.generated.ts"));
        Assert.False(WorkerLiteralScan.IsScanned("worker/storage/plans.generated.ts"));
        Assert.False(WorkerLiteralScan.IsScanned("worker/types.d.ts"));
        Assert.False(WorkerLiteralScan.IsScanned("tests/worker/ai-internal.test.ts"));
    }
}
