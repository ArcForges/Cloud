// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.Cloud.Tools.Generation.StoragePlans;
using Xunit;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>
/// CLOUD.84 U7: one-for-one C# replacement of tests/worker/storage-plans-generator.test.ts. The same plan-format rules, the same refusal
/// cases (each with its message pattern), the hash identity, the checked-in parity and the stale and foreign-file checks run against the
/// C# generator in tools/ArcForges.Cloud.Generation.
/// </summary>
public sealed class StoragePlanGeneratorTests
{
    private const string SampleFile = "storage/plans/foundation/sample.sql";

    private const string Read = """
        -- plan: foundation.sample
        -- version: 1
        -- access: read
        -- maxRows: 1
        -- statement: params=scope,int64,text returns=int64,text?
        SELECT CAST(a AS TEXT), b FROM t WHERE scope = ? AND a = CAST(? AS INTEGER) AND b = ?;

        """;

    private const string Write = """
        -- plan: foundation.sample
        -- version: 2
        -- access: write
        -- statement: params=int64,scope
        UPDATE t SET a = CAST(? AS INTEGER) WHERE scope = ?;

        """;

    private static PlanDefinition Parse(string text) => StoragePlanParser.ParsePlanFile(text, SampleFile);

    private static void AssertRefused(string text, string pattern, string label)
    {
        var refusal = Assert.Throws<PlanRefusal>(() => Parse(text));
        Assert.True(Regex.IsMatch(refusal.Message, pattern), $"{label}: {refusal.Message}");
    }

    [Fact]
    public void ValidReadPlanParsesIntoTypedParametersAndResults()
    {
        var plan = Parse(Read);
        Assert.Equal("foundation.sample", plan.Id);
        Assert.Equal("read", plan.Access);
        Assert.Equal(
            new[] { new PlanParameter("scope", false), new PlanParameter("int64", false), new PlanParameter("text", false) },
            plan.Statements[0].Params);
        Assert.Equal(
            new[] { new PlanParameter("int64", false), new PlanParameter("text", true) },
            plan.Statements[0].Returns);
    }

    [Fact]
    public void EveryRuleOfThePlanFormatIsEnforced()
    {
        var refused = new (string Label, string Text, string Pattern)[]
        {
            ("comment inside a statement", Read.Replace("WHERE", "-- note\nWHERE", StringComparison.Ordinal), "comments|unknown comment"),
            ("two statements in one block", Read.Replace(";\n", "; SELECT 1;\n", StringComparison.Ordinal), "exactly one statement"),
            ("DDL", Read.Replace("SELECT", "CREATE TABLE x AS SELECT", StringComparison.Ordinal), "forbidden SQL|only DML"),
            ("PRAGMA", Read.Replace("SELECT CAST", "PRAGMA foreign_keys; SELECT CAST", StringComparison.Ordinal), "forbidden SQL|exactly one"),
            ("RETURNING", Write.Replace(";", " RETURNING a;", StringComparison.Ordinal), "forbidden SQL"),
            ("sqlite internals", Read.Replace("FROM t", "FROM sqlite_master", StringComparison.Ordinal), "forbidden SQL"),
            ("named placeholder", Read.Replace("b = ?", "b = :name", StringComparison.Ordinal), "anonymous"),
            ("numbered placeholder", Read.Replace("b = ?", "b = ?1", StringComparison.Ordinal), "anonymous"),
            ("int64 argument not cast", Read.Replace("CAST(? AS INTEGER)", "?", StringComparison.Ordinal), "must be wrapped"),
            ("non-int64 argument cast", Read.Replace("scope = ?", "scope = CAST(? AS INTEGER)", StringComparison.Ordinal), "must not be wrapped"),
            ("placeholder count differs", Read.Replace("params=scope,int64,text", "params=scope,int64", StringComparison.Ordinal), "placeholder count"),
            ("unknown kind", Read.Replace("int64,text", "int64,float", StringComparison.Ordinal), "unknown parameter kind"),
            ("scope as a result column", Read.Replace("returns=int64,text?", "returns=int64,scope", StringComparison.Ordinal), "cannot have kind scope"),
            ("nullable scope", Read.Replace("params=scope,", "params=scope?,", StringComparison.Ordinal), "never null"),
            ("nullable int64 parameter", Read.Replace("scope,int64,text", "scope,int64?,text", StringComparison.Ordinal), "nullable int64"),
            ("write plan with results", Write.Replace("params=int64,scope", "params=int64,scope returns=int64", StringComparison.Ordinal), "returns no rows"),
            ("read plan without results", Read.Replace(" returns=int64,text?", string.Empty, StringComparison.Ordinal), "declares its returned columns"),
            ("read plan without maxRows", Read.Replace("-- maxRows: 1\n", string.Empty, StringComparison.Ordinal), "maxRows"),
            ("read plan with an update", Read.Replace("SELECT CAST(a AS TEXT), b FROM t WHERE", "UPDATE t SET b = 'x' WHERE", StringComparison.Ordinal), "SELECT|only DML"),
            ("maxRows too large", Read.Replace("maxRows: 1", "maxRows: 201", StringComparison.Ordinal), "maxRows"),
            ("bad plan id", Read.Replace("foundation.sample", "Foundation", StringComparison.Ordinal), "invalid plan id"),
            ("file name differs", Read.Replace("foundation.sample", "foundation.other", StringComparison.Ordinal), "file name"),
            ("wrong module directory", Read.Replace("foundation.sample", "other.sample", StringComparison.Ordinal), "directory"),
            ("version zero", Read.Replace("version: 1", "version: 0", StringComparison.Ordinal), "version"),
            ("unknown access", Read.Replace("access: read", "access: admin", StringComparison.Ordinal), "access"),
            ("SQL before any statement block", string.Join("\n", Read.Split('\n').Take(4)) + "\nSELECT 1;\n", "outside a statement"),
            ("unknown statement field", Read.Replace("params=", "bogus=1 params=", StringComparison.Ordinal), "unknown statement field"),
        };
        foreach (var (label, text, pattern) in refused) AssertRefused(text, pattern, label);

        var many = string.Join("\n", Write.Split('\n').Take(3))
            + "\n"
            + string.Join("\n", Enumerable.Range(0, 101).Select(_ => "-- statement: params=int64,scope\nUPDATE t SET a = CAST(? AS INTEGER) WHERE scope = ?;"))
            + "\n";
        AssertRefused(many, "statement count", "too many statements");

        var wide = "-- plan: foundation.sample\n-- version: 1\n-- access: write\n-- statement: params="
            + string.Join(",", Enumerable.Repeat("text", 101))
            + "\nUPDATE t SET a = "
            + string.Join(", ", Enumerable.Repeat("?", 101))
            + ";\n";
        AssertRefused(wide, "too many parameters", "too many parameters");
    }

    [Fact]
    public void StringLiteralsCannotHidePlaceholdersOrForbiddenWords()
    {
        var text = Read.Replace("b = ?", "b = ? AND c = '?' AND d = 'DROP; --'", StringComparison.Ordinal);
        Assert.Equal(3, Parse(text).Statements[0].Params.Count);
    }

    [Fact]
    public void TheManifestHashIsDeterministicOrderIndependentAndSensitiveToEveryByte()
    {
        var a = Parse(Read);
        var b = Parse(Write);
        Assert.Equal(
            StoragePlanParser.ManifestHashOf([a, b]),
            StoragePlanParser.ManifestHashOf([b, a]));
        Assert.Equal(a.Sha256, Parse(Read.Replace("\n", "\r\n", StringComparison.Ordinal)).Sha256);
        Assert.Equal("x\n", StoragePlanParser.NormalizePlanText("x  \r\n\r\n"));
        Assert.NotEqual(a.Sha256, Parse(Read.Replace("b = ?", "b <> ?", StringComparison.Ordinal)).Sha256);
        Assert.NotEqual(StoragePlanParser.ManifestHashOf([a]), StoragePlanParser.ManifestHashOf([a, b]));
    }

    [Fact]
    public void TheCheckedInOutputsEqualAFreshGenerationFromThePlanFiles()
    {
        var root = T.RepoRoot().FullName;
        var manifest = StoragePlanParser.BuildManifest(root);
        Assert.NotEmpty(manifest.Plans);
        Assert.Empty(StoragePlanGenerator.Sync(root, write: false));
        foreach (var (path, text) in StoragePlanOutputs.Render(manifest))
            Assert.Equal(text, File_ReadAllText(Path.Combine(root, path)));
    }

    [Fact]
    public void StaleOrMissingGeneratedOutputFailsTheCheckAndIsRepairedByGeneration()
    {
        var root = TemporaryRoot();
        try
        {
            foreach (var relative in new[] { "storage/plans", "worker/storage", "src/ArcForges.Cloud.Storage.D1" })
                Directory.CreateDirectory(Path.Combine(root, relative));
            CopyDirectory(Path.Combine(T.RepoRoot().FullName, "storage", "plans"), Path.Combine(root, "storage", "plans"));
            // The family plans are expanded against the physical manifest, so the temporary root needs it too.
            CopyDirectory(
                Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", "Physical", "manifest"),
                Path.Combine(root, "src", "ArcForges.Cloud.Storage.D1", "Physical", "manifest"));
            Assert.NotEmpty(StoragePlanGenerator.Sync(root, write: false));
            Assert.NotEmpty(StoragePlanGenerator.Sync(root, write: true));
            Assert.Empty(StoragePlanGenerator.Sync(root, write: false));
            Assert.Empty(StoragePlanGenerator.Sync(root, write: true));

            // Editing a plan without regenerating is caught.
            var target = Path.Combine(root, "storage", "plans", "foundation", "readiness.sql");
            File.WriteAllText(target, File_ReadAllText(target).Replace("probe_schema", "probe_schema WHERE 1 = 1", StringComparison.Ordinal));
            Assert.NotEmpty(StoragePlanGenerator.Sync(root, write: false));
            StoragePlanGenerator.Sync(root, write: true);

            // Editing a generated file by hand is caught too.
            var generated = Path.Combine(root, "worker", "storage", "plans.generated.ts");
            File.WriteAllText(generated, File_ReadAllText(generated) + "\n// edited\n");
            Assert.Contains(StoragePlanOutputs.TypeScriptOutput, StoragePlanGenerator.Sync(root, write: false));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ForeignFilesInThePlanDirectoryAreRefused()
    {
        var root = TemporaryRoot();
        try
        {
            var directory = Path.Combine(root, "storage", "plans", "foundation");
            Directory.CreateDirectory(directory);
            File.Copy(Path.Combine(T.RepoRoot().FullName, StoragePlanParser.OwnerRegistryPath), Path.Combine(root, StoragePlanParser.OwnerRegistryPath));
            File.WriteAllText(Path.Combine(directory, "sample.sql"), Read.Replace("FROM t", "FROM probe_t", StringComparison.Ordinal));
            File.WriteAllText(Path.Combine(directory, "notes.txt"), "x");
            var refusal = Assert.Throws<PlanRefusal>(() => StoragePlanParser.BuildManifest(root));
            Assert.Matches("end with \\.sql", refusal.Message);
            File.Delete(Path.Combine(directory, "notes.txt"));
            Assert.Single(StoragePlanParser.BuildManifest(root).Plans);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static readonly HashSet<string> RealmLevelPlatformPlans =
    [
        "platform.command-load",
        "platform.command-record-failure",
        "platform.inbox-load",
        "platform.inbox-record",
        "platform.archive-state",
        "platform.archive-select",
        "platform.archive-ack",
        "platform.archive-purge",
    ];

    // The identity reads and the credential-use record are keyed by realm and user or by provider subject, before any workspace exists
    // (an enrollment looks the subject up first), so they carry no workspace scope; every identity write that has a workspace names it.
    private static readonly HashSet<string> RealmLevelIdentityPlans =
    [
        "identity.user-load",
        "identity.credential-find",
        "identity.credential-list",
        "identity.credential-touch",
    ];

    [Fact]
    public void EveryCheckedInPlanIsDmlOnlyScopedAndExact()
    {
        var manifest = StoragePlanParser.BuildManifest(T.RepoRoot().FullName);
        foreach (var plan in manifest.Plans)
        {
            foreach (var statement in plan.Statements)
            {
                Assert.False(Regex.IsMatch(statement.Sql, @"\b(?:pragma|attach|create|drop|alter)\b", RegexOptions.IgnoreCase), plan.Id);
                var casts = Regex.Matches(statement.Sql, @"CAST\(\?\s+AS\s+INTEGER\)").Count;
                Assert.Equal(statement.Params.Count(param => param.Kind == "int64"), casts);
            }

            // Every plan names the owner scope in at least one parameter, except the schema probe and the realm-level platform plans,
            // whose rows are keyed by a command id, an inbox key or the one change archive and not by a scope.
            if (plan.Id != "foundation.readiness" && !RealmLevelPlatformPlans.Contains(plan.Id) && !RealmLevelIdentityPlans.Contains(plan.Id))
                Assert.True(plan.Statements.Any(statement => statement.Params.Any(param => param.Kind == "scope")), $"{plan.Id} is not scoped");
        }
    }

    private static string File_ReadAllText(string path) => System.IO.File.ReadAllText(path);

    private static string TemporaryRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "plans-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.GetFiles(source))
            System.IO.File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), overwrite: true);
        foreach (var directory in Directory.GetDirectories(source))
            CopyDirectory(directory, Path.Combine(destination, Path.GetFileName(directory)));
    }
}
