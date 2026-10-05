// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests;

/// <summary>
/// The C# side of the named-plan bridge boundary (Design D1 profile section 3): the plan manifest identity is reproduced from the plan
/// files by an implementation independent of the generator, the generated definitions equal the reviewed files, a plan touches only its
/// owner's tables, no SQL text exists in C#, and nothing the bridge can send names SQL or a table.
/// </summary>
public sealed partial class StoragePlanBoundaryTests
{
    internal sealed record PlanFile(string Owner, string Name, string Text, string Id, int Version, string Access, int MaxRows, string[][] StatementParams, string?[] StatementReturns);

    private static string PlanRoot => Path.Combine(T.RepoRoot().FullName, "storage", "plans");

    private static string Normalize(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).TrimEnd() + "\n";

    internal static IReadOnlyList<PlanFile> ReadPlans()
    {
        var plans = new List<PlanFile>();
        foreach (var directory in Directory.EnumerateDirectories(PlanRoot).Where(directory => !string.Equals(Path.GetFileName(directory), "families", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*.sql").Order(StringComparer.Ordinal))
            {
                var text = Normalize(File.ReadAllText(file));
                string Header(string key) => Regex.Match(text, "^-- " + key + ": (.+)$", RegexOptions.Multiline).Groups[1].Value;
                var statements = Regex.Matches(text, "^-- statement:(.*)$", RegexOptions.Multiline).Select(match => match.Groups[1].Value).ToArray();
                string[] Kinds(string field, string line) => Regex.Match(line, field + "=(\\S*)").Groups[1].Value is { Length: > 0 } list ? list.Split(',') : [];
                plans.Add(new PlanFile(
                    Path.GetFileName(directory), Path.GetFileNameWithoutExtension(file), text, Header("plan"), int.Parse(Header("version"), System.Globalization.CultureInfo.InvariantCulture), Header("access"),
                    Header("maxRows") is { Length: > 0 } rows ? int.Parse(rows, System.Globalization.CultureInfo.InvariantCulture) : 0,
                    statements.Select(line => Kinds("params", line)).ToArray(),
                    statements.Select(line => line.Contains("returns=", StringComparison.Ordinal) ? string.Join(',', Kinds("returns", line)) : null).ToArray()));
            }
        }

        return plans;
    }

    /// <summary>The manifest identity: the sorted <c>id@version:sha256(normalized text)</c> lines, hashed. Independent of the TypeScript generator.</summary>
    internal static string ManifestHash(IEnumerable<(string Id, int Version, string Text)> plans, IEnumerable<(string Id, int Version, string Sha256)>? familyIdentities = null)
    {
        var identities = plans.Select(plan => (plan.Id, plan.Version, Sha256: Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(plan.Text))))))
            .Concat(familyIdentities ?? []);
        var lines = identities.OrderBy(plan => plan.Id, StringComparer.Ordinal).ThenBy(plan => plan.Version)
            .Select(plan => plan.Id + "@" + plan.Version.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + plan.Sha256);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n")));
    }

    [Fact]
    public void TheManifestHashIsReproducedFromThePlanFilesAndAgreesWithTheWorkerDictionary()
    {
        var plans = ReadPlans();
        // A family plan's identity covers its generated statements; it is recomputed independently from the plan file and the listed SQL.
        var families = SharedFamilies.FamilyExpansion.Identities();
        var hash = ManifestHash(plans.Select(plan => (plan.Id, plan.Version, plan.Text)), families);
        Assert.Equal(PlanManifest.Hash, hash);
        var worker = File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "worker", "storage", "plans.generated.ts"));
        Assert.Equal(hash, Regex.Match(worker, "manifestHash = \"([0-9a-f]{64})\"").Groups[1].Value);
        Assert.Equal(plans.Count + families.Count, PlanManifest.All.Count);
    }

    [Fact]
    public void AnyChangeToAPlanFileOrItsVersionChangesTheIdentityAndOrderDoesNot()
    {
        var plans = ReadPlans().Select(plan => (plan.Id, plan.Version, plan.Text)).ToArray();
        var baseline = ManifestHash(plans);
        Assert.Equal(baseline, ManifestHash(plans.Reverse()));
        var changed = plans.ToArray();
        changed[3] = (changed[3].Id, changed[3].Version, changed[3].Text.Replace("?", "? ", StringComparison.Ordinal));
        Assert.NotEqual(baseline, ManifestHash(changed));
        var bumped = plans.ToArray();
        bumped[0] = (bumped[0].Id, bumped[0].Version + 1, bumped[0].Text);
        Assert.NotEqual(baseline, ManifestHash(bumped));
        Assert.NotEqual(baseline, ManifestHash(plans.Skip(1)));
        Assert.NotEqual(baseline, ManifestHash(plans.Append(("foundation.extra", 1, plans[0].Text))));
        // Line endings are not part of the identity: the Windows and Linux checkouts hash alike.
        Assert.Equal(baseline, ManifestHash(plans.Select(plan => (plan.Id, plan.Version, plan.Text.Replace("\n", "\r\n", StringComparison.Ordinal)))));
    }

    [Fact]
    public void EveryGeneratedDefinitionEqualsItsReviewedPlanFile()
    {
        var files = ReadPlans().ToDictionary(plan => plan.Id + "@" + plan.Version);
        // Family plans are described statement by statement by the shared-family checks (FamilyExpansionTests); this one covers the owner plans.
        var ordinary = PlanManifest.All.Where(definition => !definition.Id.StartsWith("families.", StringComparison.Ordinal)).ToArray();
        Assert.Equal(files.Count, ordinary.Length);
        foreach (var definition in ordinary)
        {
            var file = files[definition.Id + "@" + definition.Version];
            Assert.Equal(file.Access, definition.Access == PlanAccess.Read ? "read" : "write");
            Assert.Equal(file.MaxRows, definition.MaxRows);
            Assert.Equal(file.StatementParams.Length, definition.Statements.Count);
            for (var index = 0; index < definition.Statements.Count; index++)
            {
                Assert.Equal(file.StatementParams[index], definition.Statements[index].Params.Select(Kind));
                Assert.Equal(file.StatementReturns[index], definition.Statements[index].Returns is { } returns ? string.Join(',', returns.Select(Kind)) : null);
            }
        }

        static string Kind(PlanParam param) => param.Kind.ToString().ToLowerInvariant() + (param.Nullable ? "?" : "");
    }

    [GeneratedRegex("\\b(from|join|into|update)\\s+(?:or\\s+(?:abort|fail|ignore|replace|rollback)\\s+)?([a-z_][a-z0-9_]*)", RegexOptions.CultureInvariant)]
    private static partial Regex TableReference();

    /// <summary>The physical tables a plan names after FROM, JOIN, INTO or UPDATE (a second, simpler implementation of the generator's rule).</summary>
    internal static IReadOnlyList<string> Tables(string sql)
    {
        var text = Regex.Replace(sql, "'(?:[^']|'')*'", "''").ToLowerInvariant();
        var ctes = Regex.Matches(text, "(?:with(?:\\s+recursive)?|,)\\s*([a-z_][a-z0-9_]*)\\s*(?:\\([^)]*\\))?\\s+as\\s*\\(").Select(match => match.Groups[1].Value).ToHashSet();
        var tables = new List<string>();
        foreach (Match match in TableReference().Matches(text))
        {
            var name = match.Groups[2].Value;
            if (name is "json_each" or "json_tree" || ctes.Contains(name)) continue;
            if (match.Groups[1].Value == "update" && name == "set") continue;
            tables.Add(name);
        }

        return tables;
    }

    private static string[] AllowedPrefixes(JsonElement owners, string owner)
    {
        var row = owners.EnumerateArray().Single(entry => entry.GetProperty("owner").GetString() == owner);
        var prefix = row.GetProperty("tablePrefix").GetString()!;
        return row.GetProperty("kind").GetString() == "module" ? [prefix, "platform_"] : [prefix];
    }

    [Fact]
    public void EveryPlanBelongsToARegisteredOwnerAndTouchesOnlyItsOwnersTables()
    {
        using var registry = JsonDocument.Parse(File.ReadAllText(Path.Combine(PlanRoot, "owners.json")));
        var owners = registry.RootElement.GetProperty("owners");
        foreach (var plan in ReadPlans())
        {
            Assert.Equal(plan.Owner, plan.Id.Split('.')[0]);
            Assert.Equal(plan.Name, string.Join('.', plan.Id.Split('.').Skip(1)));
            var allowed = AllowedPrefixes(owners, plan.Owner);
            foreach (var table in Tables(plan.Text))
                Assert.True(allowed.Any(prefix => table.StartsWith(prefix, StringComparison.Ordinal)), plan.Id + " touches " + table);
        }
    }

    [Theory]
    [InlineData("chat", "SELECT 1 FROM identity_user WHERE id = ?;", "identity_user")]
    [InlineData("chat", "UPDATE sync_change SET x = 1;", "sync_change")]
    [InlineData("identity", "INSERT INTO chat_message (id) VALUES (?);", "chat_message")]
    [InlineData("foundation", "INSERT INTO platform_outbox (x) VALUES (?);", "platform_outbox")]
    [InlineData("identity", "SELECT a FROM identity_user JOIN device_device ON 1 = 1;", "device_device")]
    public void ACrossOwnerReferenceIsDetected(string owner, string sql, string offender)
    {
        using var registry = JsonDocument.Parse(File.ReadAllText(Path.Combine(PlanRoot, "owners.json")));
        var allowed = AllowedPrefixes(registry.RootElement.GetProperty("owners"), owner);
        Assert.Contains(offender, Tables(sql).Where(table => !allowed.Any(prefix => table.StartsWith(prefix, StringComparison.Ordinal))));
    }

    [Fact]
    public void AnOwnPlatformCteAndTableFunctionReferenceIsAccepted()
    {
        using var registry = JsonDocument.Parse(File.ReadAllText(Path.Combine(PlanRoot, "owners.json")));
        var allowed = AllowedPrefixes(registry.RootElement.GetProperty("owners"), "chat");
        const string sql = "WITH recent AS (SELECT id FROM chat_message) SELECT r.id FROM recent r JOIN platform_command c ON c.command_id = r.id, json_each(?) ;";
        Assert.All(Tables(sql), table => Assert.True(allowed.Any(prefix => table.StartsWith(prefix, StringComparison.Ordinal)), table));
    }

    [GeneratedRegex("\"[^\"\\n]*\\b(?:select\\s+[^\"]+\\s+from|insert\\s+into|update\\s+\\w+\\s+set|delete\\s+from|create\\s+table|drop\\s+table|alter\\s+table|pragma\\s+\\w+)\\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlLiteral();

    [Fact]
    public void NoSqlTextExistsInCSharpSource()
    {
        var root = T.RepoRoot().FullName;
        foreach (var file in Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains("/obj/", StringComparison.Ordinal) || file.Contains("\\obj\\", StringComparison.Ordinal) || file.EndsWith(".g.cs", StringComparison.Ordinal)) continue;
            foreach (var line in File.ReadLines(file).Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal)))
                Assert.False(SqlLiteral().IsMatch(line), Path.GetRelativePath(root, file) + ": " + line.Trim());
        }

        Assert.Matches(SqlLiteral(), "var x = \"SELECT a FROM t\";");
        Assert.Matches(SqlLiteral(), "var x = \"insert into t values (1)\";");
        Assert.DoesNotMatch(SqlLiteral(), "var x = \"Storage plan failed: \" + kind;");
    }

    private static string[] Strings(Type type) =>
        type.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(property => property.PropertyType == typeof(string)).Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();

    [Fact]
    public void NothingTheBridgeCanSendNamesSqlOrATable()
    {
        // A plan is identified by id, version and manifest hash; the Worker looks the SQL up in its own dictionary.
        Assert.Equal(["Id"], Strings(typeof(PlanDefinition)));
        Assert.Empty(Strings(typeof(PlanStatement)));
        Assert.Equal(["OwnerScope"], Strings(typeof(PlanCall)));
        Assert.Equal(typeof(PlanDefinition), typeof(PlanCall).GetProperty(nameof(PlanCall.Plan))!.PropertyType);
        var execute = Assert.Single(typeof(IPlanExecutor).GetMethods());
        Assert.Equal([typeof(PlanCall), typeof(CancellationToken)], execute.GetParameters().Select(parameter => parameter.ParameterType));
        // The generated wire request has exactly these fields: a contract change that adds a SQL or table field fails here first.
        Assert.Equal(
            ["Arguments", "DeadlineUtc", "ManifestHash", "OwnerScope", "PlanId", "PlanVersion", "RecoveryGeneration", "RequestId"],
            typeof(ExecutePlanRequest).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Select(property => property.Name).Order(StringComparer.Ordinal));
        // The executor sends nothing but a plan call; its only public entry point is that method.
        Assert.Equal(["ExecuteAsync"], typeof(WorkerPlanExecutor).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Select(method => method.Name));
    }
}
