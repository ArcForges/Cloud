// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using Xunit;

namespace ArcForges.Cloud.Tests.SharedFamilies;

/// <summary>
/// The generated listing of family plans (<c>storage/plans/families.expanded.json</c>): what the Worker runs for each family plan,
/// readable in a review. C# recomputes every family plan identity from the authored plan file and the listed SQL, independently of the
/// generator, and holds the generated C# roles and parameter kinds to the listing.
/// </summary>
internal static class FamilyExpansion
{
    internal sealed record Statement(string Role, string Sql, IReadOnlyList<string> Params);

    internal sealed record Plan(string Id, int Version, string Family, string Sha256, IReadOnlyList<Statement> Statements, bool RequiresScopedContributions);

    private static string StorageRoot => Path.Combine(T.RepoRoot().FullName, "storage", "plans");

    private static string Normalize(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).TrimEnd() + "\n";

    /// <summary>The identity of a family plan: the normalized authored text and every expanded statement, in order (shared with the generator by <c>Vectors/family-lock-order.json</c>).</summary>
    public static string Identity(string normalizedText, IEnumerable<string> statementSql, bool requiresScopedContributions = false) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(normalizedText + "\n-- expanded\n" + string.Join('\n', statementSql) + "\n"
            + (requiresScopedContributions ? "-- security-metadata/v1\nrequiresScopedContributions=true\n" : ""))));

    public static IReadOnlyList<Plan> Read()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(StorageRoot, "families.expanded.json")));
        Assert.Equal(1, document.RootElement.GetProperty("schemaVersion").GetInt32());
        return document.RootElement.GetProperty("plans").EnumerateArray()
            .Select(plan => new Plan(
                plan.GetProperty("id").GetString()!,
                plan.GetProperty("version").GetInt32(),
                plan.GetProperty("family").GetString()!,
                plan.GetProperty("sha256").GetString()!,
                plan.GetProperty("statements").EnumerateArray()
                    .Select(statement => new Statement(
                        statement.GetProperty("role").GetString()!,
                        statement.GetProperty("sql").GetString()!,
                        statement.GetProperty("params").EnumerateArray().Select(kind => kind.GetString()!).ToArray()))
                    .ToArray(),
                plan.TryGetProperty("requiresScopedContributions", out var scoped) && scoped.GetBoolean()))
            .ToArray();
    }

    /// <summary>The identities recomputed from the plan files; each must equal the identity the generator listed.</summary>
    public static IReadOnlyList<(string Id, int Version, string Sha256)> Identities()
    {
        var identities = new List<(string, int, string)>();
        foreach (var plan in Read())
        {
            var parts = plan.Id.Split('.');
            var file = Path.Combine(StorageRoot, "families", parts[1] + "." + parts[2] + ".sql");
            var recomputed = Identity(Normalize(File.ReadAllText(file)), plan.Statements.Select(statement => statement.Sql), plan.RequiresScopedContributions);
            Assert.Equal(plan.Sha256, recomputed);
            identities.Add((plan.Id, plan.Version, recomputed));
        }

        return identities;
    }

    public static string KindText(PlanParam param) => param.Kind.ToString().ToLowerInvariant() + (param.Nullable ? "?" : "");

    public static string RoleText(FamilyStatementRole role) => role.Phase.ToString().ToLowerInvariant() + " " + ModuleLockOrder.Owner(role.Module) + " " + role.Class.ToString().ToLowerInvariant() + " " + role.Key;
}

public sealed class FamilyExpansionTests
{
    [Fact]
    public void TheIdentityFormulaIsTheSharedVector()
    {
        var vector = FamilyFixture.Vectors.GetProperty("identity");
        var sql = vector.GetProperty("statementSql").EnumerateArray().Select(item => item.GetString()!).ToArray();
        Assert.Equal(vector.GetProperty("sha256").GetString(), FamilyExpansion.Identity(vector.GetProperty("normalizedText").GetString()!, sql));
        // Any statement, its order, or the authored text changes it.
        Assert.NotEqual(vector.GetProperty("sha256").GetString(), FamilyExpansion.Identity(vector.GetProperty("normalizedText").GetString()!, sql.Reverse()));
        Assert.NotEqual(vector.GetProperty("sha256").GetString(), FamilyExpansion.Identity(vector.GetProperty("normalizedText").GetString()! + " ", sql));
        Assert.NotEqual(vector.GetProperty("sha256").GetString(), FamilyExpansion.Identity(vector.GetProperty("normalizedText").GetString()!, sql.Take(1)));
        Assert.Equal(vector.GetProperty("sha256").GetString(), FamilyExpansion.Identity(vector.GetProperty("normalizedText").GetString()!, sql, false));
        Assert.Equal("3a8e78364f3b876cda67dc85b69bba52af6146f3b778738601e6d23bbee34756", FamilyExpansion.Identity(vector.GetProperty("normalizedText").GetString()!, sql, true));
    }

    [Fact]
    public void EveryListedFamilyPlanEqualsItsGeneratedDefinitionStatementByStatement()
    {
        var listed = FamilyExpansion.Read();
        using var registry = JsonDocument.Parse(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "storage", "plans", "families.json")));
        var scopedPlans = registry.RootElement.TryGetProperty("scopedContributionPlans", out var scoped)
            ? scoped.EnumerateArray().Select(plan => plan.GetString()!).ToArray() : [];
        Assert.Equal(scopedPlans.Length, scopedPlans.Distinct(StringComparer.Ordinal).Count());
        Assert.All(scopedPlans, id => Assert.Single(listed, plan => plan.Id == id));
        Assert.Equal(PlanManifest.FamilyPlans.Count, listed.Count);
        foreach (var plan in listed)
        {
            var generated = Assert.Single(PlanManifest.FamilyPlans, candidate => candidate.Plan.Id == plan.Id && candidate.Plan.Version == plan.Version);
            Assert.Equal(plan.Family, generated.Family);
            Assert.Equal(scopedPlans.Contains(plan.Id, StringComparer.Ordinal), plan.RequiresScopedContributions);
            Assert.Equal(plan.RequiresScopedContributions, generated.RequiresScopedContributions);
            Assert.Equal(plan.Statements.Count, generated.Roles.Count);
            Assert.Equal(plan.Statements.Count, generated.Plan.Statements.Count);
            for (var index = 0; index < plan.Statements.Count; index++)
            {
                Assert.Equal(plan.Statements[index].Role, FamilyExpansion.RoleText(generated.Roles[index]));
                Assert.Equal(plan.Statements[index].Params, generated.Plan.Statements[index].Params.Select(FamilyExpansion.KindText));
            }
        }

        _ = FamilyExpansion.Identities();
    }

    [Fact]
    public void TheListedSqlOfEveryFamilyPlanIsGuardedMutationsAndOneRelease()
    {
        // The generator already refuses anything else; this reads the listing as a reviewer would, with C# as a second pair of eyes.
        foreach (var plan in FamilyExpansion.Read())
        {
            Assert.EndsWith("DELETE FROM platform_command_guard WHERE command_id = ?;", plan.Statements[^1].Sql, StringComparison.Ordinal);
            foreach (var statement in plan.Statements.Where(statement => statement.Role.StartsWith("guard ", StringComparison.Ordinal)))
                Assert.StartsWith("INSERT INTO platform_command_guard (command_id, guard_key, allowed)", statement.Sql, StringComparison.Ordinal);
            foreach (var statement in plan.Statements.Where(statement => statement.Role.StartsWith("mutation ", StringComparison.Ordinal)))
                Assert.DoesNotContain("platform_command_guard", statement.Sql, StringComparison.Ordinal);
            Assert.Equal(1, plan.Statements.Count(statement => statement.Role.StartsWith("release ", StringComparison.Ordinal)));
            Assert.All(plan.Statements.Select(statement => statement.Sql), sql => Assert.Equal(1, sql.Count(character => character == ';')));
        }
    }
}
