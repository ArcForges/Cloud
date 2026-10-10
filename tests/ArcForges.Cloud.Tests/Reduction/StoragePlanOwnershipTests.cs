// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ArcForges.Cloud.Tools.Generation.StoragePlans;
using Xunit;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>
/// CLOUD.84 U7: one-for-one C# replacement of tests/worker/storage-plan-ownership.test.ts. The owner registry, the table-reference scanner,
/// the ownership rule and the manifest builder run against the C# generator; the SQLite-oracle cases ask node:sqlite (through
/// <see cref="SqliteOracle"/>) which statements SQLite accepts, exactly as the TypeScript test did.
/// </summary>
public sealed class StoragePlanOwnershipTests
{
    private const string SecretSchema = "CREATE TABLE secret_t (a, b); CREATE TABLE chat_message (a, b); CREATE TABLE platform_outbox (a, b);";

    private const string ReservedSchema =
        "CREATE TABLE secret_t (a, b); CREATE TABLE identity_u (a, b, key, do, conflict, window, filter, over, replace, abort, action, after, asc, desc, end, fail, ignore, match, no, of, offset, plan, query, row, rows, temp, view, virtual, within, first, last, nulls, current, following, partition, preceding, range, unbounded, exclude, groups, others, ties, generated, always, materialized, rename, restrict, cascade, by, cast, database, deferred, each, exclusive, explain, for, immediate, initially, instead, raise, recursive, release, rollback, savepoint, trigger, vacuum, without, analyze, attach, before, begin, detach, pragma); CREATE TABLE platform_r (a, b);";

    private static readonly string[] ReservedWords =
    [
        "do", "conflict", "window", "key", "filter", "over", "replace", "abort", "action", "after", "asc", "desc", "end", "fail", "ignore",
        "match", "no", "of", "offset", "plan", "query", "row", "rows", "temp", "view", "virtual", "within", "first", "last", "nulls",
        "current", "following", "partition", "preceding", "range", "unbounded", "exclude", "groups", "others", "ties", "generated",
        "always", "materialized", "rename", "restrict", "cascade", "by", "cast", "database", "deferred", "each", "exclusive", "explain",
        "for", "immediate", "initially", "instead", "raise", "recursive", "release", "rollback", "savepoint", "trigger", "vacuum", "without",
        "analyze", "attach", "before", "begin", "detach", "pragma", "left", "inner", "cross", "natural", "outer", "with", "not", "like",
        "glob", "regexp", "escape", "values",
    ];

    private static readonly Func<string, string>[] JoinShapes =
    [
        word => $"SELECT 1 FROM identity_u {word}, secret_t",
        word => $"SELECT 1 FROM identity_u AS {word}, secret_t",
        word => $"SELECT 1 FROM identity_u a JOIN platform_r p ON a.{word} = 1, secret_t",
        word => $"SELECT 1 FROM identity_u AS {word} JOIN platform_r p ON {word}.a = 1, secret_t",
        word => $"SELECT 1 FROM identity_u a JOIN platform_r p ON p.a = a.{word} WHERE 1, secret_t",
    ];

    private static OwnerRegistry Registry() =>
        StoragePlanParser.ParseOwnerRegistry(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, StoragePlanParser.OwnerRegistryPath)));

    private static string Header(string id, string access = "write") => $"-- plan: {id}\n-- version: 1\n-- access: {access}\n";

    private static PlanDefinition Plan(string id, string sql) =>
        StoragePlanParser.ParsePlanFile(
            $"{Header(id)}-- statement: params=scope\n{sql}\n",
            $"storage/plans/{id.Replace(".", "/", StringComparison.Ordinal)}.sql");

    private static PlanDefinition Bypass(string sql) =>
        new("chat.bypass", 1, "write", 0, [new PlanStatement(sql, [], null)], string.Empty, null, null);

    private static string TemporaryRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "plans-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    [Fact]
    public void OwnerRegistryListsTheNineteenModuleOwnersTheSharedPlatformAndTheProofOwner()
    {
        var owners = Registry().Owners;
        Assert.Equal(19, owners.Count(entry => entry.Kind == "module"));
        Assert.Equal(new[] { "platform", "foundation" }, owners.Where(entry => entry.Kind != "module").Select(entry => entry.Owner));
        foreach (var entry in owners.Where(candidate => candidate.Kind == "module"))
            Assert.Equal($"{entry.Owner.Replace("-", "_", StringComparison.Ordinal)}_", entry.TablePrefix);
        foreach (var entry in owners)
            Assert.False(entry.TablePrefix.StartsWith("cte_", StringComparison.Ordinal), entry.Owner);
    }

    [Fact]
    public void AMalformedOwnerRegistryIsRefused()
    {
        var good = File.ReadAllText(Path.Combine(T.RepoRoot().FullName, StoragePlanParser.OwnerRegistryPath));
        var refused = new (string Label, Action<JsonObject> Mutate, string Pattern)[]
        {
            ("schema version", value => value["schemaVersion"] = 2, "schemaVersion"),
            ("duplicate owner", value => Owner(value, 1)["owner"] = "identity", "duplicate owner"),
            ("duplicate class", value => Owner(value, 1)["className"] = "Identity", "duplicate class"),
            ("duplicate prefix", value => Owner(value, 1)["tablePrefix"] = "identity_", "duplicate table prefix"),
            ("module prefix that is not its schema", value => Owner(value, 1)["tablePrefix"] = "ws_", "is its schema"),
            ("a prefix that contains another", value => Owners(value).Add(
                OwnerNode("form", "Form", "module", "form_")), "contains"),
            ("unknown field", value => Owner(value, 0)["extra"] = "x", "fields of"),
            ("unknown kind", value => Owner(value, 0)["kind"] = "other", "kind of"),
            ("bad owner name", value => Owner(value, 0)["owner"] = "Identity", "invalid owner"),
            ("second platform", value => Owners(value).Add(
                OwnerNode("platform", "Platform2", "platform", "platform_")), "duplicate"),
        };
        foreach (var (label, mutate, pattern) in refused)
        {
            var value = (JsonObject)JsonNode.Parse(good)!;
            mutate(value);
            if (label == "a prefix that contains another")
                Owners(value).Add(OwnerNode("form-a", "FormA", "module", "form_a_"));
            var refusal = Assert.Throws<PlanRefusal>(() => StoragePlanParser.ParseOwnerRegistry(value.ToJsonString()));
            Assert.Contains(pattern, refusal.Message, StringComparison.Ordinal);
        }
    }

    private static JsonArray Owners(JsonObject value) => value["owners"]!.AsArray();

    private static JsonObject Owner(JsonObject value, int index) => Owners(value)[index]!.AsObject();

    private static JsonObject OwnerNode(string owner, string className, string kind, string prefix) =>
        new() { ["owner"] = owner, ["className"] = className, ["kind"] = kind, ["tablePrefix"] = prefix };

    [Fact]
    public void TableReferencesAreFoundThroughEveryStatementFormAndHiddenOnesAreRefused()
    {
        static List<string> Tables(string sql) => SqlText.ReferencedTables(sql, "t");
        Assert.Equal(new[] { "chat_message" }, Tables("SELECT a FROM chat_message WHERE b = ?;"));
        Assert.Equal(new[] { "chat_message" }, Tables("INSERT INTO chat_message (a, b) VALUES (?, ?);"));
        Assert.Equal(new[] { "chat_message" }, Tables("UPDATE chat_message SET a = ? WHERE b = ?;"));
        Assert.Equal(new[] { "chat_message" }, Tables("DELETE FROM chat_message WHERE a = ?;"));
        Assert.Equal(new[] { "chat_message", "platform_outbox" }, Tables("INSERT OR IGNORE INTO chat_message (a) SELECT a FROM platform_outbox;"));
        Assert.Equal(
            ["chat_message", "platform_command", "task_x"],
            Tables("SELECT a FROM chat_message m JOIN platform_command c ON c.id = m.id LEFT JOIN task_x t ON 1;"));
        // CTE names and table-valued functions are not tables, and an upsert names no second table.
        Assert.Equal(
            ["chat_message"],
            Tables("WITH cte_r AS (SELECT a FROM chat_message), cte_s(x) AS MATERIALIZED (SELECT 1) SELECT a FROM cte_r JOIN json_each(?) ON 1;"));
        Assert.Equal(new[] { "chat_message" }, Tables("INSERT INTO chat_message (a) VALUES (?) ON CONFLICT (a) DO UPDATE SET a = excluded.a;"));
        Assert.Equal(new[] { "chat_message" }, Tables("SELECT a IS NOT DISTINCT FROM b FROM chat_message;"));
        // A string literal cannot hide or fake a table.
        Assert.Equal(new[] { "chat_message" }, Tables("SELECT 'FROM other_table' FROM chat_message;"));
        var hidden = new (string Label, string Sql, string Pattern)[]
        {
            ("quoted identifier", "SELECT a FROM \"identity_user\";", "quoted identifiers"),
            ("backtick identifier", "SELECT a FROM `identity_user`;", "quoted identifiers"),
            ("bracket identifier", "SELECT a FROM [identity_user];", "quoted identifiers"),
            ("schema qualification", "SELECT a FROM main.identity_user;", "schema-qualified"),
            ("temp schema", "INSERT INTO temp.x (a) VALUES (?);", "schema-qualified"),
            ("comma join", "SELECT a FROM chat_message, identity_user;", "comma join"),
            ("comma join with alias", "SELECT a FROM chat_message m, identity_user u;", "comma join"),
            ("unknown table function", "SELECT a FROM pragma_table_info(?);", "table-valued function"),
        };
        foreach (var (label, sql, pattern) in hidden)
        {
            var refusal = Assert.Throws<PlanRefusal>(() => Tables(sql));
            Assert.Matches(pattern, refusal.Message);
            Assert.True(refusal.Message.Length > 0, label);
        }
    }

    [Fact]
    public void EveryAcceptedSpellingOfAForeignTableIsRefusedSqliteIsTheOracle()
    {
        var bypasses = new (string Label, string Sql)[]
        {
            ("single-quoted FROM", "SELECT a FROM 'secret_t';"),
            ("single-quoted JOIN", "SELECT m.a FROM chat_message m JOIN 'secret_t' s ON 1;"),
            ("single-quoted INSERT INTO", "INSERT INTO 'secret_t' (a) VALUES (?);"),
            ("single-quoted UPDATE", "UPDATE 'secret_t' SET a = ?;"),
            ("single-quoted DELETE", "DELETE FROM 'secret_t';"),
            ("comma join after a JOIN", "SELECT 1 FROM chat_message m JOIN platform_outbox o ON 1, secret_t;"),
            ("comma join after a subquery", "SELECT 1 FROM (SELECT a FROM chat_message), secret_t;"),
            ("comma join after json_each", "SELECT 1 FROM json_each(?), secret_t;"),
            ("comma join after an alias", "SELECT 1 FROM chat_message AS m, secret_t AS s;"),
            ("parenthesised FROM", "SELECT a FROM (secret_t);"),
            ("parenthesised JOIN", "SELECT 1 FROM chat_message m JOIN (secret_t) ON 1;"),
            ("doubly parenthesised", "SELECT a FROM ((secret_t));"),
            ("unscoped CTE name collision", "WITH secret_t AS (SELECT 1 AS a) SELECT a FROM secret_t;"),
            ("CTE name collision through a window name", "SELECT sum(a) OVER secret_t FROM secret_t WINDOW secret_t AS (ORDER BY a);"),
            ("CTE declared after use", "SELECT 1 FROM secret_t, (WITH secret_t AS (SELECT 1 AS a) SELECT a FROM secret_t);"),
            ("mixed case", "sElEcT a fRoM Secret_T;"),
            ("tabs and newlines", "SELECT\ta\nFROM\r\n\t'secret_t'\t;"),
            ("block comment between tokens", "SELECT a FROM/**/secret_t;"),
            ("line comment between tokens", "SELECT a FROM -- note\nsecret_t;"),
            ("comment before a comma join", "SELECT 1 FROM chat_message/**/,/**/secret_t;"),
        };
        var accepted = SqliteOracle.Accepts(SecretSchema, bypasses.Select(entry => entry.Sql).ToList());
        for (var index = 0; index < bypasses.Length; index++)
        {
            var (label, sql) = bypasses[index];
            // The oracle accepts it (the placeholders are bound where there are any).
            Assert.True(accepted[index], $"{label}: SQLite accepts the statement");
            List<string>? tables;
            try
            {
                tables = SqlText.ReferencedTables(sql, label).Select(table => table.ToLowerInvariant()).ToList();
            }
            catch (PlanRefusal)
            {
                tables = null;
            }

            Assert.True(tables is null || tables.Contains("secret_t"), $"{label}: neither refused nor reported");
        }

        // The same statements are refused by the ownership rule itself, whichever way the check answered.
        foreach (var (_, sql) in bypasses)
            Assert.Throws<PlanRefusal>(() => StoragePlanParser.AssertOwnership(Bypass(sql), Registry())); // label kept for failure messages
    }

    [Fact]
    public void UnaccountedTablePositionsAreRefusedAndConstructsPlansUseStayAccepted()
    {
        static List<string> Tables(string sql) => SqlText.ReferencedTables(sql, "t");
        var refused = new (string Label, string Sql, string Pattern)[]
        {
            ("number in a table position", "SELECT a FROM 1;", "plain table name"),
            ("keyword in a table position", "SELECT a FROM select;", "plain table name"),
            ("nothing after FROM", "SELECT a FROM", "plain table name"),
            ("CTE not starting with the reserved prefix", "WITH r AS (SELECT 1) SELECT 1 FROM r;", "cte_"),
            ("CTE as a write target", "WITH cte_r AS (SELECT 1) INSERT INTO cte_r (a) VALUES (1);", "not a write target"),
            ("CTE without AS", "WITH cte_r (SELECT 1) SELECT 1;", "defined with AS"),
            ("unterminated string", "SELECT a FROM chat_message WHERE a = 'x;", "unterminated string"),
            ("unterminated comment", "SELECT a FROM chat_message /* x;", "unterminated comment"),
            ("unbalanced parenthesis", "SELECT a FROM (SELECT a FROM chat_message;", "unbalanced"),
            ("update with a column list", "UPDATE chat_message (a) SET a = 1;", "not followed by a list"),
            ("subquery comma join", "SELECT 1 WHERE a IN (SELECT a FROM chat_message, secret_t);", "comma join"),
        };
        foreach (var (label, sql, pattern) in refused)
        {
            var refusal = Assert.Throws<PlanRefusal>(() => Tables(sql));
            Assert.True(Regex.IsMatch(refusal.Message, pattern), label);
        }

        // A non-ASCII spelling is its own table for SQLite: it is reported as written and refused by the owner prefix.
        Assert.Equal(new[] { "ſecret_t" }, Tables("SELECT a FROM ſecret_t;"));
        var unicode = Assert.Throws<PlanRefusal>(() => StoragePlanParser.AssertOwnership(Plan("chat.unicode", "UPDATE ſecret_t SET a = 1 WHERE scope = ?;"), Registry()));
        Assert.Contains("not owned by chat", unicode.Message, StringComparison.Ordinal);
        Assert.Equal(new[] { "chat_message" }, Tables("SELECT a FROM chat_message ORDER BY a, b LIMIT ?, ?;"));
        Assert.Equal(new[] { "chat_message" }, Tables("SELECT 1 FROM chat_message GROUP BY a, b HAVING count(*) > 1;"));
        Assert.Equal(
            ["chat_message"],
            Tables("INSERT INTO chat_message (a, b) SELECT value, 2 FROM json_each(?) ON CONFLICT (a, b) DO UPDATE SET a = excluded.a, b = excluded.b;"));
        Assert.Equal(
            ["chat_message", "platform_outbox"],
            Tables("UPDATE chat_message SET a = ?, b = (SELECT x FROM platform_outbox WHERE y = ?) WHERE c = ?;"));
        Assert.Equal(new[] { "chat_message" }, Tables("SELECT 'a, b' FROM chat_message WHERE b = 'JOIN x';"));
        Assert.Equal(new[] { "chat_message" }, Tables("SELECT a FROM chat_message AS m /* c */ WHERE a = 1;"));
    }

    [Fact]
    public void NoWordThatSqliteAcceptsAsANameResetsTheCommaJoinGuard()
    {
        var words = SqlText.FromEnders.Concat(ReservedWords).ToList();
        var candidates = new List<string>();
        foreach (var word in words)
            foreach (var shape in JoinShapes)
                candidates.Add(shape(word));
        var reviewed = new[]
        {
            "SELECT 1 FROM identity_u do, secret_t",
            "SELECT 1 FROM identity_u AS conflict, secret_t",
            "SELECT 1 FROM identity_u window, secret_t",
            "SELECT 1 FROM identity_u a JOIN platform_r p ON a.conflict = 1, secret_t",
            "SELECT 1 FROM identity_u a JOIN platform_r p ON a.do = 1, secret_t",
            "SELECT 1 FROM identity_u AS window, secret_t",
            "SELECT 1 FROM identity_u AS do, secret_t",
        };
        var clauseEnders = SqlText.FromEnders.ToList();
        var probes = new List<string>();
        foreach (var word in clauseEnders)
        {
            probes.Add($"SELECT 1 FROM identity_u AS {word}");
            probes.Add($"SELECT 1 FROM identity_u {word}");
            probes.Add($"SELECT {word} FROM identity_u");
        }

        var all = candidates.Concat(reviewed).Concat(probes).ToList();
        var accepted = SqliteOracle.Accepts(ReservedSchema, all);
        var accepting = 0;
        for (var index = 0; index < candidates.Count; index++)
        {
            if (!accepted[index]) continue;
            accepting++;
            Assert.NotEqual("missed", Verdict(candidates[index]));
        }

        Assert.True(accepting > 30, $"the oracle accepted only {accepting} statements");
        // The four statements and the AS variants of the review, spelled out.
        for (var index = 0; index < reviewed.Length; index++)
        {
            var sql = reviewed[index];
            Assert.True(accepted[candidates.Count + index], $"SQLite accepts: {sql}");
            Assert.Equal("refused", Verdict(sql));
        }

        // A clause ender is a reserved word: SQLite refuses it as an alias and as a column, so it can only start a clause.
        for (var index = 0; index < clauseEnders.Count; index++)
        {
            var word = clauseEnders[index];
            var offset = candidates.Count + reviewed.Length + index * 3;
            Assert.False(accepted[offset], $"{word} is accepted as an alias");
            Assert.True(!accepted[offset + 1] || word == "where", $"{word} is accepted as an alias");
            Assert.False(accepted[offset + 2], $"{word} is accepted as a column");
        }
    }

    private static string Verdict(string sql)
    {
        try
        {
            return SqlText.ReferencedTables(sql, sql).Contains("secret_t") ? "reported" : "missed";
        }
        catch (PlanRefusal)
        {
            return "refused";
        }
    }

    [Fact]
    public void APlanMayTouchItsOwnTablesAndTheSharedPlatformTablesOnly()
    {
        var registry = Registry();
        StoragePlanParser.AssertOwnership(
            Plan("chat.own", "INSERT INTO chat_message (a) SELECT a FROM chat_draft WHERE scope = ?;"),
            registry);
        StoragePlanParser.AssertOwnership(
            Plan("chat.shared", "INSERT INTO platform_outbox (a) SELECT a FROM chat_draft WHERE scope = ?;"),
            registry);
        var foreign = new (string Sql, string Table)[]
        {
            ("UPDATE chat_message SET a = (SELECT a FROM identity_user WHERE scope = ?);", "identity_user"),
            ("INSERT INTO sync_change (a) VALUES (?);", "sync_change"),
            ("DELETE FROM task_item WHERE scope = ?;", "task_item"),
            // A name that merely starts like the owner's prefix is not the owner's table.
            ("UPDATE chatty_draft SET a = 1 WHERE scope = ?;", "chatty_draft"),
            ("UPDATE chat SET a = 1 WHERE scope = ?;", "chat"),
        };
        foreach (var (sql, table) in foreign)
        {
            var refusal = Assert.Throws<PlanRefusal>(() => StoragePlanParser.AssertOwnership(Plan("chat.foreign", sql), registry));
            Assert.Matches($"table {table} is not owned by chat", refusal.Message);
        }

        Assert.Matches("not owned by platform", Assert.Throws<PlanRefusal>(() =>
            StoragePlanParser.AssertOwnership(Plan("platform.sample", "DELETE FROM chat_message WHERE scope = ?;"), registry)).Message);
        Assert.Matches("not owned by foundation", Assert.Throws<PlanRefusal>(() =>
            StoragePlanParser.AssertOwnership(Plan("foundation.sample", "DELETE FROM platform_outbox WHERE scope = ?;"), registry)).Message);
        Assert.Matches(@"not in storage/plans/owners\.json", Assert.Throws<PlanRefusal>(() =>
            StoragePlanParser.AssertOwnership(Plan("unknown.sample", "DELETE FROM unknown_x WHERE scope = ?;"), registry)).Message);
    }

    [Fact]
    public void TheManifestBuilderRefusesAnUnregisteredOwnerDirectoryAForeignRootFileAndAForeignTable()
    {
        var root = TemporaryRoot();
        try
        {
            var sample = $"{Header("foundation.sample")}-- statement: params=scope\nDELETE FROM probe_t WHERE scope = ?;\n";
            var directory = Path.Combine(root, "storage", "plans", "foundation");
            Directory.CreateDirectory(directory);
            File.Copy(Path.Combine(T.RepoRoot().FullName, StoragePlanParser.OwnerRegistryPath), Path.Combine(root, StoragePlanParser.OwnerRegistryPath));
            File.WriteAllText(Path.Combine(directory, "sample.sql"), sample);
            Assert.Single(StoragePlanParser.BuildManifest(root).Plans);
            Directory.CreateDirectory(Path.Combine(root, "storage", "plans", "stranger"));
            Assert.Matches("not an owner", Assert.Throws<PlanRefusal>(() => StoragePlanParser.BuildManifest(root)).Message);
            Directory.Delete(Path.Combine(root, "storage", "plans", "stranger"), recursive: true);
            File.WriteAllText(Path.Combine(root, "storage", "plans", "notes.md"), "x");
            Assert.Matches("foreign file", Assert.Throws<PlanRefusal>(() => StoragePlanParser.BuildManifest(root)).Message);
            File.Delete(Path.Combine(root, "storage", "plans", "notes.md"));
            File.WriteAllText(Path.Combine(directory, "sample.sql"), sample.Replace("probe_t", "identity_user", StringComparison.Ordinal));
            Assert.Matches("not owned by foundation", Assert.Throws<PlanRefusal>(() => StoragePlanParser.BuildManifest(root)).Message);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void PlansOfDifferentOwnersMayShareANameWithoutClashingInTheCSharpDefinitions()
    {
        var root = TemporaryRoot();
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "storage", "plans"));
            File.Copy(Path.Combine(T.RepoRoot().FullName, StoragePlanParser.OwnerRegistryPath), Path.Combine(root, StoragePlanParser.OwnerRegistryPath));
            foreach (var owner in new[] { "chat", "task" })
            {
                Directory.CreateDirectory(Path.Combine(root, "storage", "plans", owner));
                File.WriteAllText(
                    Path.Combine(root, "storage", "plans", owner, "get.sql"),
                    $"{Header($"{owner}.get", "read")}-- maxRows: 1\n-- statement: params=scope returns=int64\nSELECT CAST(a AS TEXT) FROM {owner}_x WHERE scope = ?;\n");
            }

            var source = StoragePlanOutputs.RenderCSharp(StoragePlanParser.BuildManifest(root));
            Assert.Matches(@"internal static class Chat\b[\s\S]*PlanDefinition Get = new\(\s*""chat\.get""", source);
            Assert.Matches(@"internal static class Task\b[\s\S]*PlanDefinition Get = new\(\s*""task\.get""", source);
            Assert.Contains("All = [Chat.Get, Task.Get]", source, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void EveryCheckedInPlanSatisfiesTheOwnershipRuleOfItsOwnerDirectory()
    {
        var manifest = StoragePlanParser.BuildManifest(T.RepoRoot().FullName);
        // A shared family plan is not an owner plan: the family grammar checks it statement by statement.
        var owned = manifest.Plans.Where(entry => entry.Family is null).ToList();
        foreach (var definition in owned) StoragePlanParser.AssertOwnership(definition, manifest.Registry);
        Assert.Equal(
            ["entitlement", "foundation", "identity", "platform", "task"],
            owned.Select(entry => entry.Id.Split('.')[0]).Distinct(StringComparer.Ordinal));
        Assert.Equal(
            ["families.account-enrollment.create-user"],
            manifest.Plans.Where(entry => entry.Family is not null).Select(entry => entry.Id));
    }
}
