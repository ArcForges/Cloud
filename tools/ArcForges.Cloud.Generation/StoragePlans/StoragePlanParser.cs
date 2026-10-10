// SPDX-License-Identifier: AGPL-3.0-only
// The storage-plan parser and checks (CLOUD.84 U7; port of eng/verification/storage-plans.ts). It reads the owner and family registries,
// parses each reviewed plan file, expands the guard primitives against the physical manifest, applies the ownership, commit-tail and
// SU-04 order rules, and assembles the manifest with its single hash. Every refusal throws a PlanRefusal with the Node message.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Tools.Generation.StoragePlans;

/// <summary>What a family plan needs to parse: the family registry and the physical columns the guards are expanded against.</summary>
public sealed record FamilyParseContext(FamilyRegistry Registry, Func<PhysicalManifest> Schema);

public static partial class StoragePlanParser
{
    public const string PlanDirectory = "storage/plans";
    public const string OwnerRegistryPath = "storage/plans/owners.json";
    public const string FamilyRegistryPath = "storage/plans/families.json";
    public const string FamilyExpansionPath = "storage/plans/families.expanded.json";
    public const string FamilyOwner = "families";
    public const string FamilyDirectory = "storage/plans/families";
    public const string SharedPrefix = "platform_";
    public const string PlatformModule = "platform";
    public const string GuardTable = "platform_command_guard";
    public const int MaxStatements = 100;
    public const int MaxParameters = 100;
    public const string CtePrefix = SqlText.CtePrefix;

    /// <summary>The parameter kinds a plan may bind or return.</summary>
    public static readonly IReadOnlyList<string> Kinds = ["int64", "uint64", "decimal", "text", "bytes", "bool", "scope"];

    /// <summary>Design SU-04: the fixed order in which the modules of one guarded batch contribute their statements.</summary>
    public static readonly IReadOnlyList<string> LockOrder =
    [
        "config", "identity", "workspace", "device", "entitlement", "commerce", "policy", "agent", "chat", "scope", "task",
        "search", "package-catalog", "notification", "resource", "sync", "audit",
    ];

    public static readonly IReadOnlyList<string> GuardKinds = ["authorization", "revision", "policy", "balance", "lease"];

    public static readonly IReadOnlyList<string> MutationClasses = ["bucket", "reservation", "record"];

    /// <summary>Tables only the migration runner writes; a family plan never names them.</summary>
    private static readonly HashSet<string> BookkeepingTables = ["platform_schema_state", "platform_migration_receipt", "platform_backfill_checkpoint"];

    /// <summary>SQLite reserved words: a column with one of these names cannot be written without quoting, and plans never quote.</summary>
    private static readonly HashSet<string> ReservedWords = new(
        "add all alter and as autoincrement between case check collate commit constraint create default deferrable delete distinct drop else escape except exists foreign from group having in index insert intersect into is isnull join limit not notnull null on or order primary references select set table then to transaction union unique update using values when where".Split(' '),
        StringComparer.Ordinal);

    private static readonly IReadOnlyDictionary<string, string[]> GuardFields = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["authorization"] = ["match", "fresh"],
        ["policy"] = ["match", "fresh"],
        ["revision"] = ["rev"],
        ["balance"] = ["rev", "exact"],
        ["lease"] = ["holder", "fence", "until"],
    };

    private static readonly IReadOnlyDictionary<string, int> PhaseRank = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["guard"] = 0,
        ["mutation"] = 1,
        ["release"] = 2,
    };

    private static readonly Regex OwnerPattern = new(@"^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant);
    private static readonly Regex ClassPattern = new(@"^[A-Z][A-Za-z0-9]*$", RegexOptions.CultureInvariant);
    private static readonly Regex FamilyPattern = new(@"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant);
    private static readonly Regex StableKeyPattern = new(@"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant);
    private static readonly Regex PlanIdPattern = new(@"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$", RegexOptions.CultureInvariant);
    private static readonly Regex ForbiddenSql = new(
        @"\b(?:pragma|attach|detach|drop|alter|create|vacuum|reindex|returning|load_extension|replace\s+into)\b|\bsqlite_",
        RegexOptions.IgnoreCase | RegexOptions.ECMAScript);
    private static readonly Regex StatementStart = new(@"^(?:INSERT|UPDATE|DELETE|SELECT|WITH)\b", RegexOptions.IgnoreCase | RegexOptions.ECMAScript);
    private static readonly Regex ReadStart = new(@"^(?:SELECT|WITH)\b", RegexOptions.IgnoreCase | RegexOptions.ECMAScript);
    private static readonly Regex MutationStart = new(@"^(?:INSERT|UPDATE|DELETE)\b", RegexOptions.IgnoreCase | RegexOptions.ECMAScript);
    private static readonly Regex StringLiteral = new(@"'(?:[^']|'')*'", RegexOptions.CultureInvariant);
    private static readonly Regex BadPlaceholder = new(@"[:@$][A-Za-z0-9_]|\?[0-9]", RegexOptions.CultureInvariant);
    private static readonly Regex CastBefore = new(@"CAST\(\s*\z", RegexOptions.CultureInvariant);
    private static readonly Regex CastAfter = new(@"\A\s*AS\s+INTEGER\s*\)", RegexOptions.CultureInvariant);
    private static readonly Regex HeaderLine = new(@"^-- (plan|version|access|maxRows|tail): (.+)$", RegexOptions.CultureInvariant);
    private static readonly Regex StatementMarker = new(@"^-- statement:(.*)$", RegexOptions.CultureInvariant);
    private static readonly Regex GuardMarker = new(@"^-- guard:(.*)$", RegexOptions.CultureInvariant);
    private static readonly Regex FieldPair = new(@"^([a-z]+)=(.*)$", RegexOptions.CultureInvariant);
    private static readonly Regex GuardKindField = new(@"(?:^|\s)kind=(\S+)", RegexOptions.CultureInvariant);

    /// <summary>The generated last statement of every family plan.</summary>
    public static readonly PlanStatement FamilyReleaseStatement = new(
        $"DELETE FROM {GuardTable} WHERE command_id = ?;",
        [new PlanParameter("text", false)],
        null,
        new FamilyStatementMeta(PlatformModule, "release", "release", "release"));

    public static string Sha256Hex(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    /// <summary>The normalized text of a plan file: CRLF to LF, trailing whitespace removed, exactly one final newline.</summary>
    public static string NormalizePlanText(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).TrimEnd() + "\n";

    private static string ModulePrefix(string module) =>
        module == PlatformModule ? SharedPrefix : module.Replace('-', '_') + "_";

    private static void RequireKeys(JsonElement entry, string[] expected, string message)
    {
        var names = entry.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
        SqlText.Require(names.SequenceEqual(expected.Order(StringComparer.Ordinal)), message);
    }

    private static JsonElement RequireArray(JsonElement parent, string name, string message)
    {
        SqlText.Require(parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array, message);
        return value;
    }

    private static string RequireString(JsonElement parent, string name, string message)
    {
        SqlText.Require(parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String, message);
        return value.GetString() ?? string.Empty;
    }

    private static int RequireSchemaVersion(JsonElement root, string file)
    {
        SqlText.Require(
            root.TryGetProperty("schemaVersion", out var version) && version.ValueKind == JsonValueKind.Number && version.GetInt32() == 1,
            $"{file}: schemaVersion");
        return 1;
    }

    /// <summary>Parses owners.json: the module, platform and proof owners, their classes and table prefixes.</summary>
    public static OwnerRegistry ParseOwnerRegistry(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        RequireSchemaVersion(root, "owners.json");
        var entries = RequireArray(root, "owners", "owners.json: owners");
        SqlText.Require(entries.GetArrayLength() > 0, "owners.json: owners");
        var owners = new List<PlanOwner>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var classes = new HashSet<string>(StringComparer.Ordinal);
        var prefixes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries.EnumerateArray())
        {
            RequireKeys(entry, ["className", "kind", "owner", "tablePrefix"], "owners.json: fields of an owner");
            var owner = RequireString(entry, "owner", "owners.json: owner");
            var className = RequireString(entry, "className", "owners.json: class name");
            var kind = RequireString(entry, "kind", "owners.json: kind");
            var tablePrefix = RequireString(entry, "tablePrefix", "owners.json: table prefix");
            SqlText.Require(OwnerPattern.IsMatch(owner), $"owners.json: invalid owner {owner}");
            SqlText.Require(owner != FamilyOwner, $"owners.json: {FamilyOwner} is reserved for family plans");
            SqlText.Require(ClassPattern.IsMatch(className), $"owners.json: invalid class name {className}");
            SqlText.Require(kind is "module" or "platform" or "proof", $"owners.json: kind of {owner}");
            SqlText.Require(seen.Add(owner), $"owners.json: duplicate owner {owner}");
            SqlText.Require(classes.Add(className), $"owners.json: duplicate class {className}");
            SqlText.Require(prefixes.Add(tablePrefix), $"owners.json: duplicate table prefix {tablePrefix}");
            SqlText.Require(!tablePrefix.StartsWith(CtePrefix, StringComparison.Ordinal), $"owners.json: {owner} prefix collides with CTE names");
            if (kind == "module")
                SqlText.Require(tablePrefix == owner.Replace('-', '_') + "_", $"owners.json: the table prefix of module {owner} is its schema");
            if (kind == "platform")
                SqlText.Require(owner == "platform" && tablePrefix == SharedPrefix, "owners.json: platform");
            if (kind == "proof") SqlText.Require(tablePrefix == "probe_", "owners.json: proof prefix");
            owners.Add(new PlanOwner(owner, className, kind, tablePrefix));
        }

        foreach (var a in prefixes)
            foreach (var b in prefixes)
                SqlText.Require(a == b || !b.StartsWith(a, StringComparison.Ordinal), $"owners.json: prefix {a} contains {b}");
        SqlText.Require(owners.Count(entry => entry.Kind == "platform") == 1, "owners.json: exactly one platform owner");
        return new OwnerRegistry(owners);
    }

    /// <summary>Parses families.json: the closed registry of shared families and their participants.</summary>
    public static FamilyRegistry ParseFamilyRegistry(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        RequireSchemaVersion(root, FamilyRegistryPath);
        var entries = RequireArray(root, "families", $"{FamilyRegistryPath}: families");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var families = new List<FamilyDefinition>();
        foreach (var entry in entries.EnumerateArray())
        {
            RequireKeys(entry, ["family", "participants", "source", "title"], $"{FamilyRegistryPath}: fields of a family");
            var family = RequireString(entry, "family", $"{FamilyRegistryPath}: family id");
            SqlText.Require(FamilyPattern.IsMatch(family), $"{FamilyRegistryPath}: invalid family id {family}");
            SqlText.Require(seen.Add(family), $"{FamilyRegistryPath}: duplicate family {family}");
            foreach (var field in new[] { "title", "source" })
            {
                var value = RequireString(entry, field, $"{FamilyRegistryPath}: {family} {field}");
                SqlText.Require(value.Length >= 1 && value.Length <= 300, $"{FamilyRegistryPath}: {family} {field}");
            }

            var participantEntries = RequireArray(entry, "participants", $"{FamilyRegistryPath}: participants of {family}");
            var participants = new List<FamilyParticipant>();
            foreach (var raw in participantEntries.EnumerateArray())
            {
                var module = RequireString(raw, "module", $"{FamilyRegistryPath}: {family}: module");
                SqlText.Require(
                    LockOrder.Contains(module, StringComparer.Ordinal),
                    $"{FamilyRegistryPath}: {family}: module {module} has no position in the SU-04 order; the Architecture Owner must extend the order before it may participate");
                SqlText.Require(
                    participants.All(participant => participant.Module != module),
                    $"{FamilyRegistryPath}: {family}: duplicate participant {module}");
                var requirement = RequireString(raw, "requirement", $"{FamilyRegistryPath}: {family}: requirement of {module}");
                SqlText.Require(
                    requirement is "required" or "conditional",
                    $"{FamilyRegistryPath}: {family}: requirement of {module}");
                string? when = null;
                if (requirement == "conditional")
                {
                    when = RequireString(raw, "when", $"{FamilyRegistryPath}: {family}: a conditional participant states when ({module})");
                    SqlText.Require(
                        when.Length >= 1 && when.Length <= 200,
                        $"{FamilyRegistryPath}: {family}: a conditional participant states when ({module})");
                }
                else
                {
                    SqlText.Require(
                        !raw.TryGetProperty("when", out _),
                        $"{FamilyRegistryPath}: {family}: {module} is required, so it has no condition");
                }

                var keys = raw.EnumerateObject().Select(property => property.Name).Where(name => name != "when").Order(StringComparer.Ordinal);
                SqlText.Require(
                    keys.SequenceEqual(["module", "requirement"]),
                    $"{FamilyRegistryPath}: {family}: fields of participant {module}");
                participants.Add(new FamilyParticipant(module, requirement, when));
            }

            SqlText.Require(participants.Count >= 2, $"{FamilyRegistryPath}: {family} needs at least two participants");
            SqlText.Require(
                participants.Any(participant => participant.Requirement == "required"),
                $"{FamilyRegistryPath}: {family} needs a required participant");
            families.Add(new FamilyDefinition(family, RequireString(entry, "title", $"{FamilyRegistryPath}: title"), RequireString(entry, "source", $"{FamilyRegistryPath}: source"), participants));
        }

        return new FamilyRegistry(families);
    }

    /// <summary>Splits the `key=value` fields of a statement or guard header and refuses unknown or duplicate fields.</summary>
    private static Dictionary<string, string> ParseFields(string header, IReadOnlyList<string> allowed, string where)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in header.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = FieldPair.Match(part);
            SqlText.Require(pair.Success && allowed.Contains(pair.Groups[1].Value, StringComparer.Ordinal), $"{where}: unknown field '{part}'");
            SqlText.Require(!fields.ContainsKey(pair.Groups[1].Value), $"{where}: duplicate {pair.Groups[1].Value}");
            fields[pair.Groups[1].Value] = pair.Groups[2].Value;
        }

        return fields;
    }

    private static int Rank(IReadOnlyList<string> order, string value) => order.ToList().IndexOf(value);

    /// <summary>Expands one `-- guard:` directive into the statement it stands for (Design model 04 section 4).</summary>
    public static (string Sql, List<PlanParameter> Params, FamilyStatementMeta Meta) ExpandGuard(string header, PhysicalManifest schema, string where)
    {
        var kindMatch = GuardKindField.Match(header);
        var kindText = kindMatch.Success ? kindMatch.Groups[1].Value : string.Empty;
        SqlText.Require(GuardKinds.Contains(kindText, StringComparer.Ordinal), $"{where}: guard kind must be one of {string.Join(", ", GuardKinds)}");
        var allowed = new List<string> { "kind", "module", "key", "table", "by" };
        allowed.AddRange(GuardFields[kindText]);
        var fields = ParseFields(header, allowed, where);

        string Need(string name)
        {
            var value = fields.GetValueOrDefault(name);
            SqlText.Require(!string.IsNullOrEmpty(value), $"{where}: a {kindText} guard needs {name}=");
            return value!;
        }

        IReadOnlyList<string> Items(string name) =>
            Need(name).Split(',').Select(item =>
            {
                SqlText.Require(item != string.Empty, $"{where}: empty item in {name}=");
                return item;
            }).ToList();

        var module = Need("module");
        SqlText.Require(
            module == PlatformModule || LockOrder.Contains(module, StringComparer.Ordinal),
            $"{where}: module {module} has no position in the SU-04 order");
        var key = Need("key");
        SqlText.Require(StableKeyPattern.IsMatch(key), $"{where}: the stable key is lower-case words joined by hyphens");
        SqlText.Require($"{module}.{key}".Length <= 128, $"{where}: the guard key is at most 128 characters");
        var tableName = Need("table");
        var table = schema.Tables.FirstOrDefault(candidate => candidate.Name == tableName)
            ?? throw new PlanRefusal($"{where}: {tableName} is not a table of the physical manifest");

        PhysicalColumnInfo Column(string name, string what, string[]? kinds = null)
        {
            var found = table.Columns.FirstOrDefault(candidate => candidate.Name == name)
                ?? throw new PlanRefusal($"{where}: {what} {name} is not a column of {tableName}");
            SqlText.Require(!ReservedWords.Contains(name), $"{where}: column {name} is a reserved SQL word, plans never quote a name");
            SqlText.Require(found.Kind != "json" && found.Kind != "proto", $"{where}: {what} {name} is a {found.Kind} column");
            if (kinds is not null)
                SqlText.Require(
                    kinds.Contains(found.Kind, StringComparer.Ordinal),
                    $"{where}: {what} {name} must be {string.Join(" or ", kinds)}, not {found.Kind}");
            return found;
        }

        var used = new HashSet<string>(StringComparer.Ordinal);
        void Once(string name)
        {
            SqlText.Require(used.Add(name), $"{where}: column {name} is used twice");
        }

        (string Sql, PlanParameter Param) Compare(string name, string what, string[]? kinds = null)
        {
            var found = Column(name, what, kinds);
            Once(name);
            var planKind = PhysicalPlanColumns.PlanKindOf(found.Kind);
            return (planKind == "int64" ? $"{name} = CAST(? AS INTEGER)" : $"{name} = ?", new PlanParameter(planKind, false));
        }

        var conditions = new List<string>();
        var parameters = new List<PlanParameter> { new("text", false) };
        void Add((string Sql, PlanParameter Param) part)
        {
            conditions.Add(part.Sql);
            parameters.Add(part.Param);
        }

        var byParts = Items("by");
        SqlText.Require(byParts.Count <= 6, $"{where}: at most 6 key columns");
        foreach (var item in byParts)
        {
            var scoped = item.StartsWith("scope:", StringComparison.Ordinal);
            var name = scoped ? item["scope:".Length..] : item;
            var part = Compare(name, "key column");
            var parameter = part.Param;
            if (scoped)
            {
                SqlText.Require(part.Param.Kind == "text", $"{where}: only a text key column can be the owner scope ({name})");
                parameter = new PlanParameter("scope", false);
            }

            conditions.Add(part.Sql);
            parameters.Add(parameter);
        }

        var byConditions = conditions.ToList();
        (string Sql, PlanParameter Param) Instant(string name, string what)
        {
            var found = Column(name, what, ["instant"]);
            Once(name);
            return (found.Name, new PlanParameter("int64", false));
        }

        string predicate;
        switch (kindText)
        {
            case "authorization":
            case "policy":
                {
                    foreach (var item in Items("match")) Add(Compare(item, "match column"));
                    if (fields.TryGetValue("fresh", out var fresh))
                    {
                        var instant = Instant(fresh, "fresh column");
                        conditions.Add($"{instant.Sql} > CAST(? AS INTEGER)");
                        parameters.Add(new PlanParameter("int64", false));
                    }

                    predicate = $"EXISTS (SELECT 1 FROM {tableName} WHERE {string.Join(" AND ", conditions)})";
                    break;
                }
            case "revision":
                {
                    var rev = Need("rev");
                    Column(rev, "revision column", ["rev"]);
                    Once(rev);
                    predicate = $"COALESCE((SELECT {rev} FROM {tableName} WHERE {string.Join(" AND ", byConditions)}), 0) = CAST(? AS INTEGER)";
                    parameters.Add(new PlanParameter("int64", false));
                    break;
                }
            case "balance":
                {
                    Add(Compare(Need("rev"), "revision column", ["rev"]));
                    foreach (var item in Items("exact")) Add(Compare(item, "exact column"));
                    predicate = $"EXISTS (SELECT 1 FROM {tableName} WHERE {string.Join(" AND ", conditions)})";
                    break;
                }
            default:
                {
                    Add(Compare(Need("holder"), "holder column", ["id", "text", "key"]));
                    Add(Compare(Need("fence"), "fence column", ["rev", "int", "int64"]));
                    var until = Instant(Need("until"), "expiry column");
                    conditions.Add($"{until.Sql} > CAST(? AS INTEGER)");
                    parameters.Add(new PlanParameter("int64", false));
                    predicate = $"EXISTS (SELECT 1 FROM {tableName} WHERE {string.Join(" AND ", conditions)})";
                    break;
                }
        }

        var sql = $"INSERT INTO {GuardTable} (command_id, guard_key, allowed)\nSELECT ?, '{module}.{key}', CASE WHEN {predicate} THEN 1 ELSE 0 END;";
        return (sql, parameters, new FamilyStatementMeta(module, "guard", kindText, key));
    }

    /// <summary>The identity of a family plan: the normalized text and every expanded statement, in order.</summary>
    public static string FamilyIdentity(string normalizedText, IReadOnlyList<string> statementSql) =>
        Sha256Hex($"{normalizedText}\n-- expanded\n{string.Join("\n", statementSql)}\n");

    /// <summary>The problems of one family plan's statement roles under the SU-04 rule (guards, then mutations, then the release).</summary>
    public static List<string> FamilyOrderProblems(IReadOnlyList<FamilyStatementMeta> metas)
    {
        var problems = new List<string>();
        for (var index = 0; index < metas.Count; index++)
        {
            var meta = metas[index];
            var where = $"statement {index + 1} ({meta.Phase} {meta.Module}.{meta.Key})";
            if (meta.Module != PlatformModule && !LockOrder.Contains(meta.Module, StringComparer.Ordinal))
                problems.Add($"{where}: module {meta.Module} has no position in the SU-04 order");
            if (ClassRank(meta) < 0)
                problems.Add($"{where}: class {meta.Class} does not belong to a {meta.Phase} statement");
            if (meta.Phase == "release" && (index != metas.Count - 1 || meta.Module != PlatformModule))
                problems.Add($"{where}: the release is the one platform statement at the very end");
            if (index == 0) continue;
            var previous = metas[index - 1];
            if (PhaseRank[meta.Phase] < PhaseRank[previous.Phase])
            {
                problems.Add($"{where}: a {meta.Phase} statement may not follow a {previous.Phase} statement (guards, then mutations, then the release)");
                continue;
            }

            if (meta.Phase != previous.Phase) continue;
            if (ModuleRank(meta) < ModuleRank(previous))
            {
                problems.Add($"{where}: module {meta.Module} may not follow module {previous.Module} (SU-04 order)");
            }
            else if (ModuleRank(meta) == ModuleRank(previous))
            {
                if (ClassRank(meta) < ClassRank(previous))
                {
                    problems.Add($"{where}: class {meta.Class} may not follow class {previous.Class} within module {meta.Module}");
                }
                else if (ClassRank(meta) == ClassRank(previous))
                {
                    var order = string.CompareOrdinal(meta.Key, previous.Key);
                    if (order < 0)
                        problems.Add($"{where}: stable key {meta.Key} may not follow {previous.Key} (ascending within a class)");
                    else if (order == 0)
                        problems.Add($"{where}: duplicate {meta.Class} key {meta.Key} in module {meta.Module}");
                }
            }
        }

        return problems;
    }

    private static int ModuleRank(FamilyStatementMeta meta)
    {
        if (meta.Module == PlatformModule) return meta.Phase == "guard" ? -1 : LockOrder.Count;
        return Rank(LockOrder, meta.Module);
    }

    private static int ClassRank(FamilyStatementMeta meta)
    {
        if (meta.Phase == "guard") return Rank(GuardKinds, meta.Class);
        if (meta.Phase == "mutation") return Rank(MutationClasses, meta.Class);
        return meta.Class == "release" ? 0 : -1;
    }

    /// <summary>Parses one plan file. A family plan (families.family.name, in storage/plans/families) carries the family context.</summary>
    public static PlanDefinition ParsePlanFile(string text, string file, FamilyParseContext? context = null)
    {
        var normalized = NormalizePlanText(text);
        var lines = normalized.Split('\n');
        var header = new Dictionary<string, string>(StringComparer.Ordinal);
        var cursor = 0;
        for (; cursor < lines.Length; cursor++)
        {
            var match = HeaderLine.Match(lines[cursor]);
            if (!match.Success) break;
            SqlText.Require(!header.ContainsKey(match.Groups[1].Value), $"{file}: duplicate header {match.Groups[1].Value}");
            header[match.Groups[1].Value] = match.Groups[2].Value;
        }

        var id = header.GetValueOrDefault("plan") ?? string.Empty;
        SqlText.Require(PlanIdPattern.IsMatch(id), $"{file}: invalid plan id");
        var segments = id.Split('.');
        string? familyId = null;
        var fileName = Path.GetFileNameWithoutExtension(file);
        if (context is not null)
        {
            SqlText.Require(segments.Length == 3 && segments[0] == FamilyOwner, $"{file}: a family plan id is {FamilyOwner}.<family>.<name>");
            familyId = segments[1];
            SqlText.Require(fileName == $"{segments[1]}.{segments[2]}", $"{file}: file name must be <family>.<name>");
            SqlText.Require(Path.GetFileName(Path.GetDirectoryName(file)) == FamilyOwner, $"{file}: a family plan lives in {FamilyDirectory}");
            SqlText.Require(
                context.Registry.Families.Any(candidate => candidate.Family == familyId),
                $"{file}: family {familyId} is not in {FamilyRegistryPath}");
        }
        else
        {
            SqlText.Require(segments[0] != FamilyOwner, $"{file}: {FamilyOwner} is reserved for family plans");
            SqlText.Require(fileName == string.Join(".", segments.Skip(1)), $"{file}: file name must match the plan id");
            SqlText.Require(Path.GetFileName(Path.GetDirectoryName(file)) == segments[0], $"{file}: directory must be the owning module");
        }

        var versionText = header.GetValueOrDefault("version");
        SqlText.Require(
            int.TryParse(versionText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var version)
            && version >= 1 && version <= 2147483647,
            $"{file}: version");
        var access = header.GetValueOrDefault("access");
        SqlText.Require(access is "read" or "write", $"{file}: access must be read or write");
        SqlText.Require(!(context is not null && access != "write"), $"{file}: a family plan is a write plan");
        var maxRows = 0;
        if (header.TryGetValue("maxRows", out var maxRowsText))
            SqlText.Require(
                int.TryParse(maxRowsText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out maxRows)
                && maxRows >= 0 && maxRows <= 200,
                $"{file}: maxRows is at most 200");
        var statements = new List<PlanStatement>();
        (string Header, List<string> Lines)? current = null;

        void Finish()
        {
            if (current is null) return;
            var where = $"{file}: statement {statements.Count + 1}";
            var allowed = context is not null
                ? new[] { "params", "returns", "module", "class", "key" }
                : new[] { "params", "returns" };
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var part in current.Value.Header.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            {
                var pair = FieldPair.Match(part);
                SqlText.Require(pair.Success && allowed.Contains(pair.Groups[1].Value, StringComparer.Ordinal), $"{where}: unknown statement field '{part}'");
                SqlText.Require(!fields.ContainsKey(pair.Groups[1].Value), $"{where}: duplicate {pair.Groups[1].Value}");
                fields[pair.Groups[1].Value] = pair.Groups[2].Value;
            }

            var sql = string.Join("\n", current.Value.Lines).Trim();
            var parameters = ParseKinds(fields.GetValueOrDefault("params") ?? string.Empty, where, true);
            var returns = fields.ContainsKey("returns") ? ParseKinds(fields["returns"], where, false) : null;
            CheckStatement(sql, where, parameters);
            FamilyStatementMeta? family = null;
            if (context is not null)
            {
                var module = fields.GetValueOrDefault("module") ?? string.Empty;
                var className = fields.GetValueOrDefault("class") ?? string.Empty;
                var key = fields.GetValueOrDefault("key") ?? string.Empty;
                SqlText.Require(
                    module != string.Empty && className != string.Empty && key != string.Empty,
                    $"{where}: a family statement names module=, class= and key=");
                SqlText.Require(StableKeyPattern.IsMatch(key), $"{where}: the stable key is lower-case words joined by hyphens");
                SqlText.Require(
                    MutationClasses.Contains(className, StringComparer.Ordinal),
                    $"{where}: a hand-written family statement is a mutation of class {string.Join(", ", MutationClasses)} (guards are the generated primitives)");
                SqlText.Require(MutationStart.IsMatch(sql), $"{where}: a family mutation is an INSERT, UPDATE or DELETE");
                family = new FamilyStatementMeta(module, "mutation", className, key);
            }

            statements.Add(new PlanStatement(sql, parameters, returns, family));
            current = null;
        }

        for (; cursor < lines.Length; cursor++)
        {
            var line = lines[cursor];
            var marker = StatementMarker.Match(line);
            var guard = GuardMarker.Match(line);
            if (marker.Success)
            {
                Finish();
                current = (marker.Groups[1].Value, new List<string>());
            }
            else if (guard.Success && context is not null)
            {
                Finish();
                var where = $"{file}: statement {statements.Count + 1}";
                var expanded = ExpandGuard(guard.Groups[1].Value, context.Schema(), where);
                CheckStatement(expanded.Sql, where, expanded.Params);
                statements.Add(new PlanStatement(expanded.Sql, expanded.Params, null, expanded.Meta));
            }
            else if (current is null && line == string.Empty && cursor == lines.Length - 1)
            {
                // The end of the file after the last guard directive: nothing follows it.
            }
            else
            {
                SqlText.Require(current is not null, $"{file}:{cursor + 1}: SQL outside a statement block");
                SqlText.Require(!line.StartsWith("--", StringComparison.Ordinal), $"{file}:{cursor + 1}: unknown comment directive");
                current!.Value.Lines.Add(line);
            }
        }

        Finish();
        if (context is not null) statements.Add(FamilyReleaseStatement);
        SqlText.Require(statements.Count >= 1 && statements.Count <= MaxStatements, $"{file}: statement count");
        if (access == "read")
        {
            SqlText.Require(statements.Count == 1, $"{file}: a read plan has exactly one statement");
            SqlText.Require(statements[0].Returns is not null, $"{file}: a read plan declares its returned columns");
            SqlText.Require(maxRows >= 1, $"{file}: a read plan declares maxRows");
            SqlText.Require(ReadStart.IsMatch(statements[0].Sql), $"{file}: a read plan is a SELECT");
        }
        else
        {
            SqlText.Require(statements.All(statement => statement.Returns is null), $"{file}: a write plan returns no rows");
            SqlText.Require(maxRows == 0, $"{file}: a write plan has no maxRows");
        }

        var tail = header.GetValueOrDefault("tail");
        var identity = context is not null
            ? FamilyIdentity(normalized, statements.Select(statement => statement.Sql).ToList())
            : Sha256Hex(normalized);
        return new PlanDefinition(id, version, access!, maxRows, statements, identity, tail, familyId);
    }

    private static List<PlanParameter> ParseKinds(string list, string where, bool allowScope)
    {
        var result = new List<PlanParameter>();
        if (list == string.Empty) return result;
        foreach (var item in list.Split(','))
        {
            var nullable = item.EndsWith('?');
            var kind = nullable ? item[..^1] : item;
            SqlText.Require(Kinds.Contains(kind, StringComparer.Ordinal), $"{where}: unknown parameter kind '{item}'");
            SqlText.Require(allowScope || kind != "scope", $"{where}: a result column cannot have kind scope");
            SqlText.Require(!(nullable && kind == "scope"), $"{where}: the owner scope is never null");
            result.Add(new PlanParameter(kind, nullable));
        }

        return result;
    }

    private static string StripLiterals(string sql) => StringLiteral.Replace(sql, "''");

    /// <summary>The checks every statement passes: one DML or SELECT statement with anonymous placeholders, wrapped exactly where its kinds require.</summary>
    private static void CheckStatement(string sql, string where, IReadOnlyList<PlanParameter> parameters)
    {
        SqlText.Require(
            sql.EndsWith(';') && !StripLiterals(sql[..^1]).Contains(';', StringComparison.Ordinal),
            $"{where}: exactly one statement");
        var stripped = StripLiterals(sql);
        SqlText.Require(!stripped.Contains("--", StringComparison.Ordinal) && !stripped.Contains("/*", StringComparison.Ordinal), $"{where}: comments are not allowed in a statement");
        SqlText.Require(!ForbiddenSql.IsMatch(stripped), $"{where}: forbidden SQL");
        SqlText.Require(StatementStart.IsMatch(stripped), $"{where}: only DML and SELECT are allowed");
        var wrapped = PlaceholderCasts(sql, where);
        SqlText.Require(wrapped.Count == parameters.Count, $"{where}: ? placeholder count differs from params");
        SqlText.Require(parameters.Count <= MaxParameters, $"{where}: too many parameters");
        for (var index = 0; index < parameters.Count; index++)
        {
            var param = parameters[index];
            var isInt64 = param.Kind == "int64";
            SqlText.Require(
                wrapped[index] == isInt64,
                $"{where}: parameter {index + 1} ({param.Kind}) must {(isInt64 ? "be" : "not be")} wrapped as CAST(? AS INTEGER)");
            SqlText.Require(!(param.Nullable && isInt64), $"{where}: a nullable int64 parameter is not supported");
        }
    }

    private static List<bool> PlaceholderCasts(string sql, string where)
    {
        var stripped = StripLiterals(sql);
        SqlText.Require(!BadPlaceholder.IsMatch(stripped), $"{where}: only anonymous ? placeholders are allowed");
        var wrapped = new List<bool>();
        for (var index = 0; index < stripped.Length; index++)
        {
            if (stripped[index] != '?') continue;
            var before = stripped[..index];
            var after = stripped[(index + 1)..];
            wrapped.Add(CastBefore.IsMatch(before) && CastAfter.IsMatch(after));
        }

        return wrapped;
    }

    /// <summary>The checks that need the whole plan and the registry: the SU-04 order, the participants and the guard keys.</summary>
    public static void AssertFamilyPlan(PlanDefinition plan, FamilyRegistry registry)
    {
        var familyId = plan.Id.Split('.')[1];
        var definition = registry.Families.FirstOrDefault(candidate => candidate.Family == familyId)
            ?? throw new PlanRefusal($"{plan.Id}: family {familyId} is not in {FamilyRegistryPath}");
        var metas = plan.Statements.Select(statement => statement.Family ?? throw new PlanRefusal($"{plan.Id}: a statement has no family role")).ToList();
        var problems = FamilyOrderProblems(metas);
        SqlText.Require(problems.Count == 0, $"{plan.Id}: {string.Join("; ", problems)}");
        SqlText.Require(metas.Any(meta => meta.Phase == "guard"), $"{plan.Id}: a family plan has at least one guard");
        SqlText.Require(metas.Any(meta => meta.Phase == "mutation"), $"{plan.Id}: a family plan has at least one mutation");
        var modules = metas.Where(meta => meta.Module != PlatformModule).Select(meta => meta.Module).Distinct(StringComparer.Ordinal).ToList();
        foreach (var module in modules)
            SqlText.Require(
                definition.Participants.Any(participant => participant.Module == module),
                $"{plan.Id}: module {module} is not a participant of family {familyId} (a participant is added only through the Architecture Owner)");
        foreach (var participant in definition.Participants)
            if (participant.Requirement == "required")
                SqlText.Require(modules.Contains(participant.Module), $"{plan.Id}: required participant {participant.Module} has no statement");
        foreach (var module in modules)
        {
            var own = metas.Where(meta => meta.Module == module).ToList();
            if (own.Any(meta => meta.Phase == "mutation"))
                SqlText.Require(
                    own.Any(meta => meta.Phase == "guard"),
                    $"{plan.Id}: module {module} writes without a guard of its own (guard every pre-read revision and authorization row, SU-04)");
        }

        var guardKeys = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < plan.Statements.Count; index++)
        {
            var statement = plan.Statements[index];
            var meta = statement.Family;
            if (meta is null) continue;
            var where = $"{plan.Id} statement {index + 1} ({meta.Module}.{meta.Key})";
            if (meta.Phase == "guard")
            {
                var guardKey = $"{meta.Module}.{meta.Key}";
                SqlText.Require(guardKeys.Add(guardKey), $"{where}: duplicate guard key");
            }

            var prefix = ModulePrefix(meta.Module);
            foreach (var table in SqlText.ReferencedTables(statement.Sql, where))
            {
                SqlText.Require(
                    table.StartsWith(prefix, StringComparison.Ordinal)
                    || (meta.Module != PlatformModule && table.StartsWith(SharedPrefix, StringComparison.Ordinal)),
                    $"{where}: table {table} is not owned by module {meta.Module} (allowed prefixes: {(meta.Module == PlatformModule ? SharedPrefix : $"{prefix}, {SharedPrefix}")})");
                SqlText.Require(!BookkeepingTables.Contains(table), $"{where}: {table} is written only by the migration runner");
                SqlText.Require(
                    table != GuardTable || meta.Phase is "guard" or "release",
                    $"{where}: only the generated guard and release statements name {GuardTable}");
            }
        }
    }

    /// <summary>The ownership rule of an owner plan: it may touch only its own tables and the shared platform tables.</summary>
    public static void AssertOwnership(PlanDefinition plan, OwnerRegistry registry)
    {
        var owner = plan.Id.Split('.')[0];
        var entry = registry.Owners.FirstOrDefault(candidate => candidate.Owner == owner)
            ?? throw new PlanRefusal($"{plan.Id}: owner {owner} is not in {OwnerRegistryPath}");
        var allowed = entry.Kind == "module" ? new[] { entry.TablePrefix, SharedPrefix } : new[] { entry.TablePrefix };
        for (var index = 0; index < plan.Statements.Count; index++)
        {
            var where = $"{plan.Id} statement {index + 1}";
            foreach (var table in SqlText.ReferencedTables(plan.Statements[index].Sql, where))
                SqlText.Require(
                    allowed.Any(prefix => table.StartsWith(prefix, StringComparison.Ordinal)),
                    $"{where}: table {table} is not owned by {owner} (allowed prefixes: {string.Join(", ", allowed)})");
        }
    }

    /// <summary>Every module write plan declares its commit tail or why it has none, and no owner statement writes a reserved table.</summary>
    public static void AssertCommitTail(PlanDefinition plan, OwnerRegistry registry)
    {
        var owner = registry.Owners.FirstOrDefault(entry => entry.Owner == plan.Id.Split('.')[0]);
        var where = $"{plan.Id}: -- tail";
        (int OwnerStart, int OwnerEnd)? range = null;
        if (plan.Tail is null)
        {
            SqlText.Require(
                !(owner?.Kind == "module" && plan.Access == "write"),
                $"{plan.Id}: a module write plan declares its commit tail ('-- tail: v1 events=N [inbox]') or '-- tail: none <reason>'");
        }
        else
        {
            SqlText.Require(plan.Access == "write", $"{where}: only a write plan declares a tail");
            range = CommitTailRules.AssertTail(plan.Id, plan.Access, plan.Statements, CommitTailRules.ParseTailHeader(plan.Tail, where));
        }

        if (owner?.Kind == "module" && plan.Access == "write")
        {
            var from = range?.OwnerStart ?? 0;
            var to = range?.OwnerEnd ?? plan.Statements.Count;
            for (var index = from; index < to; index++)
            {
                foreach (var target in SqlText.WriteTargets(plan.Statements[index].Sql, $"{plan.Id} statement {index + 1}"))
                    SqlText.Require(
                        !CommitTailRules.ReservedTables.Contains(target),
                        $"{plan.Id}: statement {index + 1} writes {target}, which only the commit tail may write");
            }
        }
    }

    /// <summary>The manifest hash: every plan's id, version and identity, sorted by id and version, hashed as one text.</summary>
    public static string ManifestHashOf(IReadOnlyList<PlanDefinition> plans)
    {
        var lines = plans
            .OrderBy(plan => plan.Id, StringComparer.Ordinal)
            .ThenBy(plan => plan.Version)
            .Select(plan => $"{plan.Id}@{plan.Version}:{plan.Sha256}");
        return Sha256Hex(string.Concat(lines.Select(line => line + "\n")));
    }

    /// <summary>Reads every plan file under the repository, checks it and returns the manifest in id and version order.</summary>
    public static PlanManifest BuildManifest(string root, string? physicalDirectory = null)
    {
        var baseDirectory = Path.Combine(root, PlanDirectory);
        var registry = ParseOwnerRegistry(File.ReadAllText(Path.Combine(root, OwnerRegistryPath)));
        var familyPath = Path.Combine(root, FamilyRegistryPath);
        var families = File.Exists(familyPath) ? ParseFamilyRegistry(File.ReadAllText(familyPath)) : new FamilyRegistry([]);
        PhysicalManifest? schema = null;
        PhysicalManifest Physical()
        {
            schema ??= PhysicalPlanColumns.Load(physicalDirectory ?? Path.Combine(root, PhysicalPlanColumns.ManifestDirectory));
            return schema;
        }

        var plans = new List<PlanDefinition>();
        var allowedRootFiles = new[] { "owners.json", "families.json", "families.expanded.json" };
        foreach (var entry in Directory.GetFileSystemEntries(baseDirectory).Order(StringComparer.Ordinal))
        {
            var name = Path.GetFileName(entry);
            if (!Directory.Exists(entry))
            {
                SqlText.Require(allowedRootFiles.Contains(name, StringComparer.Ordinal), $"{PlanDirectory}/{name}: foreign file");
                continue;
            }

            if (name == FamilyOwner)
            {
                foreach (var file in Directory.GetFiles(entry).Select(Path.GetFileName).Order(StringComparer.Ordinal))
                {
                    var fileName = file!;
                    SqlText.Require(fileName.EndsWith(".sql", StringComparison.Ordinal), $"{FamilyOwner}/{fileName}: plan files end with .sql");
                    var relative = $"{FamilyDirectory}/{fileName}";
                    var plan = ParsePlanFile(File.ReadAllText(Path.Combine(root, relative)), relative, new FamilyParseContext(families, Physical));
                    AssertFamilyPlan(plan, families);
                    plans.Add(plan);
                }

                continue;
            }

            SqlText.Require(
                registry.Owners.Any(owner => owner.Owner == name),
                $"{PlanDirectory}/{name}: the directory is not an owner in {OwnerRegistryPath}");
            foreach (var file in Directory.GetFiles(entry).Select(Path.GetFileName).Order(StringComparer.Ordinal))
            {
                var fileName = file!;
                SqlText.Require(fileName.EndsWith(".sql", StringComparison.Ordinal), $"{name}/{fileName}: plan files end with .sql");
                var relative = $"{PlanDirectory}/{name}/{fileName}";
                var plan = ParsePlanFile(File.ReadAllText(Path.Combine(root, relative)), relative);
                AssertOwnership(plan, registry);
                AssertCommitTail(plan, registry);
                plans.Add(plan);
            }
        }

        SqlText.Require(plans.Count > 0, "No storage plans found");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var plan in plans)
            SqlText.Require(seen.Add($"{plan.Id}@{plan.Version}"), $"Duplicate plan {plan.Id}@{plan.Version}");
        var ordered = plans
            .OrderBy(plan => plan.Id, StringComparer.Ordinal)
            .ThenBy(plan => plan.Version)
            .ToList();
        return new PlanManifest(ManifestHashOf(ordered), ordered, registry, families);
    }
}
