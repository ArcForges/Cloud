// SPDX-License-Identifier: AGPL-3.0-only
// The deployment-time decisions of the D1 migration step (CLOUD.70; CLOUD.84 U10, S41(1)): the environment-to-database selection from
// the deployment configuration, the reading of the release migration plan, the context and identity checks, the excluded-build and
// gate refusals, and the report and secret scrubbing. The decisions are C#; the process that calls them (tools/ArcForges.Cloud.Generation)
// reads the files and the environment, and performs the database calls. Port of eng/migrations/deploy.ts.
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ArcForges.Cloud.Storage.D1.MigrationRunner;

namespace ArcForges.Cloud.Storage.D1.Deploy;

/// <summary>A refusal of the gate: nothing is promoted. The code is stable text for the job log.</summary>
public sealed class GateRefusal(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>A D1 binding as declared in the deployment configuration (wrangler.json).</summary>
public sealed record D1Binding(string? Binding, string? DatabaseName);

/// <summary>The release migration plan of a deployment.</summary>
public sealed record ReleasePlan(int Through, bool AllowContract, string Source);

/// <summary>What the step found and decided for one deployment, as the job log and the gate record report it.</summary>
public sealed record GateBefore(bool Initialized, int SchemaVersion, int ReadHorizon, int WriteHorizon, long DatabaseAhead);

public sealed record GateReport(
    ReleasePlan Plan,
    (int Highest, string Hash) Lock,
    int BuildSchemaVersion,
    GateBefore Before,
    RunResult Run,
    MigrationStatus After,
    Verdict Compatibility);

/// <summary>The inputs of the gate: the client and the catalog, the manifest's migration entry and the run identity.</summary>
public sealed record GateInput(
    IMigrationClient Client,
    IReadOnlyList<Migration> Migrations,
    IReadOnlyList<LockEntry> Lock,
    JsonElement? ManifestMigrations,
    string Runner,
    Func<long> Now,
    CompatibilityInput Compatibility,
    CancellationToken CancellationToken);

/// <summary>The gate record that promotion requires for exactly one candidate and target.</summary>
public sealed record GateRecord(string Target, string Revision, string Status, string Detail);

public static partial class DeployGate
{
    public static readonly string[] Targets = ["production", "proof"];

    [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.CultureInvariant)]
    private static partial Regex DatabaseIdPattern();

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex RevisionPattern();

    [GeneratedRegex("^[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex AccountPattern();

    /// <summary>Whether a text is a D1 database id (a lower-case UUID).</summary>
    public static bool IsDatabaseId(string text) => DatabaseIdPattern().IsMatch(text);

    /// <summary>Whether a text is a 40-hex source commit.</summary>
    public static bool IsRevision(string text) => RevisionPattern().IsMatch(text);

    /// <summary>Whether a text is a 32-hex Cloudflare account id.</summary>
    public static bool IsAccountId(string text) => AccountPattern().IsMatch(text);

    /// <summary>
    /// The business database named for a target by wrangler.json: production by the top-level d1_databases, proof by env.proof.
    /// Null when the target declares none (the production Worker binds no database yet): then there is nothing to migrate.
    /// </summary>
    public static string? DatabaseNameFor(IReadOnlyList<D1Binding>? declared, string target)
    {
        if (declared is null || declared.Count == 0) return null;
        var business = declared.Where(entry => entry.Binding == "DB").ToList();
        if (business.Count != 1)
            throw new GateRefusal("ambiguous-database", $"{target} must declare exactly one D1 binding named DB (found {business.Count})");
        var name = business[0].DatabaseName;
        if (string.IsNullOrEmpty(name)) throw new GateRefusal("ambiguous-database", $"{target} DB binding has no database_name");
        return name;
    }

    /// <summary>The database id named by the override (D1_DATABASE_ID), which must be a database id. Nothing is created.</summary>
    public static string OverrideDatabaseId(string overrideId)
    {
        if (!IsDatabaseId(overrideId)) throw new GateRefusal("bad-database-id", "D1_DATABASE_ID is not a database id");
        return overrideId;
    }

    /// <summary>The database id of an exact-name lookup: the name must match exactly once, and the id must be a database id.</summary>
    public static string SelectDatabaseId(string name, IReadOnlyList<(string Name, string? Uuid)> results)
    {
        var found = results.Where(entry => entry.Name == name).ToList();
        var id = found.Count > 0 ? found[0].Uuid : null;
        if (found.Count != 1 || id is null || !IsDatabaseId(id))
            throw new GateRefusal("database-missing", $"D1 database {name} was not found exactly once; it is provisioned before the step");
        return id;
    }

    /// <summary>
    /// The migration plan of a deployment. The candidate's release manifest may carry `migrations: { through: sequence, allowContract?: true }`;
    /// that is the only way backfill, cutover or contract migrations are applied. Without it the deployment applies expand migrations only.
    /// </summary>
    public static ReleasePlan PlanFor(JsonElement? declared, IReadOnlyList<Migration> migrations, int databaseSchemaVersion)
    {
        if (declared is null)
        {
            var through = Math.Max(databaseSchemaVersion, -1);
            while (through + 1 < migrations.Count && migrations[through + 1].Mode == MigrationMode.Expand) through++;
            return new ReleasePlan(through, false, "default");
        }

        var entry = declared.Value;
        if (entry.ValueKind != JsonValueKind.Object)
            throw new GateRefusal("bad-plan", "the manifest's migrations entry is not an object");
        var extra = entry.EnumerateObject().Select(property => property.Name)
            .Where(key => key is not ("through" or "allowContract")).ToList();
        if (extra.Count > 0) throw new GateRefusal("bad-plan", $"unknown migration plan field: {string.Join(", ", extra)}");
        if (!entry.TryGetProperty("through", out var throughValue) || throughValue.ValueKind != JsonValueKind.Number
            || !throughValue.TryGetInt64(out var throughNumber) || throughNumber < 0 || throughNumber >= migrations.Count)
            throw new GateRefusal("bad-plan", $"through must name an existing migration sequence 0..{migrations.Count - 1}");
        var allowContract = false;
        if (entry.TryGetProperty("allowContract", out var consent))
        {
            if (consent.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new GateRefusal("bad-plan", "allowContract must be a boolean");
            allowContract = consent.ValueKind == JsonValueKind.True;
        }

        var last = (int)throughNumber;
        if (!allowContract)
        {
            var contract = migrations.FirstOrDefault(item =>
                item.Sequence <= last && item.Mode == MigrationMode.Contract && item.Sequence > databaseSchemaVersion);
            if (contract is not null)
                throw new GateRefusal("contract-refused", $"{contract.File} is irreversible: the plan reaches it without allowContract");
        }

        return new ReleasePlan(last, allowContract, "manifest");
    }

    /// <summary>
    /// Order of the step: read the state; refuse a database ahead of the build or a build the horizons exclude (before anything is
    /// written); apply the plan under the lease and fence; read the state again and apply the compatible-rollback rule to the build
    /// being promoted. Any refusal or runner failure throws.
    /// </summary>
    public static async Task<GateReport> RunGateAsync(GateInput input)
    {
        var before = await MigrationEngine.StatusAsync(input.Client, input.Migrations, input.Now, input.CancellationToken).ConfigureAwait(false);
        if (before.DatabaseAhead > 0)
            throw new GateRefusal(
                "database-ahead",
                $"the database holds {before.DatabaseAhead} migration(s) this build does not contain; an older build is never promoted over a newer schema");
        var plan = PlanFor(input.ManifestMigrations, input.Migrations, before.SchemaVersion);
        if (before.Initialized && plan.Through < before.WriteHorizon)
            throw new GateRefusal("build-excluded", $"this build (schema {plan.Through}) is below the database write horizon {before.WriteHorizon}");
        var run = await MigrationEngine.ApplyPendingAsync(new RunOptions
        {
            Client = input.Client,
            Migrations = input.Migrations,
            Runner = input.Runner,
            Now = input.Now,
            Compatibility = input.Compatibility,
            StopAfter = plan.Through,
            AllowContract = plan.AllowContract,
            CancellationToken = input.CancellationToken,
        }).ConfigureAwait(false);
        var after = await MigrationEngine.StatusAsync(input.Client, input.Migrations, input.Now, input.CancellationToken).ConfigureAwait(false);
        var verdict = MigrationEngine.Compatibility(after.SchemaVersion, after.ReadHorizon, after.WriteHorizon, plan.Through);
        if (!verdict.CanWrite)
            throw new GateRefusal("build-excluded", $"the build (schema {plan.Through}) cannot use the migrated database: {verdict.Reason}");
        return new GateReport(
            plan,
            MigrationCatalog.LockIdentity(input.Lock),
            plan.Through,
            new GateBefore(before.Initialized, before.SchemaVersion, before.ReadHorizon, before.WriteHorizon, before.DatabaseAhead),
            run,
            after,
            verdict);
    }

    /// <summary>The job-log report: receipts, fence and compatibility record. It holds no credential by construction.</summary>
    public static string FormatReport(GateReport report)
    {
        var applied = new JsonArray();
        foreach (var item in report.Run.Applied)
        {
            var node = new JsonObject
            {
                ["sequence"] = item.Sequence,
                ["file"] = item.File,
                ["mode"] = item.Mode,
                ["statements"] = item.Statements,
            };
            if (item.RowsConverted is { } converted) node["rowsConverted"] = converted;
            if (item.RowsStale is { } stale) node["rowsStale"] = stale;
            if (item.Passes is { } passes) node["passes"] = passes;
            if (item.Chunks is { } chunks) node["chunks"] = chunks;
            applied.Add((JsonNode)node);
        }

        var receipts = new JsonArray();
        foreach (var receipt in report.After.Receipts)
            receipts.Add((JsonNode)new JsonObject
            {
                ["sequence"] = receipt.Sequence,
                ["file"] = receipt.File,
                ["state"] = receipt.State,
                ["statementsDone"] = receipt.StatementsDone,
                ["statementCount"] = receipt.StatementCount,
            });
        var pending = new JsonArray();
        foreach (var file in report.After.Pending) pending.Add((JsonNode?)JsonValue.Create(file));
        var document = new JsonObject
        {
            ["status"] = "passed",
            ["plan"] = new JsonObject
            {
                ["through"] = report.Plan.Through,
                ["allowContract"] = report.Plan.AllowContract,
                ["source"] = report.Plan.Source,
            },
            ["lock"] = new JsonObject { ["highest"] = report.Lock.Highest, ["hash"] = report.Lock.Hash },
            ["buildSchemaVersion"] = report.BuildSchemaVersion,
            ["before"] = new JsonObject
            {
                ["initialized"] = report.Before.Initialized,
                ["schemaVersion"] = report.Before.SchemaVersion,
                ["readHorizon"] = report.Before.ReadHorizon,
                ["writeHorizon"] = report.Before.WriteHorizon,
                ["databaseAhead"] = report.Before.DatabaseAhead,
            },
            ["fence"] = report.Run.Fence,
            ["applied"] = applied,
            ["alreadyCurrent"] = report.Run.AlreadyCurrent,
            ["schemaVersion"] = report.After.SchemaVersion,
            ["readHorizon"] = report.After.ReadHorizon,
            ["writeHorizon"] = report.After.WriteHorizon,
            ["receipts"] = receipts,
            ["pending"] = pending,
            ["compatibility"] = new JsonObject
            {
                ["canRead"] = report.Compatibility.CanRead,
                ["canWrite"] = report.Compatibility.CanWrite,
                ["reason"] = report.Compatibility.Reason,
                ["buildSchemaVersion"] = report.BuildSchemaVersion,
            },
        };
        return document.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n";
    }

    /// <summary>Removes every secret value from text before it is printed or recorded (values shorter than eight characters are not secrets here).</summary>
    public static string Scrub(string text, IEnumerable<string?> secrets)
    {
        var result = text;
        foreach (var secret in secrets)
            if (secret is { Length: >= 8 }) result = result.Replace(secret, "[redacted]", StringComparison.Ordinal);
        return result;
    }

    /// <summary>The context of the live step: only the gated jobs of ArcForges/Cloud on main, and only for the event of the target.</summary>
    public static void RequireContext(IReadOnlyDictionary<string, string?> env, string target)
    {
        string? Read(string name) => env.TryGetValue(name, out var value) ? value : null;
        if (Read("GITHUB_ACTIONS") != "true")
            throw new GateRefusal("context", "the migration step runs only in the gated deployment jobs");
        if (Read("GITHUB_REPOSITORY") != "ArcForges/Cloud")
            throw new GateRefusal("context", "the migration step runs only in ArcForges/Cloud");
        if (Read("GITHUB_REF") != "refs/heads/main")
            throw new GateRefusal("context", "the migration step runs only on main");
        var expected = target == "production" ? "push" : "workflow_dispatch";
        if (Read("GITHUB_EVENT_NAME") != expected)
            throw new GateRefusal("context", $"the {target} migration step runs only on {expected}");
    }

    /// <summary>The runner identity of the job: the run, its attempt and the job, so a retry is a different migrator.</summary>
    public static string RunnerIdentity(IReadOnlyDictionary<string, string?> env)
    {
        string Read(string name, string fallback) => env.TryGetValue(name, out var value) && value is not null ? value : fallback;
        return $"gh-{Read("GITHUB_RUN_ID", "local")}-{Read("GITHUB_RUN_ATTEMPT", "1")}-{Read("GITHUB_JOB", "job")}";
    }

    /// <summary>Whether a promotion may proceed on this gate record: a passed or not-applicable gate for exactly this target and revision.</summary>
    public static void RequireGatePassed(GateRecord? record, string target, string revision)
    {
        if (record is null) throw new GateRefusal("gate-missing", "the migration step did not run; nothing is promoted");
        if (record.Target != target) throw new GateRefusal("gate-mismatch", "the gate record is for another target");
        if (record.Revision != revision) throw new GateRefusal("gate-mismatch", "the gate record is for another revision");
        if (record.Status is not ("passed" or "not-applicable"))
            throw new GateRefusal("gate-failed", "the migration step did not pass; nothing is promoted");
    }
}
