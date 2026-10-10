// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ArcForges.Cloud.Storage.D1.Deploy;
using ArcForges.Cloud.Storage.D1.MigrationRunner;
using ArcForges.Cloud.Tools.Generation.Migrations;
using Xunit;
using static ArcForges.Cloud.Tests.Reduction.MigrationTestSupport;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>
/// CLOUD.84 U10: one-for-one C# replacement of tests/worker/d1-migration-deploy.test.ts (16 test blocks). The deployment decisions run in
/// ArcForges.Cloud.Storage.D1.Deploy and the step runs through MigrateCommand.DeployAsync, against the SQLite batch oracle behind a fake
/// Cloudflare endpoint (the same oracle backs both). SQLite is not D1 and a fake endpoint is not Cloudflare: the proof-environment run is a
/// separate, recorded live check.
/// </summary>
public sealed class DeployTests
{
    private const string Token = "cf-test-token-0123456789abcdef";
    private const string Account = "0123456789abcdef0123456789abcdef";
    private const string DatabaseId = "11111111-2222-3333-4444-555555555555";
    private const string Revision = "0123456789abcdef0123456789abcdef01234567";

    private static readonly string RepositoryRoot = T.RepoRoot().FullName;

    private static List<Migration> Chain() =>
    [
        Baseline()[0],
        Synthetic(1, "scratch", MigrationMode.Expand, Scratch),
        Synthetic(2, "scratch", MigrationMode.Backfill, BackfillBody),
        Synthetic(3, "scratch", MigrationMode.Cutover, "UPDATE \"scratch_item\" SET \"rev\" = \"rev\" WHERE 0;", " requires=2 readHorizon=1 writeHorizon=3"),
        Synthetic(4, "scratch", MigrationMode.Contract, "ALTER TABLE \"scratch_item\" DROP COLUMN \"legacy\";", " after=3 soak=3600"),
    ];

    private static JsonElement? Plan(string? json) => json is null ? null : JsonDocument.Parse(json).RootElement.Clone();

    private static GateInput Gate(IMigrationClient client, JsonElement? manifest, TestClock time, IReadOnlyList<Migration>? migrations = null) => new(
        client,
        migrations ?? Chain(),
        MigrationFiles.ReadLock(MigrationsDirectory),
        manifest,
        "gh-1-1-deploy",
        time.Read,
        new CompatibilityInput(Revision, new string('p', 8), "abi-1", "net10.0"),
        TestContext.Current.CancellationToken);

    private static string Rows(IReadOnlyList<IReadOnlyList<string?>> rows) => string.Join(";", rows.Select(row => string.Join(",", row)));

    private static void AssertRefusal(string code, Action action)
    {
        var refusal = Assert.Throws<GateRefusal>(action);
        Assert.Equal(code, refusal.Code);
    }

    private static async Task AssertRefusalAsync(string code, Func<Task> action)
    {
        var refusal = await Assert.ThrowsAsync<GateRefusal>(action);
        Assert.Equal(code, refusal.Code);
    }

    /// <summary>A fake Cloudflare: the database lookup and the D1 query endpoint, the latter backed by the SQLite batch oracle.</summary>
    private sealed class FakeCloudflare(SqliteBatchOracle client, string databaseName = "arcforges-proof-business", string? failBatchWith = null) : HttpMessageHandler
    {
        public List<(string Url, string? Authorization)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            Requests.Add((url, request.Headers.Authorization?.ToString()));
            if (url.Contains("/d1/database?", StringComparison.Ordinal))
                return ScriptedHandler.Json($$"""{"success": true, "result": [{"uuid": "{{DatabaseId}}", "name": "{{databaseName}}"}]}""");
            Assert.EndsWith($"/d1/database/{DatabaseId}/query", url, StringComparison.Ordinal);
            if (failBatchWith is not null)
                return ScriptedHandler.Json(new JsonObject { ["success"] = false, ["errors"] = new JsonArray(new JsonObject { ["message"] = failBatchWith }) }.ToJsonString(), 500);
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!;
            var statements = body["batch"]!.AsArray().Select(item => new MigrationStatement(
                item!["sql"]!.GetValue<string>(),
                item["params"]!.AsArray().Select(value => value is null ? null : value.GetValueKind() == JsonValueKind.Number ? (object)value.GetValue<long>() : value.GetValue<string>()).ToList())).ToList();
            try
            {
                var results = await client.BatchAsync(statements, cancellationToken);
                var array = new JsonArray();
                foreach (var result in results)
                {
                    var rows = new JsonArray();
                    foreach (var row in result.Rows)
                    {
                        var cells = new JsonObject();
                        for (var index = 0; index < row.Count; index++) cells[$"c{index}"] = row[index] is null ? null : JsonValue.Create(row[index]);
                        rows.Add((JsonNode)cells);
                    }

                    array.Add((JsonNode)new JsonObject { ["results"] = rows, ["meta"] = new JsonObject { ["changes"] = result.Changes } });
                }

                return ScriptedHandler.Json(new JsonObject { ["success"] = true, ["result"] = array }.ToJsonString());
            }
            catch (MigrationClientException error)
            {
                return ScriptedHandler.Json(new JsonObject { ["success"] = false, ["errors"] = new JsonArray(new JsonObject { ["message"] = error.Message }) }.ToJsonString(), 400);
            }
        }
    }

    /// <summary>A staged root: a copy of the migrations, the candidate manifest and the deployment configuration.</summary>
    private static string Stage(string? manifestMigrations = null)
    {
        var root = CopyCatalogRoot();
        Directory.CreateDirectory(Path.Combine(root, "artifacts", "candidate"));
        var manifest = manifestMigrations is null
            ? $"{{\"revision\":\"{Revision}\"}}"
            : $"{{\"revision\":\"{Revision}\",\"migrations\":{manifestMigrations}}}";
        File.WriteAllText(Path.Combine(root, "artifacts", "candidate", "manifest.json"), manifest);
        File.Copy(Path.Combine(RepositoryRoot, "wrangler.json"), Path.Combine(root, "wrangler.json"));
        return root;
    }

    private static Dictionary<string, string?> Env(string job = "deploy-proof", string @event = "workflow_dispatch") => new(StringComparer.Ordinal)
    {
        ["GITHUB_ACTIONS"] = "true",
        ["GITHUB_REPOSITORY"] = "ArcForges/Cloud",
        ["GITHUB_REF"] = "refs/heads/main",
        ["GITHUB_EVENT_NAME"] = @event,
        ["GITHUB_SHA"] = Revision,
        ["GITHUB_RUN_ID"] = "42",
        ["GITHUB_RUN_ATTEMPT"] = "1",
        ["GITHUB_JOB"] = job,
        ["CLOUDFLARE_ACCOUNT_ID"] = Account,
        ["CLOUDFLARE_API_TOKEN"] = Token,
    };

    private static async Task<(int Code, string Output)> Deploy(string target, string root, IReadOnlyDictionary<string, string?> env, HttpMessageHandler handler, TestClock? time = null)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var context = new MigrateContext(root, env, output, error, handler, (time ?? new TestClock()).Read);
        var code = await MigrateCommand.DeployAsync(target, context);
        return (code, output.ToString());
    }

    [Fact]
    public void ProductionDeclaresNoBusinessDatabaseAndProofNamesItsReservedOneFromWranglerJson()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepositoryRoot, "wrangler.json")));
        var config = document.RootElement;
        Assert.Null(DeployGate.DatabaseNameFor(MigrationFiles.DeclaredDatabases(config, "production"), "production"));
        Assert.Equal("arcforges-proof-business", DeployGate.DatabaseNameFor(MigrationFiles.DeclaredDatabases(config, "proof"), "proof"));
        AssertRefusal("ambiguous-database", () => DeployGate.DatabaseNameFor(
            [new D1Binding("DB", "a"), new D1Binding("DB", "b")], "production"));
        AssertRefusal("ambiguous-database", () => DeployGate.DatabaseNameFor([new D1Binding("OTHER", "a")], "production"));
    }

    [Fact]
    public async Task TheDatabaseIdComesFromAnExactNameLookupAMissingDuplicatedOrFailedLookupRefusesAndNothingIsCreated()
    {
        const string name = "arcforges-proof-business";
        Assert.Equal(DatabaseId, DeployGate.SelectDatabaseId(name, [(name, DatabaseId), ("other", "x")]));
        AssertRefusal("database-missing", () => DeployGate.SelectDatabaseId(name, []));
        AssertRefusal("database-missing", () => DeployGate.SelectDatabaseId(name, [(name, DatabaseId), (name, DatabaseId.Replace("1", "2", StringComparison.Ordinal))]));
        AssertRefusal("bad-database-id", () => DeployGate.OverrideDatabaseId("not-an-id"));

        var methods = new List<string>();
        var handler = new ScriptedHandler((request, body) =>
        {
            methods.Add(request.Method.Method);
            return Task.FromResult(ScriptedHandler.Json($$"""{"success": true, "result": [{"uuid": "{{DatabaseId}}", "name": "{{name}}"}]}"""));
        });
        var found = await new D1RestClient(Account, string.Empty, Token, handler).LookupDatabasesAsync(name, TestContext.Current.CancellationToken);
        Assert.Equal(200, found.Status);
        Assert.Equal(DatabaseId, DeployGate.SelectDatabaseId(name, found.Results!));
        Assert.Equal(new[] { "GET" }, methods.ToArray());

        var failed = await new D1RestClient(Account, string.Empty, Token, new ScriptedHandler((request, body) =>
            Task.FromResult(ScriptedHandler.Json("""{"success": false}""", 500)))).LookupDatabasesAsync(name, TestContext.Current.CancellationToken);
        Assert.Null(failed.Results);
    }

    [Fact]
    public async Task WithoutAManifestPlanOnlyExpandMigrationsAreAppliedAndTheStepStopsBeforeBackfillCutoverAndContract()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var chain = Chain();
        var report = await DeployGate.RunGateAsync(Gate(client, null, time));
        Assert.Equal("default", report.Plan.Source);
        Assert.Equal(1, report.Plan.Through);
        Assert.Equal(new[] { "expand" }, report.Run.Applied.Select(entry => entry.Mode).ToArray());
        Assert.Equal(1, report.After.SchemaVersion);
        Assert.Equal(new[] { chain[2].File, chain[3].File, chain[4].File }, report.After.Pending.ToArray());
        Assert.True(report.Compatibility.CanWrite);
        // A second deployment of the same release has nothing to do.
        var again = await DeployGate.RunGateAsync(Gate(client, null, time));
        Assert.True(again.Run.AlreadyCurrent);
    }

    [Fact]
    public async Task TheManifestNamesTheBackfillAndTheCutoverAContractNeedsConsentAndTheSoak()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var cutover = await DeployGate.RunGateAsync(Gate(client, Plan("{\"through\":3}"), time));
        Assert.Equal(new[] { "expand", "backfill", "cutover" }, cutover.Run.Applied.Select(entry => entry.Mode).ToArray());
        Assert.Equal(3, cutover.After.WriteHorizon);
        // The plan that reaches the contract without consent is refused before the database is touched.
        var before = Rows(client.Query("SELECT schema_version, read_horizon, write_horizon FROM platform_schema_state"));
        await AssertRefusalAsync("contract-refused", () => DeployGate.RunGateAsync(Gate(client, Plan("{\"through\":4}"), time)));
        Assert.Equal(before, Rows(client.Query("SELECT schema_version, read_horizon, write_horizon FROM platform_schema_state")));
        // With consent the runner still waits for the soak that follows the cutover.
        var soak = await Assert.ThrowsAsync<MigrationError>(() => DeployGate.RunGateAsync(Gate(client, Plan("{\"through\":4,\"allowContract\":true}"), time)));
        Assert.Equal("contract-refused", soak.Code);
        Assert.Matches("soak", soak.Message);
        time.Advance(3_600_000 + 1);
        var done = await DeployGate.RunGateAsync(Gate(client, Plan("{\"through\":4,\"allowContract\":true}"), time));
        Assert.Equal(4, done.After.SchemaVersion);
        Assert.True(done.Plan.AllowContract);
    }

    [Fact]
    public void AMalformedOrUnknownPlanIsRefused()
    {
        void Bad(string json) => AssertRefusal("bad-plan", () => DeployGate.PlanFor(Plan(json), Chain(), -1));
        Bad("\"x\"");
        Bad("{\"through\":1.5}");
        Bad("{\"through\":99}");
        Bad("{\"through\":-1}");
        Bad("{\"through\":1,\"allowContract\":\"yes\"}");
        Bad("{\"through\":1,\"extra\":true}");
        Assert.Equal("manifest", DeployGate.PlanFor(Plan("{\"through\":1}"), Chain(), -1).Source);
    }

    [Fact]
    public async Task ABuildExcludedByTheHorizonsIsRefusedBeforeAnythingIsWrittenAndADatabaseAheadOfTheBuildIsRefused()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        await DeployGate.RunGateAsync(Gate(client, Plan("{\"through\":3}"), time));
        var before = Rows(client.Query("SELECT * FROM platform_schema_state"));
        // The build of schema 2 predates the cutover: its write horizon (3) excludes it.
        await AssertRefusalAsync("build-excluded", () => DeployGate.RunGateAsync(Gate(client, Plan("{\"through\":2}"), time)));
        Assert.Equal(before, Rows(client.Query("SELECT * FROM platform_schema_state")));
        // The shorter catalog of an older release finds receipts it does not contain.
        await AssertRefusalAsync("database-ahead", () => DeployGate.RunGateAsync(Gate(client, null, time, Chain().Take(2).ToList())));
        Assert.Equal(before, Rows(client.Query("SELECT * FROM platform_schema_state")));
    }

    [Fact]
    public async Task TheProofStepMigratesTheRealCatalogThroughTheRestClientPrintsReceiptsAndTheCompatibilityRecordAndNoSecret()
    {
        using var client = new SqliteBatchOracle();
        var fake = new FakeCloudflare(client);
        var root = Stage();
        try
        {
            var (code, output) = await Deploy("proof", root, Env(), fake);
            Assert.Equal(0, code);
            Assert.Matches("\"status\": \"passed\"", output);
            Assert.Matches("\"fence\": 1", output);
            Assert.Contains("\"receipts\"", output, StringComparison.Ordinal);
            Assert.Contains("\"compatibility\"", output, StringComparison.Ordinal);
            var last = Baseline()[^1].File;
            Assert.Contains(last, output, StringComparison.Ordinal);
            Assert.DoesNotContain(Token, output, StringComparison.Ordinal);
            Assert.All(fake.Requests, entry => Assert.Equal($"Bearer {Token}", entry.Authorization));
            Assert.DoesNotContain(fake.Requests, entry => entry.Url.Contains(Token, StringComparison.Ordinal));
            Assert.Equal("passed", DeployGateRecord(root, "proof").Status);
            // The runner identity names the run, and its lease was released at the end.
            Assert.Null(client.Query("SELECT lease_holder FROM platform_schema_state")[0][0]);
            Assert.Equal("gh-42-1-deploy-proof", client.Query("SELECT runner FROM platform_migration_receipt ORDER BY sequence LIMIT 1")[0][0]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static (string Status, string Detail) DeployGateRecord(string root, string target)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "artifacts", $"migration-gate-{target}.json")));
        return (document.RootElement.GetProperty("status").GetString()!, document.RootElement.GetProperty("detail").GetString()!);
    }

    [Fact]
    public async Task AFailingMigrationStepStopsPromotionWithExitCode1ARefusedGateRecordAndNoPromotionWithoutAPassedRecord()
    {
        using var client = new SqliteBatchOracle();
        var fake = new FakeCloudflare(client, failBatchWith: $"permission denied for {Token}");
        var root = Stage();
        try
        {
            var (code, output) = await Deploy("proof", root, Env(), fake);
            Assert.Equal(1, code);
            Assert.Contains("REFUSED", output, StringComparison.Ordinal);
            Assert.Contains("Nothing is promoted", output, StringComparison.Ordinal);
            Assert.DoesNotContain(Token, output, StringComparison.Ordinal);
            Assert.Equal("refused", DeployGateRecord(root, "proof").Status);
            AssertRefusal("gate-failed", () => DeployGate.RequireGatePassed(new GateRecord("proof", Revision, "refused", "failed"), "proof", Revision));
            // A missing record, a record of another revision and a record of another target never allow promotion.
            AssertRefusal("gate-missing", () => DeployGate.RequireGatePassed(null, "proof", Revision));
            AssertRefusal("gate-mismatch", () => DeployGate.RequireGatePassed(new GateRecord("proof", "f".PadRight(40, 'f'), "passed", string.Empty), "proof", Revision));
            AssertRefusal("gate-mismatch", () => DeployGate.RequireGatePassed(new GateRecord("proof", Revision, "passed", string.Empty), "production", Revision));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ABuildExcludedOrAContractWithoutConsentFailsTheStepAndStopsPromotion()
    {
        using var client = new SqliteBatchOracle();
        // The database is past the cutover of a later catalog; this release's catalog is the real baseline.
        await MigrationEngine.ApplyPendingAsync(Options(client, Chain(), "earlier", new TestClock(), stopAfter: 3));
        var root = Stage();
        try
        {
            var (code, output) = await Deploy("proof", root, Env(), new FakeCloudflare(client));
            Assert.Equal(1, code);
            Assert.Contains("REFUSED", output, StringComparison.Ordinal);
            AssertRefusal("gate-failed", () => DeployGate.RequireGatePassed(new GateRecord("proof", Revision, DeployGateRecord(root, "proof").Status, string.Empty), "proof", Revision));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ProductionDeclaresNoDatabaseTheStepReportsNotApplicableAndRecordsItWithNoNetworkCall()
    {
        var root = Stage();
        try
        {
            var env = Env("deploy", "push");
            var handler = new ScriptedHandler((request, body) =>
            {
                Assert.Fail("no network call is expected for a target without a database");
                return Task.FromResult(ScriptedHandler.Json("{}"));
            });
            var (code, output) = await Deploy("production", root, env, handler);
            Assert.Equal(0, code);
            Assert.Empty(handler.Bodies);
            Assert.Matches("not applicable", output);
            Assert.Equal("not-applicable", DeployGateRecord(root, "production").Status);
            AssertRefusal("gate-failed", () => DeployGate.RequireGatePassed(new GateRecord("production", Revision, "refused", string.Empty), "production", Revision));
            DeployGate.RequireGatePassed(new GateRecord("production", Revision, "not-applicable", string.Empty), "production", Revision);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AMissingTokenRefusesBeforeTheTargetIsSelectedSoATargetWithoutADatabaseIsNeverReportedNotApplicable()
    {
        // S42(3): the TypeScript order is kept. Context, account and token presence are checked first, then the candidate manifest,
        // then target selection. A missing secret therefore refuses even for a target that declares no database, with no network call
        // and no not-applicable record. The token-present not-applicable path is pinned by ProductionDeclaresNoDatabase...NoNetworkCall.
        var root = Stage();
        try
        {
            var env = Env("deploy", "push");
            env["CLOUDFLARE_API_TOKEN"] = string.Empty;
            var handler = new ScriptedHandler((request, body) =>
            {
                Assert.Fail("no network call is expected when the token is missing");
                return Task.FromResult(ScriptedHandler.Json("{}"));
            });
            var (code, output) = await Deploy("production", root, env, handler);
            Assert.Equal(1, code);
            Assert.Empty(handler.Bodies);
            Assert.Matches("REFUSED \\(context\\)", output);
            Assert.DoesNotMatch("not applicable", output);
            Assert.Equal("refused", DeployGateRecord(root, "production").Status);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task TheLiveStepRefusesAPullRequestAForkAnotherBranchAnotherRepositoryAndACandidateOfAnotherCommit()
    {
        var root = Stage();
        try
        {
            var baseEnv = Env();
            Dictionary<string, string?> With(params (string Key, string? Value)[] changes)
            {
                var copy = new Dictionary<string, string?>(baseEnv, StringComparer.Ordinal);
                foreach (var (key, value) in changes) copy[key] = value;
                return copy;
            }

            void Refused(Dictionary<string, string?> env, string target = "proof") =>
                AssertRefusal("context", () => DeployGate.RequireContext(env, target));
            Refused(With(("GITHUB_EVENT_NAME", "pull_request")));
            Refused(With(("GITHUB_EVENT_NAME", "pull_request_target")));
            Refused(With(("GITHUB_REPOSITORY", "someone/Cloud")));
            Refused(With(("GITHUB_REF", "refs/pull/7/merge")));
            Refused(With(("GITHUB_REF", "refs/heads/feature")));
            Refused(With(("GITHUB_ACTIONS", null)));
            Refused(With(("GITHUB_EVENT_NAME", "workflow_dispatch")), "production");
            Refused(With(("GITHUB_EVENT_NAME", "push")), "proof");

            foreach (var changes in new[]
            {
                With(("GITHUB_EVENT_NAME", "pull_request")),
                With(("CLOUDFLARE_API_TOKEN", string.Empty)),
                With(("GITHUB_SHA", new string('e', 40))),
                With(("CLOUDFLARE_ACCOUNT_ID", "nope")),
            })
            {
                var calls = new List<string>();
                var handler = new ScriptedHandler((request, body) =>
                {
                    calls.Add(request.RequestUri!.ToString());
                    return Task.FromResult(ScriptedHandler.Json("{}"));
                });
                var (code, output) = await Deploy("proof", root, changes, handler);
                Assert.Equal(1, code);
                Assert.Empty(calls);
                Assert.DoesNotContain(Token, output, StringComparison.Ordinal);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ScrubRemovesASecretWhereverItAppearsAndIgnoresEmptyValues()
    {
        Assert.Equal("a [redacted] b [redacted]", DeployGate.Scrub($"a {Token} b {Token}", [Token, null, string.Empty]));
    }

    [Fact]
    public async Task TheDryRunAppliesTheRealCatalogToAnEmptyDatabaseWithTheSameGatedFlow()
    {
        using var client = new SqliteBatchOracle();
        var report = await DeployGate.RunGateAsync(Gate(client, null, new TestClock(), Baseline()));
        Assert.Equal(Baseline().Count - 1, report.After.SchemaVersion);
        Assert.Equal("default", report.Plan.Source);
        var text = DeployGate.FormatReport(report);
        Assert.Contains("\"applied\"", text, StringComparison.Ordinal);
        Assert.True(JsonNode.Parse(text)!["compatibility"]!["canWrite"]!.GetValue<bool>());
    }

    private static Dictionary<string, string> Jobs(string workflow)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var afterJobs = Regex.Split(workflow, "^jobs:\\n", RegexOptions.Multiline)[1];
        var parts = Regex.Split(afterJobs, "^ {2}([a-z][a-z-]*):\\n", RegexOptions.Multiline);
        for (var index = 1; index + 1 < parts.Length; index += 2) result[parts[index]] = parts[index + 1];
        return result;
    }

    [Fact]
    public void TheMigrationStepIsInExactlyTheTwoGatedDeploymentJobsBeforePromotionAndCannotBeSkippedByAFailure()
    {
        var workflow = File.ReadAllText(Path.Combine(RepositoryRoot, ".github", "workflows", "ci.yml"));
        var all = Jobs(workflow);
        foreach (var (name, promotion, target) in new[] { ("deploy", "npm run deploy\n", "production"), ("deploy-proof", "npm run deploy:proof\n", "proof") })
        {
            var job = all[name];
            var step = $"run: node eng/migrations/deploy.ts deploy --target {target}";
            Assert.Contains(step, job, StringComparison.Ordinal);
            Assert.True(job.IndexOf(step, StringComparison.Ordinal) < job.IndexOf($"run: {promotion}", StringComparison.Ordinal), $"{name}: the migration step runs before promotion");
            // A step that follows a failed step does not run unless it says so; neither the migration step nor the promotion may.
            var start = Math.Max(0, job.IndexOf(step, StringComparison.Ordinal) - 400);
            var end = Math.Min(job.Length, job.IndexOf($"run: {promotion}", StringComparison.Ordinal) + 200);
            var between = job[start..end];
            Assert.False(Regex.IsMatch(between, "continue-on-error|if:\\s*(always|failure|\\$\\{\\{ ?always)"), $"{name}: no escape around the migration step");
        }

        Assert.Equal(2, Regex.Matches(workflow, "eng/migrations/deploy\\.ts").Count);
    }

    [Fact]
    public void PullRequestJobsHoldNoSecretAndNoMigrationStepAndGatedJobsRunOnMainOnly()
    {
        var workflow = File.ReadAllText(Path.Combine(RepositoryRoot, ".github", "workflows", "ci.yml"));
        var all = Jobs(workflow);
        var gated = new HashSet<string>(StringComparer.Ordinal) { "deploy", "deploy-proof", "proof-access" };
        foreach (var (name, body) in all)
        {
            if (gated.Contains(name)) continue;
            Assert.False(Regex.IsMatch(body, "secrets\\.|CLOUDFLARE_API_TOKEN|migrations/deploy"), $"{name} holds no secret or migration step");
        }

        foreach (var name in gated)
        {
            var job = all[name];
            Assert.Contains("environment: cloudflare", job, StringComparison.Ordinal);
            Assert.Contains("github.ref == 'refs/heads/main'", job, StringComparison.Ordinal);
            Assert.False(Regex.IsMatch(job.Split("steps:")[0], "pull_request"), $"{name} is not a pull-request job");
        }

        Assert.Matches("(?m)^permissions:\\n {2}contents: read", workflow);
    }

    [Fact]
    public void ProductionPromotionIsAlsoCodeGatedTheDeploymentScriptRequiresTheGateRecordBeforeItPushesAnything()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "tooling", "cloudflare.ts"));
        var gateAt = source.IndexOf("requireGatePassed(\"production\"", StringComparison.Ordinal);
        Assert.True(gateAt > 0);
        Assert.True(gateAt < source.IndexOf("\"containers\", \"push\"", StringComparison.Ordinal));
        Assert.True(gateAt < source.IndexOf("wrangler,\n    \"deploy\"", StringComparison.Ordinal));
    }
}
