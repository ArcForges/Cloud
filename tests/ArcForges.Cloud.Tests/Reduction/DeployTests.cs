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
/// Historical D1 guard fixture coverage and the current Go deployment's D1-absence and PostgreSQL gate wiring.
/// The pre-cutover proof D1 REST/catalog, provider failure and build exclusion checks remain at Cloud
/// 9b8796eac760982d9814f371b820b736ddd945c4.
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
    public void CurrentProductionAndProofBothOmitD1BindingsInWranglerJson()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepositoryRoot, "wrangler.json")));
        var config = document.RootElement;
        Assert.Null(DeployGate.DatabaseNameFor(MigrationFiles.DeclaredDatabases(config, "production"), "production"));
        Assert.Null(DeployGate.DatabaseNameFor(MigrationFiles.DeclaredDatabases(config, "proof"), "proof"));
        AssertRefusal("ambiguous-database", () => DeployGate.DatabaseNameFor(
            [new D1Binding("DB", "a"), new D1Binding("DB", "b")], "production"));
        AssertRefusal("ambiguous-database", () => DeployGate.DatabaseNameFor([new D1Binding("OTHER", "a")], "production"));
    }

    [Fact]
    public void HistoricalProofSelectsItsReservedD1BindingAndNamesTheRunner()
    {
        // This fixture represents the proof declaration at 9b8796e, with no provider lookup.
        using var legacy = JsonDocument.Parse("""
            { "env": { "proof": { "d1_databases": [{ "binding": "DB", "database_name": "arcforges-proof-business" }] } } }
            """);
        Assert.Null(DeployGate.DatabaseNameFor(MigrationFiles.DeclaredDatabases(legacy.RootElement, "production"), "production"));
        Assert.Equal("arcforges-proof-business",
            DeployGate.DatabaseNameFor(MigrationFiles.DeclaredDatabases(legacy.RootElement, "proof"), "proof"));
        var env = Env();
        Assert.Equal("gh-42-1-deploy-proof", DeployGate.RunnerIdentity(env));
        env["GITHUB_RUN_ATTEMPT"] = "2";
        Assert.Equal("gh-42-2-deploy-proof", DeployGate.RunnerIdentity(env));
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
        var formatted = DeployGate.FormatReport(report);
        using var output = JsonDocument.Parse(formatted);
        var fields = output.RootElement;
        Assert.Equal("passed", fields.GetProperty("status").GetString());
        Assert.Equal(report.Run.Fence, fields.GetProperty("fence").GetInt64());
        Assert.Contains(fields.GetProperty("receipts").EnumerateArray(), entry => entry.GetProperty("file").GetString() == chain[1].File);
        Assert.True(fields.GetProperty("compatibility").GetProperty("canWrite").GetBoolean());
        Assert.DoesNotContain(Token, formatted, StringComparison.Ordinal);
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
    public async Task TheProofD1AbsenceFixtureRecordsNotApplicableWithoutProviderCalls()
    {
        var root = Stage();
        try
        {
            var handler = new ScriptedHandler((request, body) =>
            {
                Assert.Fail("current proof declares no D1 database");
                return Task.FromResult(ScriptedHandler.Json("{}"));
            });
            var (code, output) = await Deploy("proof", root, Env(), handler);
            Assert.Equal(0, code);
            Assert.Empty(handler.Bodies);
            Assert.Contains("not applicable", output, StringComparison.Ordinal);
            Assert.DoesNotContain("\"receipts\"", output, StringComparison.Ordinal);
            Assert.DoesNotContain(Token, output, StringComparison.Ordinal);
            Assert.Equal("not-applicable", DeployGateRecord(root, "proof").Status);
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
    public void TheGoD1AbsenceReceiptRequiresTheExactCleanCandidateAndEmptyD1Configuration()
    {
        var gate = File.ReadAllText(Path.Combine(RepositoryRoot, "eng", "migrations", "deploy.ts"));
        var verified = gate.IndexOf("const candidate = await verifyCandidate();", StringComparison.Ordinal);
        var revision = gate.IndexOf("assert.equal(candidate.revision, process.env.GITHUB_SHA);", StringComparison.Ordinal);
        var clean = gate.IndexOf("assert.equal(candidate.dirty, false);", StringComparison.Ordinal);
        var receipt = gate.IndexOf("await writeJson(", StringComparison.Ordinal);
        Assert.True(verified >= 0 && verified < revision && revision < clean && clean < receipt);
        Assert.Contains("revision: candidate.revision", gate[receipt..], StringComparison.Ordinal);
        Assert.Contains("status: \"not-applicable\"", gate[receipt..], StringComparison.Ordinal);

        var candidate = File.ReadAllText(Path.Combine(RepositoryRoot, "tooling", "project.ts"));
        Assert.Contains("assertNoD1Binding(config);", candidate, StringComparison.Ordinal);
        Assert.Contains("assertNoD1Binding(config.env?.proof);", candidate, StringComparison.Ordinal);
        var production = File.ReadAllText(Path.Combine(RepositoryRoot, "tooling", "cloudflare.ts"));
        Assert.Contains("assert.equal(record.target, target", production, StringComparison.Ordinal);
        Assert.Contains("assert.equal(record.revision, revision", production, StringComparison.Ordinal);
        Assert.Contains("assert.equal(record.status, \"not-applicable\"", production, StringComparison.Ordinal);
    }

    [Fact]
    public void ProductionAndProofRequirePostgresAfterD1AbsenceBeforePromotion()
    {
        var workflow = File.ReadAllText(Path.Combine(RepositoryRoot, ".github", "workflows", "ci.yml"));
        var jobs = Jobs(workflow);
        foreach (var (job, d1Target, postgresTarget, promotion) in new[]
        {
            ("deploy", "production", "production", "npm run deploy\n"),
            ("deploy-proof", "proof", "acceptance", "npm run deploy:proof\n"),
        })
        {
            var body = jobs[job];
            var d1 = body.IndexOf($"run: node eng/migrations/deploy.ts deploy --target {d1Target}", StringComparison.Ordinal);
            var postgres = body.IndexOf($"run: node tooling/postgres-deploy.ts migrate --target {postgresTarget}", StringComparison.Ordinal);
            var publish = body.IndexOf($"run: {promotion}", StringComparison.Ordinal);
            Assert.True(d1 >= 0 && d1 < postgres && postgres < publish, $"{job}: D1 absence and PostgreSQL gates precede promotion");
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
            var receipt = new GateRecord("production", Revision, "not-applicable", string.Empty);
            DeployGate.RequireGatePassed(receipt, "production", Revision);
            AssertRefusal("gate-failed", () => DeployGate.RequireGatePassed(receipt with { Status = "refused" }, "production", Revision));
            AssertRefusal("gate-missing", () => DeployGate.RequireGatePassed(null, "production", Revision));
            AssertRefusal("gate-mismatch", () => DeployGate.RequireGatePassed(receipt with { Target = "proof" }, "production", Revision));
            AssertRefusal("gate-mismatch", () => DeployGate.RequireGatePassed(receipt with { Revision = new string('f', 40) }, "production", Revision));
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
