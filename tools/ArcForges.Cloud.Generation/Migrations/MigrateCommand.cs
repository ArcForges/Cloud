// SPDX-License-Identifier: AGPL-3.0-only
// The `migrate` command of the generation tool (CLOUD.84 U9, U10, S41(1)): the catalog and lock commands of the integration owner, the
// live status, compatibility and apply commands, and the gated deploy step that the deployment jobs run through the sealed binary. The
// migration decisions are the C# rules of src/ArcForges.Cloud.Storage.D1 (MigrationRunner and Deploy); this file reads the files and
// the environment, calls the database and writes the output. The bearer secret is read from the environment only and never printed.
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Cloud.Storage.D1.Deploy;
using ArcForges.Cloud.Storage.D1.MigrationRunner;

namespace ArcForges.Cloud.Tools.Generation.Migrations;

/// <summary>What the command reads and writes: the repository root, the environment, the two output streams and test seams.</summary>
public sealed record MigrateContext(
    string Root,
    IReadOnlyDictionary<string, string?> Env,
    TextWriter Out,
    TextWriter Error,
    HttpMessageHandler? Handler = null,
    Func<long>? Now = null);

public static class MigrateCommand
{
    private const string Usage =
        "usage: migrate check [--base <ref>] | lock | assign [file ...] | plan | status | compat | apply [--stop-after N] [--allow-contract] | deploy --target production|proof";

    public static async Task<int> RunAsync(IReadOnlyList<string> args, MigrateContext context)
    {
        var command = args.Count > 0 ? args[0] : string.Empty;
        var rest = args.Skip(1).ToList();
        var directory = Path.Combine(context.Root, MigrationFiles.MigrationsPath);
        try
        {
            switch (command)
            {
                case "check":
                    return Check(context, directory, Flag(rest, "--base"));
                case "lock":
                    return Lock(context, directory);
                case "assign":
                    return Assign(context, directory, rest);
                case "plan":
                    return Plan(context, directory);
                case "status":
                case "compat":
                case "apply":
                    return await LiveAsync(command, rest, context, directory).ConfigureAwait(false);
                case "deploy":
                    {
                        var target = Flag(rest, "--target");
                        if (target is not ("production" or "proof"))
                        {
                            context.Error.WriteLine("usage: ArcForges.Cloud.Generation migrate deploy --target production|proof");
                            return 2;
                        }

                        return await DeployAsync(target, context).ConfigureAwait(false);
                    }
                default:
                    context.Error.WriteLine(Usage);
                    return 2;
            }
        }
        catch (MigrationError error)
        {
            context.Error.WriteLine($"{error.Message}");
            return 1;
        }
    }

    /// <summary>The value after a flag, or null when the flag is absent.</summary>
    public static string? Flag(IReadOnlyList<string> args, string name)
    {
        var at = args.ToList().IndexOf(name);
        return at >= 0 && at + 1 < args.Count ? args[at + 1] : null;
    }

    private static int Check(MigrateContext context, string directory, string? baseRef)
    {
        var files = MigrationFiles.ReadDirectory(directory);
        var locked = MigrationFiles.ReadLock(directory);
        var catalog = MigrationCatalog.Load(files, locked);
        var pending = MigrationFiles.ReadPending(directory);
        foreach (var file in pending) MigrationCatalog.CheckPendingFile(file.Name, file.Text);
        if (baseRef is not null)
        {
            var relative = Path.GetRelativePath(context.Root, Path.Combine(directory, MigrationCatalog.LockFileName)).Replace('\\', '/');
            string baseText;
            try
            {
                baseText = GitShow(context.Root, $"{baseRef}:{relative}");
            }
            catch (InvalidOperationException)
            {
                context.Error.WriteLine($"the lock does not exist at {baseRef}; nothing to compare");
                baseText = "{\"schemaVersion\":1,\"migrations\":[]}";
            }

            var problems = MigrationCatalog.AppendOnlyProblems(MigrationFiles.ParseLock(baseText), locked);
            if (problems.Count > 0)
            {
                foreach (var problem in problems) context.Error.WriteLine(problem);
                return 1;
            }
        }

        context.Out.WriteLine($"migrations ok: {catalog.Count} numbered, {pending.Count} pending");
        return 0;
    }

    private static string GitShow(string root, string spec)
    {
        var info = new ProcessStartInfo("git")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = root,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
        };
        info.ArgumentList.Add("show");
        info.ArgumentList.Add(spec);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("git could not be started");
        var text = process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) throw new InvalidOperationException("git show failed");
        return text;
    }

    private static int Lock(MigrateContext context, string directory)
    {
        var files = MigrationFiles.ReadDirectory(directory);
        var entries = MigrationCatalog.LockNumbered(MigrationFiles.ReadLock(directory), files);
        MigrationFiles.WriteLock(directory, entries);
        MigrationCatalog.Load(files, entries);
        context.Out.WriteLine($"locked {entries.Count} migrations");
        return 0;
    }

    private static int Assign(MigrateContext context, string directory, IReadOnlyList<string> rest)
    {
        var pending = rest.Count > 0
            ? rest.ToList()
            : MigrationFiles.ReadPending(directory).Select(file => file.Name).ToList();
        var assigned = new List<string>();
        foreach (var file in pending)
        {
            var module = MigrationSql.ParsePendingModule(file)
                ?? throw new MigrationError("catalog", $"pending migration {file} does not match <module>__<slug>.sql");
            var source = Path.Combine(directory, MigrationFiles.PendingDirectory, file);
            if (!File.Exists(source)) throw new MigrationError("catalog", $"pending migration {file} does not exist");
            var header = MigrationSql.ParseHeader(MigrationFiles.ReadText(source));
            if (header.Module != module) throw new MigrationError("catalog", $"{file}: header module differs from the file name");
            var existing = Directory.GetFiles(directory)
                .Select(Path.GetFileName)
                .Count(name => name is not null && MigrationSql.ParseNumberedFileName(name) is not null);
            var name = MigrationCatalog.NumberedName(existing, file);
            File.Move(source, Path.Combine(directory, name));
            assigned.Add(name);
        }

        if (assigned.Count > 0)
        {
            var files = MigrationFiles.ReadDirectory(directory);
            var entries = MigrationCatalog.LockNumbered(MigrationFiles.ReadLock(directory), files);
            MigrationFiles.WriteLock(directory, entries);
            MigrationCatalog.Load(files, entries);
        }

        context.Out.WriteLine($"assigned {assigned.Count}: {string.Join(", ", assigned)}");
        return 0;
    }

    private static int Plan(MigrateContext context, string directory)
    {
        var migrations = MigrationCatalog.Load(MigrationFiles.ReadDirectory(directory), MigrationFiles.ReadLock(directory));
        foreach (var migration in migrations)
            context.Out.WriteLine($"{migration.File} {MigrationSql.ModeName(migration.Mode)} {migration.Statements.Count} statements");
        foreach (var file in MigrationFiles.ReadPending(directory)) context.Out.WriteLine($"pending {file.Name}");
        return 0;
    }

    private static async Task<int> LiveAsync(string command, IReadOnlyList<string> rest, MigrateContext context, string directory)
    {
        foreach (var name in new[] { "CLOUDFLARE_ACCOUNT_ID", "D1_DATABASE_ID", "CLOUDFLARE_API_TOKEN" })
        {
            if (string.IsNullOrEmpty(Env(context, name)))
            {
                context.Error.WriteLine($"{name} is not set");
                return 2;
            }
        }

        var client = new D1RestClient(Env(context, "CLOUDFLARE_ACCOUNT_ID")!, Env(context, "D1_DATABASE_ID")!, Env(context, "CLOUDFLARE_API_TOKEN")!, context.Handler);
        var migrations = MigrationCatalog.Load(MigrationFiles.ReadDirectory(directory), MigrationFiles.ReadLock(directory));
        if (command == "status")
        {
            var status = await MigrationEngine.StatusAsync(client, migrations, context.Now).ConfigureAwait(false);
            context.Out.WriteLine(StatusJson(status).ToJsonString(Indented));
            return 0;
        }

        if (command == "compat")
        {
            // Whether this build may use a database that may be ahead of it: the horizons decide.
            var current = await MigrationEngine.StatusAsync(client, migrations, context.Now).ConfigureAwait(false);
            var verdict = MigrationEngine.Compatibility(current.SchemaVersion, current.ReadHorizon, current.WriteHorizon, migrations.Count - 1);
            var report = new JsonObject
            {
                ["canRead"] = verdict.CanRead,
                ["canWrite"] = verdict.CanWrite,
                ["reason"] = verdict.Reason,
                ["schemaVersion"] = current.SchemaVersion,
                ["readHorizon"] = current.ReadHorizon,
                ["writeHorizon"] = current.WriteHorizon,
                ["databaseAhead"] = current.DatabaseAhead,
            };
            context.Out.WriteLine(report.ToJsonString(Indented));
            return verdict.CanWrite ? 0 : 1;
        }

        var stopAfter = Flag(rest, "--stop-after");
        var runner = Env(context, "GITHUB_RUN_ID") is { Length: > 0 }
            ? DeployGate.RunnerIdentity(context.Env)
            : $"local-{Guid.NewGuid():D}";
        var result = await MigrationEngine.ApplyPendingAsync(new RunOptions
        {
            Client = client,
            Migrations = migrations,
            Runner = runner,
            Now = context.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
            Compatibility = new CompatibilityInput(
                Env(context, "SOURCE_REVISION") ?? "local",
                Env(context, "PLAN_MANIFEST_HASH") ?? string.Empty,
                Env(context, "ABI_VERSION") ?? string.Empty,
                Env(context, "RUNTIME_VERSION") ?? string.Empty),
            StopAfter = stopAfter is null ? null : int.Parse(stopAfter, System.Globalization.CultureInfo.InvariantCulture),
            AllowContract = rest.Contains("--allow-contract"),
        }).ConfigureAwait(false);
        context.Out.WriteLine(ApplyJson(result).ToJsonString(Indented));
        return 0;
    }

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private static string? Env(MigrateContext context, string name) => context.Env.TryGetValue(name, out var value) ? value : null;

    private static JsonObject StatusJson(MigrationStatus status)
    {
        var receipts = new JsonArray();
        foreach (var receipt in status.Receipts)
            receipts.Add((JsonNode)new JsonObject
            {
                ["sequence"] = receipt.Sequence,
                ["file"] = receipt.File,
                ["state"] = receipt.State,
                ["statementsDone"] = receipt.StatementsDone,
                ["statementCount"] = receipt.StatementCount,
            });
        var pending = new JsonArray();
        foreach (var file in status.Pending) pending.Add((JsonNode?)JsonValue.Create(file));
        return new JsonObject
        {
            ["initialized"] = status.Initialized,
            ["databaseAhead"] = status.DatabaseAhead,
            ["schemaVersion"] = status.SchemaVersion,
            ["readHorizon"] = status.ReadHorizon,
            ["writeHorizon"] = status.WriteHorizon,
            ["fence"] = status.Fence,
            ["leaseHolder"] = status.LeaseHolder is null ? null : JsonValue.Create(status.LeaseHolder),
            ["receipts"] = receipts,
            ["pending"] = pending,
        };
    }

    private static JsonObject ApplyJson(RunResult result)
    {
        var applied = new JsonArray();
        foreach (var item in result.Applied)
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

        return new JsonObject
        {
            ["fence"] = result.Fence,
            ["applied"] = applied,
            ["schemaVersion"] = result.SchemaVersion,
            ["alreadyCurrent"] = result.AlreadyCurrent,
        };
    }

    /// <summary>
    /// The gated step of a deployment target: the context, the candidate, the target's database, the release plan and the gate. Any
    /// refusal stops promotion (exit 1) and is recorded; a target with no database is not applicable and is recorded so.
    /// </summary>
    public static async Task<int> DeployAsync(string target, MigrateContext context)
    {
        var secrets = new[] { Env(context, "CLOUDFLARE_API_TOKEN") };
        var revision = "unknown";
        try
        {
            DeployGate.RequireContext(context.Env, target);
            var account = Env(context, "CLOUDFLARE_ACCOUNT_ID") ?? string.Empty;
            if (!DeployGate.IsAccountId(account))
                throw new GateRefusal("context", "CLOUDFLARE_ACCOUNT_ID is not set to an account id");
            var token = Env(context, "CLOUDFLARE_API_TOKEN") ?? string.Empty;
            if (token.Length == 0) throw new GateRefusal("context", "the CLOUDFLARE_API_TOKEN secret is not set");

            JsonElement? declaredPlan;
            using (var manifestDocument = MigrationFiles.ReadJson(Path.Combine(context.Root, "artifacts", "candidate", "manifest.json")))
            {
                var manifest = manifestDocument.RootElement;
                revision = manifest.TryGetProperty("revision", out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
                if (!DeployGate.IsRevision(revision) || revision != Env(context, "GITHUB_SHA"))
                    throw new GateRefusal("context", "the sealed candidate is not the commit being deployed");
                declaredPlan = manifest.TryGetProperty("migrations", out var plan) ? plan.Clone() : null;
            }

            var directory = Path.Combine(context.Root, MigrationFiles.MigrationsPath);
            var locked = MigrationFiles.ReadLock(directory);
            var migrations = MigrationCatalog.Load(MigrationFiles.ReadDirectory(directory), locked);
            using var configDocument = MigrationFiles.ReadJson(Path.Combine(context.Root, "wrangler.json"));
            var name = DeployGate.DatabaseNameFor(MigrationFiles.DeclaredDatabases(configDocument.RootElement, target), target);
            if (name is null)
            {
                var detail = $"{target} declares no D1 database; there is nothing to migrate";
                context.Out.Write($"migration step: not applicable ({detail})\n");
                MigrationFiles.WriteGateRecord(context.Root, new GateRecord(target, revision, "not-applicable", detail));
                return 0;
            }

            var databaseId = await ResolveDatabaseIdAsync(name, account, token, context).ConfigureAwait(false);
            var client = new D1RestClient(account, databaseId, token, context.Handler);
            context.Out.Write($"migration step: {target} database {name}, release {revision[..12]}\n");
            var report = await DeployGate.RunGateAsync(new GateInput(
                client,
                migrations,
                locked,
                declaredPlan,
                DeployGate.RunnerIdentity(context.Env),
                context.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
                new CompatibilityInput(
                    revision,
                    Env(context, "PLAN_MANIFEST_HASH") ?? string.Empty,
                    Env(context, "ABI_VERSION") ?? string.Empty,
                    Env(context, "RUNTIME_VERSION") ?? string.Empty),
                CancellationToken.None)).ConfigureAwait(false);
            context.Out.Write(DeployGate.Scrub(DeployGate.FormatReport(report), secrets));
            MigrationFiles.WriteGateRecord(context.Root, new GateRecord(target, revision, "passed", $"schema {report.After.SchemaVersion}"));
            return 0;
        }
        catch (GateRefusal refusal)
        {
            return Refuse(context, target, revision, refusal.Code, refusal.Message, secrets);
        }
        catch (MigrationError error)
        {
            return Refuse(context, target, revision, error.Code, error.Message, secrets);
        }
        catch (MigrationClientException error)
        {
            return Refuse(context, target, revision, "failed", error.Message, secrets);
        }
        catch (Exception error) when (error is JsonException or IOException or InvalidOperationException or UnauthorizedAccessException or FormatException)
        {
            return Refuse(context, target, revision, "failed", error.Message, secrets);
        }
    }

    private static int Refuse(MigrateContext context, string target, string revision, string code, string message, IEnumerable<string?> secrets)
    {
        context.Out.Write($"migration step REFUSED ({code}): {DeployGate.Scrub(message, secrets)}\nNothing is promoted.\n");
        try
        {
            MigrationFiles.WriteGateRecord(context.Root, new GateRecord(target, revision, "refused", code));
        }
        catch (IOException)
        {
            // The step still fails: the exit code is what stops the job.
        }

        return 1;
    }

    /// <summary>The database id: an explicit override, else an exact-name lookup. Nothing is created.</summary>
    private static async Task<string> ResolveDatabaseIdAsync(string name, string account, string token, MigrateContext context)
    {
        var override_ = Env(context, "D1_DATABASE_ID");
        if (!string.IsNullOrEmpty(override_)) return DeployGate.OverrideDatabaseId(override_);
        var lookup = new D1RestClient(account, string.Empty, token, context.Handler);
        (int Status, IReadOnlyList<(string Name, string? Uuid)>? Results) reply;
        try
        {
            reply = await lookup.LookupDatabasesAsync(name, CancellationToken.None).ConfigureAwait(false);
        }
        catch (InvalidOperationException error)
        {
            throw new GateRefusal("lookup-failed", error.Message);
        }

        if (reply.Results is null)
            throw new GateRefusal("lookup-failed", $"the D1 database lookup failed (HTTP {reply.Status})");
        return DeployGate.SelectDatabaseId(name, reply.Results);
    }
}
