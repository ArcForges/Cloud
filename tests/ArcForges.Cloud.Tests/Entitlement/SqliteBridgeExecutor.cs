// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// A plan executor that sends each call, exactly as the signed Worker executor would, to the production Worker plan code running over
/// SQLite with every committed migration (tests/worker/support/entitlement-sqlite-bridge.ts). The Entitlement store tests therefore run
/// the real named plans, the real constraints and the real batch rollback; only the HMAC signature, the network path and the provider's
/// limits are not exercised, and SQLite is not D1. It needs <c>node</c> on the path, which every hosted job that runs the managed tests has.
/// </summary>
internal sealed class SqliteBridgeExecutor : IPlanExecutor, IDisposable
{
    private readonly Process process;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly ulong generation;

    public SqliteBridgeExecutor(ulong recoveryGeneration = 1)
    {
        generation = recoveryGeneration;
        var script = Path.Combine(T.RepoRoot().FullName, "tests", "worker", "support", "entitlement-sqlite-bridge.ts");
        var info = new ProcessStartInfo("node")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = T.RepoRoot().FullName,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = new UTF8Encoding(false),
        };
        info.ArgumentList.Add(script);
        info.ArgumentList.Add(recoveryGeneration.ToString(CultureInfo.InvariantCulture));
        process = Process.Start(info) ?? throw new InvalidOperationException("node could not be started for the SQLite bridge.");
        process.ErrorDataReceived += (_, _) => { };
        process.BeginErrorReadLine();
    }

    /// <summary>The number of plan calls executed, for tests that count round trips.</summary>
    public int Calls { get; private set; }

    public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
    {
        PlanArguments.Validate(call);
        var write = call.Plan.Access == PlanAccess.Write;
        var requestId = call.RequestId.ToString("D");
        var body = Encoding.UTF8.GetString(ExecutePlanRequestJson.Serialize(new ExecutePlanRequest
        {
            PlanId = call.Plan.Id,
            PlanVersion = call.Plan.Version,
            ManifestHash = PlanManifest.Hash,
            RequestId = requestId,
            RecoveryGeneration = call.RecoveryGeneration.ToString(CultureInfo.InvariantCulture),
            OwnerScope = call.OwnerScope,
            Arguments = call.Arguments,
            DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(8).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture),
        }));
        var reply = await Line(Message("plan", "body", body), cancellationToken).ConfigureAwait(false);
        Calls++;
        if (!ExecutePlanResponseJson.TryParse(Encoding.UTF8.GetBytes(reply), out var parsed, out _) || parsed is null) throw Uncertain(write);
        return parsed switch
        {
            ExecutePlanResponseExecutePlanSuccess success => Accept(call, requestId, write, success.Value),
            ExecutePlanResponseExecutePlanFailure failure => Reject(requestId, write, failure.Value),
            _ => throw Uncertain(write),
        };
    }

    /// <summary>Runs fixture SQL (test setup only).</summary>
    public async Task ExecAsync(string sql, CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(await Line(Message("exec", "sql", sql), cancellationToken).ConfigureAwait(false));
        if (document.RootElement.TryGetProperty("error", out var error)) throw new InvalidOperationException(error.GetString());
    }

    /// <summary>Runs a failing statement and returns the database's refusal message (test assertions only).</summary>
    public async Task<string> RefusalAsync(string sql, CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(await Line(Message("exec", "sql", sql), cancellationToken).ConfigureAwait(false));
        return document.RootElement.TryGetProperty("error", out var error) ? error.GetString()! : throw new InvalidOperationException("The statement was not refused.");
    }

    /// <summary>Reads rows as text (test assertions only); an integer column is its decimal text, a null is null.</summary>
    public async Task<List<string?[]>> QueryAsync(string sql, CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(await Line(Message("query", "sql", sql), cancellationToken).ConfigureAwait(false));
        if (document.RootElement.TryGetProperty("error", out var error)) throw new InvalidOperationException(error.GetString());
        return [.. document.RootElement.GetProperty("rows").EnumerateArray()
            .Select(row => row.EnumerateArray().Select(cell => cell.ValueKind == JsonValueKind.Null ? null : cell.ValueKind == JsonValueKind.String ? cell.GetString() : cell.GetRawText()).ToArray())];
    }

    public async Task<long> CountAsync(string table, string where = "1 = 1", CancellationToken cancellationToken = default) =>
        long.Parse((await QueryAsync("SELECT COUNT(*) FROM " + table + " WHERE " + where, cancellationToken).ConfigureAwait(false))[0][0]!, CultureInfo.InvariantCulture);

    /// <summary>A workspace row for the tables that reference one (the foreign key to the identity owner is switched off for this fixture insert only).</summary>
    public Task SeedWorkspaceAsync(Guid workspace, CancellationToken cancellationToken) => ExecAsync(
        "PRAGMA foreign_keys = OFF; INSERT INTO workspace_workspace (workspace_id, realm_id, owner_user_id, name, data_region, protection_profile, state, created_at, rev) VALUES ('"
        + workspace.ToString("D") + "', '00000000-0000-4000-8000-0000000000a1', '" + workspace.ToString("D") + "', 'fixture', 'eu', 1, 1, 1, 0); PRAGMA foreign_keys = ON;",
        cancellationToken);

    private static string Message(string kind, string field, string value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("kind", kind);
            writer.WriteString(field, value);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private async Task<string> Line(string request, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await process.StandardInput.WriteLineAsync(request.AsMemory(), cancellationToken).ConfigureAwait(false);
            await process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
            return await process.StandardOutput.ReadLineAsync(cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException("The SQLite bridge closed.");
        }
        finally
        {
            gate.Release();
        }
    }

    private static PlanFailureException Uncertain(bool write) => new(write ? PlanFailureKind.UnknownOutcome : PlanFailureKind.Unavailable);

    private static PlanResult Accept(PlanCall call, string requestId, bool write, ExecutePlanSuccess success)
    {
        if (success.RequestId != requestId) throw Uncertain(write);
        if (success.ManifestHash != PlanManifest.Hash) throw new PlanFailureException(PlanFailureKind.ManifestMismatch);
        if (!D1Values.TryParseUint64(success.Changes, out var changes)) throw Uncertain(write);
        var rows = new IReadOnlyList<D1Scalar>[success.Rows.Length];
        for (var index = 0; index < rows.Length; index++) rows[index] = success.Rows[index];
        if (!PlanArguments.RowsMatch(call.Plan, rows)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new PlanResult(rows, changes);
    }

    private static PlanResult Reject(string requestId, bool write, ExecutePlanFailure failure)
    {
        if (failure.RequestId != requestId) throw Uncertain(write);
        throw new PlanFailureException(failure.Failure switch
        {
            "invalidPlan" => PlanFailureKind.InvalidPlan,
            "staleGeneration" => PlanFailureKind.StaleGeneration,
            "precondition" => PlanFailureKind.Precondition,
            "constraint" => PlanFailureKind.Constraint,
            "overloaded" => PlanFailureKind.Overloaded,
            "unavailable" => PlanFailureKind.Unavailable,
            "unknownOutcome" => PlanFailureKind.UnknownOutcome,
            _ => PlanFailureKind.InvalidPlan,
        });
    }

    public void Dispose()
    {
        try
        {
            if (!process.HasExited)
            {
                process.StandardInput.Close();
                if (!process.WaitForExit(3000)) process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }

        process.Dispose();
        gate.Dispose();
    }

    /// <summary>The recovery generation the bridge answers for (a call with another generation is refused as stale).</summary>
    public ulong Generation => generation;
}
