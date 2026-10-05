// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Tests.Receipts;

/// <summary>
/// A plan executor that answers from a script and records every call. Arguments are validated against the plan definition first, exactly as the production
/// executor does, so a builder that binds the wrong kind, the wrong count or the wrong scope fails the test before the script answers. The SQL
/// itself is exercised by the SQLite oracle and workerd tests in tests/worker; this double only models what the host does with the answers.
/// </summary>
internal sealed class ScriptedExecutor : IPlanExecutor
{
    public List<PlanCall> Calls { get; } = [];

    /// <summary>Answers one call; throw <see cref="PlanFailureException"/> to model a failure.</summary>
    public Func<PlanCall, PlanResult> Handler { get; set; } = call => throw new InvalidOperationException($"Unscripted plan {call.Plan.Id}.");

    public IEnumerable<string> PlanIds => Calls.Select(call => call.Plan.Id);

    public Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
    {
        PlanArguments.Validate(call);
        Calls.Add(call);
        return Task.FromResult(Handler(call));
    }

    public static PlanResult Rows(params D1Scalar[][] rows) => new(rows, 0);

    public static PlanResult Changed(ulong changes = 1) => new([], changes);

    public static PlanFailureException Fail(PlanFailureKind kind) => new(kind);

    public static string Text(D1Scalar scalar) => D1Values.TryGetText(scalar, out var value) ? value : throw new InvalidOperationException("Not text.");

    public static long Int(D1Scalar scalar) => D1Values.TryGetInt64(scalar, out var value) ? value : throw new InvalidOperationException("Not int64.");

    public static D1Scalar Opt(string? value) => value is null ? D1Values.Null() : D1Values.Text(value);

    public static D1Scalar OptInt(long? value) => value is null ? D1Values.Null() : D1Values.Int64(value.Value);
}

internal static class Samples
{
    public static readonly DateTimeOffset Now = new(2026, 10, 5, 12, 0, 0, TimeSpan.Zero);

    public static long NowMicros => ArcForges.Cloud.Storage.Receipts.StorageFormats.Micros(Now);

    public static Guid Id(int n) => new($"00000000-0000-4000-8000-{n:x12}");

    public static ArcForges.Cloud.Storage.Receipts.CommandIdentity Identity(int n = 1, string hash = "hash-1", Guid? workspace = null) =>
        new(Id(n), workspace, "actor-1", "fixture.store", hash);

    public static ArcForges.Cloud.Storage.Receipts.CommandReceipt Receipt(int n = 1, string payload = "{\"ok\":true}", long? revision = 3, string hash = "hash-1", Guid? workspace = null) =>
        new(Identity(n, hash, workspace), payload, revision, NowMicros, NowMicros + (7L * 86_400_000_000));

    public static ArcForges.Cloud.Storage.Outbox.OutboxEvent Event(int n, string payload = "{\"n\":1}", Guid? workspace = null, Guid? causation = null) =>
        new(Id(100 + n), "fixture", Id(200 + n), 4, "fixture.changed", payload, workspace, Id(300 + n), causation);

    public static ArcForges.Cloud.Storage.Archive.ChangeRecord Change(string json = "{\"row\":1}") => new(23, json);
}
