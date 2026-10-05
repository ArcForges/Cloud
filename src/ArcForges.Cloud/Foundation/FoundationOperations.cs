// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Ingress;
using ArcForges.Cloud.Readiness;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Foundation;

internal readonly record struct OperationReply(int Status, byte[] Body)
{
    public static OperationReply Json<T>(int status, T value, JsonTypeInfo<T> info) => new(status, JsonSerializer.SerializeToUtf8Bytes(value, info));

    public static OperationReply Error(int status, string code) => Json(status, new ErrorBody(code), FoundationJsonContext.Default.ErrorBody);

    public static OperationReply Invalid => Error(StatusCodes.Status400BadRequest, "invalid_request");

    public static OperationReply Conflict => Error(StatusCodes.Status409Conflict, "conflict");

    public static OperationReply NotFound => Error(StatusCodes.Status404NotFound, "not_found");
}

/// <summary>
/// The operations behind the signed internal proof routes. Every 64-bit and decimal value is an exact canonical string,
/// all arithmetic is checked, and every failure maps to a closed error code.
/// </summary>
/// <summary>The source revision compiled into this host, formatted exactly like the health route's revision.</summary>
internal static class HostRevision
{
    public static string Current { get; } = Compute();

    private static string Compute()
    {
        var build = BuildIdentity.FromAssembly(typeof(HostRevision).Assembly)["build"]!.AsObject();
        return build["sourceCommit"]!.GetValue<string>() + (build["dirty"]!.GetValue<bool>() ? "-dirty" : "");
    }
}

internal sealed class FoundationOperations(IPlanExecutor executor, SessionService sessions, JobSliceService jobs, ObjectsClient objects, EgressProbe egress, FoundationOptions options)
{
    public async Task<OperationReply> ExecuteAsync(string operation, byte[] body, CancellationToken cancellationToken)
    {
        try
        {
            return operation switch
            {
                "readiness" => await ReadinessAsync(body, cancellationToken),
                "exact" => await ExactAsync(body, cancellationToken),
                "guard" => await GuardAsync(body, cancellationToken),
                "session/issue" => await IssueAsync(body, cancellationToken),
                "objects/roundtrip" => await RoundtripAsync(body, cancellationToken),
                "egress/probe" => await EgressProbeAsync(body, cancellationToken),
                "job/start" => await JobStartAsync(body, cancellationToken),
                "job/slice" => await JobSliceAsync(body, cancellationToken),
                "job/status" => await JobStatusAsync(body, cancellationToken),
                _ => OperationReply.NotFound,
            };
        }
        catch (PlanFailureException failure)
        {
            return failure.Kind switch
            {
                PlanFailureKind.Precondition or PlanFailureKind.Constraint => OperationReply.Conflict,
                PlanFailureKind.UnknownOutcome => OperationReply.Error(StatusCodes.Status503ServiceUnavailable, "unknown_outcome"),
                _ => OperationReply.Error(StatusCodes.Status503ServiceUnavailable, "unavailable"),
            };
        }
    }

    private static bool TryParse<T>(byte[] body, JsonTypeInfo<T> info, [NotNullWhen(true)] out T? value) where T : class
    {
        try
        {
            value = JsonSerializer.Deserialize(body, info);
            return value is not null;
        }
        catch (JsonException)
        {
            value = null;
            return false;
        }
    }

    private Task<PlanResult> RunAsync(PlanDefinition plan, string scope, CancellationToken cancellationToken, D1Scalar[][] arguments) =>
        executor.ExecuteAsync(PlanCall.New(plan, scope, options.RecoveryGeneration, arguments), cancellationToken);

    private static string Text(long value) => value.ToString(CultureInfo.InvariantCulture);

    private static string HashOf(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private async Task<OperationReply> ReadinessAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.ReadinessRequest, out _)) return OperationReply.Invalid;
        // Ready is 200; anything else is 503 with the same closed report, so the Worker can tell a plan mismatch from an outage.
        var report = await new HostReadiness(executor, options).ReportAsync(cancellationToken);
        return OperationReply.Json(report.Ready ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable, report, FoundationJsonContext.Default.ReadinessResponse);
    }

    // ---- exact ----------------------------------------------------------------------------------------------------

    private async Task<OperationReply> ExactAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.ExactRequest, out var request) || !FoundationIds.IsScope(request.Scope)
            || !FoundationIds.IsSafeId(request.Id) || !FoundationIds.IsUuid(request.CommandId)
            || !D1Values.TryParseInt64(request.Signed, out var signed) || !D1Values.TryParseUint64(request.Unsigned, out var unsigned)
            || !D1Values.TryParseDecimal(request.Decimal, out var amount) || !D1Values.TryParseInt64(request.ExpectedRevision, out var expected)
            || expected < 0 || expected == long.MaxValue) return OperationReply.Invalid;
        byte[]? payload = null;
        if (request.PayloadBase64Url is not null && (!Base64Url.TryDecode(request.PayloadBase64Url, out payload) || payload.Length > 1024)) return OperationReply.Invalid;
        var arithmetic = new ExactArithmetic(
            signed == long.MaxValue ? "overflow" : Text(signed + 1),
            unsigned == ulong.MaxValue ? "overflow" : (unsigned + 1).ToString(CultureInfo.InvariantCulture),
            DecimalTimesTwo(amount));
        var canonical = string.Join('|', request.Scope, request.Id, request.Signed, request.Unsigned, request.Decimal, request.PayloadBase64Url ?? "", request.ExpectedRevision);
        var requestHash = HashOf(canonical);
        var revision = Text(expected + 1);
        var planned = new ExactResponse(request.Scope, request.Id, request.Signed, request.Unsigned, request.Decimal, revision, "0", arithmetic, true, request.PayloadBase64Url);
        var result = JsonSerializer.Serialize(planned, FoundationJsonContext.Default.ExactResponse);
        PlanResult store;
        try
        {
            store = await RunAsync(PlanManifest.Foundation.ExactStore, request.Scope, cancellationToken,
                [[D1Values.Text(request.CommandId), D1Values.Text(request.Scope), D1Values.Text(request.Id), D1Values.Int64(expected)],
                    [D1Values.Text(request.Scope), D1Values.Text(request.Id), D1Values.Int64(signed), D1Values.Uint64(unsigned), D1Values.Decimal(amount),
                        payload is null ? D1Values.Null() : D1Values.Bytes(payload), D1Values.Int64(expected)],
                    [D1Values.Text(request.Scope), D1Values.Text(request.CommandId), D1Values.Text(requestHash), D1Values.Text(result)],
                    [D1Values.Text(request.CommandId)]]);
        }
        catch (PlanFailureException failure) when (failure.Kind is PlanFailureKind.Precondition or PlanFailureKind.Constraint)
        {
            // A failed guard or a duplicate command: the stored receipt decides between replay and conflict.
            var receipt = await LoadReceiptAsync(request.Scope, request.CommandId, cancellationToken);
            if (receipt is not { } stored || stored.Hash != requestHash) return OperationReply.Conflict;
            var replay = JsonSerializer.Deserialize(stored.Result, FoundationJsonContext.Default.ExactResponse);
            return replay is null ? OperationReply.Conflict : OperationReply.Json(StatusCodes.Status200OK, replay with { Replayed = true }, FoundationJsonContext.Default.ExactResponse);
        }

        var load = await RunAsync(PlanManifest.Foundation.ExactLoad, request.Scope, cancellationToken, [[D1Values.Text(request.Scope), D1Values.Text(request.Id)]]);
        var exact = false;
        if (load.Rows.Count == 1)
        {
            var row = load.Rows[0];
            exact = D1Values.TryGetInt64(row[0], out var loadedSigned) && loadedSigned == signed
                && D1Values.TryGetUint64(row[1], out var loadedUnsigned) && loadedUnsigned == unsigned
                && D1Values.TryGetDecimal(row[2], out var loadedDecimal) && loadedDecimal == amount && D1Values.FormatDecimal(loadedDecimal) == request.Decimal
                && PayloadEquals(row[3], payload)
                && D1Values.TryGetInt64(row[4], out var loadedRevision) && loadedRevision == expected + 1;
        }

        return OperationReply.Json(StatusCodes.Status200OK, planned with { StoreChanges = store.Changes.ToString(CultureInfo.InvariantCulture), RoundTripExact = exact },
            FoundationJsonContext.Default.ExactResponse);
    }

    private static bool PayloadEquals(D1Scalar stored, byte[]? payload) =>
        payload is null ? D1Values.IsNull(stored) : D1Values.TryGetBytes(stored, out var bytes) && bytes.AsSpan().SequenceEqual(payload);

    private static string DecimalTimesTwo(decimal value)
    {
        try
        {
            return D1Values.FormatDecimal(checked(value * 2));
        }
        catch (Exception exception) when (exception is OverflowException or ArgumentOutOfRangeException)
        {
            return "overflow";
        }
    }

    private async Task<(string Hash, string Result)?> LoadReceiptAsync(string scope, string commandId, CancellationToken cancellationToken)
    {
        var result = await RunAsync(PlanManifest.Foundation.ReceiptLoad, scope, cancellationToken, [[D1Values.Text(scope), D1Values.Text(commandId)]]);
        if (result.Rows.Count != 1 || !D1Values.TryGetText(result.Rows[0][0], out var hash) || !D1Values.TryGetText(result.Rows[0][1], out var stored)) return null;
        return (hash, stored);
    }

    // ---- guard ----------------------------------------------------------------------------------------------------

    private async Task<(long Balance, long Revision)?> LoadAccountAsync(string scope, string id, CancellationToken cancellationToken)
    {
        var result = await RunAsync(PlanManifest.Foundation.AccountLoad, scope, cancellationToken, [[D1Values.Text(scope), D1Values.Text(id)]]);
        if (result.Rows.Count != 1 || !D1Values.TryGetInt64(result.Rows[0][0], out var balance) || !D1Values.TryGetInt64(result.Rows[0][1], out var revision)) return null;
        return (balance, revision);
    }

    private async Task<(long Count, long MaxSequence)> LoadOutboxAsync(string scope, CancellationToken cancellationToken)
    {
        var result = await RunAsync(PlanManifest.Foundation.OutboxState, scope, cancellationToken, [[D1Values.Text(scope)]]);
        if (result.Rows.Count != 1 || !D1Values.TryGetInt64(result.Rows[0][0], out var count) || !D1Values.TryGetInt64(result.Rows[0][1], out var max))
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return (count, max);
    }

    private static GuardOutbox Show((long Count, long MaxSequence) state) => new(Text(state.Count), Text(state.MaxSequence));

    private static GuardBalances Show((long Balance, long Revision) source, (long Balance, long Revision) target) =>
        new(Text(source.Balance), Text(source.Revision), Text(target.Balance), Text(target.Revision));

    private async Task<OperationReply> GuardAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.GuardRequest, out var request) || !FoundationIds.IsScope(request.Scope)
            || !FoundationIds.IsSafeId(request.From) || !FoundationIds.IsSafeId(request.To) || request.From == request.To
            || !FoundationIds.IsUuid(request.CommandId) || !D1Values.TryParseInt64(request.Amount, out var amount) || amount <= 0)
            return OperationReply.Invalid;
        long? seedFrom = null, seedTo = null, overrideRevision = null;
        if (request.SeedFrom is not null) { if (!D1Values.TryParseInt64(request.SeedFrom, out var value) || value < 0) return OperationReply.Invalid; seedFrom = value; }
        if (request.SeedTo is not null) { if (!D1Values.TryParseInt64(request.SeedTo, out var value) || value < 0) return OperationReply.Invalid; seedTo = value; }
        if (request.ExpectedFromRevisionOverride is not null)
        {
            if (!D1Values.TryParseInt64(request.ExpectedFromRevisionOverride, out var value)) return OperationReply.Invalid;
            overrideRevision = value;
        }

        var scope = request.Scope;
        if (seedFrom is { } sf) await RunAsync(PlanManifest.Foundation.AccountSeed, scope, cancellationToken, [[D1Values.Text(scope), D1Values.Text(request.From), D1Values.Int64(sf)]]);
        if (seedTo is { } st) await RunAsync(PlanManifest.Foundation.AccountSeed, scope, cancellationToken, [[D1Values.Text(scope), D1Values.Text(request.To), D1Values.Int64(st)]]);
        var outboxBefore = await LoadOutboxAsync(scope, cancellationToken);
        if (await LoadAccountAsync(scope, request.From, cancellationToken) is not { } source || await LoadAccountAsync(scope, request.To, cancellationToken) is not { } target)
            return OperationReply.NotFound;
        (long Balance, long Revision) afterFrom, afterTo;
        try
        {
            afterFrom = (checked(source.Balance - amount), checked(source.Revision + 1));
            afterTo = (checked(target.Balance + amount), checked(target.Revision + 1));
        }
        catch (OverflowException)
        {
            return OperationReply.Invalid;
        }

        var before = Show(source, target);
        var planned = new GuardReceipt(before, Show(afterFrom, afterTo));
        var requestHash = HashOf(string.Join('|', scope, request.From, request.To, request.Amount, request.ExpectedFromRevisionOverride ?? ""));
        var command = request.CommandId;
        var payload = JsonSerializer.Serialize(new TransferEventPayload(request.From, request.To, request.Amount), FoundationJsonContext.Default.TransferEventPayload);
        var expectedFrom = overrideRevision ?? source.Revision;
        try
        {
            await RunAsync(PlanManifest.Foundation.Transfer, scope, cancellationToken,
                [[D1Values.Text(command), D1Values.Text(scope), D1Values.Text(request.From), D1Values.Int64(expectedFrom), D1Values.Int64(amount),
                        D1Values.Text(scope), D1Values.Text(request.To), D1Values.Int64(target.Revision)],
                    [D1Values.Int64(amount), D1Values.Text(scope), D1Values.Text(request.From), D1Values.Int64(expectedFrom)],
                    [D1Values.Int64(amount), D1Values.Text(scope), D1Values.Text(request.To), D1Values.Int64(target.Revision)],
                    [D1Values.Text(scope), D1Values.Text(command), D1Values.Text(requestHash), D1Values.Text(JsonSerializer.Serialize(planned, FoundationJsonContext.Default.GuardReceipt))],
                    [D1Values.Text(scope), D1Values.Text(command), D1Values.Text("transfer.committed"), D1Values.Text(payload)],
                    [D1Values.Text(command)]]);
        }
        catch (PlanFailureException failure) when (failure.Kind is PlanFailureKind.Precondition or PlanFailureKind.Constraint)
        {
            var receipt = await LoadReceiptAsync(scope, command, cancellationToken);
            if (receipt is { } stored)
            {
                var outbox = Show(await LoadOutboxAsync(scope, cancellationToken));
                if (stored.Hash != requestHash)
                    return GuardReply("idempotencyConflict", request, before, outbox, null, null, null);
                var original = JsonSerializer.Deserialize(stored.Result, FoundationJsonContext.Default.GuardReceipt);
                return original is null ? OperationReply.Conflict : GuardReply("replayed", request, original.Before, outbox, original.After, outbox, null);
            }

            if (failure.Kind != PlanFailureKind.Precondition) return OperationReply.Conflict;
            // Rejected: prove the whole batch rolled back by reading the accounts, the receipt and the outbox again.
            var nowFrom = await LoadAccountAsync(scope, request.From, cancellationToken);
            var nowTo = await LoadAccountAsync(scope, request.To, cancellationToken);
            var outboxNow = await LoadOutboxAsync(scope, cancellationToken);
            var receiptNow = await LoadReceiptAsync(scope, command, cancellationToken);
            var rolledBack = nowFrom == source && nowTo == target && receiptNow is null && outboxNow == outboxBefore;
            return GuardReply("rejected", request, before, Show(outboxBefore),
                nowFrom is { } f && nowTo is { } t ? Show(f, t) : null, Show(outboxNow), rolledBack);
        }

        var committedFrom = await LoadAccountAsync(scope, request.From, cancellationToken);
        var committedTo = await LoadAccountAsync(scope, request.To, cancellationToken);
        var outboxAfter = await LoadOutboxAsync(scope, cancellationToken);
        return GuardReply("committed", request, before, Show(outboxBefore),
            committedFrom is { } cf && committedTo is { } cp ? Show(cf, cp) : null, Show(outboxAfter), null);
    }

    private static OperationReply GuardReply(string outcome, GuardRequest request, GuardBalances before, GuardOutbox outboxBefore, GuardBalances? after, GuardOutbox? outboxAfter, bool? rolledBack) =>
        OperationReply.Json(StatusCodes.Status200OK,
            new GuardResponse(outcome, request.Scope, request.From, request.To, request.Amount, before, outboxBefore, after, outboxAfter, rolledBack),
            FoundationJsonContext.Default.GuardResponse);

    // ---- session, objects, jobs -----------------------------------------------------------------------------------

    /// <summary>Proof-only: mints a session so the browser routes can be exercised without a passkey ceremony. It returns the only copy of the handle.</summary>
    private async Task<OperationReply> IssueAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.IssueRequest, out var request) || !FoundationIds.IsUuid(request.UserId) || !FoundationIds.IsUuid(request.DeviceId)
            || request.WorkspaceIds.Length > SessionService.MaxWorkspaces || !request.WorkspaceIds.All(FoundationIds.IsUuid)) return OperationReply.Invalid;
        // Proof-only short lifetimes (2 to 300 seconds) let the live run observe both expiries; omitted, the configured defaults apply.
        if (request.IdleSeconds is < 2 or > 300 || request.AbsoluteSeconds is < 2 or > 300) return OperationReply.Invalid;
        var issued = await sessions.IssueAsync(request.UserId, request.DeviceId, request.WorkspaceIds, cancellationToken,
            request.AbsoluteSeconds is { } absolute ? TimeSpan.FromSeconds(absolute) : null, request.IdleSeconds is { } idle ? TimeSpan.FromSeconds(idle) : null);
        return OperationReply.Json(StatusCodes.Status200OK,
            new IssueResponse(issued.SessionId, issued.Handle, issued.CsrfToken, BrowserSessionEndpoints.Timestamp(issued.AbsoluteExpiresAt), BrowserSessionEndpoints.Timestamp(issued.IdleExpiresAt)),
            FoundationJsonContext.Default.IssueResponse);
    }

    private async Task<OperationReply> RoundtripAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.RoundtripRequest, out var request) || !FoundationIds.IsUuid(request.WorkspaceId) || !FoundationIds.IsUuid(request.ResourceId)
            || request.Size is < 1 or > ObjectsClient.MaxBytes) return OperationReply.Invalid;
        var data = new byte[request.Size];
        var state = request.Seed == 0 ? 0x6D2B79F5u : request.Seed;
        for (var index = 0; index < data.Length; index++)
        {
            if (index % 4 == 0)
            {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
            }

            data[index] = (byte)(state >> (index % 4 * 8));
        }

        var sha = Convert.ToHexStringLower(SHA256.HashData(data));
        var put = await objects.PutAsync(request.WorkspaceId, request.ResourceId, data, sha, cancellationToken);
        if (put.Outcome != ObjectOutcome.Ok) return OperationReply.Error(StatusCodes.Status503ServiceUnavailable, "unavailable");
        var whole = await objects.GetAsync(request.WorkspaceId, request.ResourceId, sha, null, request.Size, cancellationToken);
        var last = Math.Min(request.Size, 1024) - 1;
        var range = await objects.GetAsync(request.WorkspaceId, request.ResourceId, sha, (0, last), request.Size, cancellationToken);
        var other = (byte[])data.Clone();
        other[0] ^= 0xff;
        // Bytes that do not match the declared hash must be refused whether the key already exists or not:
        // once under the same resource (the object exists) and once under a fresh resource (nothing stored).
        var existingMismatch = await objects.PutAsync(request.WorkspaceId, request.ResourceId, other, sha, cancellationToken);
        var freshMismatch = await objects.PutAsync(request.WorkspaceId, Guid.NewGuid().ToString("D"), other, sha, cancellationToken);
        var existingRejected = existingMismatch.Outcome == ObjectOutcome.Rejected;
        var freshRejected = freshMismatch.Outcome == ObjectOutcome.Rejected;
        return OperationReply.Json(StatusCodes.Status200OK,
            new RoundtripResponse(sha, request.Size,
                whole is { Outcome: ObjectOutcome.Ok, Bytes: { } fullBytes } && Convert.ToHexStringLower(SHA256.HashData(fullBytes)) == sha && fullBytes.AsSpan().SequenceEqual(data),
                range is { Outcome: ObjectOutcome.Ok, Bytes: { } partial } && partial.AsSpan().SequenceEqual(data.AsSpan(0, last + 1)),
                existingRejected && freshRejected, range.ContentRange,
                put.StatusCode, whole.StatusCode, range.StatusCode, existingMismatch.StatusCode, freshMismatch.StatusCode, existingRejected, freshRejected),
            FoundationJsonContext.Default.RoundtripResponse);
    }

    private async Task<OperationReply> EgressProbeAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.EgressProbeRequest, out _)) return OperationReply.Invalid;
        var (blocked, controlOk, attempts) = await egress.RunAsync(cancellationToken);
        return OperationReply.Json(StatusCodes.Status200OK,
            new EgressProbeResponse(blocked, controlOk, [.. attempts.Select(a => new EgressAttemptResponse(a.Host, a.Outcome, a.Status, a.ElapsedMs))]),
            FoundationJsonContext.Default.EgressProbeResponse);
    }

    private async Task<OperationReply> JobStartAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.JobStartRequest, out var request) || !FoundationIds.IsScope(request.Scope) || request.Total is < 1 or > JobSliceService.MaxTotal)
            return OperationReply.Invalid;
        var jobId = await jobs.StartAsync(request.Scope, request.Total, cancellationToken);
        return OperationReply.Json(StatusCodes.Status200OK, new JobStartResponse(jobId, request.Scope, request.Total), FoundationJsonContext.Default.JobStartResponse);
    }

    private async Task<OperationReply> JobSliceAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.JobSliceRequest, out var request) || !FoundationIds.IsScope(request.Scope) || !FoundationIds.IsUuid(request.JobId)
            || !FoundationIds.IsUuid(request.EventId) || request.MaxItems is < 1 or > JobSliceService.MaxItemsPerSlice
            || request.MaxMilliseconds is < 1 or > JobSliceService.MaxMillisecondsPerSlice
            || !CorrelationContext.IsValidId(request.CorrelationId) || !CorrelationContext.IsValidId(request.CausationId)) return OperationReply.Invalid;
        // The wake's identity is carried into the call context of the slice; it never decides whether the slice may run.
        var correlation = CorrelationContext.Continue(request.CorrelationId, request.CausationId);
        var slice = await jobs.SliceAsync(request.Scope, request.JobId, request.EventId, request.MaxItems, request.MaxMilliseconds, correlation, cancellationToken);
        if (slice.State == SliceState.NotFound) return OperationReply.NotFound;
        var state = slice.State switch
        {
            SliceState.Running => "running",
            SliceState.Complete => "complete",
            SliceState.Duplicate => "duplicate",
            SliceState.Busy => "busy",
            _ => "stale",
        };
        return OperationReply.Json(StatusCodes.Status200OK,
            new JobSliceResponse(state, Text(slice.Cursor), Text(slice.Processed), Text(slice.Fence), slice.Checksum.ToString(CultureInfo.InvariantCulture), slice.JobComplete,
                correlation.CorrelationId, correlation.CausationId!),
            FoundationJsonContext.Default.JobSliceResponse);
    }

    private async Task<OperationReply> JobStatusAsync(byte[] body, CancellationToken cancellationToken)
    {
        if (!TryParse(body, FoundationJsonContext.Default.JobStatusRequest, out var request) || !FoundationIds.IsScope(request.Scope) || !FoundationIds.IsUuid(request.JobId))
            return OperationReply.Invalid;
        if (await jobs.StatusAsync(request.Scope, request.JobId, cancellationToken) is not { } status) return OperationReply.NotFound;
        return OperationReply.Json(StatusCodes.Status200OK,
            new JobStatusResponse(status.State, Text(status.Total), Text(status.Cursor), Text(status.Fence), status.Checksum.ToString(CultureInfo.InvariantCulture),
                Text(status.ItemCount), Text(status.ItemSum), status.ExpectedChecksum.ToString(CultureInfo.InvariantCulture), status.Matches),
            FoundationJsonContext.Default.JobStatusResponse);
    }
}
