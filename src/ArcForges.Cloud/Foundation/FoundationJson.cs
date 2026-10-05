// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Serialization;

namespace ArcForges.Cloud.Foundation;

// Requests of the internal proof routes. 64-bit integers and decimals are canonical strings; the few small
// bounded integers (sizes, counts, windows, the seed) are JSON numbers. Unknown, missing or duplicate members refuse.
internal sealed record ReadinessRequest;

internal sealed record ExactRequest(string Scope, string Id, string Signed, string Unsigned, string Decimal, string ExpectedRevision,
    string CommandId, string? PayloadBase64Url = null);

internal sealed record GuardRequest(string Scope, string From, string To, string Amount, string CommandId, string? SeedFrom = null,
    string? SeedTo = null, string? ExpectedFromRevisionOverride = null);

internal sealed record IssueRequest(string UserId, string DeviceId, string[] WorkspaceIds, int? IdleSeconds = null, int? AbsoluteSeconds = null);

internal sealed record RoundtripRequest(string WorkspaceId, string ResourceId, int Size, uint Seed);

internal sealed record JobStartRequest(string Scope, int Total);

internal sealed record JobSliceRequest(string Scope, string JobId, string EventId, string CorrelationId, string CausationId, int MaxItems, int MaxMilliseconds);

internal sealed record JobStatusRequest(string Scope, string JobId);

// Replies.
internal sealed record ErrorBody(string Error);

internal sealed record ReadinessResponse(bool Ready, string ManifestHash, string SchemaVersion, string? Revision = null);

internal sealed record ExactArithmetic(string SignedPlusOne, string UnsignedPlusOne, string DecimalTimesTwo);

internal sealed record ExactResponse(string Scope, string Id, string Signed, string Unsigned, string Decimal, string Revision,
    string StoreChanges, ExactArithmetic Arithmetic, bool RoundTripExact, string? PayloadBase64Url = null, bool? Replayed = null);

internal sealed record GuardBalances(string FromBalance, string FromRevision, string ToBalance, string ToRevision);

internal sealed record GuardOutbox(string Count, string MaxSequence);

internal sealed record GuardResponse(string Outcome, string Scope, string From, string To, string Amount, GuardBalances Before,
    GuardOutbox OutboxBefore, GuardBalances? After = null, GuardOutbox? OutboxAfter = null, bool? RolledBack = null);

internal sealed record IssueResponse(string SessionId, string Handle, string CsrfToken, string ExpiresAt, string IdleExpiresAt);

internal sealed record RoundtripResponse(string Sha256, int Size, bool FullMatches, bool RangeMatches, bool MismatchRejected,
    string? ContentRangeHeader = null, int PutStatus = 0, int WholeStatus = 0, int RangeStatus = 0, int ExistingMismatchStatus = 0,
    int FreshMismatchStatus = 0, bool ExistingMismatchRejected = false, bool FreshMismatchRejected = false);

internal sealed record EgressProbeRequest;

internal sealed record EgressAttemptResponse(string Host, string Outcome, int? Status, long ElapsedMs);

internal sealed record EgressProbeResponse(bool Blocked, bool ControlOk, EgressAttemptResponse[] Attempts);

internal sealed record JobStartResponse(string JobId, string Scope, int Total);

internal sealed record JobSliceResponse(string State, string Cursor, string Processed, string Fence, string Checksum, bool JobComplete,
    string CorrelationId, string CausationId);

internal sealed record JobStatusResponse(string State, string Total, string Cursor, string Fence, string Checksum, string ItemCount,
    string ItemSum, string ExpectedChecksum, bool Matches);

// Stored receipt results and outbox payloads: small valid JSON documents written by the Container.
internal sealed record GuardReceipt(GuardBalances Before, GuardBalances After);

internal sealed record SessionEventPayload(string SessionId);

internal sealed record TransferEventPayload(string From, string To, string Amount);

internal sealed record JobStartedPayload(string JobId, string Total);

internal sealed record JobSlicePayload(string JobId, string Cursor, string Processed, string CorrelationId, string CausationId);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    AllowDuplicateProperties = false,
    AllowTrailingCommas = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    MaxDepth = 16,
    NumberHandling = JsonNumberHandling.Strict,
    ReadCommentHandling = System.Text.Json.JsonCommentHandling.Disallow,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    WriteIndented = false)]
[JsonSerializable(typeof(ReadinessRequest))]
[JsonSerializable(typeof(ExactRequest))]
[JsonSerializable(typeof(GuardRequest))]
[JsonSerializable(typeof(IssueRequest))]
[JsonSerializable(typeof(RoundtripRequest))]
[JsonSerializable(typeof(EgressProbeRequest))]
[JsonSerializable(typeof(JobStartRequest))]
[JsonSerializable(typeof(JobSliceRequest))]
[JsonSerializable(typeof(JobStatusRequest))]
[JsonSerializable(typeof(ErrorBody))]
[JsonSerializable(typeof(ReadinessResponse))]
[JsonSerializable(typeof(ExactResponse))]
[JsonSerializable(typeof(GuardResponse))]
[JsonSerializable(typeof(IssueResponse))]
[JsonSerializable(typeof(RoundtripResponse))]
[JsonSerializable(typeof(EgressProbeResponse))]
[JsonSerializable(typeof(JobStartResponse))]
[JsonSerializable(typeof(JobSliceResponse))]
[JsonSerializable(typeof(JobStatusResponse))]
[JsonSerializable(typeof(GuardReceipt))]
[JsonSerializable(typeof(SessionEventPayload))]
[JsonSerializable(typeof(TransferEventPayload))]
[JsonSerializable(typeof(JobStartedPayload))]
[JsonSerializable(typeof(JobSlicePayload))]
[JsonSerializable(typeof(string[]))]
internal sealed partial class FoundationJsonContext : JsonSerializerContext;

internal static class FoundationIds
{
    /// <summary>Lowercase hyphenated UUID, the only accepted spelling.</summary>
    public static bool IsUuid(string? text) => text is { Length: 36 } && Guid.TryParseExact(text, "D", out var guid) && guid != Guid.Empty && guid.ToString("D") == text;

    /// <summary>Plain identifier of at most 64 characters.</summary>
    public static bool IsSafeId(string? text)
    {
        if (text is null || text.Length is 0 or > 64) return false;
        foreach (var c in text)
        {
            if (!(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-')) return false;
        }

        return true;
    }

    /// <summary>An owner scope used by the proof routes: a short path-like name.</summary>
    public static bool IsScope(string? text)
    {
        if (text is null || text.Length is 0 or > 128 || !char.IsAsciiLetterOrDigit(text[0])) return false;
        foreach (var c in text)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '/')) return false;
        }

        return true;
    }
}
