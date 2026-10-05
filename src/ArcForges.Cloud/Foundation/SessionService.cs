// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Foundation;

internal sealed record SessionRecord(string SessionId, string UserId, string DeviceId, string[] WorkspaceIds, long RecoveryGeneration,
    long AuthEpoch, long CreatedAt, long AbsoluteExpiresAt, long IdleExpiresAt, long LastSeenAt, long? RevokedAt, string? RevokeReason);

/// <summary>The one-time result of a proof session issue; the handle is the cookie value and is never stored.</summary>
internal sealed record IssuedSession(string SessionId, string Handle, string CsrfToken, long AbsoluteExpiresAt, long IdleExpiresAt);

/// <summary>An authenticated request carries the session and the stored handle hash; every other outcome is unauthenticated.</summary>
internal sealed record SessionResolution(SessionRecord? Session, byte[]? HandleHash)
{
    public static readonly SessionResolution Unauthenticated = new(null, null);

    public bool IsAuthenticated => Session is not null && HandleHash is not null;
}

/// <summary>The receipt of a logout: the effect is <c>happened</c>, <c>didNotHappen</c> or <c>unknown</c>.</summary>
internal sealed record SessionReceipt(Guid CommandId, string Effect);

/// <summary>
/// Server-side opaque sessions over the guarded session plans. Only the SHA-256 of the 256-bit handle is stored;
/// the CSRF token is derived from the session and a deployment secret, so it needs no storage.
/// </summary>
internal sealed class SessionService(IPlanExecutor executor, FoundationOptions options, TimeProvider time)
{
    public const int MaxWorkspaces = 3;
    private const string CsrfLabel = "af-csrf-v1\n";

    public static long Micros(DateTimeOffset moment) => (moment.UtcDateTime - DateTime.UnixEpoch).Ticks / 10;

    public static DateTimeOffset FromMicros(long micros) => new(DateTime.UnixEpoch.AddTicks(micros * 10), TimeSpan.Zero);

    /// <summary>Exactly 43 base64url characters that strictly decode to 32 bytes.</summary>
    public static bool TryParseHandle(string? cookieValue, out byte[] handle)
    {
        handle = [];
        return cookieValue is { Length: 43 } && Base64Url.TryDecode(cookieValue, out handle) && handle.Length == 32;
    }

    public long NowMicros() => Micros(time.GetUtcNow());

    /// <summary>Proof-only issue: there is no passkey ceremony in this task, so the internal route mints a session directly.</summary>
    /// <param name="absoluteLifetime">Proof-only override of the twelve hour absolute lifetime (the stored expiry is enforced exactly as for the default).</param>
    /// <param name="idleWindow">Proof-only override of the thirty minute idle window.</param>
    public async Task<IssuedSession> IssueAsync(string userId, string deviceId, IReadOnlyList<string> workspaceIds, CancellationToken cancellationToken,
        TimeSpan? absoluteLifetime = null, TimeSpan? idleWindow = null)
    {
        if (!FoundationIds.IsUuid(userId) || !FoundationIds.IsUuid(deviceId) || workspaceIds.Count > MaxWorkspaces || !workspaceIds.All(FoundationIds.IsUuid))
            throw new ArgumentException("Invalid session identity.", nameof(userId));
        var handle = RandomNumberGenerator.GetBytes(32);
        var hash = SHA256.HashData(handle);
        var sessionId = Guid.NewGuid().ToString("D");
        var now = NowMicros();
        var absolute = now + (long)(absoluteLifetime ?? options.AbsoluteLifetime).TotalMicroseconds;
        var idle = Math.Min(now + (long)(idleWindow ?? options.IdleWindow).TotalMicroseconds, absolute);
        var workspaces = JsonSerializer.Serialize([.. workspaceIds], FoundationJsonContext.Default.StringArray);
        var payload = JsonSerializer.Serialize(new SessionEventPayload(sessionId), FoundationJsonContext.Default.SessionEventPayload);
        await executor.ExecuteAsync(Call(PlanManifest.SessionCreate,
            [[D1Values.Text(options.SessionScope), D1Values.Text(sessionId), D1Values.Bytes(hash), D1Values.Text(userId), D1Values.Text(deviceId),
                D1Values.Text(workspaces), D1Values.Int64((long)options.RecoveryGeneration), D1Values.Int64(1), D1Values.Int64(now),
                D1Values.Int64(absolute), D1Values.Int64(idle), D1Values.Int64(now)],
            [D1Values.Text(options.SessionScope), D1Values.Text(Guid.NewGuid().ToString("D")), D1Values.Text("session.created"), D1Values.Text(payload)]]),
            cancellationToken);
        return new IssuedSession(sessionId, Base64Url.Encode(handle), CsrfFor(hash), absolute, idle);
    }

    /// <summary>
    /// Authenticated only for a well-formed handle whose stored session is not revoked, before both expiries and in the
    /// configured recovery generation; unknown, revoked, expired and foreign-generation sessions are indistinguishable.
    /// </summary>
    public async Task<SessionResolution> ResolveAsync(string? cookieValue, CancellationToken cancellationToken)
    {
        if (!TryParseHandle(cookieValue, out var handle)) return SessionResolution.Unauthenticated;
        var hash = SHA256.HashData(handle);
        var result = await executor.ExecuteAsync(Call(PlanManifest.SessionLoad, [[D1Values.Text(options.SessionScope), D1Values.Bytes(hash)]]), cancellationToken);
        if (result.Rows.Count == 0) return SessionResolution.Unauthenticated;
        var session = FromRow(result.Rows[0]);
        var now = NowMicros();
        if (session.RevokedAt is not null || (ulong)session.RecoveryGeneration != options.RecoveryGeneration
            || now >= session.AbsoluteExpiresAt || now >= session.IdleExpiresAt) return SessionResolution.Unauthenticated;
        return new SessionResolution(session, hash);
    }

    /// <summary>Idle renewal for an explicit active request: min(now + idle window, absolute expiry). Zero changes is not an error.</summary>
    public async Task<SessionResolution> TouchAsync(SessionResolution resolution, CancellationToken cancellationToken)
    {
        if (resolution.Session is not { } session || resolution.HandleHash is not { } hash) return resolution;
        var now = NowMicros();
        var idle = Math.Min(now + (long)options.IdleWindow.TotalMicroseconds, session.AbsoluteExpiresAt);
        var result = await executor.ExecuteAsync(Call(PlanManifest.SessionTouch,
            [[D1Values.Int64(now), D1Values.Int64(idle), D1Values.Text(options.SessionScope), D1Values.Bytes(hash), D1Values.Int64(now), D1Values.Int64(now)]]),
            cancellationToken);
        return result.Changes == 0 ? resolution : resolution with { Session = session with { IdleExpiresAt = idle, LastSeenAt = now } };
    }

    /// <summary>Guarded revocation. A failed guard means the session is already revoked or unknown, which is an idempotent success.</summary>
    public async Task<SessionReceipt> RevokeAsync(string sessionId, CancellationToken cancellationToken)
    {
        var command = Guid.NewGuid();
        var commandText = command.ToString("D");
        var payload = JsonSerializer.Serialize(new SessionEventPayload(sessionId), FoundationJsonContext.Default.SessionEventPayload);
        var effect = "happened";
        try
        {
            await executor.ExecuteAsync(Call(PlanManifest.SessionRevoke,
                [[D1Values.Text(commandText), D1Values.Text(options.SessionScope), D1Values.Text(sessionId)],
                [D1Values.Int64(NowMicros()), D1Values.Text("logout"), D1Values.Text(options.SessionScope), D1Values.Text(sessionId)],
                [D1Values.Text(options.SessionScope), D1Values.Text(commandText), D1Values.Text("session.revoked"), D1Values.Text(payload)],
                [D1Values.Text(commandText)]]), cancellationToken);
        }
        catch (PlanFailureException failure) when (failure.Kind == PlanFailureKind.Precondition)
        {
            effect = "didNotHappen";
        }
        catch (PlanFailureException failure) when (failure.Kind == PlanFailureKind.UnknownOutcome)
        {
            effect = "unknown";
        }

        if (effect == "happened")
        {
            var read = await executor.ExecuteAsync(Call(PlanManifest.SessionLoadById, [[D1Values.Text(options.SessionScope), D1Values.Text(sessionId)]]), cancellationToken);
            if (read.Rows.Count == 0 || FromRow(read.Rows[0]).RevokedAt is null) effect = "unknown";
        }

        return new SessionReceipt(command, effect);
    }

    /// <summary>The readiness plan returns exactly the schema version 1.</summary>
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await executor.ExecuteAsync(Call(PlanManifest.Readiness, [[]]), cancellationToken);
            return result.Rows.Count == 1 && D1Values.TryGetInt64(result.Rows[0][0], out var version) && version == 1;
        }
        catch (PlanFailureException)
        {
            return false;
        }
    }

    /// <summary>CSRF token of a session: HMAC over the base64url of the stored SHA-256 handle hash.</summary>
    public string CsrfFor(ReadOnlySpan<byte> handleHash) => CsrfToken(CsrfLabel + Base64Url.Encode(handleHash));

    /// <summary>The token of an anonymous bootstrap; it is never accepted for an unsafe route.</summary>
    public string AnonymousCsrf() => CsrfToken(CsrfLabel + "anonymous");

    /// <summary>Only an authenticated session's own token verifies; the anonymous token never does.</summary>
    public bool VerifyCsrf(SessionResolution resolution, string? provided)
    {
        if (!resolution.IsAuthenticated || provided is not { Length: 43 }) return false;
        var expected = Encoding.UTF8.GetBytes(CsrfFor(resolution.HandleHash!));
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(provided), expected);
    }

    private string CsrfToken(string text) => Base64Url.Encode(HMACSHA256.HashData(options.CsrfSecret, Encoding.UTF8.GetBytes(text)));

    private PlanCall Call(PlanDefinition plan, D1Scalar[][] arguments) =>
        PlanCall.New(plan, options.SessionScope, options.RecoveryGeneration, arguments);

    private static SessionRecord FromRow(IReadOnlyList<D1Scalar> row)
    {
        string[]? workspaces = null;
        if (D1Values.TryGetText(row[3], out var workspaceText))
        {
            try { workspaces = JsonSerializer.Deserialize(workspaceText, FoundationJsonContext.Default.StringArray); }
            catch (JsonException) { workspaces = null; }
        }

        if (workspaces is null) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        long? revokedAt = null;
        string? reason = null;
        var valid = D1Values.TryGetText(row[0], out var id) & D1Values.TryGetText(row[1], out var user)
            & D1Values.TryGetText(row[2], out var device) & D1Values.TryGetInt64(row[4], out var recovery) & D1Values.TryGetInt64(row[5], out var epoch)
            & D1Values.TryGetInt64(row[6], out var created) & D1Values.TryGetInt64(row[7], out var absolute) & D1Values.TryGetInt64(row[8], out var idle)
            & D1Values.TryGetInt64(row[9], out var seen);
        if (D1Values.TryGetInt64(row[10], out var revoked)) revokedAt = revoked;
        else if (!D1Values.IsNull(row[10])) valid = false;
        if (D1Values.TryGetText(row[11], out var revokeReason)) reason = revokeReason;
        else if (!D1Values.IsNull(row[11])) valid = false;
        if (!valid || recovery < 0) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new SessionRecord(id, user, device, workspaces, recovery, epoch, created, absolute, idle, seen, revokedAt, reason);
    }
}
