// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Ingress;

internal enum CredentialKind
{
    None,
    BrowserSession,
    NativeBearer,
}

/// <summary>The authenticated principal of one request. It is a validated fact about the credential, never a client assertion.</summary>
internal sealed record CallerContext(CredentialKind Credential, string? SessionId, string? UserId, string? DeviceId,
    IReadOnlyList<string> WorkspaceIds, ulong RecoveryGeneration)
{
    public static readonly CallerContext Anonymous = new(CredentialKind.None, null, null, null, [], 0);

    public bool IsAuthenticated => Credential != CredentialKind.None;
}

/// <summary>
/// The current owner of a workspace-scoped call: the workspace the envelope addressed, which the validated session of the caller
/// currently owns (workspaces are single-owner), in the recovery generation that session is bound to.
/// </summary>
internal sealed record CurrentOwner(string WorkspaceId, string UserId, string? DeviceId, ulong RecoveryGeneration);

/// <summary>
/// Everything the pipeline decided about one admitted request; business handlers read it and never re-derive authority. The
/// <see cref="Correlation"/> is the call-scoped identity that handlers return in <c>ResponseMeta</c> and <c>ArcError</c> and hand to the
/// hops they start; it is not an authorization input.
/// </summary>
internal sealed record IngressCall(RpcPolicy Policy, CallerContext Caller, CurrentOwner? Owner, CorrelationContext Correlation);

/// <summary>A resolved browser session: the caller, and the check of the CSRF token that belongs to exactly this session.</summary>
internal sealed record BrowserCredential(CallerContext Caller, Func<string?, bool> VerifyCsrf);

/// <summary>
/// Validates the origin-bound browser cookie. Implementations read the authoritative store on every call (no stale positive cache) and
/// must not renew idle expiry: a passive stream never extends a session.
/// </summary>
internal interface IBrowserSessionVerifier
{
    /// <summary>The one exact origin that may use the cookie on an unsafe request.</summary>
    string AllowedOrigin { get; }

    /// <summary>Null when the cookie is absent, malformed, unknown, revoked, expired or in another recovery generation.</summary>
    Task<BrowserCredential?> ResolveAsync(string? cookieValue, CancellationToken cancellationToken);
}

/// <summary>Validates a native bearer credential against the authoritative store; null is unauthenticated.</summary>
internal interface IBearerTokenVerifier
{
    Task<CallerContext?> VerifyAsync(string token, CancellationToken cancellationToken);
}
