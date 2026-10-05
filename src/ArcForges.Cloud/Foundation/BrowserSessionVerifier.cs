// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Ingress;

namespace ArcForges.Cloud.Foundation;

/// <summary>
/// The browser cookie verifier of the ingress pipeline over the existing guarded session plans. It resolves, and never touches: a passive
/// request or stream does not renew idle expiry (only the explicit bootstrap does). Every call reads the primary through the plan bridge.
/// </summary>
internal sealed class BrowserSessionVerifier(SessionService sessions, FoundationOptions options) : IBrowserSessionVerifier
{
    public string AllowedOrigin => options.AllowedOrigin;

    public async Task<BrowserCredential?> ResolveAsync(string? cookieValue, CancellationToken cancellationToken)
    {
        var resolution = await sessions.ResolveAsync(cookieValue, cancellationToken);
        if (!resolution.IsAuthenticated) return null;
        var session = resolution.Session!;
        var caller = new CallerContext(CredentialKind.BrowserSession, session.SessionId, session.UserId, session.DeviceId, session.WorkspaceIds,
            (ulong)session.RecoveryGeneration);
        return new BrowserCredential(caller, token => sessions.VerifyCsrf(resolution, token));
    }
}
