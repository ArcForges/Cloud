// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.PublicApi.Http.V1.Browser;

namespace ArcForges.Cloud.Foundation;

/// <summary>
/// The two same-origin browser session routes of the proof (contracts 05 browser session). The cookie is the only
/// credential: no ASP.NET session or cookie handler is involved. Origin, cookie and CSRF are checked before any write.
/// </summary>
internal static class BrowserSessionEndpoints
{
    public const string BootstrapPath = "/session/v1/bootstrap";
    public const string LogoutPath = "/session/v1/logout";
    public const string CsrfHeader = "X-AF-CSRF";
    private const string ClearCookie = FoundationOptions.CookieName + "=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax";

    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet(BootstrapPath, BootstrapAsync);
        app.MapPost(LogoutPath, LogoutAsync);
    }

    internal static string Timestamp(long micros) =>
        SessionService.FromMicros(micros).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    /// <summary>The unique session cookie value; absent, repeated or empty cookies are no credential.</summary>
    internal static string? SessionCookie(HttpRequest request)
    {
        string? found = null;
        foreach (var header in request.Headers.Cookie)
        {
            foreach (var pair in (header ?? "").Split(';'))
            {
                var text = pair.Trim();
                var separator = text.IndexOf('=', StringComparison.Ordinal);
                if (separator <= 0 || !string.Equals(text[..separator], FoundationOptions.CookieName, StringComparison.Ordinal)) continue;
                if (found is not null) return null;
                found = text[(separator + 1)..];
            }
        }

        return found;
    }

    /// <summary>An Origin header, when present, must be exactly the configured origin; <paramref name="required"/> also refuses its absence.</summary>
    private static bool OriginAllowed(HttpContext context, FoundationOptions options, bool required)
    {
        if (!context.Request.Headers.TryGetValue("Origin", out var values)) return !required;
        return values.Count == 1 && string.Equals(values[0], options.AllowedOrigin, StringComparison.Ordinal);
    }

    private static async Task BootstrapAsync(HttpContext context)
    {
        var options = context.RequestServices.GetRequiredService<FoundationOptions>();
        var sessions = context.RequestServices.GetRequiredService<SessionService>();
        if (!OriginAllowed(context, options, required: false))
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status403Forbidden, "forbidden_origin");
            return;
        }

        try
        {
            var resolution = await sessions.ResolveAsync(SessionCookie(context.Request), context.RequestAborted);
            BrowserBootstrapResponse body;
            if (resolution.IsAuthenticated)
            {
                resolution = await sessions.TouchAsync(resolution, context.RequestAborted);
                var session = resolution.Session!;
                body = new BrowserBootstrapResponse
                {
                    CsrfToken = sessions.CsrfFor(resolution.HandleHash!),
                    Authenticated = true,
                    Session = new BrowserSessionProjection
                    {
                        SessionId = session.SessionId,
                        ExpiresAt = Timestamp(session.AbsoluteExpiresAt),
                        IdleExpiresAt = Timestamp(session.IdleExpiresAt),
                        UserId = session.UserId,
                        DeviceId = session.DeviceId,
                        WorkspaceIds = session.WorkspaceIds,
                        RecoveryGeneration = session.RecoveryGeneration.ToString(CultureInfo.InvariantCulture),
                        Purpose = "authenticate",
                    },
                };
            }
            else
            {
                body = new BrowserBootstrapResponse { CsrfToken = sessions.AnonymousCsrf(), Authenticated = false };
            }

            await FoundationHttp.WriteJsonAsync(context, StatusCodes.Status200OK, body, BrowserBootstrapResponseJsonContext.Default.BrowserBootstrapResponse);
        }
        catch (PlanFailureException)
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "unavailable");
        }
    }

    private static async Task LogoutAsync(HttpContext context)
    {
        var options = context.RequestServices.GetRequiredService<FoundationOptions>();
        var sessions = context.RequestServices.GetRequiredService<SessionService>();
        if (!OriginAllowed(context, options, required: true))
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status403Forbidden, "forbidden_origin");
            return;
        }

        var request = context.Request;
        if (request.ContentLength is > 0 || (request.ContentLength is null && request.Headers.ContainsKey("Transfer-Encoding")))
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        try
        {
            var resolution = await sessions.ResolveAsync(SessionCookie(request), context.RequestAborted);
            if (!resolution.IsAuthenticated)
            {
                await FoundationHttp.ErrorAsync(context, StatusCodes.Status401Unauthorized, "unauthenticated");
                return;
            }

            if (!sessions.VerifyCsrf(resolution, FoundationHttp.Single(request, CsrfHeader)))
            {
                await FoundationHttp.ErrorAsync(context, StatusCodes.Status403Forbidden, "csrf_invalid");
                return;
            }

            var receipt = await sessions.RevokeAsync(resolution.Session!.SessionId, context.RequestAborted);
            context.Response.Headers.SetCookie = ClearCookie;
            await FoundationHttp.WriteJsonAsync(context, StatusCodes.Status200OK,
                new BrowserReceipt { CommandId = receipt.CommandId.ToString("D"), Effect = receipt.Effect },
                BrowserReceiptJsonContext.Default.BrowserReceipt);
        }
        catch (PlanFailureException)
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "unavailable");
        }
    }
}
