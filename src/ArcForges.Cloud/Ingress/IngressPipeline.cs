// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Net.Http.Headers;

namespace ArcForges.Cloud.Ingress;

/// <summary>
/// The public gRPC-Web admission pipeline that runs before the gRPC-Web adapter and every generated business handler:
/// deny-by-default method policy, binary gRPC-Web framing, credential validation (native bearer or origin-bound browser cookie with
/// exact Origin and CSRF), the current-owner gate and the per-method body bound. A refusal is a trailers-only gRPC-Web status; no
/// business code, plan or write has run when it is produced. Deny by default does not depend on the shape of a path: a path that is not
/// byte-for-byte canonical is refused, and a canonical path must be a registered RPC or one of the declared plain routes.
/// </summary>
internal static class IngressPipeline
{
    public const string SessionCookieName = "__Host-af_session";
    public const string CsrfHeader = "X-AF-CSRF";
    public const int MaxBearerLength = 4096;
    private const int MinBearerLength = 16;

    public static Task InvokeAsync(HttpContext context, RequestDelegate next, IngressRoutes routes)
    {
        var path = context.Request.Path.Value;
        if (!IsCanonical(context, path)) return Plain(context, StatusCodes.Status404NotFound);
        if (routes.IsPlain(path!)) return next(context);
        // A path shaped like a method but not registered gets a gRPC status; anything else is simply not served.
        return LooksLikeRpc(path) ? AdmitAsync(context, next, routes.Registry) : Plain(context, StatusCodes.Status404NotFound);
    }

    /// <summary>
    /// The request target is exactly its decoded path: no percent-encoding, no dot segments (the server resolves those before routing),
    /// no empty segment, no trailing slash, no backslash and no absolute-form target. Routing would otherwise match variants that the
    /// exact tables here (and the Worker's) do not, such as a trailing slash or a different case.
    /// </summary>
    internal static bool IsCanonical(HttpContext context, string? path)
    {
        if (path is not { Length: > 0 } || path[0] != '/' || path.Contains("//", StringComparison.Ordinal) || path.Contains('\\')) return false;
        if (path.Length > 1 && path[^1] == '/') return false;
        foreach (var segment in path.Split('/', StringSplitOptions.None)[1..])
        {
            if (segment is "." or "..") return false;
        }

        var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(target)) return true; // a context that carries no raw target (never a real request)
        var query = target.IndexOf('?', StringComparison.Ordinal);
        var rawPath = query < 0 ? target : target[..query];
        return string.Equals(rawPath, path, StringComparison.Ordinal);
    }

    /// <summary>Two segments, the first a dotted proto package and service: the shape every public gRPC-Web method has.</summary>
    internal static bool LooksLikeRpc(string? path)
    {
        if (path is not { Length: > 3 } || path[0] != '/') return false;
        var separator = path.IndexOf('/', 1);
        return separator > 1 && separator < path.Length - 1 && path.IndexOf('/', separator + 1) < 0 && path.AsSpan(1, separator - 1).Contains('.');
    }

    private static async Task AdmitAsync(HttpContext context, RequestDelegate next, RpcPolicyRegistry registry)
    {
        var request = context.Request;
        if (!HttpMethods.IsPost(request.Method))
        {
            await Plain(context, StatusCodes.Status405MethodNotAllowed);
            return;
        }

        if (!registry.TryGet(request.Path.Value!, out var policy))
        {
            await RefuseAsync(context, GrpcWebFraming.Unimplemented, "unimplemented");
            return;
        }

        if (!IsBinaryGrpcWeb(request.ContentType) || request.Headers.ContainsKey(HeaderNames.ContentEncoding) || !IsIdentityEncoding(request))
        {
            await Plain(context, StatusCodes.Status415UnsupportedMediaType);
            return;
        }

        var cancellation = context.RequestAborted;
        try
        {
            var outcome = policy.Authentication == RpcAuthentication.Anonymous
                ? new Admission(CallerContext.Anonymous, 0, null)
                : await AuthenticateAsync(context, cancellation);
            if (outcome.Status != 0)
            {
                await RefuseAsync(context, outcome.Status, outcome.Key!);
                return;
            }

            SetBodyLimit(context, policy.MaxRequestBytes);
            CurrentOwner? owner = null;
            if (policy.Scope == RpcScope.Workspace)
            {
                var buffered = await ReadBoundedAsync(context, policy.MaxRequestBytes, cancellation);
                if (buffered is null)
                {
                    await RefuseAsync(context, GrpcWebFraming.ResourceExhausted, "validation.invalid_request");
                    return;
                }

                var gate = AuthorizeOwner(outcome.Caller, buffered);
                if (gate.Status != 0)
                {
                    await RefuseAsync(context, gate.Status, gate.Key!);
                    return;
                }

                owner = gate.Owner;
                request.Body = new MemoryStream(buffered, writable: false);
            }

            context.Features.Set(new IngressCall(policy, outcome.Caller, owner));
            context.Response.OnStarting(static state =>
            {
                var headers = ((HttpContext)state).Response.Headers;
                headers.CacheControl = "no-store";
                headers.XContentTypeOptions = "nosniff";
                return Task.CompletedTask;
            }, context);
            // A server stream must reach the Worker frame by frame; nothing here or downstream may hold it back.
            if (policy.Kind == RpcKind.ServerStream) context.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();
            await next(context);
        }
        catch (PlanFailureException)
        {
            await RefuseAsync(context, GrpcWebFraming.Unavailable, "dependency.unavailable");
        }
        catch (BadHttpRequestException) when (!context.Response.HasStarted)
        {
            await RefuseAsync(context, GrpcWebFraming.ResourceExhausted, "validation.invalid_request");
        }
    }

    private readonly record struct Admission(CallerContext Caller, int Status, string? Key);

    private static async Task<Admission> AuthenticateAsync(HttpContext context, CancellationToken cancellation)
    {
        var services = context.RequestServices;
        var headers = context.Request.Headers;
        var cookie = SessionCookie(context.Request);
        var hasAuthorization = headers.ContainsKey(HeaderNames.Authorization);
        if (hasAuthorization && cookie is not null) return Refused(GrpcWebFraming.Unauthenticated, "auth.unauthenticated");
        if (hasAuthorization)
        {
            var token = BearerToken(headers.Authorization);
            if (token is null || services.GetService<IBearerTokenVerifier>() is not { } bearer) return Refused(GrpcWebFraming.Unauthenticated, "auth.unauthenticated");
            var caller = await bearer.VerifyAsync(token, cancellation);
            return caller is { Credential: CredentialKind.NativeBearer } ? new Admission(caller, 0, null) : Refused(GrpcWebFraming.Unauthenticated, "auth.unauthenticated");
        }

        if (cookie is null || services.GetService<IBrowserSessionVerifier>() is not { } browser) return Refused(GrpcWebFraming.Unauthenticated, "auth.unauthenticated");
        // Every RPC is an unsafe request: exact Origin first, then the session, then that session's CSRF token.
        if (!headers.TryGetValue(HeaderNames.Origin, out var origins) || origins.Count != 1 || !string.Equals(origins[0], browser.AllowedOrigin, StringComparison.Ordinal))
            return Refused(GrpcWebFraming.PermissionDenied, "perm.resource_denied");
        var credential = await browser.ResolveAsync(cookie, cancellation);
        if (credential is not { Caller.Credential: CredentialKind.BrowserSession }) return Refused(GrpcWebFraming.Unauthenticated, "auth.unauthenticated");
        var csrf = headers.TryGetValue(CsrfHeader, out var tokens) && tokens.Count == 1 ? tokens[0] : null;
        return credential.VerifyCsrf(csrf) ? new Admission(credential.Caller, 0, null) : Refused(GrpcWebFraming.PermissionDenied, "perm.resource_denied");
    }

    private static Admission Refused(int status, string key) => new(CallerContext.Anonymous, status, key);

    private readonly record struct Gate(CurrentOwner? Owner, int Status, string? Key);

    /// <summary>The caller addressed one workspace, owns it now and is in the generation of its own session; nothing else is admitted.</summary>
    private static Gate AuthorizeOwner(CallerContext caller, byte[] body)
    {
        if (!GrpcWebFraming.TryReadSingleMessage(body, out var message) || !RequestEnvelopeReader.TryRead(message, out var envelope) || envelope.WorkspaceId is null)
            return new Gate(null, GrpcWebFraming.InvalidArgument, "validation.invalid_request");
        if (!caller.WorkspaceIds.Contains(envelope.WorkspaceId, StringComparer.Ordinal) || caller.UserId is null)
            return new Gate(null, GrpcWebFraming.PermissionDenied, "perm.resource_denied");
        if (envelope.RecoveryGeneration is { } stated && stated != caller.RecoveryGeneration)
            return new Gate(null, GrpcWebFraming.FailedPrecondition, "state.stale_generation");
        return new Gate(new CurrentOwner(envelope.WorkspaceId, caller.UserId, caller.DeviceId, caller.RecoveryGeneration), 0, null);
    }

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
                if (separator <= 0 || !string.Equals(text[..separator], SessionCookieName, StringComparison.Ordinal)) continue;
                if (found is not null) return null;
                found = text[(separator + 1)..];
            }
        }

        return string.IsNullOrEmpty(found) ? null : found;
    }

    /// <summary>The token of exactly one <c>Bearer</c> authorization value of plausible length and alphabet; anything else is no credential.</summary>
    internal static string? BearerToken(Microsoft.Extensions.Primitives.StringValues values)
    {
        if (values.Count != 1 || values[0] is not { } value || !value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var token = value[7..];
        if (token.Length is < MinBearerLength or > MaxBearerLength) return null;
        foreach (var c in token)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '~' or '+' or '/' or '=' or '-')) return null;
        }

        return token;
    }

    private static bool IsBinaryGrpcWeb(string? contentType)
    {
        if (contentType is null) return false;
        var type = contentType.Split(';', 2)[0].Trim();
        return type.Equals("application/grpc-web", StringComparison.OrdinalIgnoreCase) || type.Equals("application/grpc-web+proto", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsIdentityEncoding(HttpRequest request) =>
        !request.Headers.TryGetValue("grpc-encoding", out var values) || (values.Count == 1 && string.Equals(values[0], "identity", StringComparison.OrdinalIgnoreCase));

    /// <summary>The host-wide limit protects the anonymous Hello; each method states its own bound before any body byte is read.</summary>
    private static void SetBodyLimit(HttpContext context, int limit)
    {
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } feature) feature.MaxRequestBodySize = limit;
    }

    /// <summary>The whole body, or null when it exceeds the bound (declared or actual).</summary>
    private static async Task<byte[]?> ReadBoundedAsync(HttpContext context, int limit, CancellationToken cancellation)
    {
        if (context.Request.ContentLength > limit) return null;
        using var buffer = new MemoryStream();
        var chunk = new byte[Math.Min(limit, 8192)];
        int read;
        try
        {
            while ((read = await context.Request.Body.ReadAsync(chunk, cancellation)) > 0)
            {
                if (buffer.Length + read > limit) return null;
                buffer.Write(chunk, 0, read);
            }
        }
        catch (BadHttpRequestException)
        {
            return null;
        }

        return buffer.ToArray();
    }

    private static Task Plain(HttpContext context, int status)
    {
        var response = context.Response;
        response.StatusCode = status;
        response.Headers.CacheControl = "no-store";
        response.Headers.XContentTypeOptions = "nosniff";
        response.ContentLength = 0;
        return Task.CompletedTask;
    }

    /// <summary>A trailers-only gRPC-Web refusal: HTTP 200 and one trailer frame, the form binary clients read.</summary>
    internal static Task RefuseAsync(HttpContext context, int status, string key)
    {
        var response = context.Response;
        if (response.HasStarted) return Task.CompletedTask;
        response.Clear();
        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = "application/grpc-web+proto";
        response.Headers.CacheControl = "no-store";
        response.Headers.XContentTypeOptions = "nosniff";
        var frame = GrpcWebFraming.TrailerFrame(status, key);
        response.ContentLength = frame.Length;
        return response.Body.WriteAsync(frame, context.RequestAborted).AsTask();
    }
}
