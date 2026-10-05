// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;
using Microsoft.Extensions.Primitives;

namespace ArcForges.Cloud.Ingress;

/// <summary>
/// The call-scoped correlation of one admitted call (CLOUD.69; Design CR-01, CR-02, CR-03, CR-06, HP-06): the one correlation identity
/// of the causal chain, the W3C trace and span identifiers that join this hop to the Worker's, and the causation id when the hop was
/// started by a message rather than by the public request. It is a diagnostic fact and never an input to authorization: nothing in
/// this type is read by <see cref="IngressPipeline"/> when it decides who the caller is or what the caller owns.
/// </summary>
/// <param name="CorrelationId">Canonical lowercase UUID; the trace id of the traceparent is exactly its 32 hex digits.</param>
/// <param name="ParentSpanId">The Worker's span (16 hex digits) when the traceparent that reached the host agrees with the correlation id.</param>
/// <param name="SpanId">This hop's own span (16 hex digits), created here.</param>
/// <param name="CausationId">The operation that caused this hop (a wake's originating request or previous wake event), or null for a public call.</param>
internal sealed record CorrelationContext(string CorrelationId, string? ParentSpanId, string SpanId, string? CausationId)
{
    /// <summary>The traceparent this hop continues with: the same trace as the Worker's, this hop's span.</summary>
    public string Traceparent => string.Create(CultureInfo.InvariantCulture, $"00-{TraceId}-{SpanId}-01");

    public string TraceId => CorrelationId.Replace("-", "", StringComparison.Ordinal);

    /// <summary>The identity of a new chain, created at this edge.</summary>
    public static CorrelationContext Create() => new(NewCorrelationId(), null, NewSpanId(), null);

    /// <summary>A hop of an existing chain started by a message (a wake): the same correlation, a new span, the stated cause.</summary>
    public static CorrelationContext Continue(string correlationId, string causationId) => new(correlationId, null, NewSpanId(), causationId);

    /// <summary>A canonical lowercase hyphenated UUID that is not the nil UUID: the only accepted spelling of a correlation or causation id.</summary>
    public static bool IsValidId(string? text) =>
        text is { Length: 36 } && Guid.TryParseExact(text, "D", out var guid) && guid != Guid.Empty && guid.ToString("D") == text;

    public static string NewCorrelationId() => Guid.NewGuid().ToString("D");

    /// <summary>The correlation id of a call: the validated envelope value, else the trace id of the Worker's traceparent, else a fresh identity.</summary>
    public static CorrelationContext ForRequest(StringValues traceparent, string? envelopeCorrelation)
    {
        var parsed = TryParseTraceparent(traceparent, out var traceCorrelation, out var parent);
        var correlation = envelopeCorrelation ?? (parsed ? traceCorrelation : null) ?? NewCorrelationId();
        // A traceparent that names a different trace than the identity chosen here is not a parent of this hop: the join is by identifier.
        return new CorrelationContext(correlation, parsed && correlation == traceCorrelation ? parent : null, NewSpanId(), null);
    }

    /// <summary>
    /// A strict W3C <c>traceparent</c>: exactly one header value, version 00, lowercase hex, a nonzero trace id and a nonzero parent id.
    /// Anything else (a repeated header, another version, uppercase, extra text) is no traceparent; the host then creates its own.
    /// </summary>
    internal static bool TryParseTraceparent(StringValues values, out string? correlationId, out string? parentSpanId)
    {
        correlationId = null;
        parentSpanId = null;
        if (values.Count != 1 || values[0] is not { Length: 55 } text) return false;
        if (text[..3] != "00-" || text[35] != '-' || text[52] != '-') return false;
        var trace = text.Substring(3, 32);
        var parent = text.Substring(36, 16);
        var flags = text.Substring(53, 2);
        if (!IsLowerHex(trace) || !IsLowerHex(parent) || !IsLowerHex(flags) || IsAllZero(trace) || IsAllZero(parent)) return false;
        correlationId = $"{trace[..8]}-{trace[8..12]}-{trace[12..16]}-{trace[16..20]}-{trace[20..]}";
        parentSpanId = parent;
        return true;
    }

    public static string NewSpanId()
    {
        Span<byte> bytes = stackalloc byte[8];
        do
        {
            RandomNumberGenerator.Fill(bytes);
        }
        while (bytes.IndexOfAnyExcept((byte)0) < 0);
        return Convert.ToHexStringLower(bytes);
    }

    private static bool IsLowerHex(string text)
    {
        foreach (var c in text)
        {
            if (!(c is >= '0' and <= '9' or >= 'a' and <= 'f')) return false;
        }

        return true;
    }

    private static bool IsAllZero(string text) => text.AsSpan().IndexOfAnyExcept('0') < 0;
}

/// <summary>
/// Builds the two generated messages that carry the identity in a reply (wire registry 04): <c>ResponseMeta.correlationId</c> (tag 4) and
/// <c>ArcError.correlationId</c> (tag 6). Every reply the host builds from a call uses these, so no module re-implements the echo. A
/// transport refusal of the pipeline itself (a trailers-only status) has no message and therefore carries none; the registry treats
/// those as transport failures without a fabricated result.
/// </summary>
internal static class CorrelationReplies
{
    public static Id ToId(string correlationId) => new() { Value = ByteString.CopyFrom(Convert.FromHexString(correlationId.Replace("-", "", StringComparison.Ordinal))) };

    public static ResponseMeta Meta(CorrelationContext correlation) => new() { CorrelationId = ToId(correlation.CorrelationId) };

    /// <summary>A domain refusal carrying the identity. The code and the message key are registry values, never request text.</summary>
    public static ArcError Error(CorrelationContext correlation, string code, ErrorCategory category, string messageKey) => new()
    {
        Code = code,
        Category = category,
        MessageKey = messageKey,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
        CorrelationId = ToId(correlation.CorrelationId),
    };
}
