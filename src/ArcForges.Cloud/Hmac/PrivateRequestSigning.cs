// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Hmac;

/// <summary>A direction-specific HMAC key: a pinned identifier and exactly 256 bits.</summary>
internal sealed record SigningKey(string Id, byte[] Secret)
{
    public const int SecretLength = 32;

    /// <summary>The secret is unpadded base64url that strictly decodes to exactly 32 bytes.</summary>
    public static bool TryCreate(string? id, string? secretText, [NotNullWhen(true)] out SigningKey? key)
    {
        key = null;
        if (id is null || secretText is null || !PrivateRequestSigning.IsKeyId(id)) return false;
        if (!Base64Url.TryDecode(secretText, out var bytes) || bytes.Length != SecretLength) return false;
        key = new SigningKey(id, bytes);
        return true;
    }

    public override string ToString() => "SigningKey(" + Id + ")";
}

internal readonly record struct SignatureHeaders(string KeyId, string Time, string Nonce, string RequestId, string Signature)
{
    /// <summary>Copies the five private-request headers into any header collection.</summary>
    public void CopyTo(Action<string, string> add)
    {
        add(PrivateRequestSigning.SignerHeader, KeyId);
        add(PrivateRequestSigning.TimeHeader, Time);
        add(PrivateRequestSigning.NonceHeader, Nonce);
        add(PrivateRequestSigning.RequestIdHeader, RequestId);
        add(PrivateRequestSigning.SignatureHeader, Signature);
    }
}

internal readonly record struct VerifiedRequest(string KeyId, string RequestId);

/// <summary>Shared shapes and the signing text of the private request signing (contracts 05 section 2).</summary>
internal static partial class PrivateRequestSigning
{
    public const string SignerHeader = "X-AF-Key-Id";
    public const string TimeHeader = "X-AF-Time";
    public const string NonceHeader = "X-AF-Nonce";
    public const string RequestIdHeader = "X-AF-Request-Id";
    public const string SignatureHeader = "X-AF-Signature";
    public const int MaxSkewSeconds = 60;

    public static bool IsKeyId(string value) => KeyIdPattern().IsMatch(value);
    public static bool IsTime(string value) => TimePattern().IsMatch(value);
    public static bool IsNonce(string value) => NoncePattern().IsMatch(value);
    public static bool IsRequestId(string value) => RequestIdPattern().IsMatch(value);
    public static bool IsBodyHash(string value) => HashPattern().IsMatch(value);

    public static byte[] SigningText(string method, string pathAndQuery, string time, string nonce, string requestId, string bodySha256Hex) =>
        Encoding.UTF8.GetBytes(string.Join('\n', method, pathAndQuery, time, nonce, requestId, bodySha256Hex));

    public static string Compute(byte[] secret, string method, string pathAndQuery, string time, string nonce, string requestId, string bodySha256Hex) =>
        Base64Url.Encode(HMACSHA256.HashData(secret, SigningText(method, pathAndQuery, time, nonce, requestId, bodySha256Hex)));

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z")]
    private static partial Regex KeyIdPattern();
    [GeneratedRegex(@"^[1-9][0-9]{0,15}\z")]
    private static partial Regex TimePattern();
    [GeneratedRegex(@"^[A-Za-z0-9_-]{22}\z")]
    private static partial Regex NoncePattern();
    [GeneratedRegex(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z")]
    private static partial Regex RequestIdPattern();
    [GeneratedRegex(@"^[0-9a-f]{64}\z")]
    private static partial Regex HashPattern();
}

internal static class PrivateRequestSigner
{
    /// <summary>Signs with the current time and a fresh 128-bit nonce.</summary>
    public static SignatureHeaders Sign(string method, string pathAndQuery, string bodySha256Hex, string requestId, SigningKey key, TimeProvider time)
    {
        var epoch = time.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        return Sign(method, pathAndQuery, bodySha256Hex, requestId, key, epoch, Base64Url.Encode(RandomNumberGenerator.GetBytes(16)));
    }

    /// <summary>Deterministic form for the cross-language vectors.</summary>
    public static SignatureHeaders Sign(string method, string pathAndQuery, string bodySha256Hex, string requestId, SigningKey key, string time, string nonce) =>
        new(key.Id, time, nonce, requestId,
            PrivateRequestSigning.Compute(key.Secret, method, pathAndQuery, time, nonce, requestId, bodySha256Hex));
}

internal static class PrivateRequestVerifier
{
    /// <summary>
    /// Header shapes, skew, key selection and the constant-time signature compare. Every failure is the same
    /// result so a reply cannot say why. <paramref name="header"/> returns a header only when it is present exactly once.
    /// </summary>
    public static bool Verify(string method, string rawPathAndQuery, string bodySha256Hex, Func<string, string?> header,
        IReadOnlyList<SigningKey> keys, DateTimeOffset now, out VerifiedRequest verified)
    {
        verified = default;
        var id = header(PrivateRequestSigning.SignerHeader) ?? "";
        var time = header(PrivateRequestSigning.TimeHeader) ?? "";
        var nonce = header(PrivateRequestSigning.NonceHeader) ?? "";
        var requestId = header(PrivateRequestSigning.RequestIdHeader) ?? "";
        var signature = header(PrivateRequestSigning.SignatureHeader) ?? "";
        if (!PrivateRequestSigning.IsKeyId(id) || !PrivateRequestSigning.IsTime(time) || !PrivateRequestSigning.IsNonce(nonce)
            || !PrivateRequestSigning.IsRequestId(requestId) || !PrivateRequestSigning.IsBodyHash(bodySha256Hex)) return false;
        if (Math.Abs(now.ToUnixTimeSeconds() - long.Parse(time, NumberStyles.None, CultureInfo.InvariantCulture)) > PrivateRequestSigning.MaxSkewSeconds) return false;
        if (!Base64Url.TryDecode(signature, out var provided) || provided.Length != 32) return false;
        SigningKey? key = null;
        foreach (var candidate in keys)
        {
            if (candidate.Id == id) { key = candidate; break; }
        }

        if (key is null) return false;
        var expected = HMACSHA256.HashData(key.Secret, PrivateRequestSigning.SigningText(method, rawPathAndQuery, time, nonce, requestId, bodySha256Hex));
        if (!CryptographicOperations.FixedTimeEquals(provided, expected)) return false;
        verified = new VerifiedRequest(id, requestId);
        return true;
    }
}
