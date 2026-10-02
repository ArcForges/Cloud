// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Hmac;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class PrivateSigningTests
{
    private sealed record Vector(string Name, string Method, string PathAndQuery, string Body, string? Declared, string Time, string Nonce, string RequestId, string Signer, string Signature)
    {
        public string BodyHash => Declared ?? T.Sha256Hex(Body);
    }

    private static (SigningKey Key, Vector[] Cases) Load()
    {
        var path = Path.Combine(T.RepoRoot().FullName, "tests", "ArcForges.Cloud.Tests", "Vectors", "private-signing.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var material = document.RootElement.GetProperty("material").GetString()!;
        var key = new SigningKey("c2w-1", SHA256.HashData(Encoding.UTF8.GetBytes(material)));
        var cases = document.RootElement.GetProperty("cases").EnumerateArray().Select(c => new Vector(
            c.GetProperty("name").GetString()!, c.GetProperty("method").GetString()!, c.GetProperty("pathAndQuery").GetString()!,
            c.GetProperty("body").GetString()!, c.GetProperty("declaredContentHash").GetString(), c.GetProperty("time").GetString()!,
            c.GetProperty("nonce").GetString()!, c.GetProperty("requestId").GetString()!, c.GetProperty("signer").GetString()!,
            c.GetProperty("signature").GetString()!)).ToArray();
        return (key, cases);
    }

    private static bool Verify(Vector vector, SigningKey[] keys, long now, Dictionary<string, string>? overrides = null, string? method = null, string? path = null, string? bodyHash = null)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-AF-Key-Id"] = vector.Signer,
            ["X-AF-Time"] = vector.Time,
            ["X-AF-Nonce"] = vector.Nonce,
            ["X-AF-Request-Id"] = vector.RequestId,
            ["X-AF-Signature"] = vector.Signature,
        };
        foreach (var (name, value) in overrides ?? []) headers[name] = value;
        return PrivateRequestVerifier.Verify(method ?? vector.Method, path ?? vector.PathAndQuery, bodyHash ?? vector.BodyHash,
            name => headers.GetValueOrDefault(name), keys, DateTimeOffset.FromUnixTimeSeconds(now), out _);
    }

    [Fact]
    public void IndependentlyGeneratedVectorsVerifyAndTheSignerReproducesThem()
    {
        var (key, cases) = Load();
        Assert.True(cases.Length >= 3);
        foreach (var vector in cases)
        {
            Assert.True(Verify(vector, [key], long.Parse(vector.Time, System.Globalization.CultureInfo.InvariantCulture) + 5), vector.Name);
            var headers = PrivateRequestSigner.Sign(vector.Method, vector.PathAndQuery, vector.BodyHash, vector.RequestId, key, vector.Time, vector.Nonce);
            Assert.Equal(vector.Signature, headers.Signature);
        }
    }

    [Fact]
    public void AnyAlteredSignedElementFailsTheSame()
    {
        var (key, cases) = Load();
        var vector = cases[0];
        var now = long.Parse(vector.Time, System.Globalization.CultureInfo.InvariantCulture);
        Assert.False(Verify(vector, [key], now, method: "PUT"));
        Assert.False(Verify(vector, [key], now, path: vector.PathAndQuery + "x"));
        Assert.False(Verify(vector, [key], now, bodyHash: new string('0', 64)));
        Assert.False(Verify(vector, [key], now, new() { ["X-AF-Time"] = (now + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) }));
        Assert.False(Verify(vector, [key], now, new() { ["X-AF-Nonce"] = "BBBBBBBBBBBBBBBBBBBBBB" }));
        Assert.False(Verify(vector, [key], now, new() { ["X-AF-Request-Id"] = "99999999-9999-4999-8999-999999999999" }));
        Assert.False(Verify(vector, [key], now, new() { ["X-AF-Key-Id"] = "c2w-2" }));
        Assert.False(Verify(vector, [key], now, new() { ["X-AF-Signature"] = vector.Signature[..^1] }));
        Assert.False(Verify(vector, [key], now, new() { ["X-AF-Signature"] = vector.Signature + "A" }));
        Assert.False(Verify(vector, [key], now, new() { ["X-AF-Signature"] = (vector.Signature[0] == 'A' ? "B" : "A") + vector.Signature[1..] }));
    }

    [Theory]
    [InlineData("X-AF-Key-Id", "")]
    [InlineData("X-AF-Key-Id", "-bad")]
    [InlineData("X-AF-Time", "01790000000")]
    [InlineData("X-AF-Time", "17.9")]
    [InlineData("X-AF-Nonce", "short")]
    [InlineData("X-AF-Nonce", "AAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("X-AF-Request-Id", "A1111111-1111-4111-8111-111111111111")]
    [InlineData("X-AF-Request-Id", "not-a-uuid")]
    [InlineData("X-AF-Signature", "")]
    [InlineData("X-AF-Signature", "AA==")]
    public void MalformedHeadersAreRefused(string header, string value)
    {
        var (key, cases) = Load();
        var vector = cases[0];
        Assert.False(Verify(vector, [key], long.Parse(vector.Time, System.Globalization.CultureInfo.InvariantCulture), new() { [header] = value }));
    }

    [Fact]
    public void MissingHeadersAndMalformedBodyHashesAreRefused()
    {
        var (key, cases) = Load();
        var vector = cases[0];
        var now = DateTimeOffset.FromUnixTimeSeconds(long.Parse(vector.Time, System.Globalization.CultureInfo.InvariantCulture));
        Assert.False(PrivateRequestVerifier.Verify(vector.Method, vector.PathAndQuery, vector.BodyHash, _ => null, [key], now, out _));
        Assert.False(Verify(vector, [key], now.ToUnixTimeSeconds(), bodyHash: "ABC"));
        Assert.False(Verify(vector, [key], now.ToUnixTimeSeconds(), bodyHash: vector.BodyHash.ToUpperInvariant()));
    }

    [Fact]
    public void ClockSkewIsLimitedToSixtySecondsEitherWay()
    {
        var (key, cases) = Load();
        var vector = cases[0];
        var now = long.Parse(vector.Time, System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(Verify(vector, [key], now + 60));
        Assert.True(Verify(vector, [key], now - 60));
        Assert.False(Verify(vector, [key], now + 61));
        Assert.False(Verify(vector, [key], now - 61));
    }

    [Fact]
    public void PreviousKeyVerifiesDuringRotationAndUnknownKeysNever()
    {
        var (key, cases) = Load();
        var vector = cases[0];
        var now = long.Parse(vector.Time, System.Globalization.CultureInfo.InvariantCulture);
        var current = new SigningKey("c2w-2", RandomNumberGenerator.GetBytes(32));
        Assert.True(Verify(vector, [current, key], now));
        Assert.False(Verify(vector, [current], now));
        // The same identifier with different material never verifies.
        Assert.False(Verify(vector, [new SigningKey("c2w-1", RandomNumberGenerator.GetBytes(32))], now));
    }

    [Fact]
    public void SignerUsesTheCurrentClockAndAFreshNonceEachTime()
    {
        var key = T.Key("c2w-1");
        var time = new FakeTime(DateTimeOffset.FromUnixTimeSeconds(1_790_000_000));
        var first = PrivateRequestSigner.Sign("POST", "/p", T.Sha256Hex("a"), T.Uuid(), key, time);
        var second = PrivateRequestSigner.Sign("POST", "/p", T.Sha256Hex("a"), T.Uuid(), key, time);
        Assert.Equal("1790000000", first.Time);
        Assert.NotEqual(first.Nonce, second.Nonce);
        Assert.Matches("^[A-Za-z0-9_-]{22}$", first.Nonce);
    }

    [Fact]
    public void DeploymentSecretsAreExactly256BitsOfStrictBase64Url()
    {
        var good = Base64Url.Encode(new byte[32]);
        Assert.True(SigningKey.TryCreate("c2w-1", good, out _));
        foreach (var bad in new[] { "", good[1..], good + "A", good + "=", "+" + good[1..], new string('A', 42) })
            Assert.False(SigningKey.TryCreate("c2w-1", bad, out _), bad);
        Assert.False(SigningKey.TryCreate(null, good, out _));
        Assert.False(SigningKey.TryCreate("c2w-1", null, out _));
        Assert.False(SigningKey.TryCreate("-x", good, out _));
        Assert.DoesNotContain(good, new SigningKey("c2w-1", new byte[32]).ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Base64UrlIsStrictAndRoundTripsEveryLength()
    {
        for (var length = 0; length < 70; length++)
        {
            var bytes = Enumerable.Range(0, length).Select(i => (byte)((i * 37) + length)).ToArray();
            var text = Base64Url.Encode(bytes);
            Assert.Equal(Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'), text);
            Assert.True(Base64Url.TryDecode(text, out var decoded));
            Assert.Equal(bytes, decoded);
        }

        foreach (var bad in new[] { "A", "AAAAA", "AB", "AAB", "A+A=", "A A A", "AA==", "=AAA", "ÄAAA" })
            Assert.False(Base64Url.TryDecode(bad, out _), bad);
    }
}
