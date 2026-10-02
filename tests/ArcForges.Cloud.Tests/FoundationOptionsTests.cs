// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class FoundationOptionsTests
{
    private static FoundationOptions Parse(Dictionary<string, string?> environment) =>
        FoundationOptions.Parse(name => environment.GetValueOrDefault(name));

    [Fact]
    public void AValidEnabledConfigurationParsesWithSafeDefaults()
    {
        var options = Parse(T.Environment());
        Assert.Equal("http://storage.internal/", options.StorageBaseUrl.ToString());
        Assert.Equal("http://objects.internal/", options.ObjectsBaseUrl.ToString());
        Assert.Equal("proof", options.RealmId);
        Assert.Equal(0UL, options.RecoveryGeneration);
        Assert.Equal("proof/sessions", options.SessionScope);
        Assert.Equal(TimeSpan.FromHours(12), options.AbsoluteLifetime);
        Assert.Equal(TimeSpan.FromMinutes(30), options.IdleWindow);
        Assert.Single(options.VerifyKeys);
        Assert.Equal(32, options.CsrfSecret.Length);
    }

    [Fact]
    public void NothingIsEnabledUnlessTheVariableIsExactlyEnabled()
    {
        foreach (var value in new string?[] { null, "", "disabled", "ENABLED", "true", "1", " enabled", "enabled " })
        {
            var environment = T.Environment();
            environment["ARCFORGES_FOUNDATION_PROOF"] = value;
            Assert.False(FoundationOptions.IsEnabled(name => environment.GetValueOrDefault(name)), value);
            Assert.Throws<FoundationConfigurationException>(() => Parse(environment));
        }

        Assert.True(FoundationOptions.IsEnabled(name => T.Environment().GetValueOrDefault(name)));
    }

    [Theory]
    [InlineData("AF_HMAC_C2W_KEY_ID")]
    [InlineData("AF_HMAC_C2W_SECRET")]
    [InlineData("AF_HMAC_W2C_KEY_ID")]
    [InlineData("AF_HMAC_W2C_SECRET")]
    [InlineData("AF_CSRF_SECRET")]
    [InlineData("AF_ALLOWED_ORIGIN")]
    public void EveryRequiredValueIsMandatoryAndNamedWithoutItsValue(string variable)
    {
        var environment = T.Environment();
        environment[variable] = null;
        var failure = Assert.Throws<FoundationConfigurationException>(() => Parse(environment));
        Assert.Contains("AF_", failure.Message, StringComparison.Ordinal);
        environment[variable] = "x";
        var malformed = Assert.Throws<FoundationConfigurationException>(() => Parse(environment));
        Assert.DoesNotContain("x\"", malformed.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MalformedValuesAreRefusedAndNeverEchoed()
    {
        var secret = Base64Url.Encode(RandomNumberGenerator.GetBytes(31));
        foreach (var (variable, value) in new[]
        {
            ("AF_HMAC_C2W_SECRET", secret),
            ("AF_CSRF_SECRET", secret),
            ("AF_ALLOWED_ORIGIN", "http://example.com"),
            ("AF_ALLOWED_ORIGIN", "https://example.com/path"),
            ("AF_ALLOWED_ORIGIN", "https://Example.com"),
            ("AF_REALM_ID", "bad realm"),
            ("AF_RECOVERY_GENERATION", "-1"),
            ("AF_RECOVERY_GENERATION", "9223372036854775808"),
            ("AF_RECOVERY_GENERATION", "1.5"),
            ("AF_SESSION_SCOPE", "../x"),
            ("ARCFORGES_STORAGE_BASE_URL", "ftp://storage.internal"),
            ("ARCFORGES_STORAGE_BASE_URL", "http://storage.internal/path"),
            ("ARCFORGES_STORAGE_BASE_URL", "http://user:pass@storage.internal"),
            ("ARCFORGES_OBJECTS_BASE_URL", "not a url"),
        })
        {
            var environment = T.Environment();
            environment[variable] = value;
            var failure = Assert.Throws<FoundationConfigurationException>(() => Parse(environment));
            Assert.Equal(variable, failure.Variable);
            Assert.DoesNotContain(value, failure.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void LocalHttpOriginsAndOverridesAreAcceptedForLocalRuns()
    {
        var environment = T.Environment();
        environment["AF_ALLOWED_ORIGIN"] = "http://127.0.0.1:5000";
        environment["ARCFORGES_STORAGE_BASE_URL"] = "http://127.0.0.1:9000";
        environment["AF_RECOVERY_GENERATION"] = "7";
        environment["AF_REALM_ID"] = "local-1";
        var options = Parse(environment);
        Assert.Equal("http://127.0.0.1:5000", options.AllowedOrigin);
        Assert.Equal(7UL, options.RecoveryGeneration);
        Assert.Equal("local-1", options.RealmId);
    }

    [Fact]
    public void ARotationPreviousKeyIsAllOrNothingAndDistinct()
    {
        var environment = T.Environment();
        environment["AF_HMAC_W2C_PREVIOUS_KEY_ID"] = "w2c-0";
        Assert.Throws<FoundationConfigurationException>(() => Parse(environment));
        environment["AF_HMAC_W2C_PREVIOUS_SECRET"] = "short";
        Assert.Throws<FoundationConfigurationException>(() => Parse(environment));
        environment["AF_HMAC_W2C_PREVIOUS_SECRET"] = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        Assert.Equal(2, Parse(environment).VerifyKeys.Count);
        environment["AF_HMAC_W2C_PREVIOUS_KEY_ID"] = "w2c-1";
        Assert.Throws<FoundationConfigurationException>(() => Parse(environment));
    }
}
