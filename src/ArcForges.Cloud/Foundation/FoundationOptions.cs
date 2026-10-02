// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Storage;

namespace ArcForges.Cloud.Foundation;

/// <summary>A refused foundation configuration; the message names the variable and never its value.</summary>
internal sealed class FoundationConfigurationException(string variable) : Exception("Invalid foundation configuration: " + variable)
{
    public string Variable { get; } = variable;
}

/// <summary>
/// Fail-closed foundation proof configuration read from environment variables. Nothing foundation-related is
/// registered unless the proof variable is exactly <c>enabled</c>; an enabled module with a missing or invalid value throws.
/// </summary>
internal sealed partial record FoundationOptions(
    Uri StorageBaseUrl,
    Uri ObjectsBaseUrl,
    SigningKey SigningKeyC2w,
    SigningKey VerifyKeyW2c,
    SigningKey? VerifyKeyW2cPrevious,
    byte[] CsrfSecret,
    string AllowedOrigin,
    string RealmId,
    ulong RecoveryGeneration,
    string SessionScope)
{
    public const string EnabledVariable = "ARCFORGES_FOUNDATION_PROOF";
    public const string CookieName = "__Host-af_session";

    public TimeSpan AbsoluteLifetime { get; init; } = TimeSpan.FromHours(12);
    public TimeSpan IdleWindow { get; init; } = TimeSpan.FromMinutes(30);

    public IReadOnlyList<SigningKey> VerifyKeys => VerifyKeyW2cPrevious is null ? [VerifyKeyW2c] : [VerifyKeyW2c, VerifyKeyW2cPrevious];

    public static bool IsEnabled(Func<string, string?> read) => read(EnabledVariable) == "enabled";

    public static FoundationOptions Parse(Func<string, string?> read)
    {
        if (!IsEnabled(read)) throw new FoundationConfigurationException(EnabledVariable);
        var storage = Url(read, "ARCFORGES_STORAGE_BASE_URL", "http://storage.internal");
        var objects = Url(read, "ARCFORGES_OBJECTS_BASE_URL", "http://objects.internal");
        var signer = Signer(read, "AF_HMAC_C2W_KEY_ID", "AF_HMAC_C2W_SECRET");
        var current = Signer(read, "AF_HMAC_W2C_KEY_ID", "AF_HMAC_W2C_SECRET");
        SigningKey? previous = null;
        var previousId = Value(read, "AF_HMAC_W2C_PREVIOUS_KEY_ID");
        var previousMaterial = Value(read, "AF_HMAC_W2C_PREVIOUS_SECRET");
        if (previousId is not null || previousMaterial is not null)
        {
            previous = Signer(read, "AF_HMAC_W2C_PREVIOUS_KEY_ID", "AF_HMAC_W2C_PREVIOUS_SECRET");
            if (previous.Id == current.Id) throw new FoundationConfigurationException("AF_HMAC_W2C_PREVIOUS_KEY_ID");
        }

        if (!Base64Url.TryDecode(Value(read, "AF_CSRF_SECRET") ?? "", out var csrf) || csrf.Length != SigningKey.SecretLength)
            throw new FoundationConfigurationException("AF_CSRF_SECRET");
        var origin = Value(read, "AF_ALLOWED_ORIGIN") ?? "";
        if (!OriginPattern().IsMatch(origin)) throw new FoundationConfigurationException("AF_ALLOWED_ORIGIN");
        var realm = Value(read, "AF_REALM_ID") ?? "proof";
        if (!IdentifierPattern().IsMatch(realm)) throw new FoundationConfigurationException("AF_REALM_ID");
        ulong generation = 0;
        if (Value(read, "AF_RECOVERY_GENERATION") is { } generationText
            && (!D1Values.TryParseUint64(generationText, out generation) || generation > long.MaxValue))
            throw new FoundationConfigurationException("AF_RECOVERY_GENERATION");
        var scope = Value(read, "AF_SESSION_SCOPE") ?? "proof/sessions";
        if (!ScopePattern().IsMatch(scope)) throw new FoundationConfigurationException("AF_SESSION_SCOPE");
        return new FoundationOptions(storage, objects, signer, current, previous, csrf, origin, realm, generation, scope);
    }

    private static string? Value(Func<string, string?> read, string name) => read(name) is { Length: > 0 } text ? text : null;

    private static Uri Url(Func<string, string?> read, string name, string fallback)
    {
        var text = Value(read, name) ?? fallback;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")
            || uri.PathAndQuery != "/" || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
            throw new FoundationConfigurationException(name);
        return uri;
    }

    private static SigningKey Signer(Func<string, string?> read, string idName, string materialName)
    {
        if (!SigningKey.TryCreate(Value(read, idName), Value(read, materialName), out var key))
            throw new FoundationConfigurationException(Value(read, idName) is null ? idName : materialName);
        return key;
    }

    [GeneratedRegex(@"^(https://[a-z0-9.-]+(:[0-9]{1,5})?|http://127\.0\.0\.1:[0-9]{1,5})\z")]
    private static partial Regex OriginPattern();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z")]
    private static partial Regex IdentifierPattern();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\z")]
    private static partial Regex ScopePattern();
}
