// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace ArcForges.Cloud.Modules.Commerce.Adapters;

public sealed class ProviderNotificationKey
{
    public ProviderNotificationKey(string version, string secret)
    {
        if (!ProviderInput.Key(version) || secret is null || secret.Length is < 16 or > 1024 || secret.Any(c => c is < '!' or > '~'))
            throw new ArgumentException("Invalid notification verification key.");
        Version = version; Secret = secret;
    }
    public string Version { get; }
    internal string Secret { get; }
}

/// <summary>Operator-supplied, approved configuration. Secrets are never exposed as public properties or record diagnostics.</summary>
public sealed class ProviderAdapterSettings
{
    internal string Credential { get; }
    internal ProviderNotificationKey[] WebhookKeys { get; }
    public BillingEnvironment Environment { get; }
    public string Source { get; }
    public Uri CheckoutPage { get; }
    public BillingProviderCapabilities Capabilities { get; }
    public TimeSpan OperationTimeout { get; }
    public TimeSpan SignatureTolerance { get; }
    public int MaxResponseBytes { get; }
    public int MaxReadRetries { get; }

    public ProviderAdapterSettings(BillingEnvironment environment, string credential, IReadOnlyList<ProviderNotificationKey> webhookSecrets,
        string source, Uri checkoutPage, BillingProviderCapabilities capabilities, TimeSpan? operationTimeout = null,
        TimeSpan? signatureTolerance = null, int maxResponseBytes = 1024 * 1024, int maxReadRetries = 2)
    {
        if (!Enum.IsDefined(environment)) throw new ArgumentException("Invalid billing environment.", nameof(environment));
        if (credential is null || credential.Length is < 16 or > 512 || credential.Any(c => c is < '!' or > '~'))
            throw new ArgumentException("Invalid operator credential.", nameof(credential));
        if (webhookSecrets is null || webhookSecrets.Count is < 1 or > 2
            || webhookSecrets.Any(s => s is null) || webhookSecrets.Select(s => s.Version).Distinct(StringComparer.Ordinal).Count() != webhookSecrets.Count
            || webhookSecrets.Select(s => s.Secret).Distinct(StringComparer.Ordinal).Count() != webhookSecrets.Count)
            throw new ArgumentException("Invalid notification key inventory.", nameof(webhookSecrets));
        if (!ProviderInput.Key(source)) throw new ArgumentException("Invalid provider source.", nameof(source));
        if (checkoutPage is null || !checkoutPage.IsAbsoluteUri || checkoutPage.Scheme != "https" || checkoutPage.Port != 443
            || checkoutPage.UserInfo.Length != 0 || checkoutPage.Query.Length != 0 || checkoutPage.Fragment.Length != 0
            || checkoutPage.HostNameType != UriHostNameType.Dns || checkoutPage.AbsoluteUri.Length > 2048)
            throw new ArgumentException("Invalid approved checkout page.", nameof(checkoutPage));
        ArgumentNullException.ThrowIfNull(capabilities);
        if (capabilities.ScheduledPlanSwitch || capabilities.NativeMutationIdempotency)
            throw new ArgumentException("An unimplemented provider capability cannot be admitted.", nameof(capabilities));
        var methods = capabilities.PaymentMethods ?? throw new ArgumentException("Missing payment method capabilities.", nameof(capabilities));
        if (methods.Count > 64 || methods.Any(m => m is null) || methods.Select(m => m.Key).Distinct(StringComparer.Ordinal).Count() != methods.Count)
            throw new ArgumentException("Invalid payment method inventory.", nameof(capabilities));
        var copied = methods.Select(CopyMethod).ToArray();
        OperationTimeout = operationTimeout ?? TimeSpan.FromSeconds(30);
        SignatureTolerance = signatureTolerance ?? TimeSpan.FromSeconds(5);
        if (OperationTimeout < TimeSpan.FromMilliseconds(1) || OperationTimeout > TimeSpan.FromMinutes(2)
            || SignatureTolerance < TimeSpan.FromSeconds(1) || SignatureTolerance > TimeSpan.FromMinutes(5)
            || maxResponseBytes is < 1024 or > 16 * 1024 * 1024 || maxReadRetries is < 0 or > 3)
            throw new ArgumentException("Invalid bounded transport configuration.");
        Environment = environment; Credential = credential; Source = source; CheckoutPage = checkoutPage;
        WebhookKeys = webhookSecrets.ToArray();
        Capabilities = capabilities with { PaymentMethods = Array.AsReadOnly(copied) };
        MaxResponseBytes = maxResponseBytes; MaxReadRetries = maxReadRetries;
    }

    private static PaymentMethodCapability CopyMethod(PaymentMethodCapability method)
    {
        if (!ProviderInput.Key(method.Key) || method.Currencies is null || method.Platforms is null || method.RenewalCaps is null
            || method.Currencies.Count is < 1 or > 256 || method.Platforms.Count is < 1 or > 3
            || method.Currencies.Any(c => !ProviderInput.Currency(c)) || method.Platforms.Any(p => !Enum.IsDefined(p))
            || method.Currencies.Distinct(StringComparer.Ordinal).Count() != method.Currencies.Count
            || method.Platforms.Distinct().Count() != method.Platforms.Count
            || method.RenewalCaps.Any(p => !method.Currencies.Contains(p.Key, StringComparer.Ordinal) || !ProviderInput.Amount(p.Value, positive: true)))
            throw new ArgumentException("Invalid payment method capability data.");
        return method with
        {
            Currencies = Array.AsReadOnly(method.Currencies.ToArray()),
            Platforms = Array.AsReadOnly(method.Platforms.ToArray()),
            RenewalCaps = new ReadOnlyDictionary<string, string>(method.RenewalCaps.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal)),
        };
    }
}

internal static class ProviderInput
{
    internal static bool Key(string? value) => value is { Length: > 0 and <= 128 }
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
    internal static bool Currency(string? value) => value is { Length: 3 } && value.All(c => c is >= 'A' and <= 'Z');
    internal static bool Country(string? value) => value is { Length: 2 } && value.All(c => c is >= 'A' and <= 'Z');
    internal static bool Amount(string? value, bool positive = false, bool signed = false)
    {
        if (value is null || value.Length is 0 or > 29) return false;
        var digits = value.AsSpan();
        if (signed && digits[0] == '-') digits = digits[1..];
        if (digits.Length is 0 or > 28 || (digits.Length > 1 && digits[0] == '0') || value == "-0") return false;
        foreach (var digit in digits) if (digit is < '0' or > '9') return false;
        if (!decimal.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var amount)) return false;
        return !positive || amount > 0;
    }
    internal static bool Id(string? value) => value is not null && Guid.TryParseExact(value, "D", out var id)
        && id != Guid.Empty && id.ToString("D", CultureInfo.InvariantCulture) == value;
    internal static bool Metadata(PurchaseMetadata? value) => value is not null
        && Id(value.RealmId) && Id(value.BillingAccountId) && Id(value.WorkspaceId) && Id(value.PurchaseIntentId)
        && Id(value.CheckoutAttemptId) && Id(value.OfferId) && Key(value.PriceVersion) && Key(value.PolicyVersion);
    internal static bool Reference(string? value, string prefix) => value is not null && value.StartsWith(prefix + "_", StringComparison.Ordinal)
        && value.Length == prefix.Length + 27 && value.AsSpan(prefix.Length + 1).ToArray().All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9');
    internal static void RequireReference(ProviderReference? reference, string prefix)
    {
        if (!Reference(reference?.Value, prefix)) throw new ArgumentException("Invalid opaque provider reference.", nameof(reference));
    }
    internal static void RequireCursor(string? cursor, string prefix)
    {
        if (cursor is not null && !Reference(cursor, prefix)) throw new ArgumentException("Invalid opaque cursor.", nameof(cursor));
    }
}
