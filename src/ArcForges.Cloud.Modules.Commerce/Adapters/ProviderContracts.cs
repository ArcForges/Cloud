// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Commerce.Adapters;

public enum BillingEnvironment { Production, Sandbox }
public enum PurchaseKind { OneTime, Recurring }
public enum ProviderTaxTreatment { Included, Excluded, AccountSetting }
public enum CommerceClientPlatform { DesktopWeb, MobileWeb, DesktopApplication }
public enum ProviderFailureKind { Unsupported, Unauthorized, Forbidden, NotFound, Conflict, Rejected, RateLimited, Transport, Protocol, UnknownOutcome }
public enum ProviderPaymentState { Pending, Completed, Failed, Canceled }
public enum ProviderSubscriptionState { Pending, Active, PastDue, Paused, Canceled, Unknown }
public enum ProviderAdjustmentKind { Refund, Credit, CreditReversal, Dispute, DisputeReversal, Warning, WarningReversal, Unknown }
public enum ProviderAdjustmentState { Pending, Approved, Rejected, Reversed, Unknown }
public enum ProviderAdjustmentScope { Full, Partial, Tax, Prorated, Unknown }
public enum ProviderEventKind { PaymentChanged, PaymentCompleted, SubscriptionChanged, AdjustmentChanged, Unsupported }
public enum WebhookVerdict { Verified, MissingSignature, InvalidSignature, ExpiredSignature, InvalidPayload, TooLarge }

/// <summary>All references are opaque: consumers must never parse or infer a provider identifier format.</summary>
public sealed record ProviderReference(string Value);
public sealed record ProviderMoney(string MinorUnits, string Currency);
public sealed record CountryPrice(IReadOnlyList<string> Countries, ProviderMoney Money);
public sealed record ProviderPriceSnapshot(ProviderReference Reference, ProviderReference Product, bool Active, string TaxCategory, ProviderTaxTreatment TaxTreatment,
    ProviderMoney Money, string? Interval, int? Frequency, IReadOnlyList<CountryPrice> CountryPrices);

public sealed record PaymentMethodCapability(string Key, bool OneTime, bool Recurring, IReadOnlyList<string> Currencies,
    IReadOnlyList<CommerceClientPlatform> Platforms, bool SeparateApprovalRequired, bool Approved, bool Chargebacks,
    bool SavedMethods, IReadOnlyDictionary<string, string> RenewalCaps);

public sealed record BillingProviderCapabilities(bool HostedCheckout, bool CancelAtPeriodEnd, bool ReactivateScheduledCancellation,
    bool PartialRefund, bool CustomerPortal, bool ScheduledPlanSwitch, bool NativeMutationIdempotency,
    IReadOnlyList<PaymentMethodCapability> PaymentMethods);

/// <summary>Server-owned immutable binding. It contains no email or payment-instrument data.</summary>
public sealed record PurchaseMetadata(string RealmId, string BillingAccountId, string WorkspaceId, string PurchaseIntentId,
    string CheckoutAttemptId, string OfferId, string PriceVersion, string PolicyVersion);

public sealed record CheckoutRequest(ProviderReference Price, ProviderMoney ExpectedUnitPrice, PurchaseKind Kind,
    CommerceClientPlatform Platform, string Country, string ExpectedTaxCategory, ProviderTaxTreatment ExpectedTaxTreatment, PurchaseMetadata Metadata);
public sealed record HostedCheckout(ProviderReference Transaction, Uri Url);
public sealed record ProviderLineFinancials(ProviderMoney UnitSubtotal, ProviderMoney UnitDiscount, ProviderMoney UnitTax, ProviderMoney UnitTotal,
    ProviderMoney Subtotal, ProviderMoney Discount, ProviderMoney Tax, ProviderMoney Total, string TaxCategory);
public sealed record ProviderLineItem(ProviderReference Price, ProviderReference? TransactionItem, int Quantity, ProviderLineFinancials? Financials, ProviderPeriod? ProrationPeriod = null);
public sealed record ProviderPeriod(DateTimeOffset StartsAt, DateTimeOffset EndsAt);
public sealed record ProviderTransaction(ProviderReference Reference, ProviderReference? Customer, ProviderReference? Subscription,
    ProviderPaymentState State, string DiagnosticStatus, ProviderMoney Total, ProviderMoney? Tax, ProviderMoney? Fee,
    ProviderMoney? Earnings, PurchaseMetadata? Metadata, IReadOnlyList<ProviderLineItem> Items, ProviderPeriod? Period,
    DateTimeOffset UpdatedAt, string? BillingCountry, DateTimeOffset? CustomerInformationRevisedAt,
    ProviderFinancialTotals Financials, ProviderFinancialTotals? PayoutFinancials, ProviderFinancialTotals? AdjustedFinancials, ProviderFinancialTotals? AdjustedPayoutFinancials);
/// <summary>The provider's current period is evidence to reconcile; it is never paid-service or authorization authority.</summary>
public sealed record ProviderSubscription(ProviderReference Reference, ProviderReference Customer, ProviderSubscriptionState State,
    string DiagnosticStatus, bool AutoRenew, DateTimeOffset? CancellationAt, ProviderPeriod? CurrentPeriod,
    PurchaseMetadata? Metadata, IReadOnlyList<ProviderLineItem> Items, DateTimeOffset UpdatedAt);
public sealed record RefundItem(ProviderReference TransactionItem, string? PartialMinorUnits);
public sealed record RefundRequest(ProviderReference Transaction, string Reason, IReadOnlyList<RefundItem> Items);
public sealed record ProviderFinancialTotals(ProviderMoney Subtotal, ProviderMoney Tax, ProviderMoney Total,
    ProviderMoney? Fee, ProviderMoney? Earnings, ProviderMoney? RetainedFee, ProviderMoney? ChargebackFee, ProviderMoney? OriginalChargebackFee,
    ProviderMoney? Discount, ProviderMoney? Credit, ProviderMoney? CreditToBalance, ProviderMoney? Balance, ProviderMoney? GrandTotal, ProviderMoney? GrandTotalTax);
public sealed record ProviderAdjustmentLine(ProviderReference Reference, ProviderReference TransactionItem, ProviderAdjustmentScope Scope,
    ProviderMoney? Amount, ProviderMoney Subtotal, ProviderMoney Tax, ProviderMoney Total, ProviderPeriod? Period);
public sealed record ProviderAdjustment(ProviderReference Reference, ProviderReference Transaction, ProviderReference? Subscription,
    ProviderAdjustmentKind Kind, ProviderAdjustmentState State, ProviderMoney Total, DateTimeOffset UpdatedAt,
    ProviderReference Customer, ProviderAdjustmentScope Scope, IReadOnlyList<ProviderAdjustmentLine> Items,
    ProviderFinancialTotals Financials, ProviderFinancialTotals? PayoutFinancials, bool? CreditAppliedToBalance);
public sealed record ProviderPage<T>(IReadOnlyList<T> Items, string? NextCursor);

/// <summary>Only the adapter can construct a verified event; no provider JSON schema crosses this boundary.</summary>
public sealed class VerifiedProviderEvent
{
    internal VerifiedProviderEvent(string source, ProviderReference reference, string dedupeKey, ProviderEventKind kind,
        DateTimeOffset occurredAt, ProviderTransaction? transaction, ProviderSubscription? subscription, ProviderAdjustment? adjustment)
    {
        Source = source; Reference = reference; DedupeKey = dedupeKey; Kind = kind; OccurredAt = occurredAt;
        Transaction = transaction; Subscription = subscription; Adjustment = adjustment;
    }

    public string Source { get; }
    public ProviderReference Reference { get; }
    public string DedupeKey { get; }
    public ProviderEventKind Kind { get; }
    public DateTimeOffset OccurredAt { get; }
    public ProviderTransaction? Transaction { get; }
    public ProviderSubscription? Subscription { get; }
    public ProviderAdjustment? Adjustment { get; }
}

/// <summary>Facts about the exact received bytes; projection integrity is distinct from re-verifying an original signature.</summary>
public sealed class ProviderVerificationReceipt
{
    internal ProviderVerificationReceipt(string source, string verificationKeyVersion, DateTimeOffset signedAt, DateTimeOffset verifiedAt,
        string bodySha256, int bodyBytes, string? projectionSha256)
    {
        Source = source; VerificationKeyVersion = verificationKeyVersion; SignedAt = signedAt; VerifiedAt = verifiedAt;
        BodySha256 = bodySha256; BodyBytes = bodyBytes; ProjectionSha256 = projectionSha256;
    }
    public string Source { get; }
    public string Algorithm => "HMAC-SHA256";
    public string VerificationKeyVersion { get; }
    public DateTimeOffset SignedAt { get; }
    public DateTimeOffset VerifiedAt { get; }
    public string BodySha256 { get; }
    public int BodyBytes { get; }
    public string? ProjectionSha256 { get; }
}

public sealed class WebhookVerification
{
    private readonly byte[]? projection;
    internal WebhookVerification(WebhookVerdict verdict, string? bodySha256, VerifiedProviderEvent? providerEvent,
        ProviderVerificationReceipt? receipt = null, byte[]? projection = null, int bodyBytes = 0)
    {
        Verdict = verdict; BodySha256 = bodySha256; Event = providerEvent; Receipt = receipt; this.projection = projection?.ToArray(); BodyBytes = receipt?.BodyBytes ?? bodyBytes;
    }
    public WebhookVerdict Verdict { get; }
    public string? BodySha256 { get; }
    public int BodyBytes { get; }
    public VerifiedProviderEvent? Event { get; }
    public ProviderVerificationReceipt? Receipt { get; }
    /// <summary>Version-one UTF-8 normalized projection. Each access returns an independent copy. Never contains the original supplier envelope.</summary>
    public ReadOnlyMemory<byte> Projection => projection?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
}

/// <summary>A portal URL is a temporary bearer credential, deliberately excluded from diagnostic stringification.</summary>
public sealed class CustomerPortalLink(Uri url, DateTimeOffset createdAt)
{
    public Uri Url { get; } = url;
    public DateTimeOffset CreatedAt { get; } = createdAt;
    public override string ToString() => "Temporary customer portal link";
}

public sealed class BillingProviderException(ProviderFailureKind kind, int statusCode = 0, TimeSpan? retryAfter = null)
    : Exception("Billing provider request failed: " + kind)
{
    public ProviderFailureKind Kind { get; } = kind;
    public int StatusCode { get; } = statusCode;
    public TimeSpan? RetryAfter { get; } = retryAfter;
}

/// <summary>Business admission and durable mutation fencing are Commerce responsibilities, before calling this port.</summary>
public interface IBillingProvider : IDisposable
{
    BillingProviderCapabilities Capabilities { get; }
    Uri ApiOrigin { get; }
    Task<ProviderPriceSnapshot> GetPriceAsync(ProviderReference reference, CancellationToken cancellationToken);
    Task<HostedCheckout> CreateCheckoutAsync(CheckoutRequest request, CancellationToken cancellationToken);
    Task<ProviderTransaction> GetTransactionAsync(ProviderReference reference, CancellationToken cancellationToken);
    Task<ProviderPage<ProviderTransaction>> ListTransactionsAsync(DateTimeOffset updatedFrom, DateTimeOffset updatedTo, string? cursor, CancellationToken cancellationToken);
    Task<ProviderSubscription> GetSubscriptionAsync(ProviderReference reference, CancellationToken cancellationToken);
    Task<ProviderPage<ProviderSubscription>> ListSubscriptionsAsync(string? cursor, CancellationToken cancellationToken);
    Task<ProviderSubscription> CancelSubscriptionAsync(ProviderReference reference, CancellationToken cancellationToken);
    Task<ProviderSubscription> ReactivateScheduledCancellationAsync(ProviderReference reference, CancellationToken cancellationToken);
    Task<ProviderAdjustment> CreateRefundAsync(RefundRequest request, CancellationToken cancellationToken);
    Task<ProviderAdjustment> GetAdjustmentAsync(ProviderReference reference, CancellationToken cancellationToken);
    Task<ProviderPage<ProviderAdjustment>> ListAdjustmentsAsync(string? cursor, CancellationToken cancellationToken);
    Task<ProviderPage<VerifiedProviderEvent>> ListEventsAsync(string? cursor, CancellationToken cancellationToken);
    Task<CustomerPortalLink> CreateCustomerPortalAsync(ProviderReference customer, IReadOnlyList<ProviderReference> subscriptions, CancellationToken cancellationToken);
    WebhookVerification VerifyWebhook(ReadOnlyMemory<byte> rawBody, Func<string, string?> header);
}
