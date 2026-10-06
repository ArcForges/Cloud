// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Cloud.Modules.Commerce.Adapters;

public static class BillingProviderFactory
{
    /// <summary>The handler is owned by the returned adapter. Infrastructure may supply its restricted egress/TLS handler.</summary>
    public static IBillingProvider Create(ProviderAdapterSettings settings, HttpMessageHandler? handler = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return new PaddleBillingProvider(settings, handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            MaxConnectionsPerServer = 16,
            ConnectTimeout = TimeSpan.FromSeconds(10),
        }, timeProvider ?? TimeProvider.System);
    }
}

internal sealed class PaddleBillingProvider : IBillingProvider
{
    private readonly ProviderAdapterSettings settings;
    private readonly TimeProvider clock;
    private readonly PaddleNormalization normalize;
    private readonly HttpClient client;
    private readonly CancellationTokenSource lifetime = new();
    private readonly CancellationToken lifetimeToken;
    private readonly (string Version, byte[] Key)[] webhookKeys;
    private int disposed;
    public BillingProviderCapabilities Capabilities => settings.Capabilities;
    public Uri ApiOrigin { get; }

    internal PaddleBillingProvider(ProviderAdapterSettings settings, HttpMessageHandler handler, TimeProvider clock)
    {
        this.settings = settings; this.clock = clock; normalize = new PaddleNormalization(settings);
        ApiOrigin = new Uri(settings.Environment == BillingEnvironment.Production ? "https://api.paddle.com/" : "https://sandbox-api.paddle.com/");
        client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan, BaseAddress = ApiOrigin };
        lifetimeToken = lifetime.Token;
        webhookKeys = settings.WebhookKeys.Select(k => (k.Version, Encoding.UTF8.GetBytes(k.Secret))).ToArray();
    }

    private static bool ValidTerms(ProviderPricingTerms? terms)
    {
        static bool ValidCycle(ProviderBillingCycle? cycle) => cycle is null || cycle.Frequency > 0 && cycle.Interval is "day" or "week" or "month" or "year";
        if (terms is null || !ValidCycle(terms.BillingCycle)) return false;
        if (terms.Trial is not { } trial) return true;
        if (terms.BillingCycle is null || trial.Cycle is null || !ValidCycle(trial.Cycle) || trial.CountryPrices is null || trial.CountryPrices.Count > 250) return false;
        static bool ValidMoney(ProviderMoney? money) => money is null || ProviderInput.Currency(money.Currency) && ProviderInput.Amount(money.MinorUnits);
        if (!ValidMoney(trial.Money)) return false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        return trial.CountryPrices.All(p => p is not null && p.Money is not null && ValidMoney(p.Money) && p.Countries is { Count: > 0 }
            && p.Countries.All(c => ProviderInput.Country(c) && seen.Add(c)));
    }
    private static ProviderPricingTerms SnapshotTerms(ProviderPricingTerms terms) => terms with
    {
        Trial = terms.Trial is null ? null : terms.Trial with
        { CountryPrices = Array.AsReadOnly(terms.Trial.CountryPrices.Select(p => p with { Countries = Array.AsReadOnly(p.Countries.ToArray()) }).ToArray()) }
    };
    private static bool SameTerms(ProviderPricingTerms left, ProviderPricingTerms right)
    {
        if (left.BillingCycle != right.BillingCycle) return false;
        if (left.Trial is null || right.Trial is null) return left.Trial is null && right.Trial is null;
        return left.Trial.Cycle == right.Trial.Cycle && left.Trial.RequiresPaymentMethod == right.Trial.RequiresPaymentMethod
            && left.Trial.Money == right.Trial.Money
            && left.Trial.CountryPrices.SelectMany(p => p.Countries.Select(c => (c, p.Money))).OrderBy(p => p.c, StringComparer.Ordinal)
                .SequenceEqual(right.Trial.CountryPrices.SelectMany(p => p.Countries.Select(c => (c, p.Money))).OrderBy(p => p.c, StringComparer.Ordinal));
    }
    public Task<ProviderPriceSnapshot> GetPriceAsync(ProviderReference reference, CancellationToken cancellationToken)
    {
        ProviderInput.RequireReference(reference, "pri");
        return Read("prices/" + reference.Value + "?include=product", d => Bound(normalize.Price(d), reference), cancellationToken);
    }

    public async Task<HostedCheckout> CreateCheckoutAsync(CheckoutRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ProviderInput.RequireReference(request.Price, "pri");
        if (!Enum.IsDefined(request.Kind) || !Enum.IsDefined(request.Platform) || !Enum.IsDefined(request.ExpectedTaxTreatment) || !ProviderInput.Country(request.Country)
            || request.ExpectedUnitPrice is null || !ProviderInput.Currency(request.ExpectedUnitPrice.Currency)
            || !ProviderInput.Amount(request.ExpectedUnitPrice.MinorUnits, positive: true) || !ProviderInput.Key(request.ExpectedTaxCategory)
            || !ProviderInput.Metadata(request.Metadata) || !ValidTerms(request.ExpectedTerms)) throw new ArgumentException("Invalid captured checkout terms.", nameof(request));
        var expectedTerms = SnapshotTerms(request.ExpectedTerms);
        if (!Capabilities.HostedCheckout || !Capabilities.PaymentMethods.Any(m => m.Approved && m.Currencies.Contains(request.ExpectedUnitPrice.Currency, StringComparer.Ordinal)
            && m.Platforms.Contains(request.Platform) && (request.Kind == PurchaseKind.OneTime ? m.OneTime : m.Recurring)
            && (request.Kind != PurchaseKind.Recurring || !m.RenewalCaps.TryGetValue(request.ExpectedUnitPrice.Currency, out var cap)
                || decimal.Parse(request.ExpectedUnitPrice.MinorUnits, CultureInfo.InvariantCulture) <= decimal.Parse(cap, CultureInfo.InvariantCulture))))
            throw new BillingProviderException(ProviderFailureKind.Unsupported);
        using var deadline = new CancellationTokenSource(settings.OperationTimeout, clock);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            var price = await GetPriceAsync(request.Price, operation.Token).ConfigureAwait(false);
            var amount = price.CountryPrices.SingleOrDefault(p => p.Countries.Contains(request.Country, StringComparer.Ordinal))?.Money ?? price.Money;
            if (!price.Active || amount != request.ExpectedUnitPrice || price.TaxCategory != request.ExpectedTaxCategory || price.TaxTreatment != request.ExpectedTaxTreatment
                || (price.Interval is null ? PurchaseKind.OneTime : PurchaseKind.Recurring) != request.Kind || !SameTerms(price.Terms, expectedTerms))
                throw new BillingProviderException(ProviderFailureKind.Conflict);
            var m = request.Metadata;
            var body = new ApiCheckoutBody([new ApiItem(request.Price.Value, 1)], amount.Currency, "automatic",
                new ApiMetadata(m.RealmId, m.BillingAccountId, m.WorkspaceId, m.PurchaseIntentId, m.CheckoutAttemptId, m.OfferId, m.PriceVersion, m.PolicyVersion),
                new ApiCheckout(settings.CheckoutPage.AbsoluteUri));
            return await Write(HttpMethod.Post, "transactions", JsonSerializer.SerializeToUtf8Bytes(body, PaddleJsonContext.Default.ApiCheckoutBody), data =>
            {
                var reference = PaddleNormalization.Reference(data, "id", "txn");
                if (PaddleNormalization.Metadata(data) != request.Metadata) throw PaddleNormalization.Invalid();
                if (PaddleNormalization.Text(data, "currency_code", 3) != amount.Currency) throw PaddleNormalization.Invalid();
                var receiptItems = PaddleNormalization.Required(data, "items", JsonValueKind.Array);
                if (receiptItems.GetArrayLength() != 1) throw PaddleNormalization.Invalid();
                var item = receiptItems[0]; var receiptPrice = PaddleNormalization.Required(item, "price", JsonValueKind.Object);
                if (PaddleNormalization.Reference(receiptPrice, "id", "pri") != request.Price || item.GetProperty("quantity").GetInt32() != 1)
                    throw PaddleNormalization.Invalid();
                var receiptMoney = PaddleNormalization.Required(receiptPrice, "unit_price", JsonValueKind.Object);
                // Region overrides remain in the price snapshot; the top-level transaction currency and the selected price override are bound together.
                var receiptBase = PaddleNormalization.Money(receiptMoney, "amount", PaddleNormalization.Text(receiptMoney, "currency_code", 3));
                var receiptCountryPrices = PaddleNormalization.CountryPrices(receiptPrice);
                var receiptEffectivePrice = receiptCountryPrices.SingleOrDefault(p => p.Countries.Contains(request.Country, StringComparer.Ordinal))?.Money ?? receiptBase;
                if (receiptBase != price.Money || PaddleNormalization.TaxTreatment(receiptPrice) != request.ExpectedTaxTreatment
                    || receiptEffectivePrice != request.ExpectedUnitPrice
                    || !SameTerms(PaddleNormalization.PricingTerms(receiptPrice), expectedTerms)) throw PaddleNormalization.Invalid();
                var checkout = PaddleNormalization.Required(data, "checkout", JsonValueKind.Object);
                var url = SafeUrl(PaddleNormalization.Text(checkout, "url"));
                if (url.GetLeftPart(UriPartial.Path) != settings.CheckoutPage.GetLeftPart(UriPartial.Path)
                    || url.Query != "?_ptxn=" + reference.Value) throw PaddleNormalization.Invalid();
                return new HostedCheckout(reference, url);
            }, operation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new BillingProviderException(ProviderFailureKind.Transport); }
    }

    public Task<ProviderTransaction> GetTransactionAsync(ProviderReference reference, CancellationToken cancellationToken)
    {
        ProviderInput.RequireReference(reference, "txn");
        return Read("transactions/" + reference.Value + "?include=address", d => Bound(normalize.Transaction(d), reference), cancellationToken);
    }
    public Task<ProviderPage<ProviderTransaction>> ListTransactionsAsync(DateTimeOffset updatedFrom, DateTimeOffset updatedTo, string? cursor, CancellationToken cancellationToken)
    {
        if (updatedFrom > updatedTo || updatedFrom.UtcTicks % 10 != 0 || updatedTo.UtcTicks % 10 != 0) throw new ArgumentException("Invalid reconciliation window.");
        ProviderInput.RequireCursor(cursor, "txn");
        var query = "per_page=30&include=address&updated_at[GTE]=" + Uri.EscapeDataString(updatedFrom.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture))
            + "&updated_at[LTE]=" + Uri.EscapeDataString(updatedTo.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture));
        return List("transactions", query, cursor, "txn", 30, normalize.Transaction, cancellationToken);
    }
    public Task<ProviderSubscription> GetSubscriptionAsync(ProviderReference reference, CancellationToken cancellationToken)
    {
        ProviderInput.RequireReference(reference, "sub");
        return Read("subscriptions/" + reference.Value, d => Bound(normalize.Subscription(d), reference), cancellationToken);
    }
    public Task<ProviderPage<ProviderSubscription>> ListSubscriptionsAsync(string? cursor, CancellationToken cancellationToken)
        => List("subscriptions", "per_page=30", cursor, "sub", 30, normalize.Subscription, cancellationToken);
    public Task<ProviderSubscription> CancelSubscriptionAsync(ProviderReference reference, CancellationToken cancellationToken)
    {
        ProviderInput.RequireReference(reference, "sub");
        Require(Capabilities.CancelAtPeriodEnd);
        return Write(HttpMethod.Post, "subscriptions/" + reference.Value + "/cancel",
            JsonSerializer.SerializeToUtf8Bytes(new ApiCancellation("next_billing_period"), PaddleJsonContext.Default.ApiCancellation), data =>
            {
                var result = Bound(normalize.Subscription(data), reference);
                if (result.CancellationAt is null && result.State != ProviderSubscriptionState.Canceled) throw PaddleNormalization.Invalid();
                return result;
            }, cancellationToken);
    }
    public async Task<ProviderSubscription> ReactivateScheduledCancellationAsync(ProviderReference reference, CancellationToken cancellationToken)
    {
        ProviderInput.RequireReference(reference, "sub");
        Require(Capabilities.ReactivateScheduledCancellation);
        using var deadline = new CancellationTokenSource(settings.OperationTimeout, clock);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            var current = await GetSubscriptionAsync(reference, operation.Token).ConfigureAwait(false);
            if (current.ScheduledAction != ProviderScheduledAction.Cancel || current.CancellationAt is null
                || current.State is not (ProviderSubscriptionState.Active or ProviderSubscriptionState.PastDue or ProviderSubscriptionState.Pending))
                throw new BillingProviderException(ProviderFailureKind.Conflict);
            return await Write(HttpMethod.Patch, "subscriptions/" + reference.Value,
                JsonSerializer.SerializeToUtf8Bytes(new ApiReactivation(null), PaddleJsonContext.Default.ApiReactivation), data =>
                {
                    var result = Bound(normalize.Subscription(data), reference);
                    if (!result.AutoRenew || result.ScheduledAction != ProviderScheduledAction.None || result.CancellationAt is not null
                        || result.Customer != current.Customer) throw PaddleNormalization.Invalid();
                    return result;
                }, operation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new BillingProviderException(ProviderFailureKind.Transport); }
    }
    public Task<ProviderAdjustment> CreateRefundAsync(RefundRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ProviderInput.RequireReference(request.Transaction, "txn");
        if (request.Reason is null || request.Reason.Length is < 1 or > 255 || request.Reason.Any(char.IsControl)
            || request.Items is null || request.Items.Count > 100 || request.Items.Any(i => i is null || i.TransactionItem is null)
            || request.Items.Select(i => i.TransactionItem.Value).Distinct(StringComparer.Ordinal).Count() != request.Items.Count)
            throw new ArgumentException("Invalid refund request.", nameof(request));
        foreach (var item in request.Items)
        {
            ProviderInput.RequireReference(item.TransactionItem, "txnitm");
            if (item.PartialMinorUnits is not null && !ProviderInput.Amount(item.PartialMinorUnits, positive: true))
                throw new ArgumentException("Invalid refund amount.", nameof(request));
        }
        if (request.Items.Count > 0) Require(Capabilities.PartialRefund);
        var requestedItems = request.Items.ToArray();
        var items = requestedItems.Length == 0 ? null : requestedItems.Select(i => new ApiRefundItem(i.TransactionItem.Value,
            i.PartialMinorUnits is null ? "full" : "partial", i.PartialMinorUnits)).ToArray();
        var body = new ApiRefundBody("refund", items is null ? "full" : "partial", request.Transaction.Value, request.Reason, items);
        return Write(HttpMethod.Post, "adjustments", JsonSerializer.SerializeToUtf8Bytes(body, PaddleJsonContext.Default.ApiRefundBody), data =>
        {
            var result = normalize.Adjustment(data);
            if (result.Transaction != request.Transaction || result.Kind != ProviderAdjustmentKind.Refund
                || result.Scope != (items is null ? ProviderAdjustmentScope.Full : ProviderAdjustmentScope.Partial)
                || items is not null && (result.Items.Count != items.Length || requestedItems.Any(expected =>
                    !result.Items.Any(actual => actual.TransactionItem == expected.TransactionItem
                        && actual.Scope == (expected.PartialMinorUnits is null ? ProviderAdjustmentScope.Full : ProviderAdjustmentScope.Partial)
                        && actual.Amount?.MinorUnits == expected.PartialMinorUnits)))) throw PaddleNormalization.Invalid();
            return result;
        }, cancellationToken);
    }
    public async Task<ProviderAdjustment> GetAdjustmentAsync(ProviderReference reference, CancellationToken cancellationToken)
    {
        ProviderInput.RequireReference(reference, "adj");
        var page = await List("adjustments", "per_page=1&id=" + reference.Value, null, "adj", 1, normalize.Adjustment, cancellationToken).ConfigureAwait(false);
        if (page.Items.Count == 0) throw new BillingProviderException(ProviderFailureKind.NotFound);
        if (page.NextCursor is not null) throw PaddleNormalization.Invalid();
        return Bound(page.Items.Single(), reference);
    }
    public Task<ProviderPage<ProviderAdjustment>> ListAdjustmentsAsync(string? cursor, CancellationToken cancellationToken)
        => List("adjustments", "per_page=30", cursor, "adj", 30, normalize.Adjustment, cancellationToken);
    public Task<ProviderPage<VerifiedProviderEvent>> ListEventsAsync(string? cursor, CancellationToken cancellationToken)
        => List("events", "per_page=200&order_by=id[ASC]", cursor, "evt", 200, normalize.Event, cancellationToken);

    public async Task<CustomerPortalLink> CreateCustomerPortalAsync(ProviderReference customer, IReadOnlyList<ProviderReference> subscriptions, CancellationToken cancellationToken)
    {
        ProviderInput.RequireReference(customer, "ctm"); Require(Capabilities.CustomerPortal);
        if (subscriptions is null || subscriptions.Count > 25 || subscriptions.Any(s => s is null)
            || subscriptions.Select(s => s.Value).Distinct(StringComparer.Ordinal).Count() != subscriptions.Count)
            throw new ArgumentException("Invalid portal subscription inventory.", nameof(subscriptions));
        using var deadline = new CancellationTokenSource(settings.OperationTimeout, clock);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            foreach (var subscription in subscriptions)
            {
                ProviderInput.RequireReference(subscription, "sub");
                if ((await GetSubscriptionAsync(subscription, operation.Token).ConfigureAwait(false)).Customer != customer)
                    throw new BillingProviderException(ProviderFailureKind.Forbidden);
            }
            return await Write(HttpMethod.Post, "customers/" + customer.Value + "/portal-sessions",
                JsonSerializer.SerializeToUtf8Bytes(new ApiPortalBody(subscriptions.Select(s => s.Value).ToArray()), PaddleJsonContext.Default.ApiPortalBody), data =>
                {
                    if (PaddleNormalization.Reference(data, "customer_id", "ctm") != customer) throw PaddleNormalization.Invalid();
                    var general = PaddleNormalization.Required(PaddleNormalization.Required(data, "urls", JsonValueKind.Object), "general", JsonValueKind.Object);
                    var url = SafeUrl(PaddleNormalization.Text(general, "overview", 4096));
                    var host = settings.Environment == BillingEnvironment.Production ? "customer-portal.paddle.com" : "sandbox-customer-portal.paddle.com";
                    var tokens = url.Query.TrimStart('?').Split('&').Where(p => p.StartsWith("token=", StringComparison.Ordinal)).ToArray();
                    if (url.Host != host || !ProviderInput.Reference(url.AbsolutePath.TrimStart('/'), "cpl")
                        || tokens.Length != 1 || tokens[0].Length <= 6) throw PaddleNormalization.Invalid();
                    return new CustomerPortalLink(url, PaddleNormalization.Instant(data, "created_at"));
                }, operation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new BillingProviderException(ProviderFailureKind.Transport); }
    }

    public WebhookVerification VerifyWebhook(ReadOnlyMemory<byte> rawBody, Func<string, string?> header)
    {
        ThrowIfDisposed(); ArgumentNullException.ThrowIfNull(header);
        if (rawBody.Length > settings.MaxResponseBytes) return new(WebhookVerdict.TooLarge, null, null, bodyBytes: rawBody.Length);
        rawBody = rawBody.ToArray(); // Signature, digest, and parsing must observe the same private snapshot even if the caller reuses its buffer.
        var digest = Convert.ToHexStringLower(SHA256.HashData(rawBody.Span));
        WebhookVerification Failure(WebhookVerdict verdict) => new(verdict, digest, null, bodyBytes: rawBody.Length);
        var signature = header("Paddle-Signature");
        if (string.IsNullOrEmpty(signature)) return Failure(WebhookVerdict.MissingSignature);
        if (signature.Length > 2048) return Failure(WebhookVerdict.InvalidSignature);
        string? timestamp = null; var hashes = new List<byte[]>();
        foreach (var part in signature.Split(';'))
        {
            var segment = part.Trim(); var equals = segment.IndexOf('=');
            if (equals <= 0) return Failure(WebhookVerdict.InvalidSignature);
            var key = segment[..equals]; var value = segment[(equals + 1)..];
            if (key == "ts" && timestamp is null && value.Length is > 0 and <= 12 && value.All(char.IsAsciiDigit)) timestamp = value;
            else if (key == "h1" && hashes.Count < 4 && value.Length == 64)
            {
                try { hashes.Add(Convert.FromHexString(value)); }
                catch (FormatException) { return Failure(WebhookVerdict.InvalidSignature); }
            }
            else return Failure(WebhookVerdict.InvalidSignature);
        }
        if (timestamp is null || hashes.Count == 0 || !long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            return Failure(WebhookVerdict.InvalidSignature);
        DateTimeOffset signedAt;
        try { signedAt = DateTimeOffset.FromUnixTimeSeconds(seconds); }
        catch (ArgumentOutOfRangeException) { return Failure(WebhookVerdict.InvalidSignature); }
        if ((clock.GetUtcNow() - signedAt).Duration() > settings.SignatureTolerance) return Failure(WebhookVerdict.ExpiredSignature);
        var prefix = Encoding.UTF8.GetBytes(timestamp + ":"); var material = new byte[prefix.Length + rawBody.Length];
        prefix.CopyTo(material, 0); rawBody.Span.CopyTo(material.AsSpan(prefix.Length));
        string? matchingVersion = null;
        foreach (var key in webhookKeys)
        {
            var expected = HMACSHA256.HashData(key.Key, material); var match = false;
            foreach (var hash in hashes) match |= CryptographicOperations.FixedTimeEquals(expected, hash);
            if (match && matchingVersion is null) matchingVersion = key.Version;
        }
        if (matchingVersion is null) return Failure(WebhookVerdict.InvalidSignature);
        var verifiedAt = clock.GetUtcNow();
        try
        {
            using var document = Parse(rawBody);
            var providerEvent = normalize.Event(document.RootElement);
            var projection = providerEvent.Kind == ProviderEventKind.Unsupported ? null
                : JsonSerializer.SerializeToUtf8Bytes(new ProviderProjectionEnvelope(1, providerEvent), PaddleJsonContext.Default.ProviderProjectionEnvelope);
            var projectionDigest = projection is null ? null : Convert.ToHexStringLower(SHA256.HashData(projection));
            var receipt = new ProviderVerificationReceipt(settings.Source, matchingVersion, signedAt, verifiedAt, digest, rawBody.Length, projectionDigest);
            return new(WebhookVerdict.Verified, digest, providerEvent, receipt, projection);
        }
        catch (Exception ex) when (Malformed(ex))
        {
            return new(WebhookVerdict.InvalidPayload, digest, null,
                new ProviderVerificationReceipt(settings.Source, matchingVersion, signedAt, verifiedAt, digest, rawBody.Length, null));
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        lifetime.Cancel(); client.Dispose(); lifetime.Dispose();
        // Notification verification may already be executing concurrently; immutable key copies avoid a dispose/verification race.
    }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private static void Require(bool supported) { if (!supported) throw new BillingProviderException(ProviderFailureKind.Unsupported); }
    private static ProviderPriceSnapshot Bound(ProviderPriceSnapshot value, ProviderReference expected) => value.Reference == expected ? value : throw PaddleNormalization.Invalid();
    private static ProviderTransaction Bound(ProviderTransaction value, ProviderReference expected) => value.Reference == expected ? value : throw PaddleNormalization.Invalid();
    private static ProviderSubscription Bound(ProviderSubscription value, ProviderReference expected) => value.Reference == expected ? value : throw PaddleNormalization.Invalid();
    private static ProviderAdjustment Bound(ProviderAdjustment value, ProviderReference expected) => value.Reference == expected ? value : throw PaddleNormalization.Invalid();
    private static Uri SafeUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Port != 443 || uri.UserInfo.Length != 0
            || uri.Fragment.Length != 0 || uri.HostNameType != UriHostNameType.Dns) throw PaddleNormalization.Invalid();
        return uri;
    }
    private Task<T> Read<T>(string path, Func<JsonElement, T> extract, CancellationToken cancellationToken)
        => Request(HttpMethod.Get, path, null, root => extract(PaddleNormalization.Required(root, "data", JsonValueKind.Object)), false, cancellationToken);
    private Task<T> Write<T>(HttpMethod method, string path, byte[] body, Func<JsonElement, T> extract, CancellationToken cancellationToken)
        => Request(method, path, body, root => extract(PaddleNormalization.Required(root, "data", JsonValueKind.Object)), true, cancellationToken);
    private Task<ProviderPage<T>> List<T>(string resource, string query, string? cursor, string prefix, int max, Func<JsonElement, T> extract, CancellationToken cancellationToken)
    {
        ProviderInput.RequireCursor(cursor, prefix);
        return Request(HttpMethod.Get, resource + "?" + query + (cursor is null ? "" : "&after=" + cursor), null, root =>
        {
            var items = new List<T>();
            foreach (var item in PaddleNormalization.Required(root, "data", JsonValueKind.Array).EnumerateArray())
            {
                if (items.Count == max || item.ValueKind != JsonValueKind.Object) throw PaddleNormalization.Invalid();
                items.Add(extract(item));
            }
            var pagination = PaddleNormalization.Required(PaddleNormalization.Required(root, "meta", JsonValueKind.Object), "pagination", JsonValueKind.Object);
            var more = pagination.GetProperty("has_more").GetBoolean();
            string? next = null;
            if (more)
            {
                var uri = SafeUrl(PaddleNormalization.Text(pagination, "next", 4096));
                if (uri.GetLeftPart(UriPartial.Authority) != ApiOrigin.GetLeftPart(UriPartial.Authority) || uri.AbsolutePath != "/" + resource) throw PaddleNormalization.Invalid();
                var pairs = uri.Query.TrimStart('?').Split('&');
                var after = pairs.Where(p => p.StartsWith("after=", StringComparison.Ordinal)).ToArray();
                if (after.Length != 1) throw PaddleNormalization.Invalid();
                next = Uri.UnescapeDataString(after[0][6..]);
                if (!ProviderInput.Reference(next, prefix) || next == cursor || items.Count == 0) throw PaddleNormalization.Invalid();
            }
            return new ProviderPage<T>(items.AsReadOnly(), next);
        }, false, cancellationToken);
    }
    private async Task<T> Request<T>(HttpMethod method, string path, byte[]? body, Func<JsonElement, T> extract, bool mutation, CancellationToken cancellationToken)
    {
        ThrowIfDisposed(); cancellationToken.ThrowIfCancellationRequested();
        using var timeout = new CancellationTokenSource(settings.OperationTimeout, clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetimeToken, timeout.Token);
        var token = linked.Token; var dispatched = false;
        try
        {
            for (var attempt = 0; ; attempt++)
            {
                token.ThrowIfCancellationRequested();
                using var request = new HttpRequestMessage(method, path);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.Credential);
                request.Headers.Add("Paddle-Version", "1");
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                if (body is not null) { request.Content = new ByteArrayContent(body); request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json"); }
                HttpResponseMessage response;
                try { dispatched = true; response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false); }
                catch (HttpRequestException) when (!mutation && attempt < settings.MaxReadRetries)
                {
                    await Task.Delay(Backoff(attempt), clock, token).ConfigureAwait(false); continue;
                }
                using (response)
                {
                    var status = (int)response.StatusCode;
                    if (status is 429 or >= 500 && !mutation && attempt < settings.MaxReadRetries)
                    {
                        await Task.Delay(RetryAfter(response) ?? Backoff(attempt), clock, token).ConfigureAwait(false); continue;
                    }
                    if (!response.IsSuccessStatusCode)
                    {
                        var kind = status switch
                        {
                            401 => ProviderFailureKind.Unauthorized,
                            403 => ProviderFailureKind.Forbidden,
                            404 => ProviderFailureKind.NotFound,
                            409 => ProviderFailureKind.Conflict,
                            429 => ProviderFailureKind.RateLimited,
                            >= 500 when mutation => ProviderFailureKind.UnknownOutcome,
                            >= 500 => ProviderFailureKind.Transport,
                            >= 400 and < 500 => ProviderFailureKind.Rejected,
                            _ => mutation ? ProviderFailureKind.UnknownOutcome : ProviderFailureKind.Protocol
                        };
                        throw new BillingProviderException(kind, status, RetryAfter(response));
                    }
                    if (response.Content.Headers.ContentType?.MediaType != "application/json") throw PaddleNormalization.Invalid();
                    if (response.Content.Headers.ContentLength > settings.MaxResponseBytes) throw PaddleNormalization.Invalid();
                    await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
                    using var buffer = new MemoryStream(); var chunk = new byte[8192];
                    while (true)
                    {
                        var read = await stream.ReadAsync(chunk, token).ConfigureAwait(false); if (read == 0) break;
                        if (buffer.Length + read > settings.MaxResponseBytes) throw PaddleNormalization.Invalid();
                        buffer.Write(chunk, 0, read);
                    }
                    using var document = Parse(buffer.ToArray());
                    return extract(document.RootElement);
                }
            }
        }
        catch (OperationCanceledException) when (mutation && dispatched) { throw new BillingProviderException(ProviderFailureKind.UnknownOutcome); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && !lifetimeToken.IsCancellationRequested)
        { throw new BillingProviderException(ProviderFailureKind.Transport); }
        catch (HttpRequestException) { throw new BillingProviderException(mutation && dispatched ? ProviderFailureKind.UnknownOutcome : ProviderFailureKind.Transport); }
        catch (IOException) { throw new BillingProviderException(mutation && dispatched ? ProviderFailureKind.UnknownOutcome : ProviderFailureKind.Transport); }
        catch (ObjectDisposedException) when (mutation && dispatched) { throw new BillingProviderException(ProviderFailureKind.UnknownOutcome); }
        catch (Exception ex) when (Malformed(ex)) { throw new BillingProviderException(mutation && dispatched ? ProviderFailureKind.UnknownOutcome : ProviderFailureKind.Protocol); }
    }
    private static bool Malformed(Exception ex) => ex is JsonException or InvalidOperationException or FormatException or OverflowException or KeyNotFoundException
        || ex is BillingProviderException { Kind: ProviderFailureKind.Protocol };
    private static JsonDocument Parse(ReadOnlyMemory<byte> bytes)
    {
        var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        try { PaddleNormalization.NoDuplicateProperties(document.RootElement); return document; }
        catch { document.Dispose(); throw; }
    }
    private static TimeSpan Backoff(int attempt) => TimeSpan.FromMilliseconds(100 * (1 << attempt));
    private TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter; if (header is null) return null;
        var duration = header.Delta ?? (header.Date - clock.GetUtcNow());
        return duration is null ? null : TimeSpan.FromTicks(Math.Clamp(duration.Value.Ticks, 0, TimeSpan.FromSeconds(2).Ticks));
    }
}
