// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Commerce.Adapters;
using Xunit;

namespace ArcForges.Cloud.Tests.Commerce.Adapter;

public sealed class ProviderAdapterTests
{
    private const string Suffix = "01grnn4zta5a1mf02jjze7y2ys";
    private const string Credential = "component-test-credential-only";
    private const string Secret = "component-test-webhook-key-only";
    private const string Instant = "2026-10-06T17:00:00.123456Z";
    private static readonly ProviderReference PriceId = new("pri_" + Suffix);
    private static readonly ProviderReference TransactionId = new("txn_" + Suffix);
    private static readonly ProviderReference SubscriptionId = new("sub_" + Suffix);
    private static readonly ProviderReference CustomerId = new("ctm_" + Suffix);
    private static readonly ProviderReference AdjustmentId = new("adj_" + Suffix);
    private static readonly PurchaseMetadata Metadata = new("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555",
        "66666666-6666-6666-6666-666666666666", "price-v1", "policy-v2");
    private static readonly BillingProviderCapabilities Capabilities = new(true, true, true, true, true, false, false,
        [new PaymentMethodCapability("approved-method", true, true, ["USD", "EUR"], [CommerceClientPlatform.DesktopWeb],
            true, true, true, true, new Dictionary<string, string> { ["USD"] = "5000" })]);
    private static readonly CheckoutRequest Checkout = new(PriceId, new ProviderMoney("1000", "USD"), PurchaseKind.Recurring,
        CommerceClientPlatform.DesktopWeb, "US", "standard", ProviderTaxTreatment.Included, Metadata);
    private static ProviderAdapterSettings Settings(BillingProviderCapabilities? capabilities = null, TimeSpan? timeout = null, int limit = 1024 * 1024,
        IReadOnlyList<string>? secrets = null, BillingEnvironment environment = BillingEnvironment.Production)
        => new(environment, Credential, (secrets ?? [Secret]).Select((s, i) => new ProviderNotificationKey("notification-v" + (i + 1), s)).ToArray(), "merchant-production-v1", new Uri("https://arcforges.com/billing/checkout"),
            capabilities ?? Capabilities, operationTimeout: timeout, maxResponseBytes: limit);
    private static string Json(object value) => JsonSerializer.Serialize(value);
    private static object MetadataJson => new
    {
        realm_id = Metadata.RealmId,
        billing_account_id = Metadata.BillingAccountId,
        workspace_id = Metadata.WorkspaceId,
        purchase_intent_id = Metadata.PurchaseIntentId,
        checkout_attempt_id = Metadata.CheckoutAttemptId,
        offer_id = Metadata.OfferId,
        price_version = Metadata.PriceVersion,
        policy_version = Metadata.PolicyVersion
    };
    private static object[] Items => [new { price = new { id = PriceId.Value }, quantity = 1 }];
    private static object Price(string amount = "1000", string currency = "USD", string status = "active") => new
    {
        id = PriceId.Value,
        product_id = "pro_" + Suffix,
        status,
        tax_mode = "internal",
        product = new { id = "pro_" + Suffix, status = "active", tax_category = "standard" },
        unit_price = new { amount, currency_code = currency },
        billing_cycle = new { interval = "month", frequency = 1 },
        unit_price_overrides = new[] { new { country_codes = new[] { "DE" }, unit_price = new { amount = "900", currency_code = "EUR" } } },
    };
    private static object Transaction(string status = "completed", string amount = "1000", object? metadata = null) => new
    {
        id = TransactionId.Value,
        customer_id = CustomerId.Value,
        subscription_id = SubscriptionId.Value,
        status,
        currency_code = "USD",
        details = new
        {
            totals = new { total = amount, tax = "100", fee = "20", earnings = "980" },
            line_items = new[] { new { id = "txnitm_" + Suffix, price_id = PriceId.Value, quantity = 1,
                unit_totals = new { subtotal = "900", discount = "0", tax = "100", total = "1000" },
                totals = new { subtotal = "900", discount = "0", tax = "100", total = "1000" }, product = new { tax_category = "standard" } } }
        },
        custom_data = metadata ?? MetadataJson,
        items = Items,
        updated_at = Instant,
        address = new { customer_id = CustomerId.Value, country_code = "US", first_line = "private not exported" },
        revised_at = (string?)null,
        billing_period = new { starts_at = "2026-10-01T00:00:00Z", ends_at = "2026-11-01T00:00:00Z" },
        payments = new[] { new { method_details = new { card = new { last4 = "7777" } } } },
    };
    private static object Subscription(bool canceled = false, string customer = "") => new
    {
        id = SubscriptionId.Value,
        customer_id = customer.Length == 0 ? CustomerId.Value : customer,
        status = "active",
        custom_data = MetadataJson,
        items = Items,
        updated_at = Instant,
        scheduled_change = canceled ? new { action = "cancel", effective_at = "2026-11-01T00:00:00Z" } : null,
        current_billing_period = new { starts_at = "2026-10-01T00:00:00Z", ends_at = "2026-11-01T00:00:00Z" },
    };
    private static object Adjustment(string status = "pending_approval", string action = "refund") => new
    {
        id = AdjustmentId.Value,
        transaction_id = TransactionId.Value,
        subscription_id = SubscriptionId.Value,
        action,
        status,
        currency_code = "USD",
        totals = new { total = "1000" },
        updated_at = Instant
    };
    private static object Event(string type = "transaction.completed", object? data = null) => new
    { event_id = "evt_" + Suffix, event_type = type, occurred_at = Instant, data = data ?? Transaction() };
    private static object CheckoutReceipt(string currency = "USD", string amount = "1000", string url = "") => new
    {
        id = TransactionId.Value,
        custom_data = MetadataJson,
        currency_code = currency,
        items = new[] { new { price = new { id = PriceId.Value, tax_mode = "internal", unit_price = new { amount, currency_code = "USD" } }, quantity = 1 } },
        checkout = new { url = url.Length == 0 ? "https://arcforges.com/billing/checkout?_ptxn=" + TransactionId.Value : url },
    };
    private static HttpResponseMessage Response(object data, HttpStatusCode status = HttpStatusCode.OK) => Raw(Json(new { data }), status);
    private static HttpResponseMessage Raw(string json, HttpStatusCode status = HttpStatusCode.OK)
        => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    private static HttpResponseMessage Page(object[] data, string? next = null) => Raw(Json(new { data, meta = new { pagination = new { has_more = next is not null, next } } }));
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => DateTimeOffset.Parse(Instant, CultureInfo.InvariantCulture); }
    private sealed record Call(string Method, Uri Uri, string Body, string? Authorization, string Version);
    private sealed class Transport(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        internal ConcurrentQueue<Call> Calls { get; } = new();
        internal bool Disposed { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls.Enqueue(new Call(request.Method.Method, request.RequestUri!, request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken),
                request.Headers.Authorization?.ToString(), request.Headers.GetValues("Paddle-Version").Single()));
            return await send(request, cancellationToken);
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private static Transport Handler(Func<HttpRequestMessage, HttpResponseMessage> send) => new((r, _) => Task.FromResult(send(r)));
    private static string Sign(byte[] body, string key = Secret, long? seconds = null)
    {
        var ts = (seconds ?? new Clock().GetUtcNow().ToUnixTimeSeconds()).ToString(CultureInfo.InvariantCulture);
        return "ts=" + ts + ";h1=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(ts + ":").Concat(body).ToArray()));
    }

    [Fact]
    public async Task FactoryUsesFixedEnvironmentAuthenticationAndNormalizesPriceAndRegions()
    {
        var transport = Handler(_ => Response(Price()));
        using var provider = BillingProviderFactory.Create(Settings(environment: BillingEnvironment.Sandbox), transport);
        var price = await provider.GetPriceAsync(PriceId, CancellationToken.None);
        Assert.Equal("https://sandbox-api.paddle.com/", provider.ApiOrigin.AbsoluteUri);
        Assert.Equal("1000", price.Money.MinorUnits); Assert.Equal("EUR", price.CountryPrices.Single().Money.Currency);
        Assert.Equal("standard", price.TaxCategory); Assert.True(price.Active); Assert.Equal("month", price.Interval);
        var call = transport.Calls.Single(); Assert.Equal("Bearer " + Credential, call.Authorization); Assert.Equal("1", call.Version);
        Assert.Equal("/prices/" + PriceId.Value + "?include=product", call.Uri.PathAndQuery);
    }
    [Fact]
    public async Task CheckoutBindsCapturedTermsAndServerMetadataBeforeOneRealMutation()
    {
        var transport = Handler(r => r.Method == HttpMethod.Get ? Response(Price()) : Response(CheckoutReceipt()));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        var checkout = await provider.CreateCheckoutAsync(Checkout, CancellationToken.None);
        Assert.Equal(TransactionId, checkout.Transaction); Assert.Equal(2, transport.Calls.Count);
        using var body = JsonDocument.Parse(transport.Calls.Last().Body);
        Assert.Equal(Metadata.WorkspaceId, body.RootElement.GetProperty("custom_data").GetProperty("workspace_id").GetString());
        Assert.Equal("automatic", body.RootElement.GetProperty("collection_mode").GetString());
        Assert.DoesNotContain("idempotency", transport.Calls.Last().Body, StringComparison.OrdinalIgnoreCase);
    }
    [Fact]
    public async Task RegionTermsApprovalAndRenewalCapsAreRealAdmissionChecks()
    {
        var transport = Handler(_ => Response(Price())); using var provider = BillingProviderFactory.Create(Settings(), transport);
        var stale = await Assert.ThrowsAsync<BillingProviderException>(() => provider.CreateCheckoutAsync(Checkout with { ExpectedUnitPrice = new("999", "USD") }, CancellationToken.None));
        Assert.Equal(ProviderFailureKind.Conflict, stale.Kind);
        var limit = await Assert.ThrowsAsync<BillingProviderException>(() => provider.CreateCheckoutAsync(Checkout with { ExpectedUnitPrice = new("5001", "USD") }, CancellationToken.None));
        Assert.Equal(ProviderFailureKind.Unsupported, limit.Kind); Assert.Single(transport.Calls);
        using var unavailable = BillingProviderFactory.Create(Settings(Capabilities with { PaymentMethods = [] }));
        var absent = await Assert.ThrowsAsync<BillingProviderException>(() => unavailable.CreateCheckoutAsync(Checkout, CancellationToken.None));
        Assert.Equal(ProviderFailureKind.Unsupported, absent.Kind);
    }
    [Fact]
    public async Task CapturedRegionalCurrencyCanCheckoutWithoutCurrencyFallback()
    {
        var transport = Handler(r => r.Method == HttpMethod.Get ? Response(Price()) : Response(CheckoutReceipt(currency: "EUR")));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        await provider.CreateCheckoutAsync(Checkout with { Country = "DE", ExpectedUnitPrice = new("900", "EUR") }, CancellationToken.None);
        Assert.Contains("\"currency_code\":\"EUR\"", transport.Calls.Last().Body, StringComparison.Ordinal);
    }
    [Theory]
    [InlineData("USD", "1001", "https://arcforges.com/billing/checkout?_ptxn=txn_01grnn4zta5a1mf02jjze7y2ys")]
    [InlineData("EUR", "1000", "https://arcforges.com/billing/checkout?_ptxn=txn_01grnn4zta5a1mf02jjze7y2ys")]
    [InlineData("USD", "1000", "https://attacker.invalid/billing/checkout?_ptxn=txn_01grnn4zta5a1mf02jjze7y2ys")]
    [InlineData("USD", "1000", "https://arcforges.com/billing/checkout?_ptxn=txn_01grnn4zta5a1mf02jjze7y2yt")]
    public async Task ChangedPriceOrUnboundCheckoutReceiptIsAnUnknownWriteOutcome(string currency, string amount, string url)
    {
        var transport = Handler(r => r.Method == HttpMethod.Get ? Response(Price()) : Response(CheckoutReceipt(currency, amount, url)));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        Assert.Equal(ProviderFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.CreateCheckoutAsync(Checkout, CancellationToken.None))).Kind);
        Assert.Equal(2, transport.Calls.Count);
    }
    [Fact]
    public async Task TransactionsSubscriptionsAdjustmentsAndEventPagesAreNormalizedWithoutInstrumentData()
    {
        var transport = Handler(r => r.RequestUri!.AbsolutePath switch
        {
            var p when p == "/transactions/" + TransactionId.Value => Response(Transaction()),
            "/transactions" => Page([Transaction()]),
            var p when p == "/subscriptions/" + SubscriptionId.Value => Response(Subscription()),
            "/subscriptions" => Page([Subscription()]),
            var p when p == "/adjustments/" + AdjustmentId.Value => Response(Adjustment()),
            "/adjustments" => Page([Adjustment()]),
            "/events" => Page([Event()]),
            _ => throw new InvalidOperationException(),
        });
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        var transaction = await provider.GetTransactionAsync(TransactionId, CancellationToken.None);
        Assert.Equal(ProviderPaymentState.Completed, transaction.State); Assert.Equal("1000", transaction.Total.MinorUnits);
        Assert.NotNull(transaction.Items.Single().TransactionItem); Assert.Equal(Metadata, transaction.Metadata);
        Assert.Equal("900", transaction.Items.Single().Financials!.UnitSubtotal.MinorUnits);
        Assert.Equal("US", transaction.BillingCountry); Assert.Null(transaction.CustomerInformationRevisedAt);
        Assert.DoesNotContain("private not exported", Json(transaction), StringComparison.Ordinal);
        Assert.DoesNotContain("7777", Json(transaction), StringComparison.Ordinal); Assert.DoesNotContain("method_details", Json(transaction), StringComparison.Ordinal);
        Assert.Single((await provider.ListTransactionsAsync(DateTimeOffset.Parse(Instant, CultureInfo.InvariantCulture), DateTimeOffset.Parse(Instant, CultureInfo.InvariantCulture), null, CancellationToken.None)).Items);
        Assert.True((await provider.GetSubscriptionAsync(SubscriptionId, CancellationToken.None)).AutoRenew);
        Assert.Single((await provider.ListSubscriptionsAsync(null, CancellationToken.None)).Items);
        Assert.Equal(ProviderAdjustmentState.Pending, (await provider.GetAdjustmentAsync(AdjustmentId, CancellationToken.None)).State);
        Assert.Single((await provider.ListAdjustmentsAsync(null, CancellationToken.None)).Items);
        Assert.Equal(ProviderEventKind.PaymentCompleted, (await provider.ListEventsAsync(null, CancellationToken.None)).Items.Single().Kind);
    }
    [Fact]
    public async Task CancelAtPeriodEndAndReactivationUseExactMutationContracts()
    {
        var transport = Handler(r => Response(Subscription(r.Method == HttpMethod.Post)));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        var canceled = await provider.CancelSubscriptionAsync(SubscriptionId, CancellationToken.None);
        Assert.False(canceled.AutoRenew); Assert.NotNull(canceled.CancellationAt);
        var active = await provider.ReactivateScheduledCancellationAsync(SubscriptionId, CancellationToken.None);
        Assert.True(active.AutoRenew); Assert.Null(active.CancellationAt);
        Assert.Contains("\"effective_from\":\"next_billing_period\"", transport.Calls.First().Body, StringComparison.Ordinal);
        Assert.Equal("{\"scheduled_change\":null}", transport.Calls.Last().Body);
    }
    [Fact]
    public async Task MissingOptionalCapabilitiesAreRefusedWithoutCallingProvider()
    {
        var transport = Handler(_ => throw new InvalidOperationException("No transport is allowed."));
        using var provider = BillingProviderFactory.Create(Settings(Capabilities with { CancelAtPeriodEnd = false, ReactivateScheduledCancellation = false, PartialRefund = false, CustomerPortal = false }), transport);
        Assert.Equal(ProviderFailureKind.Unsupported, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.CancelSubscriptionAsync(SubscriptionId, CancellationToken.None))).Kind);
        Assert.Equal(ProviderFailureKind.Unsupported, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.ReactivateScheduledCancellationAsync(SubscriptionId, CancellationToken.None))).Kind);
        Assert.Equal(ProviderFailureKind.Unsupported, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.CreateRefundAsync(new(TransactionId, "customer request", [new(new("txnitm_" + Suffix), "1")]), CancellationToken.None))).Kind);
        Assert.Equal(ProviderFailureKind.Unsupported, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.CreateCustomerPortalAsync(CustomerId, [], CancellationToken.None))).Kind);
        Assert.Empty(transport.Calls);
    }
    [Fact]
    public async Task FullAndPartialRefundReturnPendingApprovalRatherThanClaimingSuccess()
    {
        var transport = Handler(_ => Response(Adjustment())); using var provider = BillingProviderFactory.Create(Settings(), transport);
        var full = await provider.CreateRefundAsync(new(TransactionId, "customer request", []), CancellationToken.None);
        var partial = await provider.CreateRefundAsync(new(TransactionId, "approved partial refund", [new(new("txnitm_" + Suffix), "400")]), CancellationToken.None);
        Assert.Equal(ProviderAdjustmentState.Pending, full.State); Assert.Equal(ProviderAdjustmentState.Pending, partial.State);
        Assert.Contains("\"type\":\"full\"", transport.Calls.First().Body, StringComparison.Ordinal);
        Assert.Contains("\"amount\":\"400\"", transport.Calls.Last().Body, StringComparison.Ordinal);
    }
    [Fact]
    public async Task CustomerPortalIsBoundToCustomerAndItsTemporaryTokenIsNotInDiagnostics()
    {
        var transport = Handler(r => r.Method == HttpMethod.Get ? Response(Subscription()) : Response(new
        { customer_id = CustomerId.Value, urls = new { general = new { overview = "https://customer-portal.paddle.com/cpl_" + Suffix + "?action=overview&token=temporary" } }, created_at = Instant }));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        var link = await provider.CreateCustomerPortalAsync(CustomerId, [SubscriptionId], CancellationToken.None);
        Assert.Contains("token=temporary", link.Url.Query, StringComparison.Ordinal); Assert.DoesNotContain("temporary", link.ToString(), StringComparison.Ordinal);
        Assert.Contains(SubscriptionId.Value, transport.Calls.Last().Body, StringComparison.Ordinal);
        Assert.Equal(DateTimeOffset.Parse(Instant, CultureInfo.InvariantCulture), link.CreatedAt);
    }
    [Fact]
    public async Task CrossCustomerPortalRequestIsRefusedBeforeMutation()
    {
        var transport = Handler(_ => Response(Subscription(customer: "ctm_01grnn4zta5a1mf02jjze7y2yt")));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        Assert.Equal(ProviderFailureKind.Forbidden, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.CreateCustomerPortalAsync(CustomerId, [SubscriptionId], CancellationToken.None))).Kind);
        Assert.Single(transport.Calls);
    }
    [Theory]
    [InlineData(401, ProviderFailureKind.Unauthorized)]
    [InlineData(403, ProviderFailureKind.Forbidden)]
    [InlineData(404, ProviderFailureKind.NotFound)]
    [InlineData(409, ProviderFailureKind.Conflict)]
    [InlineData(422, ProviderFailureKind.Rejected)]
    public async Task DefinitiveErrorsAreTypedWithoutLeakingExternalBodies(int status, ProviderFailureKind expected)
    {
        var transport = Handler(_ => Raw("private external body: " + Credential, (HttpStatusCode)status));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        var error = await Assert.ThrowsAsync<BillingProviderException>(() => provider.GetTransactionAsync(TransactionId, CancellationToken.None));
        Assert.Equal(expected, error.Kind); Assert.Equal(status, error.StatusCode); Assert.Null(error.InnerException);
        Assert.DoesNotContain(Credential, error.ToString(), StringComparison.Ordinal); Assert.Single(transport.Calls);
    }
    [Fact]
    public async Task ReadRetriesAreBoundedAndHonorRateLimit()
    {
        var count = 0; var transport = Handler(_ =>
        {
            if (Interlocked.Increment(ref count) == 3) return Response(Transaction());
            var response = Raw("{}", HttpStatusCode.TooManyRequests); response.Headers.RetryAfter = new(TimeSpan.Zero); return response;
        });
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        await provider.GetTransactionAsync(TransactionId, CancellationToken.None); Assert.Equal(3, transport.Calls.Count);
        var exhausted = Handler(_ => Raw("{}", HttpStatusCode.ServiceUnavailable));
        using var failing = BillingProviderFactory.Create(Settings(), exhausted);
        Assert.Equal(ProviderFailureKind.Transport, (await Assert.ThrowsAsync<BillingProviderException>(() => failing.GetTransactionAsync(TransactionId, CancellationToken.None))).Kind);
        Assert.Equal(3, exhausted.Calls.Count);
    }
    [Fact]
    public async Task TransientTransportReadCanRecoverButMutationIsNeverBlindlyRetried()
    {
        var count = 0; var readTransport = new Transport((_, _) => Interlocked.Increment(ref count) == 1
            ? Task.FromException<HttpResponseMessage>(new HttpRequestException("private transport detail")) : Task.FromResult(Response(Transaction())));
        using var reader = BillingProviderFactory.Create(Settings(), readTransport);
        await reader.GetTransactionAsync(TransactionId, CancellationToken.None); Assert.Equal(2, readTransport.Calls.Count);
        var writeTransport = new Transport((_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("private detail")));
        using var writer = BillingProviderFactory.Create(Settings(), writeTransport);
        Assert.Equal(ProviderFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<BillingProviderException>(() => writer.CancelSubscriptionAsync(SubscriptionId, CancellationToken.None))).Kind);
        Assert.Single(writeTransport.Calls);
    }
    [Theory]
    [InlineData(503, "{}")]
    [InlineData(200, "not-json")]
    [InlineData(200, "{\"data\":{}}")]
    public async Task AmbiguousOrUnusableWriteReceiptsRequireReconciliation(int status, string body)
    {
        var transport = Handler(_ => Raw(body, (HttpStatusCode)status)); using var provider = BillingProviderFactory.Create(Settings(), transport);
        Assert.Equal(ProviderFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.CancelSubscriptionAsync(SubscriptionId, CancellationToken.None))).Kind);
        Assert.Single(transport.Calls);
    }
    [Fact]
    public async Task RateLimitedMutationIsADefinitiveRefusalWithoutAutomaticRetry()
    {
        var transport = Handler(_ => { var response = Raw("{}", HttpStatusCode.TooManyRequests); response.Headers.RetryAfter = new(TimeSpan.FromHours(1)); return response; });
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        var error = await Assert.ThrowsAsync<BillingProviderException>(() => provider.CancelSubscriptionAsync(SubscriptionId, CancellationToken.None));
        Assert.Equal(ProviderFailureKind.RateLimited, error.Kind); Assert.Equal(TimeSpan.FromSeconds(2), error.RetryAfter); Assert.Single(transport.Calls);
    }
    [Fact]
    public async Task CancellationBeforeDispatchDoesNotWriteAndAfterDispatchIsUnknown()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new Transport(async (_, ct) => { entered.SetResult(); await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); });
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.CancelSubscriptionAsync(SubscriptionId, canceled.Token)); Assert.Empty(transport.Calls);
        using var caller = new CancellationTokenSource(); var operation = provider.CancelSubscriptionAsync(SubscriptionId, caller.Token);
        await entered.Task; caller.Cancel();
        Assert.Equal(ProviderFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<BillingProviderException>(() => operation)).Kind); Assert.Single(transport.Calls);
    }
    [Fact]
    public async Task TimeoutAndDisposalCancelActualInFlightOperationsAndDisposalIsIdempotent()
    {
        var transport = new Transport(async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); });
        using (var provider = BillingProviderFactory.Create(Settings(timeout: TimeSpan.FromMilliseconds(20)), transport))
            Assert.Equal(ProviderFailureKind.Transport, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.GetTransactionAsync(TransactionId, CancellationToken.None))).Kind);
        Assert.True(transport.Disposed);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = new Transport(async (_, ct) => { entered.SetResult(); await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); });
        var disposable = BillingProviderFactory.Create(Settings(), pending);
        var task = disposable.GetTransactionAsync(TransactionId, CancellationToken.None); await entered.Task; disposable.Dispose(); disposable.Dispose();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task); Assert.True(pending.Disposed);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => disposable.GetTransactionAsync(TransactionId, CancellationToken.None));
    }
    [Fact]
    public async Task ConcurrentReadsHaveIndependentRequestsAndCancellation()
    {
        var transport = Handler(_ => Response(Transaction())); using var provider = BillingProviderFactory.Create(Settings(), transport);
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => provider.GetTransactionAsync(TransactionId, CancellationToken.None)));
        Assert.Equal(16, results.Length); Assert.Equal(16, transport.Calls.Count); Assert.All(results, r => Assert.Equal(TransactionId, r.Reference));
    }
    [Fact]
    public async Task MaliciousPaginationRedirectDuplicatePropertiesAndOversizedBodiesAreRefused()
    {
        foreach (var body in new[] { Json(new { data = new[] { Transaction() }, meta = new { pagination = new { has_more = true, next = "https://attacker.invalid/transactions?after=txn_" + Suffix } } }),
            "{\"data\":{},\"data\":{}}", new string('x', 1024 * 1024 + 1) })
        {
            var transport = Handler(_ => Raw(body)); using var provider = BillingProviderFactory.Create(Settings(), transport);
            Assert.Equal(ProviderFailureKind.Protocol, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.ListTransactionsAsync(DateTimeOffset.MinValue, DateTimeOffset.MaxValue, null, CancellationToken.None))).Kind);
            Assert.Single(transport.Calls);
        }
        var redirect = Handler(_ => Raw("{}", HttpStatusCode.Found)); using var redirected = BillingProviderFactory.Create(Settings(), redirect);
        Assert.Equal(ProviderFailureKind.Protocol, (await Assert.ThrowsAsync<BillingProviderException>(() => redirected.GetTransactionAsync(TransactionId, CancellationToken.None))).Kind);
        Assert.Single(redirect.Calls);
    }
    [Fact]
    public async Task OpaquePaginationCursorIsValidatedAndUsedWithoutFollowingRemoteUrl()
    {
        var next = "txn_01grnn4zta5a1mf02jjze7y2yt";
        var transport = Handler(r => r.RequestUri!.Query.Contains("after=", StringComparison.Ordinal) ? Page([Transaction()]) : Page([Transaction()], "https://api.paddle.com/transactions?per_page=30&after=" + next));
        using var provider = BillingProviderFactory.Create(Settings(), transport);
        var first = await provider.ListTransactionsAsync(DateTimeOffset.MinValue, DateTimeOffset.MaxValue, null, CancellationToken.None);
        Assert.Equal(next, first.NextCursor);
        Assert.Null((await provider.ListTransactionsAsync(DateTimeOffset.MinValue, DateTimeOffset.MaxValue, first.NextCursor, CancellationToken.None)).NextCursor);
        Assert.Contains("updated_at", transport.Calls.Last().Uri.Query, StringComparison.Ordinal);
    }
    [Theory]
    [InlineData("01")]
    [InlineData("1.0")]
    [InlineData("1e3")]
    [InlineData("-1")]
    [InlineData("10000000000000000000000000000")]
    public async Task MoneyIsCanonicalIntegerMinorUnitsWithoutFloatingPointCoercion(string amount)
    {
        var transport = Handler(_ => Response(Transaction(amount: amount))); using var provider = BillingProviderFactory.Create(Settings(), transport);
        Assert.Equal(ProviderFailureKind.Protocol, (await Assert.ThrowsAsync<BillingProviderException>(() => provider.GetTransactionAsync(TransactionId, CancellationToken.None))).Kind);
    }
    [Fact]
    public void RawBodySignaturesRotationFreshnessAndStableReplayIdentityAreVerified()
    {
        using var provider = BillingProviderFactory.Create(Settings(secrets: [Secret, "rotating-component-secret-only"]), Handler(_ => Response(Price())), new Clock());
        var body = Encoding.UTF8.GetBytes(Json(Event())); var signature = Sign(body, "rotating-component-secret-only");
        var verified = provider.VerifyWebhook(body, _ => signature); var replay = provider.VerifyWebhook(body, _ => signature);
        Assert.Equal(WebhookVerdict.Verified, verified.Verdict); Assert.Equal(verified.Event!.DedupeKey, replay.Event!.DedupeKey);
        Assert.Equal(Metadata, verified.Event.Transaction!.Metadata); Assert.Equal(64, verified.BodySha256!.Length);
        Assert.Equal("notification-v2", verified.Receipt!.VerificationKeyVersion); Assert.Equal(body.Length, verified.BodyBytes);
        Assert.Equal(new Clock().GetUtcNow(), verified.Receipt.VerifiedAt);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(verified.Projection.Span)), verified.Receipt.ProjectionSha256);
        using var projection = JsonDocument.Parse(verified.Projection);
        Assert.Equal(1, projection.RootElement.GetProperty("Version").GetInt32());
        Assert.DoesNotContain("method_details", Encoding.UTF8.GetString(verified.Projection.Span), StringComparison.Ordinal);
        Assert.DoesNotContain("7777", Encoding.UTF8.GetString(verified.Projection.Span), StringComparison.Ordinal);
        Assert.True(MemoryMarshal.TryGetArray(verified.Projection, out var independent)); independent.Array![independent.Offset] = 0;
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(verified.Projection.Span)), verified.Receipt.ProjectionSha256);
        var changed = Encoding.UTF8.GetBytes(Json(Event("transaction.updated")));
        Assert.NotEqual(verified.Event.DedupeKey, provider.VerifyWebhook(changed, _ => Sign(changed)).Event!.DedupeKey);
        Assert.Equal(WebhookVerdict.InvalidSignature, provider.VerifyWebhook(body.Concat(new byte[] { 32 }).ToArray(), _ => signature).Verdict);
        Assert.Equal(WebhookVerdict.ExpiredSignature, provider.VerifyWebhook(body, _ => Sign(body, seconds: new Clock().GetUtcNow().ToUnixTimeSeconds() - 6)).Verdict);
        Assert.Equal(WebhookVerdict.ExpiredSignature, provider.VerifyWebhook(body, _ => Sign(body, seconds: new Clock().GetUtcNow().ToUnixTimeSeconds() + 6)).Verdict);
        var missing = provider.VerifyWebhook(body, _ => null);
        Assert.Equal(WebhookVerdict.MissingSignature, missing.Verdict); Assert.Equal(body.Length, missing.BodyBytes); Assert.NotNull(missing.BodySha256); Assert.Null(missing.Receipt);
        Assert.Equal(WebhookVerdict.InvalidSignature, provider.VerifyWebhook(body, _ => signature + ";ts=1").Verdict);
    }
    [Fact]
    public void AuthenticatedMalformedPayloadIsQuarantinedAndUnknownEventStaysUnsupported()
    {
        using var provider = BillingProviderFactory.Create(Settings(), Handler(_ => Response(Price())), new Clock());
        foreach (var json in new[] { "{\"data\":{},\"data\":{}}", Json(Event(data: Transaction(metadata: new { workspace_id = Metadata.WorkspaceId }))), "not-json" })
        {
            var bytes = Encoding.UTF8.GetBytes(json); var result = provider.VerifyWebhook(bytes, _ => Sign(bytes));
            Assert.Equal(WebhookVerdict.InvalidPayload, result.Verdict); Assert.Null(result.Event); Assert.NotNull(result.BodySha256);
            Assert.NotNull(result.Receipt); Assert.Null(result.Receipt.ProjectionSha256); Assert.True(result.Projection.IsEmpty);
        }
        var unknown = Encoding.UTF8.GetBytes(Json(Event("new.future.event", new { arbitrary = "not retained" })));
        var unsupported = provider.VerifyWebhook(unknown, _ => Sign(unknown));
        Assert.Equal(WebhookVerdict.Verified, unsupported.Verdict); Assert.Equal(ProviderEventKind.Unsupported, unsupported.Event!.Kind);
        Assert.Null(unsupported.Event.Transaction); Assert.Null(unsupported.Event.Subscription); Assert.Null(unsupported.Event.Adjustment);
        Assert.True(unsupported.Projection.IsEmpty); Assert.Null(unsupported.Receipt!.ProjectionSha256);
    }
    [Fact]
    public void SignatureParsingIsBoundedAndReversalEventsRemainDistinct()
    {
        using var provider = BillingProviderFactory.Create(Settings(), Handler(_ => Response(Price())), new Clock());
        var bytes = Encoding.UTF8.GetBytes(Json(Event()));
        foreach (var header in new[] { "ts=1;h1=not-hex", Sign(bytes) + ";h1=" + new string('z', 64), new string('x', 2049), Sign(bytes) + ";extra=1" })
            Assert.Equal(WebhookVerdict.InvalidSignature, provider.VerifyWebhook(bytes, _ => header).Verdict);
        Assert.Equal(WebhookVerdict.TooLarge, provider.VerifyWebhook(new byte[1024 * 1024 + 1], _ => throw new InvalidOperationException()).Verdict);
        foreach (var pair in new[] { ("credit_reverse", ProviderAdjustmentKind.CreditReversal), ("chargeback_warning_reverse", ProviderAdjustmentKind.WarningReversal), ("chargeback_reverse", ProviderAdjustmentKind.DisputeReversal) })
        {
            var eventBytes = Encoding.UTF8.GetBytes(Json(Event("adjustment.updated", Adjustment(action: pair.Item1))));
            Assert.Equal(pair.Item2, provider.VerifyWebhook(eventBytes, _ => Sign(eventBytes)).Event!.Adjustment!.Kind);
        }
    }
    [Fact]
    public void VerificationUsesOnePrivateByteSnapshotWhenCallerReusesItsBuffer()
    {
        using var provider = BillingProviderFactory.Create(Settings(), Handler(_ => Response(Price())), new Clock());
        var bytes = Encoding.UTF8.GetBytes(Json(Event())); var signature = Sign(bytes);
        var expected = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var result = provider.VerifyWebhook(bytes, _ => { bytes[0] = 0; return signature; });
        Assert.Equal(WebhookVerdict.Verified, result.Verdict); Assert.Equal(expected, result.BodySha256);
        Assert.NotNull(result.Event); Assert.NotNull(result.Receipt);
    }
    [Fact]
    public void SettingsCopyCapabilitiesAndRejectUnsupportedOrUnsafeConfiguration()
    {
        var currencies = new List<string> { "USD" }; var methods = new List<PaymentMethodCapability> { Capabilities.PaymentMethods.Single() with { Currencies = currencies } };
        var settings = Settings(Capabilities with { PaymentMethods = methods }); currencies.Clear(); methods.Clear();
        Assert.Single(settings.Capabilities.PaymentMethods.Single().Currencies);
        Assert.Throws<ArgumentException>(() => Settings(Capabilities with { NativeMutationIdempotency = true }));
        Assert.Throws<ArgumentException>(() => new ProviderAdapterSettings(BillingEnvironment.Production, Credential, [new("notification-v1", Secret)], "source", new Uri("http://unsafe.invalid"), Capabilities));
        Assert.DoesNotContain(Credential, settings.ToString()!, StringComparison.Ordinal); Assert.DoesNotContain(Secret, settings.ToString()!, StringComparison.Ordinal);
    }
}
