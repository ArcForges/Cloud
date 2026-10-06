// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Cloud.Modules.Commerce.Adapters;

/// <summary>Only this adapter interprets vendor data. All financial outputs are allowlisted; payment instruments never escape.</summary>
internal sealed class PaddleNormalization(ProviderAdapterSettings settings)
{
    internal static BillingProviderException Invalid() => new(ProviderFailureKind.Protocol);
    internal static JsonElement Required(JsonElement value, string name, JsonValueKind kind)
    {
        if (!value.TryGetProperty(name, out var result) || result.ValueKind != kind) throw Invalid();
        return result;
    }
    internal static string Text(JsonElement value, string name, int max = 2048)
    {
        var result = Required(value, name, JsonValueKind.String).GetString()!;
        if (result.Length == 0 || result.Length > max) throw Invalid();
        return result;
    }
    internal static bool TryObject(JsonElement value, string name, out JsonElement result) => value.TryGetProperty(name, out result) && result.ValueKind == JsonValueKind.Object;
    internal static ProviderReference Reference(JsonElement value, string name, string prefix)
    {
        var reference = Text(value, name);
        if (!ProviderInput.Reference(reference, prefix)) throw Invalid();
        return new ProviderReference(reference);
    }
    internal static ProviderReference? OptionalReference(JsonElement value, string name, string prefix)
    {
        if (!value.TryGetProperty(name, out var result) || result.ValueKind == JsonValueKind.Null) return null;
        return Reference(value, name, prefix);
    }
    internal static DateTimeOffset Instant(JsonElement value, string name)
    {
        var raw = Text(value, name, 64);
        if (raw.Length < 20 || raw[10] != 'T' || !(raw.EndsWith('Z')
            || raw.Length >= 25 && raw[^3] == ':' && raw[^6] is '+' or '-')) throw Invalid();
        var dot = raw.IndexOf('.');
        if (dot >= 0)
        {
            var end = dot + 1;
            while (end < raw.Length && char.IsAsciiDigit(raw[end])) end++;
            if (end - dot - 1 is < 1 or > 6) throw Invalid();
        }
        if (!value.GetProperty(name).TryGetDateTimeOffset(out var instant)) throw Invalid();
        return instant.ToUniversalTime();
    }
    private static DateTimeOffset? OptionalInstant(JsonElement value, string name) => !value.TryGetProperty(name, out var item)
        || item.ValueKind == JsonValueKind.Null ? null : Instant(value, name);
    internal static ProviderMoney Money(JsonElement value, string amountName, string currency, bool signed = false)
    {
        var amount = Text(value, amountName, 29);
        if (!ProviderInput.Currency(currency) || !ProviderInput.Amount(amount, signed: signed)) throw Invalid();
        return new ProviderMoney(amount, currency);
    }
    internal static ProviderTaxTreatment TaxTreatment(JsonElement value) => Text(value, "tax_mode", 32) switch
    {
        "internal" => ProviderTaxTreatment.Included, "external" => ProviderTaxTreatment.Excluded,
        "account_setting" => ProviderTaxTreatment.AccountSetting, _ => throw Invalid(),
    };
    private static ProviderPeriod? Period(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var period) || period.ValueKind == JsonValueKind.Null) return null;
        if (period.ValueKind != JsonValueKind.Object) throw Invalid();
        var start = Instant(period, "starts_at"); var end = Instant(period, "ends_at");
        if (start >= end) throw Invalid();
        return new ProviderPeriod(start, end);
    }
    internal static PurchaseMetadata? Metadata(JsonElement value)
    {
        if (!value.TryGetProperty("custom_data", out var metadata) || metadata.ValueKind == JsonValueKind.Null) return null;
        if (metadata.ValueKind != JsonValueKind.Object) throw Invalid();
        // Unrelated supplier custom data is not an internal identity. Partial ArcForges metadata is malformed, never silently coerced.
        if (!metadata.TryGetProperty("purchase_intent_id", out _) && !metadata.TryGetProperty("workspace_id", out _)) return null;
        var result = new PurchaseMetadata(Text(metadata, "realm_id"), Text(metadata, "billing_account_id"), Text(metadata, "workspace_id"),
            Text(metadata, "purchase_intent_id"), Text(metadata, "checkout_attempt_id"), Text(metadata, "offer_id"),
            Text(metadata, "price_version"), Text(metadata, "policy_version"));
        if (!ProviderInput.Metadata(result)) throw Invalid();
        return result;
    }
    private static IReadOnlyList<ProviderLineItem> Items(JsonElement value)
    {
        var result = new List<ProviderLineItem>();
        var seenPrices = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in Required(value, "items", JsonValueKind.Array).EnumerateArray())
        {
            if (result.Count == 100 || item.ValueKind != JsonValueKind.Object) throw Invalid();
            var price = Reference(Required(item, "price", JsonValueKind.Object), "id", "pri");
            if (!seenPrices.Add(price.Value)) throw Invalid();
            if (!item.TryGetProperty("quantity", out var quantity) || !quantity.TryGetInt32(out var count) || count is < 1 or > 999999999) throw Invalid();
            ProviderReference? transactionItem = null;
            ProviderLineFinancials? financials = null;
            if (TryObject(value, "details", out var details) && details.TryGetProperty("line_items", out var lines) && lines.ValueKind == JsonValueKind.Array)
            {
                if (lines.GetArrayLength() > 100) throw Invalid();
                foreach (var line in lines.EnumerateArray())
                {
                    if (line.TryGetProperty("price_id", out var id) && id.GetString() == price.Value)
                    {
                        if (transactionItem is not null) throw Invalid();
                        transactionItem = Reference(line, "id", "txnitm");
                        var currency = Text(value, "currency_code", 3);
                        var unit = Required(line, "unit_totals", JsonValueKind.Object);
                        var totals = Required(line, "totals", JsonValueKind.Object);
                        if (line.GetProperty("quantity").GetInt32() != count) throw Invalid();
                        financials = new ProviderLineFinancials(Money(unit, "subtotal", currency), Money(unit, "discount", currency),
                            Money(unit, "tax", currency), Money(unit, "total", currency), Money(totals, "subtotal", currency), Money(totals, "discount", currency),
                            Money(totals, "tax", currency), Money(totals, "total", currency), Text(Required(line, "product", JsonValueKind.Object), "tax_category", 64));
                    }
                }
            }
            result.Add(new ProviderLineItem(price, transactionItem, count, financials));
        }
        if (result.Count == 0) throw Invalid();
        return result.AsReadOnly();
    }
    internal ProviderPriceSnapshot Price(JsonElement data)
    {
        var product = Required(data, "product", JsonValueKind.Object);
        var money = Required(data, "unit_price", JsonValueKind.Object);
        string? interval = null; int? frequency = null;
        if (data.TryGetProperty("billing_cycle", out var cycle) && cycle.ValueKind != JsonValueKind.Null)
        {
            if (cycle.ValueKind != JsonValueKind.Object) throw Invalid();
            interval = Text(cycle, "interval", 16);
            if (interval is not ("day" or "week" or "month" or "year") || !cycle.GetProperty("frequency").TryGetInt32(out var count) || count <= 0) throw Invalid();
            frequency = count;
        }
        var overrides = new List<CountryPrice>();
        if (data.TryGetProperty("unit_price_overrides", out var regional))
        {
            if (regional.ValueKind != JsonValueKind.Array) throw Invalid();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in regional.EnumerateArray())
            {
                var countries = Required(entry, "country_codes", JsonValueKind.Array).EnumerateArray().Select(v => v.GetString()!).ToArray();
                if (countries.Length == 0 || countries.Any(c => !ProviderInput.Country(c) || !seen.Add(c))) throw Invalid();
                var amount = Required(entry, "unit_price", JsonValueKind.Object);
                overrides.Add(new CountryPrice(Array.AsReadOnly(countries), Money(amount, "amount", Text(amount, "currency_code", 3))));
            }
        }
        var productRef = Reference(data, "product_id", "pro");
        if (Reference(product, "id", "pro") != productRef) throw Invalid();
        return new ProviderPriceSnapshot(Reference(data, "id", "pri"), productRef,
            Text(data, "status", 32) == "active" && Text(product, "status", 32) == "active", Text(product, "tax_category", 64), TaxTreatment(data),
            Money(money, "amount", Text(money, "currency_code", 3)), interval, frequency, overrides.AsReadOnly());
    }
    internal ProviderTransaction Transaction(JsonElement data)
    {
        var currency = Text(data, "currency_code", 3);
        var totals = Required(Required(data, "details", JsonValueKind.Object), "totals", JsonValueKind.Object);
        var status = Text(data, "status", 32);
        var state = status switch
        {
            "completed" => ProviderPaymentState.Completed,
            "past_due" => ProviderPaymentState.Failed,
            "canceled" => ProviderPaymentState.Canceled,
            "draft" or "ready" or "billed" or "paid" => ProviderPaymentState.Pending,
            _ => throw Invalid(),
        };
        ProviderMoney? OptionalMoney(string field, bool signed = false) => !totals.TryGetProperty(field, out var amount)
            || amount.ValueKind == JsonValueKind.Null ? null : Money(totals, field, currency, signed);
        if (totals.TryGetProperty("currency_code", out _) && Text(totals, "currency_code", 3) != currency) throw Invalid();
        var items = Items(data);
        if (state == ProviderPaymentState.Completed && items.Any(i => i.Financials is null)) throw Invalid();
        string? country = null;
        if (data.TryGetProperty("address", out var address) && address.ValueKind != JsonValueKind.Null)
        {
            if (address.ValueKind != JsonValueKind.Object) throw Invalid();
            country = Text(address, "country_code", 2);
            if (!ProviderInput.Country(country) || Reference(address, "customer_id", "ctm") != OptionalReference(data, "customer_id", "ctm")) throw Invalid();
        }
        return new ProviderTransaction(Reference(data, "id", "txn"), OptionalReference(data, "customer_id", "ctm"), OptionalReference(data, "subscription_id", "sub"),
            state, status, Money(totals, "total", currency), OptionalMoney("tax"), OptionalMoney("fee"), OptionalMoney("earnings", signed: true),
            Metadata(data), items, Period(data, "billing_period"), Instant(data, "updated_at"), country, OptionalInstant(data, "revised_at"));
    }
    internal ProviderSubscription Subscription(JsonElement data)
    {
        var status = Text(data, "status", 32);
        var state = status switch { "active" => ProviderSubscriptionState.Active, "trialing" => ProviderSubscriptionState.Pending,
            "past_due" => ProviderSubscriptionState.PastDue, "paused" => ProviderSubscriptionState.Paused,
            "canceled" => ProviderSubscriptionState.Canceled, _ => ProviderSubscriptionState.Unknown };
        DateTimeOffset? cancellation = null;
        if (data.TryGetProperty("scheduled_change", out var change) && change.ValueKind != JsonValueKind.Null)
        {
            if (change.ValueKind != JsonValueKind.Object) throw Invalid();
            if (Text(change, "action", 32) == "cancel") cancellation = Instant(change, "effective_at");
        }
        return new ProviderSubscription(Reference(data, "id", "sub"), Reference(data, "customer_id", "ctm"), state, status,
            (state is ProviderSubscriptionState.Active or ProviderSubscriptionState.PastDue or ProviderSubscriptionState.Pending) && cancellation is null,
            cancellation, Period(data, "current_billing_period"), Metadata(data), Items(data), Instant(data, "updated_at"));
    }
    internal ProviderAdjustment Adjustment(JsonElement data)
    {
        var action = Text(data, "action", 32);
        var kind = action switch { "refund" => ProviderAdjustmentKind.Refund, "credit" => ProviderAdjustmentKind.Credit, "credit_reverse" => ProviderAdjustmentKind.CreditReversal,
            "chargeback" => ProviderAdjustmentKind.Dispute, "chargeback_reverse" => ProviderAdjustmentKind.DisputeReversal,
            "chargeback_warning" => ProviderAdjustmentKind.Warning, "chargeback_warning_reverse" => ProviderAdjustmentKind.WarningReversal, _ => ProviderAdjustmentKind.Unknown };
        var state = Text(data, "status", 32) switch { "pending_approval" => ProviderAdjustmentState.Pending, "approved" => ProviderAdjustmentState.Approved,
            "rejected" => ProviderAdjustmentState.Rejected, "reversed" => ProviderAdjustmentState.Reversed, _ => ProviderAdjustmentState.Unknown };
        var totals = Required(data, "totals", JsonValueKind.Object);
        return new ProviderAdjustment(Reference(data, "id", "adj"), Reference(data, "transaction_id", "txn"), OptionalReference(data, "subscription_id", "sub"),
            kind, state, Money(totals, "total", Text(data, "currency_code", 3)), Instant(data, "updated_at"));
    }
    internal VerifiedProviderEvent Event(JsonElement envelope)
    {
        var reference = Reference(envelope, "event_id", "evt");
        var type = Text(envelope, "event_type", 128); var occurred = Instant(envelope, "occurred_at");
        var data = Required(envelope, "data", JsonValueKind.Object);
        var kind = type switch
        {
            "transaction.completed" => ProviderEventKind.PaymentCompleted,
            "transaction.created" or "transaction.updated" or "transaction.paid" or "transaction.canceled" or "transaction.past_due" or "transaction.payment_failed" => ProviderEventKind.PaymentChanged,
            "subscription.created" or "subscription.updated" or "subscription.activated" or "subscription.resumed" or "subscription.paused" or "subscription.canceled" or "subscription.past_due" => ProviderEventKind.SubscriptionChanged,
            "adjustment.created" or "adjustment.updated" => ProviderEventKind.AdjustmentChanged,
            _ => ProviderEventKind.Unsupported,
        };
        var dedupe = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(type + "\n" + reference.Value)));
        return new VerifiedProviderEvent(settings.Source, reference, dedupe, kind, occurred,
            kind is ProviderEventKind.PaymentChanged or ProviderEventKind.PaymentCompleted ? Transaction(data) : null,
            kind == ProviderEventKind.SubscriptionChanged ? Subscription(data) : null,
            kind == ProviderEventKind.AdjustmentChanged ? Adjustment(data) : null);
    }
    internal static void NoDuplicateProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!seen.Add(property.Name)) throw Invalid();
                NoDuplicateProperties(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var entry in value.EnumerateArray()) NoDuplicateProperties(entry);
    }
}
