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
        "internal" => ProviderTaxTreatment.Included,
        "external" => ProviderTaxTreatment.Excluded,
        "account_setting" => ProviderTaxTreatment.AccountSetting,
        "location" => ProviderTaxTreatment.LocationBased,
        _ => throw Invalid(),
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
        foreach (var item in Required(value, "items", JsonValueKind.Array).EnumerateArray())
        {
            if (result.Count == 100 || item.ValueKind != JsonValueKind.Object) throw Invalid();
            var price = Reference(Required(item, "price", JsonValueKind.Object), "id", "pri");
            if (!item.TryGetProperty("quantity", out var quantity) || !quantity.TryGetInt32(out var count) || count is < 1 or > 999999999) throw Invalid();
            result.Add(new ProviderLineItem(price, null, count, null));
        }
        if (result.Count == 0) throw Invalid();
        if (TryObject(value, "details", out var details) && details.TryGetProperty("line_items", out var lines))
        {
            if (lines.ValueKind != JsonValueKind.Array || lines.GetArrayLength() > 100) throw Invalid();
            if (lines.GetArrayLength() != 0)
            {
                // Calculated line items are the supplier's financial source of truth. Multiple prorated lines may share a price.
                result.Clear(); var ids = new HashSet<string>(StringComparer.Ordinal); var currency = Text(value, "currency_code", 3);
                foreach (var line in lines.EnumerateArray())
                {
                    var reference = Reference(line, "id", "txnitm"); if (!ids.Add(reference.Value)) throw Invalid();
                    var count = line.GetProperty("quantity").GetInt32(); if (count is < 1 or > 999999999) throw Invalid();
                    var unit = Required(line, "unit_totals", JsonValueKind.Object); var totals = Required(line, "totals", JsonValueKind.Object);
                    var financials = new ProviderLineFinancials(Money(unit, "subtotal", currency, signed: true), Money(unit, "discount", currency, signed: true),
                        Money(unit, "tax", currency, signed: true), Money(unit, "total", currency, signed: true), Money(totals, "subtotal", currency, signed: true),
                        Money(totals, "discount", currency, signed: true), Money(totals, "tax", currency, signed: true), Money(totals, "total", currency, signed: true),
                        Text(Required(line, "product", JsonValueKind.Object), "tax_category", 64));
                    ProviderPeriod? period = null;
                    if (line.TryGetProperty("proration", out var proration) && proration.ValueKind != JsonValueKind.Null)
                    {
                        if (proration.ValueKind != JsonValueKind.Object) throw Invalid();
                        period = Period(proration, "billing_period"); if (period is null) throw Invalid();
                    }
                    result.Add(new ProviderLineItem(Reference(line, "price_id", "pri"), reference, count, financials, period));
                }
            }
        }
        return result.AsReadOnly();
    }
    internal ProviderPriceSnapshot Price(JsonElement data)
    {
        var product = Required(data, "product", JsonValueKind.Object);
        var money = Required(data, "unit_price", JsonValueKind.Object);
        var terms = PricingTerms(data);
        var overrides = CountryPrices(data);
        var productRef = Reference(data, "product_id", "pro");
        if (Reference(product, "id", "pro") != productRef) throw Invalid();
        return new ProviderPriceSnapshot(Reference(data, "id", "pri"), productRef,
            Text(data, "status", 32) == "active" && Text(product, "status", 32) == "active", Text(product, "tax_category", 64), TaxTreatment(data),
            Money(money, "amount", Text(money, "currency_code", 3)), terms.BillingCycle?.Interval, terms.BillingCycle?.Frequency, overrides, terms);
    }
    internal static ProviderPricingTerms PricingTerms(JsonElement data)
    {
        var rawCycle = data.GetProperty("billing_cycle");
        var cycle = rawCycle.ValueKind == JsonValueKind.Null ? null : Cycle(rawCycle);
        var rawTrial = data.GetProperty("trial_period");
        ProviderTrialPeriod? trial = null;
        if (rawTrial.ValueKind != JsonValueKind.Null)
        {
            if (cycle is null || rawTrial.ValueKind != JsonValueKind.Object) throw Invalid();
            ProviderMoney? money = null;
            if (rawTrial.TryGetProperty("unit_price", out var unit) && unit.ValueKind != JsonValueKind.Null)
            {
                if (unit.ValueKind != JsonValueKind.Object) throw Invalid();
                money = Money(unit, "amount", Text(unit, "currency_code", 3));
            }
            trial = new ProviderTrialPeriod(Cycle(rawTrial), rawTrial.GetProperty("requires_payment_method").GetBoolean(), money, CountryPrices(rawTrial));
        }
        return new ProviderPricingTerms(cycle, trial);
    }
    private static ProviderBillingCycle Cycle(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var interval = Text(value, "interval", 16);
        if (interval is not ("day" or "week" or "month" or "year") || !value.GetProperty("frequency").TryGetInt32(out var count) || count <= 0) throw Invalid();
        return new ProviderBillingCycle(interval, count);
    }
    internal static IReadOnlyList<CountryPrice> CountryPrices(JsonElement data)
    {
        var overrides = new List<CountryPrice>();
        if (data.TryGetProperty("unit_price_overrides", out var regional))
        {
            if (regional.ValueKind != JsonValueKind.Array || regional.GetArrayLength() > 250) throw Invalid();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in regional.EnumerateArray())
            {
                var countries = Required(entry, "country_codes", JsonValueKind.Array).EnumerateArray().Select(v => v.GetString()!).ToArray();
                if (countries.Length == 0 || countries.Any(c => !ProviderInput.Country(c) || !seen.Add(c))) throw Invalid();
                var amount = Required(entry, "unit_price", JsonValueKind.Object);
                overrides.Add(new CountryPrice(Array.AsReadOnly(countries), Money(amount, "amount", Text(amount, "currency_code", 3))));
            }
        }
        return overrides.AsReadOnly();
    }
    internal ProviderTransaction Transaction(JsonElement data)
    {
        var currency = Text(data, "currency_code", 3);
        var details = Required(data, "details", JsonValueKind.Object);
        var totals = Required(details, "totals", JsonValueKind.Object);
        var status = Text(data, "status", 32);
        var state = status switch
        {
            "completed" => ProviderPaymentState.Completed,
            "past_due" => ProviderPaymentState.Failed,
            "canceled" => ProviderPaymentState.Canceled,
            "draft" or "ready" or "billed" or "paid" => ProviderPaymentState.Pending,
            _ => throw Invalid(),
        };
        ProviderMoney? OptionalMoney(string field, bool signed = true) => !totals.TryGetProperty(field, out var amount)
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
        ProviderFinancialTotals? OptionalTotals(string field, string? expectedCurrency)
        {
            if (!details.TryGetProperty(field, out var amount) || amount.ValueKind == JsonValueKind.Null) return null;
            if (amount.ValueKind != JsonValueKind.Object) throw Invalid();
            return Totals(amount, expectedCurrency ?? Text(amount, "currency_code", 3));
        }
        return new ProviderTransaction(Reference(data, "id", "txn"), OptionalReference(data, "customer_id", "ctm"), OptionalReference(data, "subscription_id", "sub"),
            state, status, Money(totals, "total", currency, signed: true), OptionalMoney("tax"), OptionalMoney("fee"), OptionalMoney("earnings", signed: true),
            Metadata(data), items, Period(data, "billing_period"), Instant(data, "updated_at"), country, OptionalInstant(data, "revised_at"),
            Totals(totals, currency), OptionalTotals("payout_totals", null), OptionalTotals("adjusted_totals", currency), OptionalTotals("adjusted_payout_totals", null));
    }
    internal ProviderSubscription Subscription(JsonElement data)
    {
        var status = Text(data, "status", 32);
        var state = status switch
        {
            "active" => ProviderSubscriptionState.Active,
            "trialing" => ProviderSubscriptionState.Pending,
            "past_due" => ProviderSubscriptionState.PastDue,
            "paused" => ProviderSubscriptionState.Paused,
            "canceled" => ProviderSubscriptionState.Canceled,
            _ => ProviderSubscriptionState.Unknown
        };
        DateTimeOffset? cancellation = null; var action = ProviderScheduledAction.None;
        if (data.TryGetProperty("scheduled_change", out var change) && change.ValueKind != JsonValueKind.Null)
        {
            if (change.ValueKind != JsonValueKind.Object) throw Invalid();
            action = Text(change, "action", 32) switch
            { "cancel" => ProviderScheduledAction.Cancel, "pause" => ProviderScheduledAction.Pause, "resume" => ProviderScheduledAction.Resume, _ => ProviderScheduledAction.Unknown };
            if (action == ProviderScheduledAction.Cancel) cancellation = Instant(change, "effective_at");
        }
        return new ProviderSubscription(Reference(data, "id", "sub"), Reference(data, "customer_id", "ctm"), state, status,
            (state is ProviderSubscriptionState.Active or ProviderSubscriptionState.PastDue or ProviderSubscriptionState.Pending) && action == ProviderScheduledAction.None,
            cancellation, Period(data, "current_billing_period"), Metadata(data), Items(data), Instant(data, "updated_at"), action);
    }
    internal ProviderAdjustment Adjustment(JsonElement data)
    {
        var action = Text(data, "action", 32);
        var kind = action switch
        {
            "refund" => ProviderAdjustmentKind.Refund,
            "credit" => ProviderAdjustmentKind.Credit,
            "credit_reverse" => ProviderAdjustmentKind.CreditReversal,
            "chargeback" => ProviderAdjustmentKind.Dispute,
            "chargeback_reverse" => ProviderAdjustmentKind.DisputeReversal,
            "chargeback_warning" => ProviderAdjustmentKind.Warning,
            "chargeback_warning_reverse" => ProviderAdjustmentKind.WarningReversal,
            _ => ProviderAdjustmentKind.Unknown
        };
        var state = Text(data, "status", 32) switch
        {
            "pending_approval" => ProviderAdjustmentState.Pending,
            "approved" => ProviderAdjustmentState.Approved,
            "rejected" => ProviderAdjustmentState.Rejected,
            "reversed" => ProviderAdjustmentState.Reversed,
            _ => ProviderAdjustmentState.Unknown
        };
        var totals = Required(data, "totals", JsonValueKind.Object);
        var currency = Text(data, "currency_code", 3);
        var items = new List<ProviderAdjustmentLine>(); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in Required(data, "items", JsonValueKind.Array).EnumerateArray())
        {
            if (items.Count == 100) throw Invalid();
            var reference = Reference(item, "id", "adjitm"); if (!seen.Add(reference.Value)) throw Invalid();
            var itemTotals = Required(item, "totals", JsonValueKind.Object);
            var scope = Scope(Text(item, "type", 32));
            ProviderMoney? amount = !item.TryGetProperty("amount", out var rawAmount) || rawAmount.ValueKind == JsonValueKind.Null ? null : Money(item, "amount", currency, signed: true);
            if (scope == ProviderAdjustmentScope.Partial && amount is null) throw Invalid();
            ProviderPeriod? period = null;
            if (item.TryGetProperty("proration", out var proration) && proration.ValueKind != JsonValueKind.Null)
            {
                if (proration.ValueKind != JsonValueKind.Object) throw Invalid();
                period = Period(proration, "billing_period");
                if (period is null) throw Invalid();
            }
            items.Add(new ProviderAdjustmentLine(reference, Reference(item, "item_id", "txnitm"), scope, amount,
                Money(itemTotals, "subtotal", currency, signed: true), Money(itemTotals, "tax", currency, signed: true), Money(itemTotals, "total", currency, signed: true), period));
        }
        var adjustmentScope = Scope(Text(data, "type", 32));
        if (items.Count == 0 && adjustmentScope != ProviderAdjustmentScope.Full) throw Invalid();
        ProviderFinancialTotals? payout = null;
        if (data.TryGetProperty("payout_totals", out var rawPayout) && rawPayout.ValueKind != JsonValueKind.Null)
        {
            if (rawPayout.ValueKind != JsonValueKind.Object) throw Invalid();
            payout = Totals(rawPayout, Text(rawPayout, "currency_code", 3));
        }
        bool? balanceCredit = !data.TryGetProperty("credit_applied_to_balance", out var credit) || credit.ValueKind == JsonValueKind.Null ? null : credit.GetBoolean();
        return new ProviderAdjustment(Reference(data, "id", "adj"), Reference(data, "transaction_id", "txn"), OptionalReference(data, "subscription_id", "sub"),
            kind, state, Money(totals, "total", currency, signed: true), Instant(data, "updated_at"), Reference(data, "customer_id", "ctm"),
            adjustmentScope, items.AsReadOnly(), Totals(totals, currency), payout, balanceCredit);
    }
    private static ProviderAdjustmentScope Scope(string value) => value switch
    {
        "full" => ProviderAdjustmentScope.Full,
        "partial" => ProviderAdjustmentScope.Partial,
        "tax" => ProviderAdjustmentScope.Tax,
        "proration" => ProviderAdjustmentScope.Prorated,
        _ => ProviderAdjustmentScope.Unknown,
    };
    private static ProviderFinancialTotals Totals(JsonElement value, string currency)
    {
        if (value.TryGetProperty("currency_code", out _) && Text(value, "currency_code", 3) != currency) throw Invalid();
        ProviderMoney? Optional(string field) => !value.TryGetProperty(field, out var amount) || amount.ValueKind == JsonValueKind.Null ? null : Money(value, field, currency, signed: true);
        ProviderMoney? chargeback = null; ProviderMoney? original = null;
        if (value.TryGetProperty("chargeback_fee", out var fee) && fee.ValueKind != JsonValueKind.Null)
        {
            if (fee.ValueKind != JsonValueKind.Object) throw Invalid();
            chargeback = Money(fee, "amount", currency, signed: true);
            if (fee.TryGetProperty("original", out var rawOriginal) && rawOriginal.ValueKind != JsonValueKind.Null)
            {
                if (rawOriginal.ValueKind != JsonValueKind.Object) throw Invalid();
                original = Money(rawOriginal, "amount", Text(rawOriginal, "currency_code", 3), signed: true);
            }
        }
        return new ProviderFinancialTotals(Money(value, "subtotal", currency, signed: true), Money(value, "tax", currency, signed: true),
            Money(value, "total", currency, signed: true), Optional("fee"), Optional("earnings"), Optional("retained_fee"), chargeback, original,
            Optional("discount"), Optional("credit"), Optional("credit_to_balance"), Optional("balance"), Optional("grand_total"), Optional("grand_total_tax"));
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
        var transaction = kind is ProviderEventKind.PaymentChanged or ProviderEventKind.PaymentCompleted ? Transaction(data) : null;
        var subscription = kind == ProviderEventKind.SubscriptionChanged ? Subscription(data) : null;
        var adjustment = kind == ProviderEventKind.AdjustmentChanged ? Adjustment(data) : null;
        if (subscription?.State == ProviderSubscriptionState.Unknown || subscription?.ScheduledAction == ProviderScheduledAction.Unknown || adjustment is { Kind: ProviderAdjustmentKind.Unknown }
            || adjustment is { Scope: ProviderAdjustmentScope.Unknown } || adjustment?.Items.Any(i => i.Scope == ProviderAdjustmentScope.Unknown) == true)
        {
            kind = ProviderEventKind.Unsupported; transaction = null; subscription = null; adjustment = null;
        }
        return new VerifiedProviderEvent(settings.Source, reference, dedupe, kind, occurred, transaction, subscription, adjustment);
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
