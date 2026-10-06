// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Serialization;

namespace ArcForges.Cloud.Modules.Commerce.Adapters;

internal sealed record ApiItem([property: JsonPropertyName("price_id")] string PriceId, [property: JsonPropertyName("quantity")] int Quantity);
internal sealed record ApiMetadata(
    [property: JsonPropertyName("realm_id")] string RealmId,
    [property: JsonPropertyName("billing_account_id")] string BillingAccountId,
    [property: JsonPropertyName("workspace_id")] string WorkspaceId,
    [property: JsonPropertyName("purchase_intent_id")] string PurchaseIntentId,
    [property: JsonPropertyName("checkout_attempt_id")] string CheckoutAttemptId,
    [property: JsonPropertyName("offer_id")] string OfferId,
    [property: JsonPropertyName("price_version")] string PriceVersion,
    [property: JsonPropertyName("policy_version")] string PolicyVersion);
internal sealed record ApiCheckout([property: JsonPropertyName("url")] string Url);
internal sealed record ApiCheckoutBody(
    [property: JsonPropertyName("items")] ApiItem[] Items,
    [property: JsonPropertyName("currency_code")] string CurrencyCode,
    [property: JsonPropertyName("collection_mode")] string CollectionMode,
    [property: JsonPropertyName("custom_data")] ApiMetadata Metadata,
    [property: JsonPropertyName("checkout")] ApiCheckout Checkout);
internal sealed record ApiCancellation([property: JsonPropertyName("effective_from")] string EffectiveFrom);
internal sealed record ApiReactivation([property: JsonPropertyName("scheduled_change"), JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? ScheduledChange);
internal sealed record ApiRefundItem([property: JsonPropertyName("item_id")] string ItemId, [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("amount")] string? Amount);
internal sealed record ApiRefundBody([property: JsonPropertyName("action")] string Action, [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("transaction_id")] string TransactionId, [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("items")] ApiRefundItem[]? Items);
internal sealed record ApiPortalBody([property: JsonPropertyName("subscription_ids")] string[] Subscriptions);
internal sealed record ProviderProjectionEnvelope(int Version, VerifiedProviderEvent Event);

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ApiCheckoutBody))]
[JsonSerializable(typeof(ApiCancellation))]
[JsonSerializable(typeof(ApiReactivation))]
[JsonSerializable(typeof(ApiRefundBody))]
[JsonSerializable(typeof(ApiPortalBody))]
[JsonSerializable(typeof(VerifiedProviderEvent))]
[JsonSerializable(typeof(ProviderProjectionEnvelope))]
internal sealed partial class PaddleJsonContext : JsonSerializerContext;
