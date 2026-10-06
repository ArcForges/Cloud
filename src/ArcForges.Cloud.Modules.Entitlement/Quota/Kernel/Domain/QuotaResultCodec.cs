// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Domain;

[JsonSerializable(typeof(QuotaKernelResult))]
[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class QuotaJsonContext : JsonSerializerContext { }

internal static class QuotaResultCodec
{
    internal static string Encode(QuotaKernelResult result) => JsonSerializer.Serialize(result, QuotaJsonContext.Default.QuotaKernelResult);
    internal static QuotaKernelResult Decode(string? json)
    {
        if (json is null || json.Length > 65536) return new(QuotaKernelStatus.Conflict);
        try
        {
            var result = JsonSerializer.Deserialize(json, QuotaJsonContext.Default.QuotaKernelResult);
            if (result is null || !Enum.IsDefined(result.Status)
                || result.Status == QuotaKernelStatus.Succeeded && result.Budgets is not { Count: > 0 }
                || result.Budgets is { Count: > QuotaRules.MaximumAdmissionBudgets } || result.Reservations is { Count: > QuotaRules.MaximumAdmissionBudgets }
                || result.Budgets?.Any(budget => budget is null || !QuotaRules.State(budget)) == true
                || result.Reservations?.Any(reservation => reservation is null || !QuotaRules.State(reservation)) == true)
                return new(QuotaKernelStatus.Conflict);
            return result;
        }
        catch (JsonException) { return new(QuotaKernelStatus.Conflict); }
    }
}
