// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Domain;

internal static class QuotaRules
{
    internal const int MaximumAdmissionBudgets = 8;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    internal static bool Text(string? value, int maximum)
    {
        if (value is not { Length: > 0 } || value.Length > maximum || value != value.Trim() || value.Any(char.IsControl)) return false;
        try { _ = StrictUtf8.GetByteCount(value); return true; }
        catch (EncoderFallbackException) { return false; }
    }

    internal static bool Key(QuotaBudgetKey? key) => key is not null
        && key.ScopeKind is QuotaScopeKind.Workspace or QuotaScopeKind.Deployment
        && Text(key.ScopeId, 128) && Text(key.QuotaKey, 128) && Text(key.PeriodKey, 128)
        && (key.ScopeKind != QuotaScopeKind.Workspace || CanonicalId(key.ScopeId));

    internal static bool Context(QuotaOwnerContext? context) => context is not null && context.RealmId != Guid.Empty
        && context.WorkspaceId != Guid.Empty && context.OwnerId != Guid.Empty && Text(context.OwnerKind, 64)
        && context.OwnerKind.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '/' or '-')
        && Text(context.ActorRef, 256) && context.AuthEpoch > 0 && context.RecoveryGeneration >= 0;

    internal static bool Owns(QuotaOwnerContext context, QuotaBudgetKey key) => key.ScopeKind != QuotaScopeKind.Workspace
        || context.WorkspaceId is { } workspace && key.ScopeId == workspace.ToString("D");

    internal static bool Budget(QuotaBudgetCommand command) => command.CommandId != Guid.Empty && Context(command.Context)
        && command.Change is { } change && Key(change.Key) && Owns(command.Context, change.Key) && Text(change.Unit, 64)
        && change.Limit >= 0 && change.PolicyVersion > 0 && change.ExpectedRevision is >= 0 and < long.MaxValue;

    internal static bool Admission(QuotaAdmissionCommand command, long now) => command.CommandId != Guid.Empty
        && command.OperationId != Guid.Empty && Context(command.Context)
        && command.Items is { Count: > 0 and <= MaximumAdmissionBudgets }
        && command.ExpiresAtMicros > now && Lease(command.JobLease, command.ExpiresAtMicros, now)
        && command.Items.All(item => item is not null && item.ReservationId != Guid.Empty && Key(item.Key)
            && Owns(command.Context, item.Key) && item.Bound > 0 && item.PolicyVersion > 0 && item.ExpectedRevision is > 0 and < long.MaxValue
            && item.AdmissionCeiling is null or >= 0)
        && command.Items.Select(item => item.Key).Distinct().Count() == command.Items.Count
        && command.Items.Select(item => item.ReservationId).Distinct().Count() == command.Items.Count;

    internal static bool Effect(QuotaEffectCommand command) => command.CommandId != Guid.Empty && Context(command.Context)
        && command.ReservationId != Guid.Empty && command.ExpectedBudgetRevision is > 0 and < long.MaxValue
        && Lease(command.JobLease, long.MaxValue, 0) && command.Measurement is { } measurement && measurement.EffectId != Guid.Empty
        && measurement.SourceObjectId != Guid.Empty && measurement.SourceSegmentId != Guid.Empty && measurement.DeletionReceiptId != Guid.Empty
        && (measurement.Kind switch
        {
            QuotaEffectKind.Consume => measurement.Quantity > 0 && (measurement.SourceObjectId is not null || measurement.SourceSegmentId is not null),
            QuotaEffectKind.Release => measurement.Quantity >= 0,
            QuotaEffectKind.Adjust => measurement.Quantity != 0 && measurement.Quantity != long.MinValue
                && (measurement.Quantity < 0 ? measurement.DeletionReceiptId is not null
                    : measurement.SourceObjectId is not null || measurement.SourceSegmentId is not null),
            _ => false,
        });

    internal static bool Cleanup(QuotaCleanupCommand command) => command.CommandId != Guid.Empty && Context(command.Context)
        && command.ReservationId != Guid.Empty && command.ExpectedBudgetRevision is > 0 and < long.MaxValue && Lease(command.JobLease, long.MaxValue, 0);

    internal static bool Matches(QuotaOwnerContext context, QuotaReservation reservation) => Owns(context, reservation.Key)
        && context.OwnerId == reservation.OwnerId && context.OwnerKind == reservation.OwnerKind;

    internal static bool State(QuotaBudgetState value) => Key(value.Key) && Text(value.Unit, 64) && value.Limit >= 0 && value.Used >= 0
        && value.Held >= 0 && value.PolicyVersion > 0 && value.Revision > 0;

    internal static bool State(QuotaReservation value) => value.ReservationId != Guid.Empty && value.OperationId != Guid.Empty
        && Key(value.Key) && Text(value.OwnerKind, 64) && value.OwnerId != Guid.Empty && value.Bound > 0
        && value.Consumed >= 0 && value.Consumed <= value.Bound
        && value.State is QuotaReservationState.Held or QuotaReservationState.Settled or QuotaReservationState.Releasing or QuotaReservationState.Released
        && value.ExpiresAtMicros >= 0 && (value.LeaseUntilMicros is null && value.Fence is null
            || value.LeaseUntilMicros is >= 0 && value.Fence is > 0);

    internal static string SortKey(QuotaBudgetKey key) => string.Join('\0', ((int)key.ScopeKind).ToString(CultureInfo.InvariantCulture), key.ScopeId, key.QuotaKey, key.PeriodKey);
    internal static string Scope(QuotaOwnerContext context) => (context.WorkspaceId ?? context.RealmId).ToString("D");
    internal static long Now(TimeProvider time) => checked((time.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
    internal static QuotaKernelStatus Status(ModulePlanStatus status) => status switch
    {
        ModulePlanStatus.Succeeded => QuotaKernelStatus.Succeeded,
        ModulePlanStatus.Replayed => QuotaKernelStatus.Replayed,
        ModulePlanStatus.ReusedIdentifier => QuotaKernelStatus.ReusedIdentifier,
        ModulePlanStatus.ReceiptExpired => QuotaKernelStatus.ReceiptExpired,
        ModulePlanStatus.StaleGeneration => QuotaKernelStatus.StaleGeneration,
        ModulePlanStatus.Unavailable => QuotaKernelStatus.Unavailable,
        ModulePlanStatus.UnknownOutcome => QuotaKernelStatus.UnknownOutcome,
        _ => QuotaKernelStatus.Conflict,
    };
    private static bool CanonicalId(string value) => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty && value == id.ToString("D");
    internal static bool Lease(CapacityJobLease? lease, long expiry, long now) => lease is null
        || lease.JobId != Guid.Empty && Text(lease.Holder, 128) && lease.Fence > 0 && lease.LeasedUntilMicros > now && lease.LeasedUntilMicros <= expiry;
    internal static void WriteLease(Utf8JsonWriter writer, CapacityJobLease? lease)
    {
        Id(writer, "jobId", lease?.JobId);
        if (lease is null) writer.WriteNull("holder"); else writer.WriteString("holder", lease.Holder);
        Number(writer, "leaseUntil", lease?.LeasedUntilMicros); Number(writer, "fence", lease?.Fence);
    }
    internal static void WriteOwnerBinding(Utf8JsonWriter writer, QuotaOwnerContext context)
    {
        writer.WriteString("realm", context.RealmId.ToString("D")); Id(writer, "workspace", context.WorkspaceId);
        Number(writer, "generation", context.RecoveryGeneration);
        writer.WriteString("ownerKind", context.OwnerKind); writer.WriteString("ownerId", context.OwnerId.ToString("D"));
    }

    internal static (string Json, string Hash) Canonical(string operation, QuotaOwnerContext context, Action<Utf8JsonWriter> fields)
    {
        using var bytes = new MemoryStream();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject(); writer.WriteString("operation", operation);
            writer.WriteString("realm", context.RealmId.ToString("D")); Id(writer, "workspace", context.WorkspaceId);
            writer.WriteString("actor", context.ActorRef); Number(writer, "authEpoch", context.AuthEpoch);
            Number(writer, "generation", context.RecoveryGeneration); writer.WriteString("ownerKind", context.OwnerKind);
            writer.WriteString("ownerId", context.OwnerId.ToString("D")); fields(writer); writer.WriteEndObject();
        }
        var content = bytes.ToArray();
        return (Encoding.UTF8.GetString(content), Convert.ToHexStringLower(SHA256.HashData(content)));
    }

    internal static void WriteKey(Utf8JsonWriter writer, QuotaBudgetKey key)
    {
        Number(writer, "scopeKind", (int)key.ScopeKind); writer.WriteString("scopeId", key.ScopeId);
        writer.WriteString("quotaKey", key.QuotaKey); writer.WriteString("periodKey", key.PeriodKey);
    }
    internal static void Number(Utf8JsonWriter writer, string name, long value) => writer.WriteString(name, value.ToString(CultureInfo.InvariantCulture));
    internal static void Number(Utf8JsonWriter writer, string name, long? value) { if (value is { } number) Number(writer, name, number); else writer.WriteNull(name); }
    internal static void Id(Utf8JsonWriter writer, string name, Guid? value) { if (value is { } id) writer.WriteString(name, id.ToString("D")); else writer.WriteNull(name); }
}
