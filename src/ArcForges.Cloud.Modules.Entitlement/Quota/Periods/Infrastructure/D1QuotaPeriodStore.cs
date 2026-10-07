// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Infrastructure;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Infrastructure;

internal sealed class D1QuotaPeriodStore(IModulePlanPort plans) : IQuotaPeriodStore
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private const int MaximumTextUnits = 262144;
    private const long MaximumHistoryBytes = 16L * 1024 * 1024;
    public async Task<QuotaPeriodStoredResult> ReadAsync(Guid realmId, Guid workspaceId, CancellationToken cancellationToken)
    {
        var scope = workspaceId.ToString("D");
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var before = await State(scope, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (before.Status != QuotaDefinitionStatus.Succeeded || before.Rows.Count == 0) return new(before.Status);
            try
            {
                var state = before.Rows.Single();
                if (state.Count != 7 || state[0].AsInt64() <= 0 || state[1].AsInt64() <= 0) return new(QuotaDefinitionStatus.Defect);
                var snapshot = SnapshotMapper.FromColumns(scope, new(state[1].AsInt64(), state[2].AsInt64(), state[3].AsOptionalInt64(), state[4].AsText(), state[5].AsText(), state[6].AsText()));
                var terms = await Pages("entitlement.quota-period-terms", scope, 5, cancellationToken).ConfigureAwait(false);
                if (terms.Status != QuotaDefinitionStatus.Succeeded) return new(terms.Status);
                var actions = await Pages("entitlement.quota-period-actions", scope, 4, cancellationToken, 2000 - terms.Rows.Count, MaximumHistoryBytes - terms.TextBytes).ConfigureAwait(false);
                if (actions.Status != QuotaDefinitionStatus.Succeeded) return new(actions.Status);
                var after = await State(scope, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (after.Status != QuotaDefinitionStatus.Succeeded) return new(after.Status);
                if (after.Rows.Count != 1 || !state.SequenceEqual(after.Rows[0])) continue;
                var normalizedTerms = terms.Rows.Select(r =>
                {
                    if (r.Count != 10) throw new FormatException();
                    return new QuotaServiceTerm(Id(r[0]), Id(r[1]), Id(r[2]), (QuotaServiceTermKind)checked((int)r[3].AsInt64() - 1),
                        r[4].AsText(), r[5].AsInt64(), r[6].AsInt64(), r[7].AsInt64(), r[8].AsInt64(), r[9].AsInt64());
                }).ToImmutableArray();
                if (normalizedTerms.Any(t => t.RealmId != realmId || t.WorkspaceId != workspaceId)) return new(QuotaDefinitionStatus.Defect);
                var normalizedActions = actions.Rows.Select(r =>
                {
                    if (r.Count != 7) throw new FormatException();
                    return new QuotaServiceTermAction(Id(r[0]), Id(r[1]), (QuotaTermActionKind)checked((int)r[2].AsInt64() - 1),
                        r[3].AsInt64(), r[4].AsInt64(), r[5].AsText(), r[6].AsOptionalText() is { } replacement ? Guid.ParseExact(replacement, "D") : null);
                }).ToImmutableArray();
                var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SnapshotCodec.Serialize(snapshot))));
                return new(QuotaDefinitionStatus.Succeeded, new(state[0].AsInt64(), snapshot, hash, normalizedTerms, normalizedActions));
            }
            catch (EntitlementStoreException error) when (error.Failure == EntitlementStoreFailure.Unavailable)
            { cancellationToken.ThrowIfCancellationRequested(); return new(QuotaDefinitionStatus.Unavailable); }
            catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException or EntitlementStoreException or DecoderFallbackException or EncoderFallbackException)
            { cancellationToken.ThrowIfCancellationRequested(); return new(QuotaDefinitionStatus.Defect); }
        }
        return new(QuotaDefinitionStatus.Unavailable);
    }
    private async Task<(QuotaDefinitionStatus Status, IReadOnlyList<IReadOnlyList<PlanValue>> Rows)> State(string scope, CancellationToken ct)
    {
        var result = await plans.ReadAsync(new("entitlement.quota-period-state", scope, [PlanValue.FromText(scope)]), ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (result.Status != ModulePlanStatus.Succeeded) return (QuotaDefinitionOutcomes.Status(result.Status), []);
        if (result.Rows.Count == 0) return (QuotaDefinitionStatus.NotFound, []);
        if (result.Rows.Count != 1 || result.Rows[0].Count != 10) return (QuotaDefinitionStatus.Defect, []);
        try
        {
            var metadata = result.Rows[0]; var values = metadata.Take(7).ToArray();
            var version = metadata[1].AsInt64(); var computedAt = metadata[2].AsInt64();
            for (var field = 0; field < 3; field++)
            {
                var capturedField = field + 1; var length = metadata[field + 7].AsInt64();
                values[field + 4] = PlanValue.FromText(await Reconstruct(metadata[field + 4], length, offset =>
                    plans.ReadAsync(new("entitlement.quota-period-snapshot-text", scope, [PlanValue.FromText(scope),
                        PlanValue.FromInt64(version), PlanValue.FromInt64(computedAt), PlanValue.FromInt64(capturedField),
                        PlanValue.FromInt64(offset), PlanValue.FromInt64(length)]), ct), ct, missingUnavailable: true).ConfigureAwait(false));
            }
            ct.ThrowIfCancellationRequested();
            return (QuotaDefinitionStatus.Succeeded, [values]);
        }
        catch (EntitlementStoreException error) when (error.Failure == EntitlementStoreFailure.Unavailable)
        { ct.ThrowIfCancellationRequested(); return (QuotaDefinitionStatus.Unavailable, []); }
        catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException or DecoderFallbackException or EncoderFallbackException)
        { ct.ThrowIfCancellationRequested(); return (QuotaDefinitionStatus.Defect, []); }
    }
    private async Task<(QuotaDefinitionStatus Status, List<IReadOnlyList<PlanValue>> Rows, long TextBytes)> Pages(string plan, string scope, int cursorColumn, CancellationToken ct, int bound = 2000, long byteBound = MaximumHistoryBytes)
    {
        var all = new List<IReadOnlyList<PlanValue>>();
        long textBytes = 0;
        long at = long.MinValue; string id = "";
        while (true)
        {
            var result = await plans.ReadAsync(new(plan, scope, [PlanValue.FromText(scope), PlanValue.FromInt64(at), PlanValue.FromText(id)]), ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (result.Status != ModulePlanStatus.Succeeded) return (QuotaDefinitionOutcomes.Status(result.Status), all, textBytes);
            if (result.Rows.Count > 100 || all.Count + result.Rows.Count > bound) return (QuotaDefinitionStatus.Defect, all, textBytes);
            foreach (var row in result.Rows)
            {
                if (row.Count <= cursorColumn) return (QuotaDefinitionStatus.Defect, all, textBytes);
                var nextAt = row[cursorColumn].AsInt64(); var nextId = row[0].AsText();
                if (nextAt < at || nextAt == at && StringComparer.Ordinal.Compare(nextId, id) <= 0) return (QuotaDefinitionStatus.Defect, all, textBytes);
                var nextBytes = row[^1].AsInt64();
                if (nextBytes <= 0 || nextBytes > MaximumTextUnits * 4L) return (QuotaDefinitionStatus.Defect, all, textBytes);
                if (nextBytes > byteBound - textBytes) return (QuotaDefinitionStatus.Unavailable, all, textBytes);
                textBytes += nextBytes;
                var textColumn = plan == "entitlement.quota-period-terms" ? 4 : 5;
                var captured = row.Take(row.Count - 1).ToArray();
                captured[textColumn] = PlanValue.FromText(await Text(plan, scope, nextId, row[textColumn], row[^1].AsInt64(), ct).ConfigureAwait(false));
                at = nextAt; id = nextId; all.Add(captured);
            }
            // A byte-budgeted page can legitimately contain fewer than 100 rows.
            // Only a verified empty keyset page proves that the full history was read.
            if (result.Rows.Count == 0) return (QuotaDefinitionStatus.Succeeded, all, textBytes);
        }
    }
    private Task<string> Text(string pagePlan, string scope, string id, PlanValue inline, long byteLength, CancellationToken ct)
    {
        if (byteLength <= 0) throw new FormatException();
        var slicePlan = pagePlan == "entitlement.quota-period-terms" ? "entitlement.quota-period-term-text" : "entitlement.quota-period-action-text";
        return Reconstruct(inline, byteLength, offset => plans.ReadAsync(new(slicePlan, scope,
            [PlanValue.FromInt64(offset), PlanValue.FromText(scope), PlanValue.FromText(id), PlanValue.FromInt64(byteLength)]), ct), ct);
    }
    private static async Task<string> Reconstruct(PlanValue inline, long byteLength,
        Func<long, Task<ModulePlanOutcome>> readSlice, CancellationToken ct, bool missingUnavailable = false)
    {
        if (byteLength is < 0 or > MaximumTextUnits * 4L) throw new FormatException();
        if (!inline.IsNull)
        {
            var value = inline.AsText();
            if (byteLength > 256 || value.Length > MaximumTextUnits || Utf8.GetByteCount(value) != byteLength) throw new FormatException();
            return value;
        }
        var bytes = new byte[checked((int)byteLength)];
        try
        {
            for (var offset = 0; offset < bytes.Length;)
            {
                var read = await readSlice(offset).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                if (read.Status != ModulePlanStatus.Succeeded || missingUnavailable && read.Rows.Count == 0)
                    throw new EntitlementStoreException(EntitlementStoreFailure.Unavailable, "Quota history text is unavailable.");
                if (read.Rows.Count != 1 || read.Rows[0].Count != 1) throw new FormatException();
                var part = read.Rows[0][0].AsBytes();
                if (part.Length != Math.Min(16384, bytes.Length - offset)) throw new FormatException();
                part.CopyTo(bytes.AsSpan(offset)); offset += part.Length;
            }
            var value = Utf8.GetString(bytes); ct.ThrowIfCancellationRequested();
            if (value.Length > MaximumTextUnits) throw new FormatException();
            return value;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static Guid Id(PlanValue value)
    {
        var text = value.AsText(); var id = Guid.ParseExact(text, "D");
        if (id == Guid.Empty || id.ToString("D") != text) throw new FormatException(); return id;
    }
}
