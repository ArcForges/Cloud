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
                var actions = await Pages("entitlement.quota-period-actions", scope, 4, cancellationToken, 2000 - terms.Rows.Count).ConfigureAwait(false);
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
            catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException or EntitlementStoreException)
            { cancellationToken.ThrowIfCancellationRequested(); return new(QuotaDefinitionStatus.Defect); }
        }
        return new(QuotaDefinitionStatus.Unavailable);
    }
    private async Task<(QuotaDefinitionStatus Status, IReadOnlyList<IReadOnlyList<PlanValue>> Rows)> State(string scope, CancellationToken ct)
    {
        var result = await plans.ReadAsync(new("entitlement.quota-period-state", scope, [PlanValue.FromText(scope)]), ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return (result.Status == ModulePlanStatus.Succeeded && result.Rows.Count == 0 ? QuotaDefinitionStatus.NotFound : QuotaDefinitionOutcomes.Status(result.Status), result.Rows);
    }
    private async Task<(QuotaDefinitionStatus Status, List<IReadOnlyList<PlanValue>> Rows)> Pages(string plan, string scope, int cursorColumn, CancellationToken ct, int bound = 2000)
    {
        var all = new List<IReadOnlyList<PlanValue>>();
        long at = long.MinValue; string id = "";
        while (true)
        {
            var result = await plans.ReadAsync(new(plan, scope, [PlanValue.FromText(scope), PlanValue.FromInt64(at), PlanValue.FromText(id)]), ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (result.Status != ModulePlanStatus.Succeeded) return (QuotaDefinitionOutcomes.Status(result.Status), all);
            if (result.Rows.Count > 100 || all.Count + result.Rows.Count > bound) return (QuotaDefinitionStatus.Defect, all);
            foreach (var row in result.Rows)
            {
                if (row.Count <= cursorColumn) return (QuotaDefinitionStatus.Defect, all);
                var nextAt = row[cursorColumn].AsInt64(); var nextId = row[0].AsText();
                if (nextAt < at || nextAt == at && StringComparer.Ordinal.Compare(nextId, id) <= 0) return (QuotaDefinitionStatus.Defect, all);
                at = nextAt; id = nextId; all.Add(row);
            }
            if (result.Rows.Count < 100) return (QuotaDefinitionStatus.Succeeded, all);
        }
    }
    private static Guid Id(PlanValue value)
    {
        var text = value.AsText(); var id = Guid.ParseExact(text, "D");
        if (id == Guid.Empty || id.ToString("D") != text) throw new FormatException(); return id;
    }
}
