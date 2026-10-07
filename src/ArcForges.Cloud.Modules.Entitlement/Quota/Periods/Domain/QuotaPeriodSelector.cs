// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Domain;

internal sealed record QuotaPeriodSelection(QuotaDefinitionStatus Status, QuotaSelectedPeriod? Selected = null, long? NextBoundaryMicros = null);

/// <summary>TM01/04/05 over complete immutable owner rows. Neither a calendar nor a subscription identifies a quota period.</summary>
internal static class QuotaPeriodSelector
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public static QuotaPeriodSelection Select(Guid realmId, Guid workspaceId, string realmKind,
        ImmutableArray<QuotaServiceTerm> terms, ImmutableArray<QuotaServiceTermAction> actions, long observedAtMicros)
    {
        if (realmId == Guid.Empty || workspaceId == Guid.Empty || realmKind is not ("official" or "selfHosted")
            || terms.IsDefault || actions.IsDefault || terms.Length + actions.Length > 2000) return Defect();
        var byId = new Dictionary<Guid, QuotaServiceTerm>();
        foreach (var term in terms)
        {
            if (term is null || term.TermId == Guid.Empty || term.RealmId != realmId || term.WorkspaceId != workspaceId
                || !Enum.IsDefined(term.Kind) || !Text(term.PeriodRef) || term.EndsAtMicros <= term.StartsAtMicros
                || !byId.TryAdd(term.TermId, term)) return Defect();
        }
        var actionIds = new HashSet<Guid>();
        var sources = new HashSet<string>(StringComparer.Ordinal);
        foreach (var action in actions)
        {
            if (action is null || action.ActionId == Guid.Empty || !actionIds.Add(action.ActionId) || !Text(action.SourceRef)
                || !sources.Add(action.SourceRef) || !Enum.IsDefined(action.Kind) || !byId.TryGetValue(action.TermId, out var term)
                || action.RecordedAtMicros < term.CreatedAtMicros
                || action.Kind == QuotaTermActionKind.Supersede && (action.ReplacementTermId is not { } replacement || !byId.ContainsKey(replacement))
                || action.Kind == QuotaTermActionKind.Revoke && action.ReplacementTermId is not null) return Defect();
        }
        long? boundary = null;
        QuotaSelectedPeriod? selected = null;
        foreach (var term in terms)
        {
            if ((term.Kind == QuotaServiceTermKind.SelfHostGrant) != (realmKind == "selfHosted")) continue;
            AddBoundary(term.CreatedAtMicros);
            var starts = Math.Max(term.StartsAtMicros, term.AuthorizedAtMicros);
            var ends = term.EndsAtMicros;
            foreach (var action in actions.Where(a => a.TermId == term.TermId))
            {
                AddBoundary(action.RecordedAtMicros);
                if (action.RecordedAtMicros > observedAtMicros) continue;
                ends = Math.Min(ends, action.EffectiveAtMicros);
                AddBoundary(action.EffectiveAtMicros);
            }
            AddBoundary(starts);
            AddBoundary(ends);
            if (term.CreatedAtMicros > observedAtMicros || starts > observedAtMicros || observedAtMicros >= ends) continue;
            var candidate = new QuotaSelectedPeriod(PeriodKey(term), term, starts, ends);
            if (selected is null || term.SelectionPriority > selected.Term.SelectionPriority
                || term.SelectionPriority == selected.Term.SelectionPriority
                && StringComparer.Ordinal.Compare(term.TermId.ToString("D"), selected.Term.TermId.ToString("D")) < 0)
                selected = candidate;
        }
        return new(QuotaDefinitionStatus.Succeeded, selected, boundary);

        void AddBoundary(long at)
        {
            if (at > observedAtMicros && (boundary is null || at < boundary)) boundary = at;
        }
    }

    /// <summary>Length-prefixed UTF8 tuple with a domain separator; fixed original interval survives actions and A-B-A reselection.</summary>
    internal static string PeriodKey(QuotaServiceTerm term)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (var field in new[] { "entitlement.quota-period.v1", term.RealmId.ToString("D"), term.WorkspaceId.ToString("D"),
            term.Kind.ToString(), term.TermId.ToString("D"), term.PeriodRef,
            term.StartsAtMicros.ToString(CultureInfo.InvariantCulture), term.EndsAtMicros.ToString(CultureInfo.InvariantCulture) })
        {
            var bytes = Utf8.GetBytes(field);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        return "term:" + Convert.ToHexStringLower(hash.GetHashAndReset());
    }
    private static bool Text(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 262144) return false;
        try { _ = Utf8.GetByteCount(value); return true; }
        catch (EncoderFallbackException) { return false; }
    }
    private static QuotaPeriodSelection Defect() => new(QuotaDefinitionStatus.Defect);
}
