// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Cloud.Modules.Commerce.Catalogue.Domain;

internal static class CatalogueValidation
{
    internal static bool Valid(CataloguePublication p) =>
        p.OfferId != Guid.Empty && p.PriceVersionId != Guid.Empty && p.ConfigurationRevisionId != Guid.Empty
        && p.Kind is >= 1 and <= 4 && !(p.Active && p.Kind == 4)
        && Text(p.Name, 256) && Text(p.Scope, 128) && Text(p.TermProfile, 4096) && Text(p.TaxCategory, 128)
        && p.ExpectedOfferRevision is >= 0 and < long.MaxValue && p.PriceVersion > 0
        && p.StartsAtMicros >= 0 && (p.EndsAtMicros is null || p.EndsAtMicros > p.StartsAtMicros)
        && Money(p.Amount, p.Active) && p.Currency is { Length: 3 } && p.Currency.All(c => c is >= 'A' and <= 'Z');

    internal static bool Text(string? value, int limit)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > limit || value != value.Trim()) return false;
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (char.IsControl(c)) return false;
            if (char.IsHighSurrogate(c))
            {
                if (++i == value.Length || !char.IsLowSurrogate(value[i])) return false;
            }
            else if (char.IsLowSurrogate(c)) return false;
        }
        return true;
    }

    private static bool Money(string? value, bool active)
    {
        if (value is null || value.Length is < 1 or > 30) return false;
        var dot = value.IndexOf('.');
        var integral = dot < 0 ? value.Length : dot;
        if (integral == 0 || (integral > 1 && value[0] == '0')) return false;
        if (dot >= 0 && (value.Length - dot - 1 is < 1 or > 9 || value[^1] == '0')) return false;
        if (value.Where((_, i) => i != dot).Any(c => c is < '0' or > '9')) return false;
        var significant = value.Count(c => c is >= '0' and <= '9');
        if (significant > 28 || !decimal.TryParse(value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var amount)) return false;
        return amount >= 0 && (!active || amount > 0);
    }
}
