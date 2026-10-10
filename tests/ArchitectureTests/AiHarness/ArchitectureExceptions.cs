// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>The result of applying the owned exception register: the findings left unsuppressed and the register's own problems.</summary>
internal sealed record ExceptionResult(IReadOnlyList<HarnessFinding> Remaining, IReadOnlyList<HarnessFinding> Problems);

/// <summary>
/// The owned, expiring exception register of the GOV.10 successor rules (a port of the AI policy's exceptions). An exception names one exact
/// finding (rule, file and detail), an owner, a reason of substance and a lifetime of at most <see cref="MaxExceptionDays"/> days, measured
/// from its creation date. An expired, malformed, over-long, future-dated or unused entry is itself a finding, so an exception cannot outlive
/// the condition it covers.
/// </summary>
internal static partial class ArchitectureExceptions
{
    /// <summary>The longest lifetime an exception may have, measured from its creation date.</summary>
    public const int MaxExceptionDays = 180;

    /// <summary>The register file, repository-relative. Its findings name this path.</summary>
    public const string RegisterPath = "eng/policy/harness-architecture-exceptions.json";

    /// <summary>The rule ids that govern the register itself.</summary>
    public static readonly IReadOnlyList<string> RegisterRules = ["exception-invalid", "exception-expired", "exception-lifetime", "exception-unused"];

    private static readonly string[] Fields = ["id", "rule", "file", "detail", "owner", "reason", "created", "expires"];

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex CalendarDay();

    /// <summary>
    /// Applies the register to the findings of one audit. <paramref name="document"/> is the parsed register (null when it is not valid JSON),
    /// and <paramref name="today"/> is the audit date. The register is valid only with exactly the keys schemaVersion and exceptions.
    /// </summary>
    public static ExceptionResult Apply(IReadOnlyList<HarnessFinding> findings, JsonElement? document, DateOnly today, IEnumerable<string>? extraRules = null)
    {
        var problems = new List<HarnessFinding>();
        void Problem(string rule, string detail) => problems.Add(new HarnessFinding(rule, RegisterPath, detail));

        if (document is not { ValueKind: JsonValueKind.Object } root || !HasExactKeys(root, "exceptions", "schemaVersion")
            || !root.TryGetProperty("schemaVersion", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out var versionNumber) || versionNumber != 1
            || !root.TryGetProperty("exceptions", out var entries) || entries.ValueKind != JsonValueKind.Array)
        {
            Problem("exception-invalid", "Expected exactly schemaVersion 1 and an exceptions array");
            return new ExceptionResult(findings, problems);
        }

        // The GOV.10 catalogue plus the standing checks that register their own rules (the WorkerAdapter literal check, CLOUD.84 S43).
        var known = HarnessArchitecture.Rules.Select(rule => rule.Id).Concat(extraRules ?? Array.Empty<string>()).ToHashSet(StringComparer.Ordinal);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var remaining = findings.ToList();
        foreach (var raw in entries.EnumerateArray())
        {
            var label = raw.ValueKind == JsonValueKind.Object && raw.TryGetProperty("id", out var idValue) && idValue.ValueKind == JsonValueKind.String
                ? idValue.GetString()!
                : "(unnamed)";
            if (raw.ValueKind != JsonValueKind.Object || !HasExactKeys(raw, Fields) || Fields.Any(name => !IsText(raw, name)))
            {
                Problem("exception-invalid", label + ": every field is required and must be text");
                continue;
            }

            var entry = Read(raw);
            if (!ids.Add(entry.Id)) Problem("exception-invalid", entry.Id + ": duplicate id");
            if (!known.Contains(entry.Rule)) Problem("exception-invalid", entry.Id + ": unknown rule " + entry.Rule);
            if (entry.Reason.Length < 20 || entry.Owner.Length < 3)
            {
                Problem("exception-invalid", entry.Id + ": owner and a substantive reason are required");
            }

            if (!CalendarDay().IsMatch(entry.Created) || !CalendarDay().IsMatch(entry.Expires)
                || !DateOnly.TryParseExact(entry.Created, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var created)
                || !DateOnly.TryParseExact(entry.Expires, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var expires))
            {
                Problem("exception-invalid", entry.Id + ": dates must be YYYY-MM-DD");
                continue;
            }

            if (created > today) Problem("exception-invalid", entry.Id + ": created date is in the future");
            var lifetime = expires.DayNumber - created.DayNumber;
            if (lifetime <= 0 || lifetime > MaxExceptionDays)
            {
                Problem("exception-lifetime", entry.Id + ": lifetime must be 1-" + MaxExceptionDays + " days");
            }

            if (expires < today)
            {
                Problem("exception-expired", entry.Id + ": expired " + entry.Expires);
                continue;
            }

            var before = remaining.Count;
            remaining = remaining.Where(finding => !(finding.Rule == entry.Rule && finding.File == entry.File && finding.Detail == entry.Detail)).ToList();
            if (remaining.Count == before) Problem("exception-unused", entry.Id + ": matches no finding");
        }

        return new ExceptionResult(remaining, problems);
    }

    /// <summary>The fields of one well-formed register entry.</summary>
    internal sealed record Entry(string Id, string Rule, string File, string Detail, string Owner, string Reason, string Created, string Expires);

    private static Entry Read(JsonElement raw) => new(
        raw.GetProperty("id").GetString()!,
        raw.GetProperty("rule").GetString()!,
        raw.GetProperty("file").GetString()!,
        raw.GetProperty("detail").GetString()!,
        raw.GetProperty("owner").GetString()!,
        raw.GetProperty("reason").GetString()!,
        raw.GetProperty("created").GetString()!,
        raw.GetProperty("expires").GetString()!);

    private static bool IsText(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && value.GetString()!.Trim().Length > 0;

    private static bool HasExactKeys(JsonElement element, params string[] names)
    {
        var actual = element.EnumerateObject().Select(property => property.Name).OrderBy(name => name, StringComparer.Ordinal).ToArray();
        return actual.SequenceEqual(names.OrderBy(name => name, StringComparer.Ordinal), StringComparer.Ordinal);
    }
}
