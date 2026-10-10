// SPDX-License-Identifier: AGPL-3.0-only
// The runner's own SQL (CLOUD.84 U9, S42(1)). The statements are embedded resources (Statements.sql, one named section each), so the
// C# engine holds no SQL literal: it asks for a section by name and fills its placeholders. The statement text is the same SQL the
// engine always ran; the `?` positions and their order are unchanged, and the engine binds them as before.
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Storage.D1.MigrationRunner;

internal static partial class RunnerSql
{
    private const string StatementsResource = "ArcForges.Cloud.Storage.D1.MigrationRunner.Statements.sql";

    private static readonly Lazy<Dictionary<string, string>> Sections = new(LoadSections, isThreadSafe: true);

    /// <summary>
    /// The text of the named section with its placeholders filled. `{name}` is replaced once, in a single pass, so a value that
    /// contains braces is inserted as it is. `{guard}`, `{applying}` and `{applied}` are always available.
    /// </summary>
    public static string Get(string name, params (string Key, string Value)[] values)
    {
        var text = Section(name);
        var map = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["guard"] = Section("guard"),
            ["applying"] = MigrationEngine.StateApplying.ToString(CultureInfo.InvariantCulture),
            ["applied"] = MigrationEngine.StateApplied.ToString(CultureInfo.InvariantCulture),
        };
        foreach (var (key, value) in values) map[key] = value;
        return Placeholder().Replace(text, match =>
            map.TryGetValue(match.Groups[1].Value, out var value)
                ? value
                : throw new MigrationError("unexpected-value", $"runner statement {name} has no value for {match.Value}"));
    }

    private static string Section(string name) =>
        Sections.Value.TryGetValue(name, out var text) ? text : throw new MigrationError("unexpected-value", $"runner statement {name} is missing");

    [GeneratedRegex(@"\{([a-z-]+)\}", RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"^-- name: ([a-z-]+)$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex SectionMarker();

    private static Dictionary<string, string> LoadSections()
    {
        using var stream = typeof(RunnerSql).Assembly.GetManifestResourceStream(StatementsResource)
            ?? throw new MigrationError("unexpected-value", "the runner statements are not embedded");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var text = reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
        var parts = SectionMarker().Split(text);
        var sections = new Dictionary<string, string>(StringComparer.Ordinal);
        // Parts alternate between the text before a marker (parts[0] is the file header) and the name and body that follow it.
        for (var index = 1; index + 1 < parts.Length; index += 2)
        {
            var name = parts[index];
            if (sections.ContainsKey(name)) throw new MigrationError("unexpected-value", $"runner statement {name} appears twice");
            sections[name] = parts[index + 1].Trim();
        }

        return sections;
    }
}
