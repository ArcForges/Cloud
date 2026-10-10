// SPDX-License-Identifier: AGPL-3.0-only
// The SQL text rules of the D1 migration runner (CLOUD.84 U9, S41(1)): statement splitting that understands strings, quoted
// identifiers, comments and trigger bodies, the migration header, the statement classes each mode may contain, the backfill
// sections and the content checksum that locks a merged migration (RES-cloud-d1-migrations). This is the C# authority; the
// TypeScript original (eng/migrations/sql.ts) is test support only.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Storage.D1.MigrationRunner;

/// <summary>The four migration modes. The numbers are the manifest's registry numbers (platform.migration_mode).</summary>
public enum MigrationMode
{
    Expand = 1,
    Backfill = 2,
    Cutover = 3,
    Contract = 4,
}

/// <summary>One statement of a migration: its text without the terminating semicolon, and the upper-cased leading words (up to three).</summary>
public sealed record SqlStatement(string Sql, IReadOnlyList<string> Head);

/// <summary>The header line of a migration: the module, the mode and the extra key=value options.</summary>
public sealed record MigrationHeader(string Module, MigrationMode Mode, IReadOnlyDictionary<string, string> Options);

/// <summary>The parsed sections and option line of a backfill migration.</summary>
public sealed record BackfillSpec(string Target, string Key, int PageSize, string Page, string Apply, string Verify);

public static partial class MigrationSql
{
    /// <summary>The mode names as they are written in the header.</summary>
    public static string ModeName(MigrationMode mode) => mode switch
    {
        MigrationMode.Expand => "expand",
        MigrationMode.Backfill => "backfill",
        MigrationMode.Cutover => "cutover",
        MigrationMode.Contract => "contract",
        _ => throw new MigrationError("unexpected-value", "unknown migration mode"),
    };

    /// <summary>Parses a mode name, or returns null when it is not one of the four.</summary>
    public static MigrationMode? ParseMode(string name) => name switch
    {
        "expand" => MigrationMode.Expand,
        "backfill" => MigrationMode.Backfill,
        "cutover" => MigrationMode.Cutover,
        "contract" => MigrationMode.Contract,
        _ => null,
    };

    /// <summary>Normalizes line endings so a checkout with CRLF has the same checksum as one with LF.</summary>
    public static string NormalizeNewlines(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal);

    /// <summary>The lower-case hex SHA-256 over the UTF-8 bytes of the normalized text.</summary>
    public static string ChecksumOf(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(NormalizeNewlines(text))));

    private enum TokenKind
    {
        Word,
        String,
        Ident,
        Number,
        Punct,
        Comment,
        Space,
    }

    private readonly record struct Token(TokenKind Kind, string Text);

    private static char At(string sql, int index) => index < sql.Length ? sql[index] : '\0';

    private static bool IsWordStart(int code) =>
        (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code == 95 || code >= 128;

    private static bool IsWordPart(int code) => IsWordStart(code) || (code >= 48 && code <= 57) || code == 36;

    private static List<Token> Tokenize(string sql)
    {
        var tokens = new List<Token>();
        var index = 0;
        while (index < sql.Length)
        {
            var ch = sql[index];
            var code = (int)ch;
            if (ch is ' ' or '\t' or '\n' or '\r')
            {
                var start = index;
                while (index < sql.Length && " \t\n\r".Contains(sql[index], StringComparison.Ordinal)) index++;
                tokens.Add(new Token(TokenKind.Space, sql[start..index]));
            }
            else if (ch == '-' && At(sql, index + 1) == '-')
            {
                var start = index;
                while (index < sql.Length && sql[index] != '\n') index++;
                tokens.Add(new Token(TokenKind.Comment, sql[start..index]));
            }
            else if (ch == '/' && At(sql, index + 1) == '*')
            {
                var start = index;
                var end = sql.IndexOf("*/", index + 2, StringComparison.Ordinal);
                index = end < 0 ? sql.Length : end + 2;
                tokens.Add(new Token(TokenKind.Comment, sql[start..index]));
            }
            else if (ch is '\'' or '"' or '`')
            {
                var start = index;
                index++;
                var closed = false;
                while (index < sql.Length)
                {
                    if (sql[index] == ch)
                    {
                        if (At(sql, index + 1) == ch)
                        {
                            index += 2;
                            continue;
                        }

                        index++;
                        closed = true;
                        break;
                    }

                    index++;
                }

                if (!closed) throw new MigrationError("migration-format", "unterminated quoted text in SQL");
                tokens.Add(new Token(ch == '\'' ? TokenKind.String : TokenKind.Ident, sql[start..index]));
            }
            else if (ch == '[')
            {
                var start = index;
                var end = sql.IndexOf(']', index);
                if (end < 0) throw new MigrationError("migration-format", "unterminated bracket identifier in SQL");
                index = end + 1;
                tokens.Add(new Token(TokenKind.Ident, sql[start..index]));
            }
            else if (IsWordStart(code))
            {
                var start = index;
                while (index < sql.Length && IsWordPart(sql[index])) index++;
                tokens.Add(new Token(TokenKind.Word, sql[start..index]));
            }
            else if (code >= 48 && code <= 57)
            {
                var start = index;
                while (index < sql.Length && (IsWordPart(sql[index]) || sql[index] == '.')) index++;
                tokens.Add(new Token(TokenKind.Number, sql[start..index]));
            }
            else
            {
                tokens.Add(new Token(TokenKind.Punct, ch.ToString()));
                index++;
            }
        }

        return tokens;
    }

    /// <summary>
    /// Splits migration SQL into statements. A semicolon ends a statement unless it is inside a string, a quoted identifier,
    /// a comment or a trigger body (the text between the trigger's BEGIN and its matching END, where CASE ... END pairs nest).
    /// </summary>
    public static List<SqlStatement> SplitStatements(string sql)
    {
        var tokens = Tokenize(NormalizeNewlines(sql));
        var statements = new List<SqlStatement>();
        var current = new List<Token>();
        var words = new List<Token>();
        var triggerDepth = 0;
        var inTrigger = false;

        void Flush()
        {
            if (words.Count > 0)
            {
                var text = string.Concat(current.Select(token => token.Text)).Trim();
                statements.Add(new SqlStatement(
                    TrimLeadingComments(text),
                    words.Take(3).Select(token => token.Text.ToUpperInvariant()).ToList()));
            }

            current.Clear();
            words.Clear();
            inTrigger = false;
            triggerDepth = 0;
        }

        foreach (var token in tokens)
        {
            if (token.Kind == TokenKind.Punct && token.Text == ";" && triggerDepth == 0)
            {
                Flush();
                continue;
            }

            current.Add(token);
            if (token.Kind != TokenKind.Word) continue;
            words.Add(token);
            var word = token.Text.ToUpperInvariant();
            if (!inTrigger && words.Count >= 2 && words[0].Text.ToUpperInvariant() == "CREATE")
            {
                var second = words[1].Text.ToUpperInvariant();
                var third = words.Count > 2 ? words[2].Text.ToUpperInvariant() : null;
                if (second == "TRIGGER" || ((second == "TEMP" || second == "TEMPORARY") && third == "TRIGGER"))
                    inTrigger = true;
            }

            if (inTrigger)
            {
                if (word is "BEGIN" or "CASE") triggerDepth++;
                else if (word == "END" && triggerDepth > 0) triggerDepth--;
            }
        }

        if (triggerDepth != 0) throw new MigrationError("migration-format", "unterminated trigger body in SQL");
        Flush();
        return statements;
    }

    private static string TrimLeadingComments(string text)
    {
        var rest = text;
        for (;;)
        {
            rest = rest.TrimStart();
            if (rest.StartsWith("--", StringComparison.Ordinal))
            {
                var end = rest.IndexOf('\n', StringComparison.Ordinal);
                rest = end < 0 ? string.Empty : rest[(end + 1)..];
            }
            else if (rest.StartsWith("/*", StringComparison.Ordinal))
            {
                var end = rest.IndexOf("*/", StringComparison.Ordinal);
                rest = end < 0 ? string.Empty : rest[(end + 2)..];
            }
            else
            {
                return rest;
            }
        }
    }

    [GeneratedRegex(@"^--\s*af-migration:\s*(.+)$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex HeaderLine();

    [GeneratedRegex(@"^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex ModulePattern();

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    private static partial Regex Whitespace();

    /// <summary>Parses the `-- af-migration:` header line: module, mode and the extra options.</summary>
    public static MigrationHeader ParseHeader(string sql)
    {
        var match = HeaderLine().Match(NormalizeNewlines(sql));
        if (!match.Success) throw new MigrationError("migration-format", "migration has no `-- af-migration:` header line");
        var pairs = new Dictionary<string, string>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var part in Whitespace().Split(match.Groups[1].Value.Trim()))
        {
            var equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0) throw new MigrationError("migration-format", $"malformed header option \"{part}\"");
            var key = part[..equals];
            if (pairs.ContainsKey(key)) throw new MigrationError("migration-format", $"duplicate header option {key}");
            pairs[key] = part[(equals + 1)..];
            order.Add(key);
        }

        pairs.TryGetValue("module", out var module);
        pairs.TryGetValue("mode", out var modeName);
        if (string.IsNullOrEmpty(module) || !ModulePattern().IsMatch(module))
            throw new MigrationError("migration-format", "header module is missing or invalid");
        var mode = modeName is null ? null : ParseMode(modeName);
        if (mode is null) throw new MigrationError("migration-format", "header mode must be one of expand, backfill, cutover, contract");
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var key in order)
            if (key is not ("module" or "mode")) options[key] = pairs[key];
        return new MigrationHeader(module, mode.Value, options);
    }

    private static readonly HashSet<string> BaseForbidden = new(StringComparer.Ordinal)
    {
        "PRAGMA", "ATTACH", "DETACH", "VACUUM", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "END",
    };

    [GeneratedRegex(@"^PRAGMA\s+defer_foreign_keys\s*=\s*(?:ON|OFF|1|0)\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DeferForeignKeys();

    [GeneratedRegex(@"^CREATE (?:UNIQUE )?(?:TABLE|INDEX|TRIGGER|VIRTUAL TABLE)\b", RegexOptions.CultureInvariant)]
    private static partial Regex CreateObject();

    [GeneratedRegex(@"^CREATE (?:UNIQUE )?INDEX\b", RegexOptions.CultureInvariant)]
    private static partial Regex CreateIndex();

    [GeneratedRegex(@"^ALTER TABLE\b", RegexOptions.CultureInvariant)]
    private static partial Regex AlterTable();

    [GeneratedRegex(@"\bADD(?: COLUMN)?\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AddColumn();

    [GeneratedRegex(@"\b(?:DROP|RENAME)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DropOrRename();

    [GeneratedRegex(@"^ALTER\s+TABLE\s+\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AlterTablePrefix();

    [GeneratedRegex(@"^(?:DROP|ALTER)\b", RegexOptions.CultureInvariant)]
    private static partial Regex DropOrAlter();

    [GeneratedRegex(@"^(?:INSERT|UPDATE|DELETE)\b", RegexOptions.CultureInvariant)]
    private static partial Regex DataChange();

    /// <summary>
    /// The statements one mode may contain. The runner owns transactions, so no migration controls them. An expand migration
    /// only adds; a contract migration is the only one that may remove or rename.
    /// </summary>
    public static List<string> ModeViolations(MigrationMode mode, IReadOnlyList<SqlStatement> statements)
    {
        var problems = new List<string>();
        for (var position = 0; position < statements.Count; position++)
        {
            var statement = statements[position];
            var head = string.Join(" ", statement.Head);
            var where = $"statement {position + 1} ({head})";
            var first = statement.Head.Count > 0 ? statement.Head[0] : string.Empty;
            if (BaseForbidden.Contains(first))
            {
                if (first == "PRAGMA" && DeferForeignKeys().IsMatch(statement.Sql)) continue;
                problems.Add($"{where}: {first} is not allowed in a migration");
                continue;
            }

            var isCreate = CreateObject().IsMatch(head) || CreateIndex().IsMatch(head);
            if (mode == MigrationMode.Expand)
            {
                if (isCreate) continue;
                if (AlterTable().IsMatch(head) && AddColumn().IsMatch(statement.Sql) &&
                    !DropOrRename().IsMatch(AlterTablePrefix().Replace(statement.Sql, string.Empty, 1)))
                    continue;
                problems.Add($"{where}: an expand migration may only create tables, indexes, triggers and virtual tables or add a column");
            }
            else if (mode == MigrationMode.Contract)
            {
                if (isCreate || DropOrAlter().IsMatch(head) || DataChange().IsMatch(head)) continue;
                problems.Add($"{where}: unsupported statement in a contract migration");
            }
            else if (mode == MigrationMode.Cutover)
            {
                if (DataChange().IsMatch(head) || isCreate) continue;
                problems.Add($"{where}: a cutover migration contains data and index statements only");
            }
        }

        return problems;
    }

    [GeneratedRegex(@"^--\s*section:\s*(page|apply|verify)\s*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex SectionMarker();

    [GeneratedRegex(@"^--\s*af-backfill:\s*(\{.*\})\s*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex BackfillLine();

    [GeneratedRegex(@"^[a-z][a-z0-9_]*$", RegexOptions.CultureInvariant)]
    private static partial Regex SnakeName();

    [GeneratedRegex(@"^\s*SELECT\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SelectStart();

    [GeneratedRegex(@"^\s*UPDATE\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UpdateStart();

    [GeneratedRegex(@"\?", RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"\bLIMIT\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Limit();

    [GeneratedRegex(@"\bORDER\s+BY\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OrderBy();

    [GeneratedRegex(@"\brev(?:ision)?\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RevisionGuard();

    /// <summary>Parses the three named sections and the JSON option line of a backfill migration.</summary>
    public static BackfillSpec ParseBackfill(string sql)
    {
        var text = NormalizeNewlines(sql);
        var optionMatch = BackfillLine().Match(text);
        if (!optionMatch.Success) throw new MigrationError("migration-format", "backfill migration has no `-- af-backfill:` JSON line");
        string? target = null;
        string? key = null;
        var pageSize = 100;
        using (var document = JsonDocument.Parse(optionMatch.Groups[1].Value))
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new MigrationError("migration-format", "backfill option line must be an object");
            if (root.TryGetProperty("target", out var targetValue) && targetValue.ValueKind == JsonValueKind.String)
                target = targetValue.GetString();
            if (root.TryGetProperty("key", out var keyValue) && keyValue.ValueKind == JsonValueKind.String)
                key = keyValue.GetString();
            if (root.TryGetProperty("pageSize", out var sizeValue))
            {
                if (sizeValue.ValueKind != JsonValueKind.Number || !sizeValue.TryGetInt32(out pageSize))
                    throw new MigrationError("migration-format", "backfill pageSize must be 1..100 (Design D1 profile section 6)");
            }
        }

        if (string.IsNullOrEmpty(target) || !SnakeName().IsMatch(target))
            throw new MigrationError("migration-format", "backfill target is missing or invalid");
        if (string.IsNullOrEmpty(key) || !SnakeName().IsMatch(key))
            throw new MigrationError("migration-format", "backfill key is missing or invalid");
        if (pageSize < 1 || pageSize > 100)
            throw new MigrationError("migration-format", "backfill pageSize must be 1..100 (Design D1 profile section 6)");

        var parts = SectionMarker().Split(text);
        var sections = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < parts.Length; index += 2)
        {
            var name = parts[index];
            if (sections.ContainsKey(name)) throw new MigrationError("migration-format", $"backfill section {name} appears twice");
            sections[name] = (index + 1 < parts.Length ? parts[index + 1] : string.Empty).Trim();
        }

        string Section(string name)
        {
            if (!sections.TryGetValue(name, out var body) || body.Length == 0)
                throw new MigrationError("migration-format", $"backfill section {name} is missing");
            var statements = SplitStatements(body);
            if (statements.Count != 1)
                throw new MigrationError("migration-format", $"backfill section {name} must hold exactly one statement");
            return statements[0].Sql;
        }

        var spec = new BackfillSpec(target, key, pageSize, Section("page"), Section("apply"), Section("verify"));
        if (!SelectStart().IsMatch(spec.Page)) throw new MigrationError("migration-format", "backfill page must be a SELECT");
        if (!SelectStart().IsMatch(spec.Verify)) throw new MigrationError("migration-format", "backfill verify must be a SELECT");
        if (!UpdateStart().IsMatch(spec.Apply)) throw new MigrationError("migration-format", "backfill apply must be one UPDATE");
        if (Placeholder().Matches(spec.Page).Count != 2)
            throw new MigrationError("migration-format", "backfill page takes exactly two parameters (the key cursor and the limit)");
        if (!Limit().IsMatch(spec.Page) || !OrderBy().IsMatch(spec.Page))
            throw new MigrationError("migration-format", "backfill page must be ordered by the key and limited");
        if (Placeholder().Matches(spec.Apply).Count != 2)
            throw new MigrationError("migration-format", "backfill apply takes exactly two parameters (the key and the expected revision)");
        if (!RevisionGuard().IsMatch(spec.Apply))
            throw new MigrationError("migration-format", "backfill apply must guard the owner revision");
        return spec;
    }

    private static string Head12(string value) => value.Length <= 12 ? value : value[..12];

    /// <summary>Shared text of a checksum excerpt in refusal messages.</summary>
    public static string ShortChecksum(string checksum) => Head12(checksum);

    [GeneratedRegex(@"^(\d{4})_([a-z][a-z0-9-]*)__([a-z0-9][a-z0-9-]*)\.sql$", RegexOptions.CultureInvariant)]
    private static partial Regex NumberedFileName();

    [GeneratedRegex(@"^([a-z][a-z0-9-]*)__([a-z0-9][a-z0-9-]*)\.sql$", RegexOptions.CultureInvariant)]
    private static partial Regex PendingFileName();

    /// <summary>The module and slug of a numbered migration file name, or null when the name does not match the pattern.</summary>
    public static (string Module, string Slug, int Sequence)? ParseNumberedFileName(string file)
    {
        var match = NumberedFileName().Match(file);
        if (!match.Success) return null;
        return (match.Groups[2].Value, match.Groups[3].Value, int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>The module of a pending migration file name (module__slug.sql), or null when it does not match.</summary>
    public static string? ParsePendingModule(string file)
    {
        var match = PendingFileName().Match(file);
        return match.Success ? match.Groups[1].Value : null;
    }
}
