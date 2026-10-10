// SPDX-License-Identifier: AGPL-3.0-only
// The SQL tokenizer and table-reference scanner of the storage-plan generator (CLOUD.84 U7; port of the tokenizer, the CTE check,
// referencedTables and writeTargets in eng/verification/storage-plans.ts). The grammar is closed and fails closed.
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Tools.Generation.StoragePlans;

public enum SqlTokenKind
{
    Word,
    String,
    Number,
    Punct,
}

/// <summary>One token. Words are ASCII-lower-cased (SQLite folds only ASCII); other kinds keep their text as written.</summary>
public readonly record struct SqlToken(SqlTokenKind Kind, string Value);

public static partial class SqlText
{
    /// <summary>CTE names must start with this, and no owner prefix may: a CTE can never shadow a physical table.</summary>
    public const string CtePrefix = "cte_";

    /// <summary>A FROM clause (and so a comma join) ends at one of these at the same depth; only reserved words belong here.</summary>
    public static readonly HashSet<string> FromEnders =
    [
        "where", "group", "order", "limit", "having", "union", "intersect", "except", "returning", "set",
    ];

    private static readonly HashSet<string> NotATable = ["select", "with", "values", "where", "set", "on", "using"];

    /// <summary>SQLite table-valued functions a plan may read from; every other FROM or JOIN target is a physical table.</summary>
    private static readonly HashSet<string> TableFunctions = ["json_each", "json_tree"];

    private static bool IsWordStart(int code) =>
        (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code == 95 || code >= 128;

    private static bool IsWordPart(int code) => IsWordStart(code) || (code >= 48 && code <= 57) || code == 36;

    private static bool IsDigit(int code) => code >= 48 && code <= 57;

    private static int CodeAt(string text, int index) => index < text.Length ? text[index] : -1;

    private static string AsciiLower(string text) => AsciiUpper().Replace(text, match => match.Value.ToLowerInvariant());

    [GeneratedRegex("[A-Z]+", RegexOptions.CultureInvariant)]
    private static partial Regex AsciiUpper();

    /// <summary>Splits one SQL statement the way SQLite does for the constructs this check cares about.</summary>
    public static List<SqlToken> Tokenize(string sql, string where)
    {
        var tokens = new List<SqlToken>();
        var index = 0;
        while (index < sql.Length)
        {
            var code = sql[index];
            if (code is ' ' or '\t' or '\n' or '\r' or '\f')
            {
                index++;
            }
            else if (code == '-' && CodeAt(sql, index + 1) == '-')
            {
                var end = sql.IndexOf('\n', index);
                index = end < 0 ? sql.Length : end + 1;
            }
            else if (code == '/' && CodeAt(sql, index + 1) == '*')
            {
                var end = sql.IndexOf("*/", index + 2, StringComparison.Ordinal);
                Require(end >= 0, $"{where}: unterminated comment");
                index = end + 2;
            }
            else if (code == '\'')
            {
                var end = index + 1;
                for (; ; )
                {
                    var close = sql.IndexOf('\'', end);
                    Require(close >= 0, $"{where}: unterminated string literal");
                    if (CodeAt(sql, close + 1) == '\'')
                    {
                        end = close + 2;
                    }
                    else
                    {
                        end = close + 1;
                        break;
                    }
                }

                tokens.Add(new SqlToken(SqlTokenKind.String, sql[index..end]));
                index = end;
            }
            else if (code is '"' or '`' or '[' or ']')
            {
                throw new PlanRefusal($"{where}: quoted identifiers are not allowed");
            }
            else if (IsWordStart(code))
            {
                var end = index + 1;
                while (end < sql.Length && IsWordPart(sql[end])) end++;
                tokens.Add(new SqlToken(SqlTokenKind.Word, AsciiLower(sql[index..end])));
                index = end;
            }
            else if (IsDigit(code) || (code == '.' && IsDigit(CodeAt(sql, index + 1))))
            {
                var end = index + 1;
                while (end < sql.Length && (IsWordPart(sql[end]) || sql[end] == '.')) end++;
                tokens.Add(new SqlToken(SqlTokenKind.Number, sql[index..end]));
                index = end;
            }
            else
            {
                tokens.Add(new SqlToken(SqlTokenKind.Punct, code.ToString()));
                index++;
            }
        }

        return tokens;
    }

    public static SqlToken? TokenAt(IReadOnlyList<SqlToken> tokens, int index) =>
        index >= 0 && index < tokens.Count ? tokens[index] : null;

    /// <summary>The value of the token at an index, or null when the index is past the end (undefined in the Node generator).</summary>
    public static string? ValueAt(IReadOnlyList<SqlToken> tokens, int index) => TokenAt(tokens, index)?.Value;

    public static bool IsPunct(SqlToken? token, string value) => token is { Kind: SqlTokenKind.Punct } t && t.Value == value;

    /// <summary>Index just past the parenthesised group that starts at <paramref name="open"/>, or -1 when it is not closed.</summary>
    private static int SkipGroup(IReadOnlyList<SqlToken> tokens, int open)
    {
        var depth = 0;
        for (var index = open; index < tokens.Count; index++)
        {
            if (IsPunct(tokens[index], "(")) depth++;
            if (IsPunct(tokens[index], ")")) depth--;
            if (depth == 0) return index + 1;
        }

        return -1;
    }

    /// <summary>The CTE names a statement defines, each strictly in the form WITH [RECURSIVE] name [(columns)] AS [[NOT] MATERIALIZED] (...).</summary>
    private static HashSet<string> DefinedCtes(IReadOnlyList<SqlToken> tokens, string where)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        for (var start = 0; start < tokens.Count; start++)
        {
            var token = tokens[start];
            if (token.Kind != SqlTokenKind.Word || token.Value != "with") continue;
            var index = start + 1;
            if (ValueAt(tokens, index) == "recursive") index++;
            for (; ; )
            {
                var name = TokenAt(tokens, index);
                Require(
                    name is { Kind: SqlTokenKind.Word } n && n.Value.StartsWith(CtePrefix, StringComparison.Ordinal),
                    $"{where}: a CTE name starts with {CtePrefix}");
                names.Add(name!.Value.Value);
                index++;
                if (IsPunct(TokenAt(tokens, index), "("))
                {
                    index = SkipGroup(tokens, index);
                    Require(index > 0, $"{where}: unbalanced CTE column list");
                }

                Require(ValueAt(tokens, index) == "as", $"{where}: a CTE is defined with AS");
                index++;
                if (ValueAt(tokens, index) == "not") index++;
                if (ValueAt(tokens, index) == "materialized") index++;
                Require(IsPunct(TokenAt(tokens, index), "("), $"{where}: a CTE body is parenthesised");
                index = SkipGroup(tokens, index);
                Require(index > 0, $"{where}: unbalanced CTE body");
                if (!IsPunct(TokenAt(tokens, index), ",")) break;
                index++;
            }
        }

        return names;
    }

    /// <summary>
    /// Every physical table a plan statement names. After FROM, JOIN, INTO and UPDATE the next tokens must be a bare table name
    /// (a CTE of the statement is not a table), a table-valued function from the allow-list for FROM and JOIN, or a parenthesised
    /// query for FROM and JOIN. Anything else is refused, and so is a comma join.
    /// </summary>
    public static List<string> ReferencedTables(string sql, string where)
    {
        var tokens = Tokenize(sql, where);
        var ctes = DefinedCtes(tokens, where);
        var tables = new List<string>();
        var fromActive = new List<bool> { false };
        var depth = 0;
        for (var index = 0; index < tokens.Count; index++)
        {
            var token = tokens[index];
            if (token.Kind == SqlTokenKind.Punct)
            {
                if (token.Value == "(")
                {
                    depth++;
                    SetFlag(fromActive, depth, false);
                }
                else if (token.Value == ")")
                {
                    Require(depth > 0, $"{where}: unbalanced parentheses");
                    SetFlag(fromActive, depth, false);
                    depth--;
                }
                else if (token.Value == ",")
                {
                    Require(!fromActive[depth], $"{where}: use JOIN, a comma join would hide a table");
                }

                continue;
            }

            if (token.Kind != SqlTokenKind.Word) continue;
            if (FromEnders.Contains(token.Value)) SetFlag(fromActive, depth, false);
            var previous = ValueAt(tokens, index - 1);
            var keyword = token.Value;
            if (keyword == "from" && previous == "distinct") continue;
            if (keyword == "update" && ValueAt(tokens, index + 1) == "set" && previous == "do") continue;
            if (keyword is not ("from" or "join" or "into" or "update")) continue;
            var at = index + 1;
            if (keyword == "update" && ValueAt(tokens, at) == "or") at += 2;
            var target = TokenAt(tokens, at);
            var following = TokenAt(tokens, at + 1);
            var queryClause = keyword is "from" or "join";
            if (keyword == "from") SetFlag(fromActive, depth, true);
            if (IsPunct(target, "("))
            {
                var inner = TokenAt(tokens, at + 1);
                Require(
                    queryClause && inner is { Kind: SqlTokenKind.Word } i && i.Value is "select" or "with" or "values",
                    $"{where}: a parenthesised table is not allowed");
                continue;
            }

            Require(
                target is { Kind: SqlTokenKind.Word } tw && !NotATable.Contains(tw.Value),
                $"{where}: a table position after {keyword} holds something that is not a plain table name");
            var targetName = target!.Value.Value;
            Require(!IsPunct(following, "."), $"{where}: a schema-qualified name is not allowed ({targetName})");
            if (IsPunct(following, "(") && queryClause)
            {
                Require(TableFunctions.Contains(targetName), $"{where}: unknown table-valued function {targetName}");
                continue;
            }

            Require(
                !(IsPunct(following, "(") && keyword == "update"),
                $"{where}: a table name after update is not followed by a list");
            if (ctes.Contains(targetName))
            {
                Require(queryClause, $"{where}: a CTE is not a write target ({targetName})");
                continue;
            }

            if (!tables.Contains(targetName, StringComparer.Ordinal)) tables.Add(targetName);
        }

        Require(depth == 0, $"{where}: unbalanced parentheses");
        return tables;
    }

    private static void SetFlag(List<bool> flags, int depth, bool value)
    {
        while (flags.Count <= depth) flags.Add(false);
        flags[depth] = value;
    }

    /// <summary>Every table a statement inserts into, updates or deletes from, wherever it stands in the statement.</summary>
    public static List<string> WriteTargets(string sql, string where)
    {
        var tokens = Tokenize(sql, where);
        var targets = new List<string>();
        for (var index = 0; index < tokens.Count; index++)
        {
            var token = tokens[index];
            if (token.Kind != SqlTokenKind.Word) continue;
            var previous = ValueAt(tokens, index - 1);
            var at = index + 1;
            if (token.Value == "into")
            {
                // INSERT INTO t, REPLACE INTO t, INSERT OR IGNORE INTO t
            }
            else if (token.Value == "update")
            {
                if (previous == "do") continue;
                if (ValueAt(tokens, at) == "or") at += 2;
            }
            else if (token.Value == "delete" && ValueAt(tokens, at) == "from")
            {
                at++;
            }
            else
            {
                continue;
            }

            var target = TokenAt(tokens, at);
            if (target is { Kind: SqlTokenKind.Word } t && !targets.Contains(t.Value, StringComparer.Ordinal))
                targets.Add(t.Value);
        }

        return targets;
    }

    /// <summary>Throws a <see cref="PlanRefusal"/> with the message when the condition does not hold.</summary>
    public static void Require(bool condition, string message)
    {
        if (!condition) throw new PlanRefusal(message);
    }
}
