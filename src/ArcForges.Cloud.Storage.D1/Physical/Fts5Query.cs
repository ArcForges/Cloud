// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;

namespace ArcForges.Cloud.Storage.Physical;

/// <summary>
/// The single owner of the scope token that partitions a D1 FTS5 table by workspace and product (Design D1 profile section 8). The
/// token is one alphanumeric word (the unicode61 tokenizer would split anything else), so a column filter on it is an index lookup.
/// </summary>
internal static class Fts5Scope
{
    public const string Separator = "x";

    public static string Word(Guid workspaceId, string productId)
    {
        if (workspaceId == Guid.Empty) throw new PhysicalValueException("A search scope needs a workspace.");
        if (productId is not ("arcscope" or "companion")) throw new PhysicalValueException("A search scope needs a closed product id.");
        return workspaceId.ToString("N", CultureInfo.InvariantCulture) + Separator + productId;
    }

    public static bool IsWord(string text)
    {
        if (text.Length < 33) return false;
        for (var index = 0; index < 32; index++)
        {
            if (text[index] is not ((>= '0' and <= '9') or (>= 'a' and <= 'f'))) return false;
        }

        return string.Equals(text[32..], Separator + "arcscope", StringComparison.Ordinal) || string.Equals(text[32..], Separator + "companion", StringComparison.Ordinal);
    }
}

internal sealed class Fts5QueryException(string message) : Exception(message);

/// <summary>
/// Builds the one MATCH expression a search plan may bind. The expression always starts with the scope filter, so a candidate set
/// is never global, and every user term is a quoted phrase confined to the title and body columns: the FTS5 operators
/// (AND, OR, NOT, NEAR, a column filter, a prefix star, parentheses, a caret) are literal text and can neither widen the scope nor
/// reach another column. The expression is a bound parameter, never SQL text.
/// </summary>
internal static class Fts5Query
{
    public const int MaxTerms = 16;
    public const int MaxTermLength = 64;
    public const int MaxInputLength = 512;
    private static readonly UTF8Encoding Strict = new(false, true);

    public static string Match(string scopeKey, string userText, bool prefixLastTerm = false)
    {
        ArgumentNullException.ThrowIfNull(scopeKey);
        ArgumentNullException.ThrowIfNull(userText);
        if (!Fts5Scope.IsWord(scopeKey)) throw new Fts5QueryException("The search scope key is malformed.");
        if (userText.Length > MaxInputLength) throw new Fts5QueryException("The search text is too long.");
        try
        {
            Strict.GetByteCount(userText);
        }
        catch (EncoderFallbackException)
        {
            throw new Fts5QueryException("The search text is not well-formed Unicode.");
        }

        var terms = new List<string>();
        var current = new StringBuilder();
        foreach (var rune in userText.EnumerateRunes())
        {
            if (Rune.IsControl(rune) && !Rune.IsWhiteSpace(rune)) throw new Fts5QueryException("The search text contains a control character.");
            if (Rune.IsWhiteSpace(rune))
            {
                Flush(terms, current);
            }
            else
            {
                current.Append(rune.ToString());
            }
        }

        Flush(terms, current);
        if (terms.Count == 0) throw new Fts5QueryException("The search text has no term.");
        if (terms.Count > MaxTerms) throw new Fts5QueryException("The search text has too many terms.");
        var phrases = terms.Select((term, index) => Phrase(term) + (prefixLastTerm && index == terms.Count - 1 ? " *" : "")).ToArray();
        return "scope_key : " + Phrase(scopeKey) + " AND {title body} : (" + string.Join(" AND ", phrases) + ")";
    }

    private static void Flush(List<string> terms, StringBuilder current)
    {
        if (current.Length == 0) return;
        var term = current.ToString();
        current.Clear();
        if (term.Length > MaxTermLength) throw new Fts5QueryException("A search term is too long.");
        terms.Add(term);
    }

    private static string Phrase(string text) => "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
}
