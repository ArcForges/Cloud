// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>The token kinds of the policy lexer (a port of the AI policy's source lexer).</summary>
internal enum TokenKind
{
    Word,
    String,
    Template,
    Number,
    Regex,
    Punct,
}

/// <summary>
/// One token. <see cref="Value"/> is the decoded text for strings and the raw text for every other kind. <see cref="Dynamic"/> marks a
/// template literal that contains at least one substitution.
/// </summary>
internal sealed record Token(TokenKind Kind, string Value, int Line, bool Dynamic = false);

/// <summary>The form of a module declaration: a static import or export, a dynamic import call, or a require call.</summary>
internal enum ModuleForm
{
    Import,
    Export,
    Dynamic,
    Require,
}

/// <summary>
/// One module declaration. <see cref="Specifier"/> is null when the specifier is computed and cannot be classified with certainty. The
/// bindings map a local name to the imported name; "*" marks a namespace import and "default" a default import.
/// </summary>
internal sealed record ModuleReference(string? Specifier, ModuleForm Form, IReadOnlyList<KeyValuePair<string, string>> Bindings, bool TypeOnly, int Line);

/// <summary>
/// The lexical model of the Worker TypeScript policy. It is deliberately not a parser: comments are discarded, string, template and regular
/// expression bodies are opaque, and module declarations are recognised from the remaining tokens. Forms it cannot classify with certainty
/// are reported as computed, so the policy fails closed instead of guessing.
/// </summary>
internal static partial class PolicyLexer
{
    private static readonly string[] Punctuators =
    [
        ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.",
        "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
    ];

    private static readonly HashSet<string> ValueWords = new(StringComparer.Ordinal) { "this", "super", "null", "true", "false", "undefined" };

    private static readonly HashSet<string> RegexStarters = new(StringComparer.Ordinal)
    {
        "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await",
    };

    [GeneratedRegex(@"\\u\{([a-fA-F0-9]+)\}|\\u([a-fA-F0-9]{4})|\\x([a-fA-F0-9]{2})|\\([\s\S])", RegexOptions.CultureInvariant)]
    private static partial Regex EscapeSequence();

    [GeneratedRegex(@"^(?:0[xXbBoO][0-9a-fA-F_]+n?|(?:[0-9][0-9_]*\.?[0-9_]*|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9]+)?n?)", RegexOptions.CultureInvariant)]
    private static partial Regex NumericLiteral();

    /// <summary>Decodes the escape sequences of a string or template body, as the policy lexer does.</summary>
    internal static string Decode(string body) =>
        EscapeSequence().Replace(body, match =>
        {
            var code = match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Success ? match.Groups[3].Value : string.Empty;
            if (code.Length == 0) return match.Groups[4].Value;
            var point = long.Parse(code, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (point > 0x10FFFF) return "\uFFFD";
            return point is >= 0xD800 and <= 0xDFFF ? ((char)point).ToString() : char.ConvertFromUtf32((int)point);
        });

    /// <summary>Tokenizes one source text. Unterminated constructs end at the end of the text rather than throwing.</summary>
    public static List<Token> Tokenize(string source)
    {
        var scanner = new Scanner(source);
        scanner.Scan(0, source.Length);
        return scanner.Tokens;
    }

    private sealed class Scanner(string source)
    {
        private int line = 1;

        public List<Token> Tokens { get; } = [];

        private char At(int index) => index >= 0 && index < source.Length ? source[index] : '\0';

        private string Slice(int start, int end)
        {
            var from = Math.Clamp(start, 0, source.Length);
            var to = Math.Clamp(end, from, source.Length);
            return source[from..to];
        }

        private bool StartsWithAt(int index, string item) =>
            index >= 0 && source.Length - index >= item.Length && string.CompareOrdinal(source, index, item, 0, item.Length) == 0;

        private static bool IsDigit(char c) => c is >= '0' and <= '9';

        private static bool IsWordStart(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or '_' or '$' || c > 127;

        private static bool IsWordPart(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '$' || c > 127;

        /// <summary>Scans the half-open range [start, end). Template substitutions recurse into this method.</summary>
        public void Scan(int start, int end)
        {
            var index = start;
            while (index < end)
            {
                var c = source[index];
                if (c == '\n')
                {
                    line++;
                    index++;
                    continue;
                }

                if (char.IsWhiteSpace(c))
                {
                    index++;
                    continue;
                }

                if (c == '/' && At(index + 1) == '/')
                {
                    while (index < end && source[index] != '\n') index++;
                    continue;
                }

                if (c == '/' && At(index + 1) == '*')
                {
                    var close = source.IndexOf("*/", index + 2, StringComparison.Ordinal);
                    var stop = close < 0 ? end : close + 2;
                    foreach (var ch in Slice(index, stop))
                    {
                        if (ch == '\n') line++;
                    }

                    index = stop;
                    continue;
                }

                if (c is '"' or '\'')
                {
                    var cursor = index + 1;
                    while (cursor < end && source[cursor] != c && source[cursor] != '\n') cursor += source[cursor] == '\\' ? 2 : 1;
                    Tokens.Add(new Token(TokenKind.String, Decode(Slice(index + 1, cursor)), line));
                    index = cursor + 1;
                    continue;
                }

                if (c == '`')
                {
                    index = ScanTemplate(index, end);
                    continue;
                }

                if (IsDigit(c) || (c == '.' && IsDigit(At(index + 1))))
                {
                    var numeric = NumericLiteral().Match(Slice(index, Math.Min(end, index + 64)));
                    if (numeric.Success)
                    {
                        Tokens.Add(new Token(TokenKind.Number, numeric.Value, line));
                        index += numeric.Value.Length;
                        continue;
                    }
                }

                if (IsWordStart(c))
                {
                    var cursor = index + 1;
                    while (cursor < end && IsWordPart(source[cursor])) cursor++;
                    Tokens.Add(new Token(TokenKind.Word, source[index..cursor], line));
                    index = cursor;
                    continue;
                }

                if (c == '/' && !DividesAfterPrevious())
                {
                    var cursor = index + 1;
                    var inClass = false;
                    while (cursor < end && source[cursor] != '\n')
                    {
                        var ch = source[cursor];
                        if (ch == '\\') cursor++;
                        else if (ch == '[') inClass = true;
                        else if (ch == ']') inClass = false;
                        else if (ch == '/' && !inClass) break;
                        cursor++;
                    }

                    cursor++;
                    while (cursor < end && source[cursor] is >= 'a' and <= 'z') cursor++;
                    Tokens.Add(new Token(TokenKind.Regex, Slice(index, cursor), line));
                    index = cursor;
                    continue;
                }

                var matched = Array.Find(Punctuators, item => StartsWithAt(index, item)) ?? c.ToString();
                Tokens.Add(new Token(TokenKind.Punct, matched, line));
                index += matched.Length;
            }
        }

        /// <summary>Whether a slash after the previous token is a division rather than the start of a regular expression.</summary>
        private bool DividesAfterPrevious()
        {
            if (Tokens.Count == 0) return false;
            var previous = Tokens[^1];
            if (previous.Kind is TokenKind.Number or TokenKind.String or TokenKind.Template or TokenKind.Regex) return true;
            if (previous.Kind == TokenKind.Word && (ValueWords.Contains(previous.Value) || !RegexStarters.Contains(previous.Value))) return true;
            return previous.Value is ")" or "]" or "}";
        }

        /// <summary>Scans a template literal; its substitutions become punctuation and tokens after the template token.</summary>
        private int ScanTemplate(int index, int end)
        {
            var cursor = index + 1;
            var text = new StringBuilder();
            var dynamic = false;
            var startLine = line;
            var inner = new List<(int From, int To)>();
            while (cursor < end && source[cursor] != '`')
            {
                if (source[cursor] == '\\')
                {
                    text.Append(Slice(cursor, cursor + 2));
                    cursor += 2;
                    continue;
                }

                if (source[cursor] == '$' && At(cursor + 1) == '{')
                {
                    dynamic = true;
                    var nesting = 1;
                    var probe = cursor + 2;
                    while (probe < end && nesting > 0)
                    {
                        var c = source[probe];
                        if (c == '{') nesting++;
                        else if (c == '}') nesting--;
                        else if (c is '"' or '\'' or '`')
                        {
                            // Skip nested literal bodies so their braces do not count.
                            probe++;
                            while (probe < end && source[probe] != c) probe += source[probe] == '\\' ? 2 : 1;
                        }

                        probe++;
                    }

                    inner.Add((cursor + 2, probe - 1));
                    cursor = probe;
                    continue;
                }

                if (source[cursor] == '\n') line++;
                text.Append(source[cursor]);
                cursor++;
            }

            Tokens.Add(new Token(TokenKind.Template, Decode(text.ToString()), startLine, dynamic));
            foreach (var (from, to) in inner)
            {
                Tokens.Add(new Token(TokenKind.Punct, "${", line));
                Scan(from, Math.Min(to, source.Length));
                Tokens.Add(new Token(TokenKind.Punct, "}", line));
            }

            return cursor + 1;
        }
    }

    private static bool Word(Token? token, string? value = null) => token?.Kind == TokenKind.Word && (value is null || token.Value == value);

    private static bool Punct(Token? token, string value) => token?.Kind == TokenKind.Punct && token.Value == value;

    private static bool Literal(Token? token) => token?.Kind == TokenKind.String || (token?.Kind == TokenKind.Template && !token.Dynamic);

    /// <summary>Reads every module declaration of a token list: static imports and exports, dynamic imports and require calls.</summary>
    public static List<ModuleReference> ModuleReferences(IReadOnlyList<Token> tokens)
    {
        var references = new List<ModuleReference>();
        for (var index = 0; index < tokens.Count; index++)
        {
            var token = tokens[index];
            if (token.Kind != TokenKind.Word) continue;
            var previous = Peek(tokens, index - 1);
            // A property or member named import or require is not a module declaration.
            if (Punct(previous, ".") || Punct(previous, "?.")) continue;
            var next = Peek(tokens, index + 1);
            if (token.Value is "import" or "require" && Punct(next, "("))
            {
                var argument = Peek(tokens, index + 2);
                var closing = Peek(tokens, index + 3);
                var specifier = Literal(argument) && (Punct(closing, ")") || Punct(closing, ",")) ? argument!.Value : null;
                references.Add(new ModuleReference(specifier, token.Value == "import" ? ModuleForm.Dynamic : ModuleForm.Require, [], false, token.Line));
                continue;
            }

            if (token.Value is not ("import" or "export")) continue;
            var cursor = index + 1;
            var typeOnly = false;
            if (Word(Peek(tokens, cursor), "type") && !Word(Peek(tokens, cursor + 1), "from"))
            {
                typeOnly = true;
                cursor++;
            }

            var bindings = new List<KeyValuePair<string, string>>();
            if (token.Value == "import" && Literal(Peek(tokens, cursor)))
            {
                references.Add(new ModuleReference(Peek(tokens, cursor)!.Value, ModuleForm.Import, bindings, typeOnly, token.Line));
                continue;
            }

            if (token.Value == "export" && !(Punct(Peek(tokens, cursor), "{") || Punct(Peek(tokens, cursor), "*"))) continue;
            var imported = true;
            while (cursor < tokens.Count)
            {
                var current = tokens[cursor];
                if (Word(current, "from")) break;
                if (current.Kind == TokenKind.Punct && current.Value is not ("{" or "}" or "," or "*"))
                {
                    imported = false;
                    break;
                }

                if (current.Kind is TokenKind.String or TokenKind.Template)
                {
                    imported = false;
                    break;
                }

                if (Punct(current, "{"))
                {
                    cursor++;
                    while (cursor < tokens.Count && !Punct(tokens[cursor], "}"))
                    {
                        var name = tokens[cursor];
                        if (Word(name, "type") && Word(Peek(tokens, cursor + 1)) && !Word(Peek(tokens, cursor + 1), "as"))
                        {
                            cursor++;
                            name = tokens[cursor];
                        }

                        var hasAlias = Word(Peek(tokens, cursor + 1), "as");
                        var alias = hasAlias ? Peek(tokens, cursor + 2) : name;
                        if (name.Kind is TokenKind.Word or TokenKind.String && alias is not null) Bind(bindings, alias.Value, name.Value);
                        cursor += hasAlias ? 3 : 1;
                        if (Punct(Peek(tokens, cursor), ",")) cursor++;
                    }

                    cursor++;
                    continue;
                }

                if (Punct(current, "*"))
                {
                    var alias = Word(Peek(tokens, cursor + 1), "as") ? Peek(tokens, cursor + 2) : null;
                    if (alias is not null) Bind(bindings, alias.Value, "*");
                    cursor += alias is not null ? 3 : 1;
                    continue;
                }

                if (Word(current))
                {
                    if (token.Value == "import") Bind(bindings, current.Value, "default");
                    cursor++;
                    continue;
                }

                cursor++;
            }

            if (!imported || !Word(Peek(tokens, cursor), "from")) continue;
            var target = Peek(tokens, cursor + 1);
            references.Add(new ModuleReference(Literal(target) ? target!.Value : null, token.Value == "import" ? ModuleForm.Import : ModuleForm.Export, bindings, typeOnly, token.Line));
        }

        return references;
    }

    /// <summary>Sets a binding; a later binding of the same local name replaces the earlier one in place, as a JavaScript Map does.</summary>
    private static void Bind(List<KeyValuePair<string, string>> bindings, string local, string imported)
    {
        var existing = bindings.FindIndex(pair => pair.Key == local);
        if (existing >= 0) bindings[existing] = new KeyValuePair<string, string>(local, imported);
        else bindings.Add(new KeyValuePair<string, string>(local, imported));
    }

    private static Token? Peek(IReadOnlyList<Token> tokens, int index) => index >= 0 && index < tokens.Count ? tokens[index] : null;
}
