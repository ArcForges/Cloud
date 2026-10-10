// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.RegularExpressions;
using ArcForges.Cloud.ArchitectureTests.AiHarness;

namespace ArcForges.Cloud.ArchitectureTests.WorkerAdapter;

/// <summary>
/// The standing check that the Worker holds no business literal (CLOUD.84 P2-021 item 1, S34 and S43). Every worker/**/*.ts source is read
/// through the policy lexer, and a literal is a finding when it is one of the forbidden kinds below and is not generated:
/// <list type="bullet">
/// <item><description>a budget: a number other than 0 or 1 in a declaration whose name names a limit (bytes, timeout, lease, skew, secret and
/// so on), in a timer or delay argument, in a length comparison of four or more, or in a fixed-size byte array;</description></item>
/// <item><description>an identifier shape: a regular expression with a digit or hexadecimal class or a counted quantifier, or a hexadecimal digest
/// or UUID string;</description></item>
/// <item><description>an admission list (an envelope key set or an admitted set), a method-table path (an RPC method or an /api/ path), a
/// plan-authority statement (SQL text), or a readiness or correlation constant.</description></item>
/// </list>
/// A structural literal is never a finding: 0 and 1, the operand of a division, a formatting argument (padStart, padEnd, slice and similar),
/// and any number in a declaration whose name names no limit. Only the generated module and the generated plan tables are excluded; their
/// values come from C# declarations and are checked by generate --check. A finding is accepted only when it is a closed protocol constant
/// (<see cref="ProtocolConstants"/>) or an owned, expiring exception of the shared register, so nothing is silently allowed. A finding's
/// detail is the declared symbol's name, or the name of the function that holds an inline literal.
/// </summary>
internal static partial class WorkerLiteralScan
{
    /// <summary>A number that names a limit, a timer or delay, a length or a fixed-size byte array.</summary>
    public const string BudgetRule = "worker-literal-budget";

    /// <summary>A regular expression or a digest string that encodes an identifier shape.</summary>
    public const string IdentifierRule = "worker-literal-identifier";

    /// <summary>A literal admission list: an envelope key set or an admitted set.</summary>
    public const string AdmissionRule = "worker-literal-admission";

    /// <summary>A public method path or an /api/ path that belongs to the generated method table.</summary>
    public const string MethodTableRule = "worker-literal-method-table";

    /// <summary>A SQL statement held in the Worker outside the generated plan tables.</summary>
    public const string PlanAuthorityRule = "worker-literal-plan-authority";

    /// <summary>A readiness vocabulary constant held in the Worker outside the generated vocabulary.</summary>
    public const string ReadinessRule = "worker-literal-readiness";

    /// <summary>A correlation constant held in the Worker outside the generated correlation guard.</summary>
    public const string CorrelationRule = "worker-literal-correlation";

    /// <summary>Every rule id of this check. The shared register accepts them alongside the GOV.10 catalogue.</summary>
    public static readonly IReadOnlyList<string> Rules =
        [BudgetRule, IdentifierRule, AdmissionRule, MethodTableRule, PlanAuthorityRule, ReadinessRule, CorrelationRule];

    /// <summary>The generated Worker outputs: the only worker files the check does not read.</summary>
    public static readonly IReadOnlySet<string> GeneratedFiles = new HashSet<string>(StringComparer.Ordinal)
    {
        "worker/tables/cloud-tables.generated.ts",
        "worker/storage/plans.generated.ts",
    };

    /// <summary>
    /// The closed protocol-constant list (S43(2)): values fixed by external wire standards, keyed by exact file and symbol. They are not
    /// budgets. A timeout limit comes from the generated module, and this list never names one.
    /// </summary>
    public static readonly IReadOnlyList<(string File, string Symbol)> ProtocolConstants =
    [
        ("worker/ingress/errors.ts", "grpcStatus"),
        ("worker/ingress/frames.ts", "dataFlag"),
        ("worker/ingress/frames.ts", "trailerFlag"),
        ("worker/ingress/pipeline.ts", "match"),
        ("worker/ingress/pipeline.ts", "units"),
    ];

    private const string ModuleScope = "<module>";

    private static readonly Regex BudgetName = new(
        "(?i)(byte|millis|second|max|min|limit|budget|timeout|delay|lease|backoff|skew|length|lifetime|deadline|window|cap|attempt|slice|item|secret|reply|body|frame|cold|elapsed|revision|sleep|tolerance|term|wake|alarm|retry|digit|count|flag|status|unit|grammar|nonce|span|size|prefix|mac)|Ms$",
        RegexOptions.CultureInvariant);

    private static readonly Regex AdmissionName = new("(?i)(envelope|admit|allow|permit)", RegexOptions.CultureInvariant);
    private static readonly Regex ReadinessName = new("(?i)readiness", RegexOptions.CultureInvariant);
    private static readonly Regex CorrelationName = new("(?i)(correlation|traceparent)", RegexOptions.CultureInvariant);
    private static readonly Regex IdentifierShape = new(@"\{\d|\\d|\[0-9|\[1-9|0-9a-f|\[a-f|A-Za-z0-9", RegexOptions.CultureInvariant);
    private static readonly Regex HexOrUuid = new(
        "^(?:[0-9a-f]{40,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", RegexOptions.CultureInvariant);
    private static readonly Regex Duration = new(@"^\d+(?:ms|s|m|h)$", RegexOptions.CultureInvariant);
    private static readonly Regex RpcMethod = new(@"^/[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+/[A-Za-z0-9_]+$", RegexOptions.CultureInvariant);
    private static readonly Regex SqlStatement = new(
        @"(?i)^\s*(?:select\s|insert\s+into\s|update\s+\w+\s+set\s|delete\s+from\s|create\s+table\s|alter\s+table\s|pragma\s)",
        RegexOptions.CultureInvariant);

    private static readonly HashSet<string> StructuralCalls = new(StringComparer.Ordinal)
    {
        "padEnd", "padStart", "slice", "substring", "substr", "charCodeAt", "charAt", "toString",
    };

    private static readonly HashSet<string> ComparisonOperators = new(StringComparer.Ordinal) { "===", "!==", "==", "!=", ">=", "<=", ">", "<" };

    /// <summary>Audits the worker sources of a checkout map. The result is ordered and free of duplicates.</summary>
    public static IReadOnlyList<HarnessFinding> Audit(IReadOnlyDictionary<string, string> sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        var findings = new HashSet<HarnessFinding>();
        foreach (var (path, text) in sources.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            if (!IsScanned(path)) continue;
            foreach (var finding in ScanFile(path, text)) findings.Add(finding);
        }

        return findings.OrderBy(finding => finding.Rule, StringComparer.Ordinal).ThenBy(finding => finding.File, StringComparer.Ordinal)
            .ThenBy(finding => finding.Detail, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Applies the shared register to every audit that the repository runs: the GOV.10 catalogue and this check. A register row for either
    /// kind of finding must name a real finding, so an unused row is itself a problem.
    /// </summary>
    public static ExceptionResult ApplyRegister(IReadOnlyDictionary<string, string> sources, System.Text.Json.JsonElement? document, DateOnly today)
    {
        var findings = HarnessArchitecture.Audit(sources).Concat(Audit(sources)).ToList();
        return ArchitectureExceptions.Apply(findings, document, today, Rules);
    }

    /// <summary>Whether a path is worker TypeScript that the check reads: a Worker source, never a declaration or a generated output.</summary>
    public static bool IsScanned(string path) =>
        path.StartsWith("worker/", StringComparison.Ordinal) && path.EndsWith(".ts", StringComparison.Ordinal)
        && !path.EndsWith(".d.ts", StringComparison.Ordinal) && !GeneratedFiles.Contains(path);

    private static IEnumerable<HarnessFinding> ScanFile(string path, string text)
    {
        var tokens = PolicyLexer.Tokenize(text);
        var (scopes, inClass) = EnclosingScopes(tokens);
        var structural = StructuralTokens(tokens);
        var covered = new bool[tokens.Count];
        var results = new HashSet<HarnessFinding>();

        // Declared symbols: a const, let or var with an initializer, or a class field with one. A function body inside an initializer is
        // inline code and is left to the inline pass.
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!IsDeclarationStart(tokens, i, inClass, out var name, out var equals, out var nameIndex)) continue;
            covered[nameIndex] = true;
            covered[equals] = true;
            var values = Initializer(tokens, equals + 1, covered);
            if (ProtocolConstants.Contains((path, name))) continue;
            foreach (var rule in DeclaredRules(name, values, tokens, structural)) results.Add(new HarnessFinding(rule, path, name));
        }

        // Inline literals outside a declared initializer, keyed by the function that holds them.
        for (var i = 0; i < tokens.Count; i++)
        {
            if (covered[i]) continue;
            foreach (var rule in InlineRules(tokens, i, structural))
            {
                if (ProtocolConstants.Contains((path, scopes[i]))) continue;
                results.Add(new HarnessFinding(rule, path, scopes[i]));
            }
        }

        return results;
    }

    /// <summary>The rules that a declared initializer breaks. The finding's detail is the declared symbol itself.</summary>
    private static IEnumerable<string> DeclaredRules(string name, IReadOnlyList<int> values, IReadOnlyList<Token> tokens, bool[] structural)
    {
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var budgetName = BudgetName.IsMatch(name);
        var admissionName = AdmissionName.IsMatch(name);
        foreach (var index in values)
        {
            var token = tokens[index];
            if (token.Kind == TokenKind.Number && budgetName && IsBudgetNumber(token.Value) && !IsStructural(tokens, index, structural))
                rules.Add(BudgetRule);
            else if (token.Kind == TokenKind.Regex && IsIdentifierRegex(token.Value))
                rules.Add(IdentifierRule);
            else if (token.Kind == TokenKind.String)
            {
                if (HexOrUuid.IsMatch(token.Value)) rules.Add(IdentifierRule);
                if (budgetName && Duration.IsMatch(token.Value)) rules.Add(BudgetRule);
                if (admissionName && token.Value.Length > 0) rules.Add(AdmissionRule);
                if (IsMethodTable(token.Value)) rules.Add(MethodTableRule);
                if (SqlStatement.IsMatch(token.Value)) rules.Add(PlanAuthorityRule);
            }
        }

        var textual = values.Any(index => tokens[index].Kind is TokenKind.String or TokenKind.Number);
        if (textual && ReadinessName.IsMatch(name)) rules.Add(ReadinessRule);
        if (textual && CorrelationName.IsMatch(name)) rules.Add(CorrelationRule);
        return rules;
    }

    /// <summary>The rules that one uncovered token breaks, for an inline literal in code.</summary>
    private static IEnumerable<string> InlineRules(IReadOnlyList<Token> tokens, int index, bool[] structural)
    {
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var token = tokens[index];
        if (token.Kind == TokenKind.Regex && IsIdentifierRegex(token.Value)) rules.Add(IdentifierRule);
        if (token.Kind == TokenKind.String)
        {
            if (HexOrUuid.IsMatch(token.Value)) rules.Add(IdentifierRule);
            if (IsMethodTable(token.Value)) rules.Add(MethodTableRule);
            if (SqlStatement.IsMatch(token.Value)) rules.Add(PlanAuthorityRule);
        }

        if (token.Kind != TokenKind.Word) return rules;
        var next = Next(tokens, index);

        // setTimeout(callback, budget) and setInterval: the second argument is a budget when it holds a number.
        if (token.Value is "setTimeout" or "setInterval" && IsPunct(next, "("))
        {
            var last = LastArgument(tokens, index + 1);
            if (last.Any(argument => tokens[argument].Kind == TokenKind.Number && IsBudgetNumber(tokens[argument].Value) && !IsStructural(tokens, argument, structural)))
                rules.Add(BudgetRule);
        }

        // delaySeconds: value and sleepAfter = value, in an object literal or a field: a budget when it holds a number or a duration.
        if (token.Value is "delaySeconds" or "sleepAfter" && (IsPunct(next, ":") || IsPunct(next, "=")))
        {
            foreach (var value in PropertyValue(tokens, index + 2))
            {
                if (tokens[value].Kind == TokenKind.Number && IsBudgetNumber(tokens[value].Value) && !IsStructural(tokens, value, structural))
                    rules.Add(BudgetRule);
                if (tokens[value].Kind == TokenKind.String && Duration.IsMatch(tokens[value].Value)) rules.Add(BudgetRule);
            }
        }

        // x.length compared with a number of four or more: a size budget (0 to 3 are counts and encoding widths).
        if (token.Value == "length" && index > 0 && (IsPunct(tokens[index - 1], ".") || IsPunct(tokens[index - 1], "?.")) && index + 2 < tokens.Count
            && tokens[index + 1].Kind == TokenKind.Punct && ComparisonOperators.Contains(tokens[index + 1].Value)
            && tokens[index + 2].Kind == TokenKind.Number && IsAtLeastFour(tokens[index + 2].Value))
        {
            rules.Add(BudgetRule);
        }

        // new Uint8Array(size): a fixed byte size when it holds a number and no division.
        if (token.Value == "Uint8Array" && index > 0 && tokens[index - 1].Kind == TokenKind.Word && tokens[index - 1].Value == "new"
            && IsPunct(next, "("))
        {
            var arguments = Arguments(tokens, index + 1);
            var divides = arguments.Any(argument => IsPunct(tokens[argument], "/"));
            if (!divides && arguments.Any(argument => tokens[argument].Kind == TokenKind.Number && IsBudgetNumber(tokens[argument].Value)
                && !IsStructural(tokens, argument, structural)))
                rules.Add(BudgetRule);
        }

        return rules;
    }

    /// <summary>The number of an initializer of a declaration is the name's budget only when it is not a structural literal.</summary>
    private static bool IsStructural(IReadOnlyList<Token> tokens, int index, bool[] structural)
    {
        if (structural[index]) return true;
        return (index > 0 && IsPunct(tokens[index - 1], "/")) || (index + 1 < tokens.Count && IsPunct(tokens[index + 1], "/"));
    }

    private static bool IsDeclarationStart(IReadOnlyList<Token> tokens, int index, bool[] inClass, out string name, out int equals, out int nameIndex)
    {
        name = string.Empty;
        equals = -1;
        nameIndex = -1;
        var token = tokens[index];
        if (token.Kind != TokenKind.Word) return false;
        if (token.Value is "const" or "let" or "var")
        {
            if (index + 1 >= tokens.Count || tokens[index + 1].Kind != TokenKind.Word) return false;
            name = tokens[index + 1].Value;
            nameIndex = index + 1;
            for (var j = index + 2; j < tokens.Count && !IsPunct(tokens[j], ";"); j++)
            {
                if (IsPunct(tokens[j], "="))
                {
                    equals = j;
                    return true;
                }
            }

            return false;
        }

        // A class field: NAME = value inside a class body, directly after a brace, a semicolon, a closing brace or a field modifier.
        // An assignment statement inside a function is not a field, so the innermost scope must be a class.
        if (!IsPunct(Next(tokens, index), "=") || index == 0 || !inClass[index]) return false;
        var previous = tokens[index - 1];
        var isField = previous.Kind == TokenKind.Punct && previous.Value is "{" or ";" or "}"
            || previous.Kind == TokenKind.Word && previous.Value is "override" or "readonly" or "static" or "public" or "private" or "protected";
        if (!isField) return false;
        name = token.Value;
        nameIndex = index;
        equals = index + 1;
        return true;
    }

    /// <summary>The value tokens of one initializer, from its first token to its end. A function body is not a value; it is skipped.</summary>
    private static List<int> Initializer(IReadOnlyList<Token> tokens, int start, bool[] covered)
    {
        var values = new List<int>();
        var depth = 0;
        for (var j = start; j < tokens.Count; j++)
        {
            var token = tokens[j];
            if (token.Kind == TokenKind.Punct)
            {
                switch (token.Value)
                {
                    case "(" or "[":
                        depth++;
                        break;
                    case ")" or "]":
                        depth--;
                        break;
                    case "{" when j > 0 && IsPunct(tokens[j - 1], "=>"):
                        j = MatchingBrace(tokens, j);
                        continue;
                    case "{":
                        depth++;
                        break;
                    case "}" when depth == 0:
                        return Mark(values, covered);
                    case "}":
                        depth--;
                        break;
                    case ";" when depth <= 0:
                        return Mark(values, covered);
                }
            }

            values.Add(j);
        }

        return Mark(values, covered);
    }

    private static List<int> Mark(List<int> values, bool[] covered)
    {
        foreach (var index in values) covered[index] = true;
        return values;
    }

    /// <summary>The token index of the brace that closes the block opened at <paramref name="open"/>.</summary>
    private static int MatchingBrace(IReadOnlyList<Token> tokens, int open)
    {
        var depth = 0;
        for (var j = open; j < tokens.Count; j++)
        {
            if (IsPunct(tokens[j], "{")) depth++;
            else if (IsPunct(tokens[j], "}") && --depth == 0) return j;
        }

        return tokens.Count - 1;
    }

    /// <summary>The indices of the tokens of the last argument of the call whose opening parenthesis is at <paramref name="open"/>.</summary>
    private static List<int> LastArgument(IReadOnlyList<Token> tokens, int open)
    {
        var arguments = Arguments(tokens, open);
        var last = new List<int>();
        var depth = 0;
        foreach (var index in arguments)
        {
            var token = tokens[index];
            if (token.Kind == TokenKind.Punct && token.Value is "(" or "[" or "{") depth++;
            else if (token.Kind == TokenKind.Punct && token.Value is ")" or "]" or "}") depth--;
            else if (depth == 0 && IsPunct(token, ",")) last.Clear();
            else last.Add(index);
        }

        return last;
    }

    /// <summary>The indices of the tokens between the parentheses of the call that opens at <paramref name="open"/>, nested brackets included.</summary>
    private static List<int> Arguments(IReadOnlyList<Token> tokens, int open)
    {
        var inside = new List<int>();
        var depth = 0;
        for (var j = open; j < tokens.Count; j++)
        {
            if (IsPunct(tokens[j], "("))
            {
                depth++;
                if (depth == 1) continue;
            }
            else if (IsPunct(tokens[j], ")"))
            {
                depth--;
                if (depth == 0) break;
            }

            inside.Add(j);
        }

        return inside;
    }

    /// <summary>The value tokens of an object property, from <paramref name="start"/> to the next comma, closing brace or semicolon.</summary>
    private static List<int> PropertyValue(IReadOnlyList<Token> tokens, int start)
    {
        var values = new List<int>();
        var depth = 0;
        for (var j = start; j < tokens.Count; j++)
        {
            var token = tokens[j];
            if (token.Kind == TokenKind.Punct)
            {
                if (token.Value is "(" or "[" or "{") depth++;
                else if (token.Value is ")" or "]" or "}")
                {
                    if (depth == 0) break;
                    depth--;
                }
                else if (depth == 0 && token.Value is "," or ";") break;
            }

            values.Add(j);
        }

        return values;
    }

    /// <summary>The enclosing named scope of every token: the function, class or declaration whose braces hold it.</summary>
    private static (string[] Scopes, bool[] InClass) EnclosingScopes(IReadOnlyList<Token> tokens)
    {
        var scopes = new string[tokens.Count];
        var inClass = new bool[tokens.Count];
        var stack = new Stack<(string Name, bool Class)>();
        stack.Push((ModuleScope, false));
        string? pending = null;
        var pendingKind = string.Empty;
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            scopes[i] = stack.Peek().Name;
            inClass[i] = stack.Peek().Class;
            if (token.Kind == TokenKind.Word)
            {
                if (token.Value is "function" or "class")
                {
                    pending = Next(tokens, i)?.Kind == TokenKind.Word ? Next(tokens, i)!.Value : null;
                    pendingKind = token.Value;
                }
                else if (token.Value is "const" or "let" or "var" && Next(tokens, i)?.Kind == TokenKind.Word)
                {
                    pending = Next(tokens, i)!.Value;
                    pendingKind = "decl";
                }

                continue;
            }

            if (token.Kind != TokenKind.Punct) continue;
            if (token.Value == "{")
            {
                var named = pending is not null
                    && (pendingKind is "function" or "class" || (pendingKind == "decl" && i > 0 && IsPunct(tokens[i - 1], "=>")));
                stack.Push(named ? (pending!, pendingKind == "class") : (stack.Peek().Name, false));
                pending = null;
            }
            else if (token.Value == "}")
            {
                if (stack.Count > 1) stack.Pop();
            }
            else if (token.Value == ";")
            {
                pending = null;
            }
        }

        return (scopes, inClass);
    }

    /// <summary>The structural literals: the tokens inside a formatting call (padStart, padEnd, slice and the like), which are never budgets.</summary>
    private static bool[] StructuralTokens(IReadOnlyList<Token> tokens)
    {
        var flags = new bool[tokens.Count];
        for (var i = 0; i + 1 < tokens.Count; i++)
        {
            if (tokens[i].Kind != TokenKind.Word || !StructuralCalls.Contains(tokens[i].Value) || !IsPunct(tokens[i + 1], "(")) continue;
            var depth = 0;
            for (var j = i + 1; j < tokens.Count; j++)
            {
                flags[j] = true;
                if (IsPunct(tokens[j], "(")) depth++;
                else if (IsPunct(tokens[j], ")") && --depth == 0) break;
            }
        }

        return flags;
    }

    private static Token? Next(IReadOnlyList<Token> tokens, int index) => index + 1 < tokens.Count ? tokens[index + 1] : null;

    private static bool IsPunct(Token? token, string value) => token is { Kind: TokenKind.Punct } && token.Value == value;

    private static bool IsMethodTable(string value) => value.StartsWith("/api/", StringComparison.Ordinal) || RpcMethod.IsMatch(value);

    private static bool IsIdentifierRegex(string raw) => raw.StartsWith('/') && IdentifierShape.IsMatch(raw);

    /// <summary>Whether a number token is a budget: its value is neither 0 nor 1 (a BigInt suffix and digit separators are read as the number).</summary>
    private static bool IsBudgetNumber(string raw)
    {
        var text = raw.Replace("_", string.Empty, StringComparison.Ordinal);
        if (text.EndsWith('n')) text = text[..^1];
        double value;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!long.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex)) return true;
            value = hex;
        }
        else if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
        {
            return true;
        }

        return value != 0 && value != 1;
    }

    private static bool IsAtLeastFour(string raw)
    {
        var text = raw.Replace("_", string.Empty, StringComparison.Ordinal);
        return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value) && value >= 4;
    }
}
