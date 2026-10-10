// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.RegularExpressions;
using ArcForges.Cloud.ArchitectureTests.AiHarness;

namespace ArcForges.Cloud.ArchitectureTests.WorkerAdapter;

/// <summary>
/// The standing check that the Worker holds no business literal (CLOUD.84 P2-021 item 1, S34, S43 and S45). Every worker/**/*.ts source is read
/// through the policy lexer. A number is a budget literal when it sits in a budget-shaped position, whatever its name: a declared value (a
/// const, let, var, class field or destructuring default), a comparison operand, an assigned value, an expression body, a return, an object
/// property value, a timer or delay argument, or a fixed-size byte array. The name of the holder does not decide it (S45(1)).
/// Structural numbers are never budgets: 0 and 1, the operand of a division, the argument of a formatting call (padStart, slice and the
/// like), a small index into an array (0 to 3), and a count of 0 to 3 compared with a length.
/// Every other finding must be covered by a closed list: a number row (<see cref="NumberRows"/>) for values fixed by an external standard,
/// keyed by file, symbol and value; a shape row (<see cref="ShapeRows"/>) for a shape that a standard fixes; or an owned, expiring row of the
/// shared register (the HAR40-EX carve-out and the CLOUD84-EX D16 rows). The generated module and the generated plan tables are not read; their
/// values come from C# declarations and are checked by generate --check.
/// </summary>
internal static partial class WorkerLiteralScan
{
    /// <summary>A number or a numeric text in a budget-shaped position: a limit, a size, a time, a count or a fixed byte size.</summary>
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

    /// <summary>
    /// The readiness terms of the generated vocabulary (S43): every state, status, reason, component, environment, evidence level and probe
    /// outcome. The Worker names each one through the generated readinessTerms object, so a term written as a string literal in worker code is
    /// a finding. A test pins this list to the generated module.
    /// </summary>
    public static readonly IReadOnlySet<string> ReadinessTerms = new HashSet<string>(StringComparer.Ordinal)
    {
        "production", "proof", "ingress", "container", "d1", "durableObject", "r2", "queue",
        "ready", "starting", "unavailable", "misconfigured", "unknown", "not_required",
        "probed", "bound",
        "binding_missing", "key_missing", "key_mismatch", "host_route_missing", "host_reply_invalid", "host_error",
        "no_instance_available", "start_failed", "rate_limited", "no_answer_in_wait", "unreachable", "container_not_ready",
        "plan_hash_mismatch", "schema_mismatch", "recovery_generation_mismatch", "d1_unavailable",
    };

    /// <summary>The generated module that holds the readiness terms; the one file that names them as literals.</summary>
    public const string GeneratedTablesPath = "worker/tables/cloud-tables.generated.ts";

    /// <summary>The generated Worker outputs: the only worker files the check does not read.</summary>
    public static readonly IReadOnlySet<string> GeneratedFiles = new HashSet<string>(StringComparer.Ordinal)
    {
        "worker/tables/cloud-tables.generated.ts",
        "worker/storage/plans.generated.ts",
    };

    /// <summary>
    /// A closed number row (S43(2), S45(1)(a)): the listed values are fixed by an external standard, and the row is keyed by the exact file and
    /// the symbol (a declaration, a function or a class) or &lt;module&gt; that holds them. A listed value passes; any other value in the same
    /// symbol is still a finding. Source is the one-line external standard that fixes the values.
    /// </summary>
    public sealed record NumberRow(string File, string Symbol, IReadOnlyList<string> Values, string Source);

    /// <summary>A closed shape row (S45(1)(a)): a rule that a named symbol may hold because an external standard fixes its shape.</summary>
    public sealed record ShapeRow(string File, string Symbol, string Rule, string Source);

    /// <summary>The closed number rows. A row that matches no literal is itself a failure (a stale row), so each is kept by a real use.</summary>
    public static readonly IReadOnlyList<NumberRow> NumberRows =
    [
        new("worker/ingress/errors.ts", "grpcStatus", ["3", "4", "7", "14", "16"], "gRPC status codes of the grpc-status trailer (gRPC over HTTP/2)"),
        new("worker/ingress/frames.ts", "observe", ["5"], "gRPC-Web message header is five bytes: one flag byte and a four-byte length"),
        new("worker/ingress/frames.ts", "take", ["5"], "gRPC-Web message header is five bytes: one flag byte and a four-byte length"),
        new("worker/ingress/frames.ts", "trailerFlag", ["0x80"], "gRPC-Web trailer frame flag (0x80 in the first byte of the frame)"),
        new("worker/ingress/io.ts", "rpcError", ["0x80"], "gRPC-Web trailer frame flag (0x80 in the first byte of the frame)"),
        new("worker/ingress/io.ts", "trailerFrame", ["0x80"], "gRPC-Web trailer frame flag (0x80 in the first byte of the frame)"),
        new("worker/ingress/pipeline.ts", "units", ["1000", "0.001", "60000", "3600000", "0.000001"],
            "grpc-timeout unit multipliers of the grpc-timeout grammar (H, M, S, u, n), in milliseconds"),
        new("worker/ingress/pipeline.ts", "handleApiRequest", ["200", "400", "404", "405", "408", "413", "415", "429", "499", "504"],
            "HTTP status codes (RFC 9110); 499 is the Worker's client-closed-request code (a de facto status, not an RFC status)"),
        new("worker/ingress/correlation.ts", "Reader",
            ["2", "4", "7", "8", "9", "10", "0x7f", "2147483647"],
            "protobuf wire format: varint seven-bit groups in ten bytes, wire types 0, 1, 2 and 5, the fixed sizes of wire types 1 and 5, and the int32 maximum of a field number"),
        new("worker/ingress/correlation.ts", "readId", ["2"], "protobuf wire type 2 (length-delimited)"),
        new("worker/ingress/correlation.ts", "readRequestCorrelation", ["2"], "protobuf wire type 2 (length-delimited)"),
        new("worker/private/encoding.ts", "base64UrlDecode", ["4"], "base64url group of four characters for three bytes (RFC 4648 section 5)"),
        new("worker/private/encoding.ts", "base64UrlEncode", ["2", "3", "6", "12", "18", "63"],
            "base64url radix arithmetic: six-bit groups (mask 63, shifts 6, 12 and 18), three-byte groups and the two-character tail (RFC 4648)"),
        new("worker/private/encoding.ts", "hexDecode", ["16"], "hexadecimal radix of the base16 encoding (RFC 4648 section 8)"),
        new("worker/private/encoding.ts", "packed", ["6", "12", "18"], "base64 bit shifts of a four-character group (RFC 4648)"),
        new("worker/private/encoding.ts", "value", ["2", "8", "16"], "byte shift arithmetic of a three-byte group (eight-bit octets)"),
        new("worker/readiness/container.ts", "classifyStartFailure", ["429", "500", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/readiness/container.ts", "classifyStartFailureResponse", ["429", "500", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/readiness/container.ts", "containerUnavailable", ["503"], "HTTP status code 503 (RFC 9110)"),
        new("worker/readiness/http.ts", "readinessResponse", ["200", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/readiness/transport.ts", "classifyHostReply", ["200", "401", "404", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/storage/handler.ts", "handleExecutePlan", ["401", "404", "405", "413", "415", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/storage/handler.ts", "reply", ["200"], "HTTP status code 200 (RFC 9110)"),
        new("worker/storage/scalars.ts", "encodeResult", ["255"], "octet range of a byte value (0 to 255, one unsigned byte)"),
        new("worker/foundation/cloud-container.ts", "defaultPort", ["8080"],
            "IANA-registered http-alt port: the container image exposes it (Dockerfile EXPOSE 8080) and the host listens on it"),
        new("worker/ai/internal/handler.ts", "handleAiInternal", ["200", "404", "405", "413", "415", "502", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/foundation/objects.ts", "handleObjects",
            ["200", "201", "206", "400", "401", "404", "405", "409", "411", "413", "416", "422", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/foundation/proof-routes.ts", "forwardSession", ["400", "405", "502", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/foundation/proof-routes.ts", "handleProof", ["404"], "HTTP status code 404 (RFC 9110)"),
        new("worker/foundation/proof-routes.ts", "operatorOperation",
            ["200", "400", "401", "404", "405", "413", "415", "501", "502", "503"], "HTTP status codes (RFC 9110)"),
        new("worker/foundation/proof-routes.ts", "unavailableRefusal", ["503"], "HTTP status code 503 (RFC 9110)"),
        new("worker/harness/run-alarm.ts", "HarnessRunAlarm", ["200"], "HTTP status code 200 (RFC 9110)"),
    ];

    /// <summary>The closed shape rows. A row that matches no finding is itself a failure.</summary>
    public static readonly IReadOnlyList<ShapeRow> ShapeRows =
    [
        new("worker/ingress/pipeline.ts", "match", IdentifierRule,
            "grpc-timeout grammar: one to eight ASCII digits and one unit letter (gRPC over HTTP/2 timeout value)"),
    ];

    private const string ModuleScope = "<module>";

    private static readonly Regex AdmissionName = new("(?i)(envelope|admit|allow|permit)", RegexOptions.CultureInvariant);
    private static readonly Regex ReadinessName = new("(?i)readiness", RegexOptions.CultureInvariant);
    private static readonly Regex CorrelationName = new("(?i)(correlation|traceparent)", RegexOptions.CultureInvariant);
    private static readonly Regex IdentifierShape = new(@"\{\d|\\d|\[0-9|\[1-9|0-9a-f|\[a-f|A-Za-z0-9", RegexOptions.CultureInvariant);
    private static readonly Regex HexOrUuid = new(
        "^(?:[0-9a-f]{40,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", RegexOptions.CultureInvariant);
    private static readonly Regex Duration = new(@"^\d+(?:ms|s|m|h)$", RegexOptions.CultureInvariant);

    /// <summary>A numeric text of three or more digits without a leading zero: a number written as a string.</summary>
    private static readonly Regex DigitText = new(@"^[1-9]\d{2,}$", RegexOptions.CultureInvariant);

    /// <summary>The operators that assign a value: the expression after one of them is a value.</summary>
    private static readonly HashSet<string> AssignmentOperators = new(StringComparer.Ordinal)
    {
        "=", "+=", "-=", "*=", "/=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??=",
    };

    private static readonly Regex RpcMethod = new(@"^/[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+/[A-Za-z0-9_]+$", RegexOptions.CultureInvariant);
    private static readonly Regex SqlStatement = new(
        @"(?i)^\s*(?:select\s|insert\s+into\s|update\s+\w+\s+set\s|delete\s+from\s|create\s+table\s|alter\s+table\s|pragma\s)",
        RegexOptions.CultureInvariant);

    private static readonly HashSet<string> StructuralCalls = new(StringComparer.Ordinal)
    {
        "padEnd", "padStart", "slice", "substring", "substr", "charCodeAt", "charAt", "toString",
    };

    private static readonly HashSet<string> ComparisonOperators = new(StringComparer.Ordinal) { "===", "!==", "==", "!=", ">=", "<=", ">", "<" };

    /// <summary>One literal the scan found: the rule it breaks, its file, its symbol (the declared name or the enclosing scope), its value text
    /// (empty when the rule has no value) and its line.</summary>
    internal sealed record Literal(string Rule, string File, string Symbol, string Value, int Line);

    /// <summary>One rule broken inside a scanned region, and the token that breaks it (-1 when the rule has no value token).</summary>
    private readonly record struct Hit(string Rule, int Token);

    /// <summary>Audits the worker sources of a checkout map. The result is ordered and free of duplicates, and excludes every exempt literal.</summary>
    public static IReadOnlyList<HarnessFinding> Audit(IReadOnlyDictionary<string, string> sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        return Literals(sources).Where(literal => !IsExempt(literal))
            .Select(literal => new HarnessFinding(literal.Rule, literal.File, literal.Symbol))
            .Distinct()
            .OrderBy(finding => finding.Rule, StringComparer.Ordinal).ThenBy(finding => finding.File, StringComparer.Ordinal)
            .ThenBy(finding => finding.Detail, StringComparer.Ordinal).ToList();
    }

    /// <summary>Every literal the scan finds in the worker sources, before any closed list applies. Ordered by file, symbol, rule, value and line.</summary>
    internal static IReadOnlyList<Literal> Literals(IReadOnlyDictionary<string, string> sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        return sources.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Where(pair => IsScanned(pair.Key))
            .SelectMany(pair => ScanFile(pair.Key, pair.Value))
            .Distinct()
            .OrderBy(literal => literal.File, StringComparer.Ordinal).ThenBy(literal => literal.Symbol, StringComparer.Ordinal)
            .ThenBy(literal => literal.Rule, StringComparer.Ordinal).ThenBy(literal => literal.Value, StringComparer.Ordinal)
            .ThenBy(literal => literal.Line)
            .ToList();
    }

    /// <summary>Whether a literal is covered by a closed list: a number row that names its value, or a shape row that names its rule.</summary>
    internal static bool IsExempt(Literal literal) =>
        literal.Rule == BudgetRule && literal.Value.Length > 0
            && NumberRows.Any(row => row.File == literal.File && row.Symbol == literal.Symbol && row.Values.Contains(literal.Value, StringComparer.Ordinal))
        || ShapeRows.Any(row => row.File == literal.File && row.Symbol == literal.Symbol && row.Rule == literal.Rule);

    /// <summary>
    /// Applies the shared register to every audit that the repository runs: the GOV.10 catalogue and this check. A register row for either
    /// kind of finding must name a real finding, so an unused row is itself a problem.
    /// </summary>
    public static ExceptionResult ApplyRegister(IReadOnlyDictionary<string, string> sources, System.Text.Json.JsonElement? document, DateOnly today)
    {
        var findings = HarnessArchitecture.Audit(sources).Concat(Audit(sources)).ToList();
        return ArchitectureExceptions.Apply(findings, document, today, Rules);
    }

    /// <summary>
    /// Whether a file is in the readiness module, where the readiness taxonomy lives. A term is read as a readiness literal only there: the
    /// storage and foundation modules use the same spelling for their own error classes (unavailable), which is not readiness vocabulary.
    /// </summary>
    public static bool InReadinessModule(string path) => path.StartsWith("worker/readiness/", StringComparison.Ordinal);

    /// <summary>Whether a path is worker TypeScript that the check reads: a Worker source, never a declaration or a generated output.</summary>
    public static bool IsScanned(string path) =>
        path.StartsWith("worker/", StringComparison.Ordinal) && path.EndsWith(".ts", StringComparison.Ordinal)
        && !path.EndsWith(".d.ts", StringComparison.Ordinal) && !GeneratedFiles.Contains(path);

    private static IEnumerable<Literal> ScanFile(string path, string text)
    {
        // The lexer emits a template substitution as "${" and a closing "}". Read "${" as the brace it opens, so the scopes and the brace
        // matching stay balanced; the shared lexer itself is unchanged.
        var tokens = PolicyLexer.Tokenize(text)
            .Select(token => token.Kind == TokenKind.Punct && token.Value == "${" ? token with { Value = "{" } : token).ToList();
        var (scopes, inClass) = EnclosingScopes(tokens);
        var structural = StructuralTokens(tokens);
        var covered = new bool[tokens.Count];
        var readinessModule = InReadinessModule(path);
        var results = new List<Literal>();

        // Declared symbols: a const, let or var with an initializer, a destructuring default, or a class field with one. A function body
        // inside an initializer is inline code and is left to the inline pass.
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!IsDeclarationStart(tokens, i, inClass, out var name, out var equals, out var nameIndex)) continue;
            covered[nameIndex] = true;
            covered[equals] = true;
            var values = Initializer(tokens, equals + 1, covered);
            foreach (var hit in DeclaredHits(name, values, tokens, structural, readinessModule)) results.Add(Record(hit, path, name, tokens));
        }

        // Inline literals outside a declared initializer, keyed by the function that holds them.
        for (var i = 0; i < tokens.Count; i++)
        {
            if (covered[i]) continue;
            foreach (var hit in InlineHits(tokens, i, structural, readinessModule)) results.Add(Record(hit, path, scopes[i], tokens));
        }

        return results;
    }

    private static Literal Record(Hit hit, string path, string symbol, IReadOnlyList<Token> tokens) =>
        hit.Token < 0
            ? new Literal(hit.Rule, path, symbol, string.Empty, 0)
            : new Literal(hit.Rule, path, symbol, ValueText(tokens[hit.Token]), tokens[hit.Token].Line);

    /// <summary>The rules that a declared initializer breaks. The symbol is the declared name itself.</summary>
    private static IEnumerable<Hit> DeclaredHits(string name, IReadOnlyList<int> values, IReadOnlyList<Token> tokens, bool[] structural, bool readinessModule)
    {
        var hits = new List<Hit>();
        var admissionName = AdmissionName.IsMatch(name);
        foreach (var index in BudgetTokens(tokens, values, structural)) hits.Add(new Hit(BudgetRule, index));
        foreach (var index in values)
        {
            var token = tokens[index];
            if (token.Kind == TokenKind.Regex && IsIdentifierRegex(token.Value)) hits.Add(new Hit(IdentifierRule, -1));
            else if (token.Kind == TokenKind.String)
            {
                if (HexOrUuid.IsMatch(token.Value)) hits.Add(new Hit(IdentifierRule, -1));
                if (admissionName && token.Value.Length > 0) hits.Add(new Hit(AdmissionRule, -1));
                if (IsMethodTable(token.Value)) hits.Add(new Hit(MethodTableRule, -1));
                if (SqlStatement.IsMatch(token.Value)) hits.Add(new Hit(PlanAuthorityRule, -1));
            }
        }

        var textual = values.Any(index => tokens[index].Kind is TokenKind.String or TokenKind.Number);
        if (textual && ReadinessName.IsMatch(name)) hits.Add(new Hit(ReadinessRule, -1));
        if (textual && CorrelationName.IsMatch(name)) hits.Add(new Hit(CorrelationRule, -1));
        if (readinessModule && values.Any(index => tokens[index].Kind == TokenKind.String && ReadinessTerms.Contains(tokens[index].Value)))
            hits.Add(new Hit(ReadinessRule, -1));
        return hits;
    }

    /// <summary>
    /// The rules that one uncovered token breaks, for an inline literal in code. A value is a budget wherever it is held: returned, assigned,
    /// compared, an object property, a timer or delay argument, or a fixed-size byte array. The symbol is the enclosing scope.
    /// </summary>
    private static IEnumerable<Hit> InlineHits(IReadOnlyList<Token> tokens, int index, bool[] structural, bool readinessModule)
    {
        var hits = new List<Hit>();
        var token = tokens[index];
        if (token.Kind == TokenKind.Regex && IsIdentifierRegex(token.Value)) hits.Add(new Hit(IdentifierRule, -1));
        if (token.Kind == TokenKind.String)
        {
            if (HexOrUuid.IsMatch(token.Value)) hits.Add(new Hit(IdentifierRule, -1));
            if (IsMethodTable(token.Value)) hits.Add(new Hit(MethodTableRule, -1));
            if (SqlStatement.IsMatch(token.Value)) hits.Add(new Hit(PlanAuthorityRule, -1));
            if (readinessModule && ReadinessTerms.Contains(token.Value)) hits.Add(new Hit(ReadinessRule, -1));
        }

        if (token.Kind == TokenKind.Punct)
        {
            // A comparison operand that is a budget: a bare limit in a condition.
            if (ComparisonOperators.Contains(token.Value)) AddBudgets(hits, ComparisonOperands(tokens, index, structural));

            // An assignment, a default value or an expression body holds the budget of its value.
            if (AssignmentOperators.Contains(token.Value)) AddBudgets(hits, BudgetTokens(tokens, Expression(tokens, index + 1, stopAtComma: true), structural));
            if (token.Value == "=>" && !IsPunct(Next(tokens, index), "{"))
                AddBudgets(hits, BudgetTokens(tokens, Expression(tokens, index + 1, stopAtComma: true), structural));
        }

        if (token.Kind == TokenKind.Word && token.Value == "return")
            AddBudgets(hits, BudgetTokens(tokens, Expression(tokens, index + 1, stopAtComma: false), structural));

        if (token.Kind != TokenKind.Word) return hits;
        var next = Next(tokens, index);

        // An object property (key: value) holds a budget when its value is a number or a duration.
        if (IsPunct(next, ":") && index > 0 && (IsPunct(tokens[index - 1], "{") || IsPunct(tokens[index - 1], ",")))
            AddBudgets(hits, BudgetTokens(tokens, PropertyValue(tokens, index + 2), structural));

        // setTimeout(callback, budget) and setInterval: the last argument is a budget when it holds a number.
        if (token.Value is "setTimeout" or "setInterval" && IsPunct(next, "("))
            AddBudgets(hits, BudgetTokens(tokens, LastArgument(tokens, index + 1), structural));

        // new Uint8Array(size): a fixed byte size when it holds a number and no division.
        if (token.Value == "Uint8Array" && index > 0 && tokens[index - 1].Kind == TokenKind.Word && tokens[index - 1].Value == "new"
            && IsPunct(next, "("))
        {
            var arguments = Arguments(tokens, index + 1);
            if (!arguments.Any(argument => IsPunct(tokens[argument], "/"))) AddBudgets(hits, BudgetTokens(tokens, arguments, structural));
        }

        return hits;
    }

    private static void AddBudgets(List<Hit> hits, IEnumerable<int> indices)
    {
        foreach (var index in indices) hits.Add(new Hit(BudgetRule, index));
    }

    /// <summary>The operands of a comparison operator that are budget tokens: the token before and the token after it.</summary>
    private static IEnumerable<int> ComparisonOperands(IReadOnlyList<Token> tokens, int index, bool[] structural) =>
        new[] { index - 1, index + 1 }.Where(operand => operand >= 0 && operand < tokens.Count && IsBudgetToken(tokens, operand, structural));

    /// <summary>The tokens of a value list that hold a budget: a number other than 0 and 1 that is not structural, or a duration or numeric text.</summary>
    private static IEnumerable<int> BudgetTokens(IReadOnlyList<Token> tokens, IEnumerable<int> values, bool[] structural) =>
        values.Where(index => IsBudgetToken(tokens, index, structural));

    private static bool IsBudgetToken(IReadOnlyList<Token> tokens, int index, bool[] structural)
    {
        var token = tokens[index];
        if (token.Kind == TokenKind.Number) return IsBudgetNumber(token.Value) && !IsStructural(tokens, index, structural);
        return token.Kind == TokenKind.String && IsBudgetText(token.Value);
    }

    /// <summary>The text of a token that a finding records: a number in its normalized form, otherwise the token's own value.</summary>
    private static string ValueText(Token token) => token.Kind == TokenKind.Number ? NormalizeNumber(token.Value) : token.Value;

    /// <summary>
    /// Whether a number token is structural and so never a budget: a formatting argument (padStart, slice and the like), the divisor of a
    /// division (a unit conversion or a byte pair), a small array index (0 to 3), or a count of 0 to 3 compared with a length.
    /// </summary>
    private static bool IsStructural(IReadOnlyList<Token> tokens, int index, bool[] structural) =>
        structural[index] || (index > 0 && IsPunct(tokens[index - 1], "/")) || IsSmallIndex(tokens, index) || IsLengthCount(tokens, index);

    /// <summary>A number from 0 to 3 that is the whole index of an array access (a regular expression group index, a short tuple index).</summary>
    private static bool IsSmallIndex(IReadOnlyList<Token> tokens, int index) =>
        index > 0 && index + 1 < tokens.Count && tokens[index].Kind == TokenKind.Number && IsPunct(tokens[index - 1], "[")
        && IsPunct(tokens[index + 1], "]") && NumericValue(tokens[index].Value) is >= 0 and <= 3;

    /// <summary>
    /// A count of 0 to 3 compared with a length (x.length &lt; 2, 3 === y.length): a short-structure check or an encoding width. A length of four
    /// or more is a size budget. It applies wherever the count is held.
    /// </summary>
    private static bool IsLengthCount(IReadOnlyList<Token> tokens, int index)
    {
        var token = tokens[index];
        if (token.Kind != TokenKind.Number || IsAtLeastFour(token.Value)) return false;
        var lengthBefore = index >= 2 && IsComparison(tokens[index - 1]) && IsLengthAt(tokens, index - 2);
        var lengthAfter = index + 4 < tokens.Count && IsComparison(tokens[index + 1]) && IsLengthAt(tokens, index + 4);
        return lengthBefore || lengthAfter;
    }

    /// <summary>Whether the token at an index is the property name length of a member access (x.length or x?.length).</summary>
    private static bool IsLengthAt(IReadOnlyList<Token> tokens, int index) =>
        index > 0 && index < tokens.Count && tokens[index].Kind == TokenKind.Word && tokens[index].Value == "length"
        && (IsPunct(tokens[index - 1], ".") || IsPunct(tokens[index - 1], "?."));

    private static bool IsComparison(Token token) => token.Kind == TokenKind.Punct && ComparisonOperators.Contains(token.Value);

    /// <summary>A string that holds a budget as text: a duration (60s) or a number of three or more digits written as a string.</summary>
    private static bool IsBudgetText(string value) => Duration.IsMatch(value) || DigitText.IsMatch(value);

    private static bool IsDeclarationStart(IReadOnlyList<Token> tokens, int index, bool[] inClass, out string name, out int equals, out int nameIndex)
    {
        name = string.Empty;
        equals = -1;
        nameIndex = -1;
        var token = tokens[index];
        if (token.Kind != TokenKind.Word) return false;
        if (token.Value is "const" or "let" or "var")
        {
            // A destructuring declaration (const { a = 4096 } = value): its name is the first word of the pattern, and the statement is its
            // value, so a default inside the pattern is a value of that name. A pattern that is not followed by an initializer is a loop head.
            if (index + 1 < tokens.Count && tokens[index + 1].Kind == TokenKind.Punct && tokens[index + 1].Value is "{" or "[")
            {
                var close = PatternClose(tokens, index + 1);
                if (close < 0 || close + 1 >= tokens.Count || !IsPunct(tokens[close + 1], "=")) return false;
                name = tokens.Skip(index + 2).Take(close - index - 2).FirstOrDefault(item => item.Kind == TokenKind.Word)?.Value ?? "destructuring";
                nameIndex = index + 1;
                equals = index;
                return true;
            }

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

    /// <summary>The token index of the bracket that closes the destructuring pattern opened at <paramref name="open"/>, or -1.</summary>
    private static int PatternClose(IReadOnlyList<Token> tokens, int open)
    {
        var depth = 0;
        for (var j = open; j < tokens.Count; j++)
        {
            if (tokens[j].Kind != TokenKind.Punct) continue;
            if (tokens[j].Value is "{" or "[" or "(") depth++;
            else if (tokens[j].Value is "}" or "]" or ")" && --depth == 0) return j;
        }

        return -1;
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

    /// <summary>
    /// The tokens of an expression that starts at <paramref name="start"/>: up to a semicolon, an unmatched closing bracket and, when
    /// <paramref name="stopAtComma"/>, a comma, all at the top nesting depth. Nested tokens, including call arguments, belong to it.
    /// </summary>
    private static List<int> Expression(IReadOnlyList<Token> tokens, int start, bool stopAtComma)
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
                else if (depth == 0 && (token.Value == ";" || stopAtComma && token.Value == ",")) break;
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

        // The parenthesis depth at which the pending declaration was seen. Its body brace is the first brace at that same depth, so a brace
        // inside a parameter list (a destructured or typed parameter) neither takes the name nor consumes the pending declaration.
        var pendingDepth = 0;
        var depth = 0;
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
                    pendingDepth = depth;
                }
                else if (token.Value is "const" or "let" or "var" && Next(tokens, i)?.Kind == TokenKind.Word)
                {
                    pending = Next(tokens, i)!.Value;
                    pendingKind = "decl";
                    pendingDepth = depth;
                }

                continue;
            }

            if (token.Kind != TokenKind.Punct) continue;
            if (token.Value == "(") depth++;
            else if (token.Value == ")") depth--;
            else if (token.Value == "{")
            {
                var atPending = pending is not null && depth == pendingDepth;
                var named = atPending
                    && (pendingKind is "function" or "class" || (pendingKind == "decl" && i > 0 && IsPunct(tokens[i - 1], "=>")));
                stack.Push(named ? (pending!, pendingKind == "class") : (stack.Peek().Name, false));
                if (atPending) pending = null;
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

    /// <summary>The number text with its digit separators and a BigInt suffix removed.</summary>
    private static string NormalizeNumber(string raw)
    {
        var text = raw.Replace("_", string.Empty, StringComparison.Ordinal);
        return text.EndsWith('n') ? text[..^1] : text;
    }

    /// <summary>The numeric value of a number token, or NaN when it cannot be read as a number.</summary>
    private static double NumericValue(string raw)
    {
        var text = NormalizeNumber(raw);
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex) ? hex : double.NaN;
        return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value) ? value : double.NaN;
    }

    /// <summary>Whether a number token is a budget: its value is neither 0 nor 1. A number that cannot be read is a budget.</summary>
    private static bool IsBudgetNumber(string raw)
    {
        var value = NumericValue(raw);
        return double.IsNaN(value) || value != 0 && value != 1;
    }

    private static bool IsAtLeastFour(string raw) => NumericValue(raw) >= 4;
}
