// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>
/// Evaluates an SPDX license expression against an allowed set (HAR.40 validation (d), WP-05.01). The grammar follows the SPDX
/// specification's license-expression syntax: simple license identifiers with an optional "+" suffix, parentheses, and the operators AND,
/// OR and WITH in upper case, with WITH binding tightest, then AND, then OR. A simple identifier is allowed when it is a member of the set.
/// A term qualified by WITH is never allowed, because an exception changes the terms of the license. Any text that is not a well-formed
/// expression (an empty or truncated expression, an unknown character, a lower-case operator, an unbalanced parenthesis) is refused.
/// </summary>
internal static class SpdxExpression
{
    /// <summary>True only when the whole expression is well formed and its value under the allowed set is true.</summary>
    public static bool Allowed(string? expression, IReadOnlySet<string> allowed)
    {
        ArgumentNullException.ThrowIfNull(allowed);
        if (string.IsNullOrEmpty(expression)) return false;
        var tokens = Lex(expression);
        if (tokens is null) return false;
        var parser = new Parser(tokens, allowed);
        var value = parser.Disjunction();
        return value && !parser.Failed && parser.AtEnd;
    }

    private static List<string>? Lex(string text)
    {
        var tokens = new List<string>();
        var index = 0;
        while (index < text.Length)
        {
            var c = text[index];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            {
                index++;
                continue;
            }

            if (c is '(' or ')')
            {
                tokens.Add(c.ToString());
                index++;
                continue;
            }

            if (!IsIdentifierCharacter(c)) return null;
            var start = index;
            while (index < text.Length && IsIdentifierCharacter(text[index])) index++;
            if (index < text.Length && text[index] == '+') index++;
            tokens.Add(text[start..index]);
        }

        return tokens;
    }

    private static bool IsIdentifierCharacter(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '.';

    /// <summary>A recursive-descent evaluator: each level returns the value of its sub-expression and records any syntax failure.</summary>
    private sealed class Parser(List<string> tokens, IReadOnlySet<string> allowed)
    {
        private int position;

        public bool Failed { get; private set; }

        public bool AtEnd => position == tokens.Count;

        private string? Peek() => position < tokens.Count ? tokens[position] : null;

        private void Fail()
        {
            Failed = true;
        }

        /// <summary>OR is the loosest operator: one alternative that is allowed makes the expression allowed.</summary>
        public bool Disjunction()
        {
            var value = Conjunction();
            while (!Failed && Peek() == "OR")
            {
                position++;
                var next = Conjunction();
                value = value || next;
            }

            return value;
        }

        /// <summary>AND needs every term to be allowed.</summary>
        private bool Conjunction()
        {
            var value = Compound();
            while (!Failed && Peek() == "AND")
            {
                position++;
                var next = Compound();
                value = value && next;
            }

            return value;
        }

        /// <summary>A term may carry a WITH exception, which is always refused.</summary>
        private bool Compound()
        {
            var value = Primary();
            if (!Failed && Peek() == "WITH")
            {
                position++;
                var exception = Peek();
                if (exception is null || !IsIdentifier(exception))
                {
                    Fail();
                    return false;
                }

                position++;
                return false;
            }

            return value;
        }

        private bool Primary()
        {
            var token = Peek();
            if (token is null)
            {
                Fail();
                return false;
            }

            if (token == "(")
            {
                position++;
                var inner = Disjunction();
                if (Failed || Peek() != ")")
                {
                    Fail();
                    return false;
                }

                position++;
                return inner;
            }

            if (!IsIdentifier(token) || token is "AND" or "OR" or "WITH")
            {
                Fail();
                return false;
            }

            position++;
            return allowed.Contains(token);
        }

        private static bool IsIdentifier(string token) => token.Length > 0 && token is not ("(" or ")") && token.All(c => IsIdentifierCharacter(c) || c == '+');
    }
}
