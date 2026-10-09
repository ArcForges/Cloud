// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>The policy lexer suite (lexer.test.ts, HAR.40 validation (d)), ported one-for-one.</summary>
public sealed class PolicyLexerTests
{
    private static List<string> Words(string source) =>
        PolicyLexer.Tokenize(source).Where(token => token.Kind == TokenKind.Word).Select(token => token.Value).ToList();

    private static List<(string Form, string? Specifier, bool TypeOnly)> References(string source) =>
        PolicyLexer.ModuleReferences(PolicyLexer.Tokenize(source)).Select(reference => (FormName(reference.Form), reference.Specifier, reference.TypeOnly)).ToList();

    private static string FormName(ModuleForm form) => form switch
    {
        ModuleForm.Dynamic => "dynamic",
        ModuleForm.Require => "require",
        ModuleForm.Export => "export",
        _ => "import",
    };

    [Fact]
    public void IgnoresCommentsStringsTemplatesWithoutSubstitutionsAndRegularExpressions()
    {
        var source = string.Join(
            "\n",
            "// eval(1)",
            "/* new Function('x') */",
            "const a = \"eval(1)\" + 'Reflect.ownKeys' + `Atomics.wait`;",
            "const b = /Reflect\\.get\\(/u.test(a) ? 1 / 2 : 3;");
        Assert.Equal(new[] { "const", "a", "const", "b", "test", "a" }, Words(source));
    }

    [Fact]
    public void ExposesTemplateSubstitutionsAsTokens()
    {
        const string source = "log(`failed ${token} ${ `${secret}` }`)";
        Assert.Equal(new[] { "log", "token", "secret" }, Words(source));
    }

    [Fact]
    public void DistinguishesDivisionFromARegularExpression()
    {
        Assert.DoesNotContain(PolicyLexer.Tokenize("x = a / b / c;"), token => token.Kind == TokenKind.Regex);
        Assert.Single(PolicyLexer.Tokenize("x = /a\\/b/g;"), token => token.Kind == TokenKind.Regex);
        Assert.Single(PolicyLexer.Tokenize("return /x/.test(y);"), token => token.Kind == TokenKind.Regex);
    }

    [Fact]
    public void RecognisesEveryStaticModuleDeclarationForm()
    {
        var source = string.Join(
            "\n",
            "import \"side-effect\";",
            "import def, { a as b, type C } from \"pkg\";",
            "import * as ns from \"namespace\";",
            "import type { T } from \"types-only\";",
            "export * from \"re-all\";",
            "export { x } from \"re-named\";",
            "export type { Y } from \"re-type\";",
            "const m = await import(\"dynamic\");",
            "const r = require(\"cjs\");",
            "export const own = 1;",
            "export { own as other };");
        Assert.Equal(
            new (string, string?, bool)[]
            {
                ("import", "side-effect", false),
                ("import", "pkg", false),
                ("import", "namespace", false),
                ("import", "types-only", true),
                ("export", "re-all", false),
                ("export", "re-named", false),
                ("export", "re-type", true),
                ("dynamic", "dynamic", false),
                ("require", "cjs", false),
            },
            References(source));
    }

    [Fact]
    public void RecordsImportBindingsAndReportsComputedSpecifiersAsNull()
    {
        var first = PolicyLexer.ModuleReferences(PolicyLexer.Tokenize("import def, { a as b, type C } from \"pkg\";"))[0];
        Assert.Equal(
            new[] { new KeyValuePair<string, string>("def", "default"), new("b", "a"), new("C", "C") },
            first.Bindings);
        Assert.Equal(
            new (string, string?, bool)[] { ("dynamic", null, false), ("require", null, false), ("dynamic", null, false) },
            References("import(`./${name}`); require(name); import(x);"));
    }

    [Fact]
    public void DoesNotMistakeMembersOrImportMetaForDeclarations()
    {
        Assert.Empty(References("obj.import('x'); obj.require('y'); import.meta.url;"));
    }

    [Fact]
    public void DoesNotReadModuleSyntaxInsideStringsOrComments()
    {
        Assert.Empty(References("const s = \"import x from 'y'\"; // import z from \"w\""));
    }
}
