// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using System.Xml.Linq;
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// Native AOT posture beyond the shared RP-07 and banned-symbol rules: declared project settings, source-level suppressions and the
/// JSON serialization path. Each check is a pure function so that a violating fixture can be asserted next to the real inputs.
/// </summary>
internal static partial class CloudAotPolicy
{
    private static readonly string[] ForbiddenProperties =
    [
        "SuppressTrimAnalysisWarnings", "TrimmerSingleWarn",
    ];

    private static readonly string[] ForbiddenItems = ["TrimmerRootAssembly", "TrimmerRootDescriptor", "RdXmlFile"];

    /// <summary>Declared settings of the AOT deliverable, read from its project file and the shared repository props.</summary>
    public static IReadOnlyList<string> CheckProject(string projectXml, string commonProps)
    {
        var problems = new List<string>();
        var documents = new[] { XDocument.Parse(commonProps), XDocument.Parse(projectXml) };
        string? Value(string name) => documents.SelectMany(document => document.Descendants()).Where(element => element.Name.LocalName == name)
            .Select(element => element.Value.Trim()).LastOrDefault();
        foreach (string required in new[] { "PublishAot", "JsonSerializerIsReflectionEnabledByDefault:false", "IlcTreatWarningsAsErrors", "ILLinkTreatWarningsAsErrors" })
        {
            string[] parts = required.Split(':');
            string expected = parts.Length == 2 ? parts[1] : "true";
            if (Value(parts[0]) != expected)
            {
                problems.Add($"{parts[0]} must be {expected}.");
            }
        }

        foreach (string forbidden in ForbiddenProperties)
        {
            if (Value(forbidden) is not null)
            {
                problems.Add($"{forbidden} weakens the AOT diagnostics.");
            }
        }

        foreach (string analyzer in new[] { "EnableTrimAnalyzer", "EnableAotAnalyzer" })
        {
            if (Value(analyzer) == "false")
            {
                problems.Add($"{analyzer} is disabled.");
            }
        }

        if (documents.SelectMany(document => document.Descendants()).Any(element => ForbiddenItems.Contains(element.Name.LocalName)))
        {
            problems.Add("A trimmer root or descriptor keeps unreferenced code alive.");
        }

        foreach (string diagnostics in documents.SelectMany(document => document.Descendants())
            .Where(element => element.Name.LocalName is "NoWarn" or "WarningsNotAsErrors").Select(element => element.Value))
        {
            if (diagnostics.Split([';', ',', ' '], StringSplitOptions.RemoveEmptyEntries).Any(code => TrimOrAotToken().IsMatch(code)))
            {
                problems.Add("Trim or AOT diagnostics are suppressed in project settings.");
            }
        }
        return problems;
    }

    /// <summary>Source-level escapes: pragmas, SuppressMessage and UnconditionalSuppressMessage for trim and AOT diagnostics.</summary>
    public static IReadOnlyList<string> FindSuppressions(Compilation compilation, string? projectDirectory = null)
    {
        var findings = new List<string>();
        foreach (var tree in compilation.SyntaxTrees.Where(tree => !CloudRepository.IsOfficialGeneratorOutput(tree.FilePath, projectDirectory)))
        {
            var root = tree.GetRoot();
            foreach (var pragma in root.DescendantTrivia(descendIntoTrivia: true).Select(trivia => trivia.GetStructure())
                .OfType<PragmaWarningDirectiveTriviaSyntax>().Where(pragma => pragma.DisableOrRestoreKeyword.IsKind(SyntaxKind.DisableKeyword)))
            {
                if (pragma.ErrorCodes.Any(code => TrimOrAotCode().IsMatch(code.ToString())))
                {
                    findings.Add(pragma.GetLocation().ToString());
                }
            }

            foreach (var attribute in root.DescendantNodes().OfType<AttributeSyntax>())
            {
                string name = attribute.Name.ToString();
                bool unconditional = name.EndsWith("UnconditionalSuppressMessage", StringComparison.Ordinal)
                    || name.EndsWith("UnconditionalSuppressMessageAttribute", StringComparison.Ordinal);
                bool suppressesTrim = name.EndsWith("SuppressMessage", StringComparison.Ordinal) && attribute.ArgumentList is { } arguments
                    && arguments.Arguments.Any(argument => TrimOrAotCode().IsMatch(argument.ToString()));
                if (unconditional || suppressesTrim)
                {
                    findings.Add(attribute.GetLocation().ToString());
                }
            }
        }

        return findings;
    }

    /// <summary>
    /// Reflection-based System.Text.Json is unavailable on the AOT path. Every serializer entry point (including the ASP.NET Core
    /// JSON helpers) must receive compile-time metadata: a JsonTypeInfo or a JsonSerializerContext.
    /// </summary>
    public static IReadOnlyList<string> FindUnregisteredJsonSerialization(Compilation compilation, string? projectDirectory = null)
    {
        var findings = new List<string>();
        foreach (var tree in compilation.SyntaxTrees.Where(tree => !CloudRepository.IsOfficialGeneratorOutput(tree.FilePath, projectDirectory)))
        {
            var model = compilation.GetSemanticModel(tree);
            foreach (var invocation in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                if (model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol method || !IsJsonEntryPoint(method))
                {
                    continue;
                }

                bool metadata = method.Parameters.Any(parameter =>
                {
                    string type = parameter.Type.OriginalDefinition.ToDisplayString();
                    return type.StartsWith("System.Text.Json.Serialization.Metadata.JsonTypeInfo", StringComparison.Ordinal)
                        || type == "System.Text.Json.Serialization.JsonSerializerContext";
                });
                if (!metadata)
                {
                    findings.Add(invocation.GetLocation().ToString());
                }
            }
        }

        return findings;
    }

    private static bool IsJsonEntryPoint(IMethodSymbol method)
    {
        string type = method.ContainingType.ToDisplayString();
        return (type == "System.Text.Json.JsonSerializer"
                && method.Name is "Serialize" or "SerializeAsync" or "SerializeToUtf8Bytes" or "SerializeToElement" or "SerializeToNode"
                    or "SerializeToDocument" or "Deserialize" or "DeserializeAsync" or "DeserializeAsyncEnumerable")
            || (type is "Microsoft.AspNetCore.Http.Results" or "Microsoft.AspNetCore.Http.TypedResults" && method.Name == "Json")
            || (type is "Microsoft.AspNetCore.Http.HttpResponseJsonExtensions" && method.Name == "WriteAsJsonAsync")
            || (type is "Microsoft.AspNetCore.Http.HttpRequestJsonExtensions" && method.Name == "ReadFromJsonAsync")
            || (type == "System.Net.Http.Json.HttpClientJsonExtensions" && method.Name is "GetFromJsonAsync" or "PostAsJsonAsync" or "PutAsJsonAsync")
            || (type == "System.Net.Http.Json.HttpContentJsonExtensions" && method.Name == "ReadFromJsonAsync");
    }

    [GeneratedRegex(@"(?<![A-Za-z0-9])IL[123]\d{3}(?![A-Za-z0-9])", RegexOptions.CultureInvariant)]
    private static partial Regex TrimOrAotCode();

    [GeneratedRegex(@"^(?:IL[123]\d{3}|IL[123]?\*|IL)$", RegexOptions.CultureInvariant)]
    private static partial Regex TrimOrAotToken();
}
