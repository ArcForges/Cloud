// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// How Cloud consumes Contracts: only exact published packages from one candidate, never sibling source, never a locally authored
/// wire schema, and every RPC service derives from a generated service base shipped in an ArcForges.Contracts package.
/// </summary>
internal static partial class ContractConsumptionPolicy
{
    private const string GrpcBindAttribute = "Grpc.Core.BindServiceMethodAttribute";

    /// <summary>All contract NuGet packages and all contract npm packages pin the same exact candidate version.</summary>
    public static IReadOnlyList<string> CheckPins(string packagesProps, string packageJson)
    {
        var problems = new List<string>();
        var nuget = XDocument.Parse(packagesProps).Descendants("PackageVersion")
            .Where(element => (element.Attribute("Include")?.Value ?? string.Empty).StartsWith("ArcForges.Contracts.", StringComparison.Ordinal))
            .ToDictionary(element => element.Attribute("Include")!.Value, element => element.Attribute("Version")?.Value ?? string.Empty);
        using var manifest = JsonDocument.Parse(packageJson);
        var npm = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string section in new[] { "dependencies", "devDependencies" })
        {
            if (!manifest.RootElement.TryGetProperty(section, out var dependencies))
            {
                continue;
            }

            foreach (var dependency in dependencies.EnumerateObject().Where(dependency => dependency.Name.StartsWith("@arcforges/", StringComparison.Ordinal)))
            {
                npm[dependency.Name] = dependency.Value.GetString() ?? string.Empty;
            }
        }

        if (nuget.Count == 0)
        {
            problems.Add("No contract NuGet package is pinned.");
        }

        foreach (var pin in nuget.Concat(npm))
        {
            if (!ExactVersion().IsMatch(pin.Value))
            {
                problems.Add($"{pin.Key} is not an exact version.");
            }
        }

        if (nuget.Values.Concat(npm.Values).Distinct(StringComparer.Ordinal).Count() > 1)
        {
            problems.Add("Contract packages come from more than one candidate version.");
        }

        return problems;
    }

    /// <summary>No project reaches contract source through a project reference, a reference path, a schema item or a sibling directory.</summary>
    public static IReadOnlyList<string> CheckProjectInputs(string root, IReadOnlyDictionary<string, string> projects)
    {
        var problems = new List<string>();
        string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        foreach (var (path, xml) in projects)
        {
            string directory = Path.GetDirectoryName(Path.GetFullPath(Path.Combine(root, path)))!;
            foreach (var element in XDocument.Parse(xml).Descendants())
            {
                string name = element.Name.LocalName;
                if (name is "Protobuf" or "ProtoRoot" or "GrpcServices")
                {
                    problems.Add($"{path}: Cloud authors no wire schema ({name}).");
                }

                if (name == "Reference" && element.Descendants().Any(child => child.Name.LocalName == "HintPath"))
                {
                    problems.Add($"{path}: assembly reference by path bypasses the published package.");
                }

                foreach (string attribute in new[] { "Include", "Update", "Link" })
                {
                    string? value = element.Attribute(attribute)?.Value;
                    if (value is null || (name is "PackageReference" or "PackageVersion" or "FrameworkReference" or "InternalsVisibleTo" or "Using"))
                    {
                        continue;
                    }

                    if (value.Contains("$(", StringComparison.Ordinal) || !(value.Contains('/') || value.Contains('\\')))
                    {
                        continue;
                    }

                    string target = Path.GetFullPath(Path.Combine(directory, value.Replace('\\', Path.DirectorySeparatorChar)));
                    if (!target.StartsWith(fullRoot, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                    {
                        problems.Add($"{path}: {name} leaves the repository ({value}).");
                    }
                    else if (name == "ProjectReference" && Regex.IsMatch(value, @"(?i)contracts"))
                    {
                        problems.Add($"{path}: project reference to contract source ({value}).");
                    }
                    else if (name is "Compile" && Regex.IsMatch(value, @"(?i)(?:^|[\\/])(?:generated|proto|contracts)[\\/]"))
                    {
                        problems.Add($"{path}: compiled contract source ({value}).");
                    }
                }
            }
        }

        return problems;
    }

    /// <summary>Tracked files that would be a local copy of contract authority: proto schemas, generated sources and submodules.</summary>
    public static IReadOnlyList<string> CheckTrackedFiles(IEnumerable<string> files) =>
    [
        .. files.Where(file => file.EndsWith(".proto", StringComparison.OrdinalIgnoreCase)
            || file.EndsWith(".gitmodules", StringComparison.Ordinal)
            || Regex.IsMatch(file, @"(?i)(?:^|/)(?:generated|gen)/[^/]+\.(?:cs|ts|kt|java)$")).Select(file => "Local contract authority: " + file),
    ];

    /// <summary>
    /// Every service class derives from a generated service base: an abstract base carrying the gRPC bind attribute that is
    /// declared in an ArcForges.Contracts assembly, never in the compiling project. A base without the attribute, or one declared in
    /// any other assembly, is a hand-written or foreign RPC surface.
    /// </summary>
    public static IReadOnlyList<string> CheckServiceBases(Compilation compilation)
    {
        var problems = new List<string>();
        foreach (var tree in compilation.SyntaxTrees)
        {
            var model = compilation.GetSemanticModel(tree);
            foreach (var declaration in tree.GetRoot().DescendantNodes().OfType<ClassDeclarationSyntax>())
            {
                if (model.GetDeclaredSymbol(declaration) is not INamedTypeSymbol type)
                {
                    continue;
                }

                for (var current = type.BaseType; current is not null && current.SpecialType != SpecialType.System_Object; current = current.BaseType)
                {
                    bool bind = current.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == GrpcBindAttribute);
                    bool serviceShaped = bind || current.Name.EndsWith("ServiceBase", StringComparison.Ordinal);
                    if (!serviceShaped)
                    {
                        continue;
                    }

                    bool contracts = !SymbolEqualityComparer.Default.Equals(current.ContainingAssembly, compilation.Assembly)
                        && current.ContainingAssembly.Name.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal);
                    if (!bind || !contracts)
                    {
                        problems.Add($"{type.ToDisplayString()} derives from {current.ToDisplayString()}, which is not a generated Contracts service base.");
                    }

                    break;
                }
            }

            foreach (var invocation in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                if (model.GetSymbolInfo(invocation).Symbol is not IMethodSymbol { Name: "MapGrpcService", TypeArguments.Length: 1 } method
                    || method.TypeArguments[0] is not INamedTypeSymbol service)
                {
                    continue;
                }

                if (!HasGeneratedBase(service))
                {
                    problems.Add($"MapGrpcService maps {service.ToDisplayString()}, which has no generated Contracts service base.");
                }
            }
        }

        return problems;

        bool HasGeneratedBase(INamedTypeSymbol service)
        {
            for (var current = service.BaseType; current is not null; current = current.BaseType)
            {
                if (current.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == GrpcBindAttribute)
                    && !SymbolEqualityComparer.Default.Equals(current.ContainingAssembly, compilation.Assembly)
                    && current.ContainingAssembly.Name.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>Cloud consumes generated messages and never declares a protobuf message (wire type) of its own.</summary>
    public static IReadOnlyList<string> CheckNoAuthoredWireMessages(Compilation compilation)
    {
        var problems = new List<string>();
        foreach (var tree in compilation.SyntaxTrees)
        {
            var model = compilation.GetSemanticModel(tree);
            foreach (var declaration in tree.GetRoot().DescendantNodes().OfType<BaseTypeDeclarationSyntax>())
            {
                if (model.GetDeclaredSymbol(declaration) is INamedTypeSymbol { TypeKind: not TypeKind.Interface } type
                    && type.AllInterfaces.Any(contract => contract.OriginalDefinition.ToDisplayString().StartsWith("Google.Protobuf.IMessage", StringComparison.Ordinal)))
                {
                    problems.Add($"{type.ToDisplayString()} is an authored wire message.");
                }
            }
        }

        return problems;
    }

    [GeneratedRegex(@"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex ExactVersion();
}
