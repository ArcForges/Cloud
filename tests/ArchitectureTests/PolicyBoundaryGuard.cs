// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>BD-01..04 semantic dependencies, independent of project references and source spelling.</summary>
internal static class PolicyBoundaryGuard
{
    internal static IReadOnlyList<string> Check(CSharpCompilation compilation)
    {
        var failures = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var tree in compilation.SyntaxTrees)
        {
            var semantic = compilation.GetSemanticModel(tree);
            foreach (var node in tree.GetRoot().DescendantNodes())
            {
                var declaration = node.AncestorsAndSelf().FirstOrDefault(candidate => candidate is BaseTypeDeclarationSyntax or DelegateDeclarationSyntax);
                var source = declaration is null ? Classify(semantic.GetEnclosingSymbol(node.SpanStart)?.ContainingNamespace?.ToDisplayString())
                    : Classify(semantic.GetDeclaredSymbol(declaration) as ITypeSymbol);
                if (source == Boundary.Other) continue;
                var symbol = node is ExpressionSyntax or TypeSyntax or AttributeSyntax
                    ? semantic.GetSymbolInfo(node).Symbol : null;
                var type = node is ExpressionSyntax or TypeSyntax ? semantic.GetTypeInfo(node).Type : null;
                foreach (var referenced in References(symbol).Concat(Types(type)).Distinct<ITypeSymbol>(SymbolEqualityComparer.Default))
                {
                    var target = Classify(referenced);
                    bool forbidden = source == Boundary.Policy && target is not (Boundary.Other or Boundary.Policy)
                        || target == Boundary.Policy && source is not (Boundary.Other or Boundary.Policy);
                    if (!forbidden) continue;
                    var location = node.GetLocation().GetLineSpan();
                    failures.Add($"BD-0{Rule(source == Boundary.Policy ? target : source)} {tree.FilePath}:{location.StartLinePosition.Line + 1}: {source} cannot depend on {target} ({referenced!.ToDisplayString()}).");
                }
            }
        }
        return [.. failures];
    }

    private static int Rule(Boundary boundary) => boundary switch
    {
        Boundary.Entitlement => 1,
        Boundary.Settings => 2,
        Boundary.Health => 3,
        Boundary.DataPlane => 4,
        _ => throw new InvalidOperationException("Not a founding boundary."),
    };

    private static IEnumerable<ITypeSymbol> References(ISymbol? symbol)
    {
        if (symbol is IAliasSymbol alias) symbol = alias.Target;
        if (symbol is ITypeSymbol type) return Types(type);
        if (symbol is IMethodSymbol method) return Types(method.ContainingType).Concat(Types(method.ReturnType))
            .Concat(method.Parameters.SelectMany(parameter => Types(parameter.Type))).Concat(method.TypeArguments.SelectMany(Types));
        if (symbol is IPropertySymbol property) return Types(property.ContainingType).Concat(Types(property.Type));
        if (symbol is IFieldSymbol field) return Types(field.ContainingType).Concat(Types(field.Type));
        if (symbol is IEventSymbol @event) return Types(@event.ContainingType).Concat(Types(@event.Type));
        return [];
    }

    private static IEnumerable<ITypeSymbol> Types(ITypeSymbol? type)
    {
        if (type is null) yield break;
        yield return type;
        if (type is INamedTypeSymbol named)
            foreach (var argument in named.TypeArguments)
                foreach (var nested in Types(argument)) yield return nested;
        if (type is IArrayTypeSymbol array)
            foreach (var nested in Types(array.ElementType)) yield return nested;
        if (type is IPointerTypeSymbol pointer)
            foreach (var nested in Types(pointer.PointedAtType)) yield return nested;
    }

    private static Boundary Classify(string? value)
    {
        static bool Under(string? actual, string root) => actual == root || actual?.StartsWith(root + ".", StringComparison.Ordinal) == true;
        if (Under(value, "ArcForges.Cloud.Modules.Policy") || Under(value, "ArcForges.Cloud.Modules.Configuration")
            || Under(value, "ArcForges.Cloud.Modules.PolicyControl")) return Boundary.Policy;
        if (Under(value, "ArcForges.Cloud.Modules.Entitlement") || Under(value, "ArcForges.Cloud.Modules.EntitlementDecisions")) return Boundary.Entitlement;
        if (Under(value, "ArcForges.Cloud.Modules.Settings") || Under(value, "ArcForges.Cloud.Modules.UserSettings")) return Boundary.Settings;
        if (Under(value, "ArcForges.Cloud.Readiness") || Under(value, "ArcForges.Cloud.Health")) return Boundary.Health;
        if (Under(value, "ArcForges.Cloud.Ingress") || Under(value, "ArcForges.Cloud.DataPlane")
            || Under(value, "Microsoft.AspNetCore.Http")) return Boundary.DataPlane;
        return Boundary.Other;
    }

    private static Boundary Classify(ITypeSymbol? type)
    {
        if (type?.ContainingType is { } containing)
        {
            var enclosing = Classify(containing);
            if (enclosing != Boundary.Other) return enclosing;
        }
        if (type?.ContainingNamespace?.ToDisplayString() == "ArcForges.Cloud" && type.Name == "HealthStatus")
            return Boundary.Health;
        // COM.16's historical primitive port lives in the root Abstractions namespace. Preserve its public identity while
        // preventing a Policy module from granting/revoking commercial authority through that otherwise neutral project.
        if (type?.ContainingNamespace?.ToDisplayString() == "ArcForges.Cloud.Modules"
            && type.Name is "IEntitlementGrantPort" or "EntitlementGrantKind" or "EntitlementGrantSource"
                or "EntitlementGrantTerms" or "CapabilityGrantTerms" or "QuotaGrantTerms" or "AllowanceGrantTerms"
                or "IssueGrantCommand" or "RevokeGrantCommand" or "EntitlementGrantRecord" or "EntitlementRevocationRecord"
                or "EntitlementPortStatus" or "EntitlementPortResult") return Boundary.Entitlement;
        return Classify(type?.ContainingNamespace?.ToDisplayString());
    }

    private enum Boundary { Other, Policy, Entitlement, Settings, Health, DataPlane }
}
