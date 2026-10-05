// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.Build.Policy.Architecture;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The shared engine classes every module project as an Abstractions seam (no layered role fits a project the Shell host must
/// reference), so AT-01 and AT-13 do not cover the layers inside a module. This guard makes that gap explicit: a module project that
/// declares Domain, Application or Infrastructure namespaces must be on the reviewed <see cref="CloudRepository.LayeredModules"/>
/// list, and a listed module must really have them. The compensating tests are ModuleBoundaryTests and LayeringTests; they are not
/// equivalent engine enforcement.
/// </summary>
public sealed partial class LayeredModuleGuardTests
{
    private const string ModulePrefix = "ArcForges.Cloud.Modules.";

    // Any namespace declaration, file-scoped or block-scoped, nested on one line or not, whose dotted name has a layer segment. A bare
    // nested "namespace Domain" matches too because the prefix is optional. It deliberately over-matches comments and strings.
    [GeneratedRegex(@"\bnamespace\s+(?:[A-Za-z0-9_]+\.)*(?:Domain|Application|Infrastructure)\b", RegexOptions.CultureInvariant)]
    private static partial Regex LayerNamespace();

    private static List<string> Violations(IReadOnlyList<(string Module, string Source)> sources, IReadOnlySet<string> reviewed)
    {
        var layered = sources.Where(item => LayerNamespace().IsMatch(item.Source)).Select(item => item.Module).ToHashSet(StringComparer.Ordinal);
        var all = sources.Select(item => item.Module).ToHashSet(StringComparer.Ordinal);
        var violations = new List<string>();
        violations.AddRange(layered.Where(module => !reviewed.Contains(module)).Order(StringComparer.Ordinal)
            .Select(module => module + " declares Domain, Application or Infrastructure namespaces but is not a reviewed layered module"));
        violations.AddRange(reviewed.Where(module => !layered.Contains(module)).Order(StringComparer.Ordinal)
            .Select(module => module + " is listed as layered but declares no layer namespace" + (all.Contains(module) ? "" : " and has no project")));
        return violations;
    }

    private static List<(string Module, string Source)> ActualSources()
    {
        var result = new List<(string, string)>();
        var src = Path.Combine(CloudRepository.FindRoot(), "src");
        foreach (var directory in Directory.GetDirectories(src, ModulePrefix + "*"))
        {
            var module = Path.GetFileName(directory)[ModulePrefix.Length..];
            if (module == "Abstractions") continue;
            foreach (var file in Directory.GetFiles(directory, "*.cs", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(directory, file).Replace('\\', '/');
                if (relative.StartsWith("obj/", StringComparison.Ordinal) || relative.StartsWith("bin/", StringComparison.Ordinal)) continue;
                result.Add((module, File.ReadAllText(file)));
            }
        }

        return result;
    }

    [Fact]
    public void EveryModuleWithLayerNamespacesIsReviewedAndEveryReviewedModuleHasThem()
    {
        var sources = ActualSources();
        Assert.Contains(sources, item => item.Module == "Entitlement");
        Assert.Empty(Violations(sources, CloudRepository.LayeredModules));
    }

    [Fact]
    public void LayeredModulesStayAbstractionsClassifiedUntilTheEngineHasAFittingRole()
    {
        foreach (var module in CloudRepository.LayeredModules)
        {
            var path = "src/" + ModulePrefix + module + "/" + ModulePrefix + module + ".csproj";
            Assert.Contains(CloudRepository.Classifications, c => c.Path == path && c.Module == module && c.Role == ProjectRole.Abstractions);
        }
    }

    [Fact]
    public void TheGuardFlagsAnUnreviewedLayeredModuleAndAStaleEntryAndNothingElse()
    {
        var layered = "namespace ArcForges.Cloud.Modules.Chat.Domain;\npublic sealed class Entity;\n";
        var plain = "namespace ArcForges.Cloud.Modules.Chat;\npublic sealed class ChatModule;\n";
        var reviewed = new HashSet<string>(StringComparer.Ordinal) { "Entitlement" };

        Assert.Empty(Violations([("Entitlement", layered), ("Chat", plain)], reviewed));
        var unreviewed = Violations([("Entitlement", layered), ("Chat", layered)], reviewed);
        Assert.Single(unreviewed);
        Assert.Contains("Chat declares", unreviewed[0], StringComparison.Ordinal);
        var stale = Violations([("Entitlement", plain), ("Chat", plain)], reviewed);
        Assert.Single(stale);
        Assert.Contains("Entitlement is listed", stale[0], StringComparison.Ordinal);
        var none = new HashSet<string>(StringComparer.Ordinal);
        foreach (var layer in new[] { "Domain", "Application", "Infrastructure" })
        {
            Assert.Single(Violations([("Chat", "namespace ArcForges.Cloud.Modules.Chat." + layer + ".Deep\n{\n}\n")], none));
            Assert.Single(Violations([("Chat", "namespace Chat { namespace " + layer + " { class A; } }")], none));
            Assert.Single(Violations([("Chat", "namespace ArcForges.Cloud.Modules\n{\n    namespace Chat\n    {\n        namespace " + layer + "\n        {\n        }\n    }\n}\n")], none));
        }

        // A name that merely contains a layer word is not a layer segment.
        Assert.Empty(Violations([("Chat", "namespace ArcForges.Cloud.Modules.Chat.Applications.DomainEvents;\n")], none));
    }
}
