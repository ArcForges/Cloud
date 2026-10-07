// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The Commerce-to-Entitlement path (COM.16, EO-03, MD-03): Commerce, the operator path and the refund path reach Entitlement only through
/// the published grant port of the shared Abstractions project, which references no module and names no Entitlement internal type; only
/// the Entitlement module implements the port and only its owner plans name its tables. These are source and project-file scans, the same
/// kind of evidence as the module boundary checks; they do not replace the compiled-assembly checks of the managed test project.
/// </summary>
public sealed partial class EntitlementPortArchitectureTests
{
    [Fact]
    public void EarlyQuotaConfigurationContractRemainsNeutralAndNotAWireOrQuotaImplementation()
    {
        var source = File.ReadAllText(Path.Combine(Src, "ArcForges.Cloud.Modules.Abstractions", "Quota", "QuotaAccountingContracts.cs"));
        Assert.DoesNotMatch(ModuleNamespace(), source);
        Assert.DoesNotMatch(EntitlementTable(), source);
        Assert.DoesNotContain("ApprovedQuotaConfiguration", source, StringComparison.Ordinal);
        Assert.DoesNotContain("QuotaDefinitionStatus", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Google.Protobuf", source, StringComparison.Ordinal);
        Assert.Contains("IModuleFamilyContributionSet", source, StringComparison.Ordinal);
        Assert.Contains("ResolverQuotaDefinition", source, StringComparison.Ordinal);
        var project = File.ReadAllText(Path.Combine(Src, "ArcForges.Cloud.Modules.Abstractions", "ArcForges.Cloud.Modules.Abstractions.csproj"));
        Assert.DoesNotContain("ProjectReference", project, StringComparison.Ordinal);
    }

    private static string Src => Path.Combine(CloudRepository.FindRoot(), "src");

    private static IEnumerable<string> Sources(string project) =>
        Directory.EnumerateFiles(Path.Combine(Src, project), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !file.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal));

    [GeneratedRegex(@"ArcForges\.Cloud\.Modules\.[A-Za-z]", RegexOptions.CultureInvariant)]
    private static partial Regex ModuleNamespace();

    [GeneratedRegex(@"\bentitlement_[a-z_]+", RegexOptions.CultureInvariant)]
    private static partial Regex EntitlementTable();

    [Fact]
    public void TheAbstractionsProjectReferencesNoModuleAndNamesNoModuleNamespace()
    {
        var project = File.ReadAllText(Path.Combine(Src, "ArcForges.Cloud.Modules.Abstractions", "ArcForges.Cloud.Modules.Abstractions.csproj"));
        Assert.DoesNotContain("ProjectReference", project, StringComparison.Ordinal);
        Assert.DoesNotContain("PackageReference", project, StringComparison.Ordinal);
        var sources = Sources("ArcForges.Cloud.Modules.Abstractions").ToArray();
        Assert.Contains(sources, file => Path.GetFileName(file) == "EntitlementGrantPort.cs");
        Assert.Contains(sources, file => Path.GetFileName(file) == "ModulePlanPort.cs");
        foreach (var file in sources) Assert.DoesNotMatch(ModuleNamespace(), File.ReadAllText(file));
    }

    [Fact]
    public void CommerceReachesEntitlementOnlyThroughThePublishedPort()
    {
        var project = File.ReadAllText(Path.Combine(Src, "ArcForges.Cloud.Modules.Commerce", "ArcForges.Cloud.Modules.Commerce.csproj"));
        Assert.DoesNotContain("Modules.Entitlement", project, StringComparison.Ordinal);
        Assert.DoesNotContain("Storage.D1", project, StringComparison.Ordinal);
        foreach (var file in Sources("ArcForges.Cloud.Modules.Commerce"))
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotContain("ArcForges.Cloud.Modules.Entitlement", text, StringComparison.Ordinal);
            Assert.DoesNotMatch(EntitlementTable(), text);
        }
    }

    [Fact]
    public void OnlyTheEntitlementModuleImplementsThePortAndNoOtherModuleNamesItsTables()
    {
        var implementers = Directory.EnumerateDirectories(Src, "ArcForges.Cloud.Modules.*")
            .SelectMany(directory => Sources(Path.GetFileName(directory)).Select(file => (Directory: Path.GetFileName(directory), File: file)))
            .Where(item => Regex.IsMatch(File.ReadAllText(item.File), @"class\s+\w+[^{;]*:\s*[^{;]*\bIEntitlementGrantPort\b"))
            .Select(item => item.Directory)
            .Distinct()
            .ToArray();
        Assert.Equal(["ArcForges.Cloud.Modules.Entitlement"], implementers);

        foreach (var directory in Directory.EnumerateDirectories(Src, "ArcForges.Cloud.Modules.*"))
        {
            var name = Path.GetFileName(directory);
            if (name is "ArcForges.Cloud.Modules.Entitlement" or "ArcForges.Cloud.Modules.Abstractions") continue;
            foreach (var file in Sources(name)) Assert.DoesNotMatch(EntitlementTable(), File.ReadAllText(file));
        }

        var plans = Path.Combine(CloudRepository.FindRoot(), "storage", "plans");
        foreach (var file in Directory.EnumerateFiles(plans, "*.sql", SearchOption.AllDirectories))
        {
            var owner = Path.GetFileName(Path.GetDirectoryName(file))!;
            if (owner == "entitlement") continue;
            if (owner == "families" && Path.GetFileName(file) == "entitlement-definition-resolution.commit-current.sql") continue;
            Assert.DoesNotMatch(EntitlementTable(), File.ReadAllText(file));
        }
    }

    [Fact]
    public void TheEntitlementModuleReachesStorageOnlyThroughTheAbstractionsPlanPort()
    {
        var project = File.ReadAllText(Path.Combine(Src, "ArcForges.Cloud.Modules.Entitlement", "ArcForges.Cloud.Modules.Entitlement.csproj"));
        Assert.DoesNotContain("Storage.D1", project, StringComparison.Ordinal);
        foreach (var file in Sources("ArcForges.Cloud.Modules.Entitlement"))
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotMatch(@"ArcForges\.Cloud\.(?:Storage|Hmac|Foundation|Ingress|Composition)\b", text);
            // No SQL text and no table name is ever written in C#: a plan is named, never composed.
            Assert.DoesNotMatch(@"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b.*\bentitlement_", text);
            Assert.DoesNotMatch(@"\bplatform_[a-z_]+", text);
        }
    }

    [Fact]
    public void ThePlanBridgeImplementsThePortWithoutReferencingAnyModule()
    {
        var project = File.ReadAllText(Path.Combine(Src, "ArcForges.Cloud.Storage.D1", "ArcForges.Cloud.Storage.D1.csproj"));
        Assert.Contains("ArcForges.Cloud.Modules.Abstractions.csproj", project, StringComparison.Ordinal);
        Assert.DoesNotMatch(@"Modules\.(?!Abstractions)[A-Za-z]+\.csproj", project);
        foreach (var file in Sources("ArcForges.Cloud.Storage.D1")) Assert.DoesNotMatch(@"ArcForges\.Cloud\.Modules\.[A-Za-z]", File.ReadAllText(file));
    }
}
