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
    private static (string Path, string Text)[] Sources(string project) =>
        ArchivedManagedSource.CSharpUnder("src/" + project);

    private static string Project(string name) => ArchivedManagedSource.Read($"src/{name}/{name}.csproj");

    [GeneratedRegex(@"ArcForges\.Cloud\.Modules\.[A-Za-z]", RegexOptions.CultureInvariant)]
    private static partial Regex ModuleNamespace();

    [GeneratedRegex(@"\bentitlement_[a-z_]+", RegexOptions.CultureInvariant)]
    private static partial Regex EntitlementTable();

    [Fact]
    public void TheAbstractionsProjectReferencesNoModuleAndNamesNoModuleNamespace()
    {
        var project = Project("ArcForges.Cloud.Modules.Abstractions");
        Assert.DoesNotContain("ProjectReference", project, StringComparison.Ordinal);
        Assert.DoesNotContain("PackageReference", project, StringComparison.Ordinal);
        var sources = Sources("ArcForges.Cloud.Modules.Abstractions");
        Assert.Contains(sources, file => Path.GetFileName(file.Path) == "EntitlementGrantPort.cs");
        Assert.Contains(sources, file => Path.GetFileName(file.Path) == "ModulePlanPort.cs");
        foreach (var file in sources) Assert.DoesNotMatch(ModuleNamespace(), file.Text);
    }

    [Fact]
    public void CommerceReachesEntitlementOnlyThroughThePublishedPort()
    {
        var project = Project("ArcForges.Cloud.Modules.Commerce");
        Assert.DoesNotContain("Modules.Entitlement", project, StringComparison.Ordinal);
        Assert.DoesNotContain("Storage.D1", project, StringComparison.Ordinal);
        foreach (var (_, text) in Sources("ArcForges.Cloud.Modules.Commerce"))
        {
            Assert.DoesNotContain("ArcForges.Cloud.Modules.Entitlement", text, StringComparison.Ordinal);
            Assert.DoesNotMatch(EntitlementTable(), text);
        }
    }

    [Fact]
    public void OnlyTheEntitlementModuleImplementsThePortAndNoOtherModuleNamesItsTables()
    {
        var implementers = ArchivedManagedSource.ModuleProjects
            .Where(name => Sources(name).Any(file => Regex.IsMatch(file.Text, @"class\s+\w+[^{;]*:\s*[^{;]*\bIEntitlementGrantPort\b")))
            .ToArray();
        Assert.Equal(["ArcForges.Cloud.Modules.Entitlement"], implementers);

        foreach (var name in ArchivedManagedSource.ModuleProjects)
        {
            if (name is "ArcForges.Cloud.Modules.Entitlement" or "ArcForges.Cloud.Modules.Abstractions") continue;
            foreach (var file in Sources(name)) Assert.DoesNotMatch(EntitlementTable(), file.Text);
        }
    }

    [Fact]
    public void OnlyEntitlementOwnerPlansNameItsTables()
    {
        var plans = Path.Combine(CloudRepository.FindRoot(), "storage", "plans");
        foreach (var file in Directory.EnumerateFiles(plans, "*.sql", SearchOption.AllDirectories))
        {
            var owner = Path.GetFileName(Path.GetDirectoryName(file))!;
            if (owner == "entitlement") continue;
            Assert.DoesNotMatch(EntitlementTable(), File.ReadAllText(file));
        }
    }

    [Fact]
    public void TheEntitlementModuleReachesStorageOnlyThroughTheAbstractionsPlanPort()
    {
        var project = Project("ArcForges.Cloud.Modules.Entitlement");
        Assert.DoesNotContain("Storage.D1", project, StringComparison.Ordinal);
        foreach (var (_, text) in Sources("ArcForges.Cloud.Modules.Entitlement"))
        {
            Assert.DoesNotMatch(@"ArcForges\.Cloud\.(?:Storage|Hmac|Foundation|Ingress|Composition)\b", text);
            // No SQL text and no table name is ever written in C#: a plan is named, never composed.
            Assert.DoesNotMatch(@"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b.*\bentitlement_", text);
            Assert.DoesNotMatch(@"\bplatform_[a-z_]+", text);
        }
    }

    [Fact]
    public void ThePlanBridgeImplementsThePortWithoutReferencingAnyModule()
    {
        var project = Project("ArcForges.Cloud.Storage.D1");
        Assert.Contains("ArcForges.Cloud.Modules.Abstractions.csproj", project, StringComparison.Ordinal);
        Assert.DoesNotMatch(@"Modules\.(?!Abstractions)[A-Za-z]+\.csproj", project);
        foreach (var file in Sources("ArcForges.Cloud.Storage.D1")) Assert.DoesNotMatch(@"ArcForges\.Cloud\.Modules\.[A-Za-z]", file.Text);
    }
}
