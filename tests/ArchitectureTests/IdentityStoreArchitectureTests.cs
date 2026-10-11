// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The Identity store (CLOUD.72) reaches storage only through the Abstractions ports: the Identity project references the shared
/// Abstractions project and nothing else, its sources name no storage or host namespace, no other module's namespace, no SQL statement and
/// no table, and they implement none of the ports they consume; the D1 store is the only implementation of the identity persistence port
/// and every Persistence type is internal to the module. These are source and project-file scans; every enumeration is sorted ordinally, so
/// the findings never depend on the order a filesystem returns its entries in (ext4 does not return them alphabetically).
/// </summary>
public sealed partial class IdentityStoreArchitectureTests
{
    private const string Project = "ArcForges.Cloud.Modules.Identity";

    private static string Src => Path.Combine(CloudRepository.FindRoot(), "src");

    private static string[] Sources(string directory) =>
        [.. Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !file.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)];

    private static (string Path, string Text)[] Read(IEnumerable<string> files) => [.. files.Select(file => (file, File.ReadAllText(file)))];

    [GeneratedRegex(@"ArcForges\.Cloud\.(?:Storage|Hmac|Foundation|Ingress|Composition|Generation)\b", RegexOptions.CultureInvariant)]
    private static partial Regex HostNamespace();

    [GeneratedRegex(@"ArcForges\.Cloud\.Modules\.(?!Identity\b)[A-Za-z]", RegexOptions.CultureInvariant)]
    private static partial Regex OtherModuleNamespace();

    [GeneratedRegex(@"\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", RegexOptions.CultureInvariant)]
    private static partial Regex SqlStatement();

    [GeneratedRegex(@"\b(?:identity|workspace|platform)_[a-z][a-z_]*", RegexOptions.CultureInvariant)]
    private static partial Regex TableName();

    [GeneratedRegex(@"(?:class|record|struct)\s+\w+[^{;]*:\s*[^{;]*\b(?:IModulePlanPort|IModulePlanPortFactory|IModuleFamilyPort|IModuleFamilyPortFactory|IWorkspaceDirectory)\b", RegexOptions.CultureInvariant)]
    private static partial Regex ConsumedPortImplementation();

    [GeneratedRegex(@"(?:class|record|struct)\s+\w+[^{;]*:\s*[^{;]*\bIIdentityStore\b", RegexOptions.CultureInvariant)]
    private static partial Regex StoreImplementation();

    /// <summary>Every rule broken by the given Identity sources, as "relative path: rule", ordinally sorted and without duplicates.</summary>
    internal static string[] Findings(string root, IEnumerable<(string Path, string Text)> files)
    {
        var findings = new List<string>();
        foreach (var (path, text) in files)
        {
            var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
            if (HostNamespace().IsMatch(text)) findings.Add(relative + ": names a storage or host namespace");
            if (OtherModuleNamespace().IsMatch(text)) findings.Add(relative + ": names another module's namespace");
            if (SqlStatement().IsMatch(text)) findings.Add(relative + ": holds an SQL statement");
            if (TableName().IsMatch(text)) findings.Add(relative + ": names a table");
            if (ConsumedPortImplementation().IsMatch(text)) findings.Add(relative + ": implements a port it consumes");
            if (StoreImplementation().IsMatch(text) && !string.Equals(relative, "Persistence/D1IdentityStore.cs", StringComparison.Ordinal))
                findings.Add(relative + ": implements the identity store outside Persistence/D1IdentityStore.cs");
        }

        return [.. findings.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    [Fact]
    public void TheIdentityProjectReferencesOnlyTheAbstractionsProject()
    {
        var project = File.ReadAllText(Path.Combine(Src, Project, Project + ".csproj"));
        var references = Regex.Matches(project, @"<ProjectReference\s+Include=""([^""]+)""").Select(match => match.Groups[1].Value).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(["../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"], references);
        Assert.DoesNotContain("PackageReference", project, StringComparison.Ordinal);
    }

    [Fact]
    public void TheIdentitySourcesReachStorageOnlyThroughTheAbstractionsPorts()
    {
        var root = Path.Combine(Src, Project);
        var files = Read(Sources(root));
        Assert.Contains(files, file => file.Path.EndsWith(Path.Combine("Persistence", "D1IdentityStore.cs"), StringComparison.Ordinal));
        Assert.Empty(Findings(root, files));
    }

    [Fact]
    public void ThePersistenceTypesAreInternalToTheModuleInTheirInfrastructureNamespace()
    {
        var files = Sources(Path.Combine(Src, Project, "Persistence"));
        Assert.Equal(["D1IdentityStore.cs", "IdentityPlans.cs", "IdentityRowCodec.cs", "RandomIdentityIdSource.cs"], files.Select(Path.GetFileName));
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            Assert.Contains("namespace ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;", text, StringComparison.Ordinal);
            Assert.DoesNotMatch(@"(?m)^\s*public\s+(?:sealed\s+|static\s+|abstract\s+)*(?:partial\s+)?(?:class|record|struct|interface|enum)\b", text);
        }
    }

    [Fact]
    public void TheIdentityStoreIsImplementedOnlyByTheD1StoreAcrossTheProductionSources()
    {
        var implementers = Read(Sources(Src))
            .Where(file => StoreImplementation().IsMatch(file.Text))
            .Select(file => Path.GetRelativePath(Src, file.Path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["ArcForges.Cloud.Modules.Identity/Persistence/D1IdentityStore.cs"], implementers);
    }

    [Fact]
    public void TheScannerFindsEveryPlantedViolationWhateverTheOrderTheFilesystemReturns()
    {
        var root = Path.Combine(Src, Project);
        var files = Read(Sources(root));
        (string, string)[] planted =
        [
            (Path.Combine(root, "Persistence", "Planted1.cs"), "using ArcForges.Cloud.Storage.ModuleBinding;"),
            (Path.Combine(root, "Persistence", "Planted2.cs"), "const string Q = \"SELECT user_id FROM identity_user\";"),
            (Path.Combine(root, "Core", "Planted3.cs"), "internal sealed class Shortcut : IModulePlanPort { }"),
            (Path.Combine(root, "Core", "Planted4.cs"), "internal sealed class Second : IIdentityStore { }"),
            (Path.Combine(root, "Planted5.cs"), "using ArcForges.Cloud.Modules.Workspace.Persistence;"),
            (Path.Combine(root, "Planted6.cs"), "// writes platform_outbox directly"),
        ];
        string[] expected =
        [
            "Core/Planted3.cs: implements a port it consumes",
            "Core/Planted4.cs: implements the identity store outside Persistence/D1IdentityStore.cs",
            "Persistence/Planted1.cs: names a storage or host namespace",
            "Persistence/Planted2.cs: holds an SQL statement",
            "Persistence/Planted2.cs: names a table",
            "Planted5.cs: names another module's namespace",
            "Planted6.cs: names a table",
        ];

        (string, string)[] first = [.. planted, .. files];
        (string, string)[] last = [.. files, .. planted];
        var reversed = first.Reverse().ToArray();
        var shuffled = first.OrderBy(file => file.Item2.Length).ThenByDescending(file => file.Item1, StringComparer.Ordinal).ToArray();

        Assert.Equal(expected, Findings(root, first));
        Assert.Equal(expected, Findings(root, last));
        Assert.Equal(expected, Findings(root, reversed));
        Assert.Equal(expected, Findings(root, shuffled));
        Assert.Equal(Findings(root, files), Findings(root, files.Reverse()));
    }

    [Fact]
    public void TheScannerDoesNotFlagThePlanIdsOrTheOwnNamespace()
    {
        var root = Path.Combine(Src, Project);
        (string, string)[] clean =
        [
            (Path.Combine(root, "A.cs"), "namespace ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure; const string P = \"identity.user-load\"; // storage/plans/identity"),
            (Path.Combine(root, "B.cs"), "using ArcForges.Cloud.Modules; internal sealed class S(IModulePlanPort plans) : IIdentityStore { } // the identity_* tables"),
        ];
        Assert.Equal(["B.cs: implements the identity store outside Persistence/D1IdentityStore.cs"], Findings(root, clean));
    }
}
