// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The generic family-execution port (CLOUD.72): it lives in the shared Abstractions project, built from primitives and naming no module and
/// no storage type, and only the Storage.D1 FamilyBinding adapter implements it, without referencing any module and without SQL or table
/// names of its own. These are source and project-file scans; every enumeration is sorted ordinally so the findings do not depend on the
/// order a filesystem returns its entries in.
/// </summary>
public sealed partial class FamilyPortArchitectureTests
{
    private static string Src => Path.Combine(CloudRepository.FindRoot(), "src");

    private static string[] Sources(string directory) =>
        [.. Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !file.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)];

    [GeneratedRegex(@"(?:class|record|struct)\s+\w+[^{;]*:\s*[^{;]*\bIModuleFamilyPort(?:Factory)?\b", RegexOptions.CultureInvariant)]
    private static partial Regex Implementation();

    /// <summary>The project-relative paths (forward slashes) of the files that implement the family port or its factory, ordinally sorted.</summary>
    internal static string[] Implementers(string root, IEnumerable<(string Path, string Text)> files) =>
        [.. files.Where(file => Implementation().IsMatch(file.Text))
            .Select(file => Path.GetRelativePath(root, file.Path).Replace('\\', '/'))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

    private static (string Path, string Text)[] Read(IEnumerable<string> files) => [.. files.Select(file => (file, File.ReadAllText(file)))];

    [Fact]
    public void ThePortIsPublishedInTheAbstractionsProjectFromPrimitivesOnly()
    {
        var file = Path.Combine(Src, "ArcForges.Cloud.Modules.Abstractions", "Families", "ModuleFamilyPort.cs");
        Assert.True(File.Exists(file));
        var text = File.ReadAllText(file);
        Assert.Contains("namespace ArcForges.Cloud.Modules;", text, StringComparison.Ordinal);
        Assert.DoesNotMatch(@"\busing\s", text);
        Assert.DoesNotMatch(@"ArcForges\.Cloud\.(?:Storage|Modules\.[A-Za-z])", text);
        Assert.DoesNotMatch(@"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b", text);
        foreach (var name in new[] { "public interface IModuleFamilyPort", "public interface IModuleFamilyPortFactory", "public sealed record ModuleFamilyCall", "public sealed record FamilyStatement" })
            Assert.Contains(name, text, StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyTheFamilyBindingAdapterImplementsThePort()
    {
        var files = Read(Sources(Src));
        Assert.Equal(["ArcForges.Cloud.Storage.D1/FamilyBinding/ModuleFamilyPortFactory.cs"], Implementers(Src, files));
    }

    [Fact]
    public void TheImplementerScanDoesNotDependOnTheOrderTheFilesystemReturns()
    {
        var files = Read(Sources(Src));
        var reversed = files.Reverse().ToArray();
        var shuffled = files.OrderBy(file => file.Path.Length).ThenByDescending(file => file.Path, StringComparer.Ordinal).ToArray();
        Assert.Equal(Implementers(Src, files), Implementers(Src, reversed));
        Assert.Equal(Implementers(Src, files), Implementers(Src, shuffled));

        // A second implementer anywhere is found whatever its position in the enumeration.
        var planted = Path.Combine(Src, "ArcForges.Cloud.Modules.Identity", "Planted.cs");
        (string, string)[] withPlanted = [(planted, "internal sealed class Planted : IModuleFamilyPort { }"), .. files];
        (string, string)[] plantedLast = [.. files, (planted, "internal sealed class Planted : IModuleFamilyPort { }")];
        Assert.Equal(["ArcForges.Cloud.Modules.Identity/Planted.cs", "ArcForges.Cloud.Storage.D1/FamilyBinding/ModuleFamilyPortFactory.cs"], Implementers(Src, withPlanted));
        Assert.Equal(Implementers(Src, withPlanted), Implementers(Src, plantedLast));
    }

    [Fact]
    public void TheAdapterReferencesNoModuleAndHoldsNoSqlOrTableName()
    {
        var folder = Path.Combine(Src, "ArcForges.Cloud.Storage.D1", "FamilyBinding");
        var files = Sources(folder);
        Assert.Equal(["FamilyContributionPolicy.cs", "ModuleFamilyPortFactory.cs"], files.Select(Path.GetFileName));
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotMatch(@"ArcForges\.Cloud\.Modules\.[A-Za-z]", text);
            Assert.DoesNotMatch(@"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b", text);
            Assert.DoesNotMatch(@"\b(?:identity|workspace|platform)_[a-z_]+", text);
            Assert.Contains("namespace ArcForges.Cloud.Storage.FamilyBinding;", text, StringComparison.Ordinal);
        }
    }
}
