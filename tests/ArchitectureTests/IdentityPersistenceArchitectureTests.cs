// SPDX-License-Identifier: AGPL-3.0-only
using System.Xml.Linq;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

public sealed class IdentityPersistenceArchitectureTests
{
    [Fact]
    public void IdentityReferencesOnlyAbstractionsAndPersistenceNamesNoStorageOrSql()
    {
        var root = CloudRepository.FindRoot();
        var folder = Path.Combine(root, "src", "ArcForges.Cloud.Modules.Identity");
        var project = XDocument.Load(Path.Combine(folder, "ArcForges.Cloud.Modules.Identity.csproj"));
        Assert.Equal(["../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"],
            project.Descendants("ProjectReference").Select(item => item.Attribute("Include")!.Value.Replace('\\', '/')));
        Assert.Empty(project.Descendants("PackageReference"));
        foreach (var file in Directory.EnumerateFiles(Path.Combine(folder, "Persistence"), "*.cs", SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(file);
            Assert.DoesNotContain("ArcForges.Cloud.Storage", source, StringComparison.Ordinal);
            Assert.DoesNotMatch(@"\b(?:identity|workspace|platform)_[a-z_]+", source);
            Assert.DoesNotMatch(@"\b(?:SELECT|INSERT INTO|DELETE FROM|UPDATE)\b", source);
        }
    }

    [Fact]
    public void FamilyBoundaryReferencesNoBusinessModuleOrStorageType()
    {
        var root = CloudRepository.FindRoot();
        var folder = Path.Combine(root, "src", "ArcForges.Cloud.Modules.Abstractions");
        var project = XDocument.Load(Path.Combine(folder, "ArcForges.Cloud.Modules.Abstractions.csproj"));
        Assert.Empty(project.Descendants("ProjectReference"));
        Assert.Empty(project.Descendants("PackageReference"));
        foreach (var file in Directory.EnumerateFiles(Path.Combine(folder, "Families"), "*.cs", SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(file);
            Assert.DoesNotContain("ArcForges.Cloud.Storage", source, StringComparison.Ordinal);
            Assert.DoesNotMatch(@"ArcForges\.Cloud\.Modules\.(?!Abstractions)[A-Za-z]", source);
        }
    }
}
