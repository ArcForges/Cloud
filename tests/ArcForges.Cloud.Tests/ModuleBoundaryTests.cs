// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests;

/// <summary>
/// The architecture tests of the nineteen module boundaries (Design CM-01 to CM-04, WP-21.02): which projects exist, what each may
/// reference, that no source crosses a boundary, that the host only lists the modules, and that listing a module opens nothing.
/// </summary>
public sealed partial class ModuleBoundaryTests
{
    /// <summary>The nineteen domain owners of the Cloud schema map (model 01 section 1); <c>platform</c> is shared infrastructure, not a module.</summary>
    internal static readonly string[] ExpectedModules =
    [
        "Identity", "Workspace", "Devices", "Entitlement", "Commerce", "Chat", "Task", "Agent", "Sync", "Resource", "Search",
        "PackageCatalog", "Notification", "Policy", "Scope", "Configuration", "Audit", "Support", "TrustSafety",
    ];

    private const string Abstractions = "ArcForges.Cloud.Modules.Abstractions";
    private const string Storage = "ArcForges.Cloud.Storage.D1";
    private const string Host = "ArcForges.Cloud";

    internal sealed record Project(string Name, string Directory, string[] ProjectReferences, string[] PackageReferences, string[] FrameworkReferences);

    internal static Project Load(string csproj)
    {
        var document = XDocument.Load(csproj);
        string[] Items(string element, string attribute) => document.Descendants(element).Select(item => (string)item.Attribute(attribute)!).Order(StringComparer.Ordinal).ToArray();
        return new Project(
            Path.GetFileNameWithoutExtension(csproj),
            Path.GetDirectoryName(csproj)!,
            Items("ProjectReference", "Include").Select(path => Path.GetFileNameWithoutExtension(path.Replace('\\', '/'))).Order(StringComparer.Ordinal).ToArray(),
            Items("PackageReference", "Include"),
            Items("FrameworkReference", "Include"));
    }

    internal static IReadOnlyList<Project> SourceProjects() =>
        Directory.EnumerateFiles(Path.Combine(T.RepoRoot().FullName, "src"), "*.csproj", SearchOption.AllDirectories).Select(Load).OrderBy(p => p.Name, StringComparer.Ordinal).ToArray();

    private static string ModuleProject(string module) => "ArcForges.Cloud.Modules." + module;

    [Fact]
    public void ExactlyTheNineteenSchemaMapOwnersHaveAModuleProject()
    {
        var found = SourceProjects().Select(p => p.Name).Where(name => name.StartsWith("ArcForges.Cloud.Modules.", StringComparison.Ordinal) && name != Abstractions)
            .Select(name => name["ArcForges.Cloud.Modules.".Length..]).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(19, ExpectedModules.Length);
        Assert.Equal(ExpectedModules.Order(StringComparer.Ordinal), found);
        foreach (var module in ExpectedModules)
        {
            var directory = Path.Combine(T.RepoRoot().FullName, "src", ModuleProject(module));
            Assert.True(File.Exists(Path.Combine(directory, ModuleProject(module) + ".csproj")), module);
            Assert.True(File.Exists(Path.Combine(directory, module + "Module.cs")), module);
        }

        // No second project of any module, so a layer split cannot appear without an architecture decision.
        Assert.DoesNotContain(SourceProjects().Select(p => p.Name), name => Regex.IsMatch(name, "^ArcForges\\.Cloud\\.Modules\\.[A-Za-z]+\\.[A-Za-z]+"));
    }

    [Fact]
    public void AModuleReferencesOnlyTheAbstractionsAndNoPackage()
    {
        var projects = SourceProjects().ToDictionary(p => p.Name);
        foreach (var module in ExpectedModules)
        {
            var project = projects[ModuleProject(module)];
            Assert.Equal([Abstractions], project.ProjectReferences);
            Assert.Empty(project.PackageReferences);
            Assert.Empty(project.FrameworkReferences);
        }
    }

    [Fact]
    public void TheSharedProjectsReferenceNoModuleAndNoHost()
    {
        var projects = SourceProjects().ToDictionary(p => p.Name);
        Assert.Empty(projects[Abstractions].ProjectReferences);
        Assert.Empty(projects[Abstractions].PackageReferences);
        Assert.Empty(projects[Storage].ProjectReferences);
        Assert.Equal(["ArcForges.Contracts.CloudInternal"], projects[Storage].PackageReferences);
    }

    [Fact]
    public void OnlyTheHostComposesTheModulesAndNothingInSrcReferencesTheHost()
    {
        var projects = SourceProjects();
        var host = projects.Single(p => p.Name == Host);
        Assert.Equal(ExpectedModules.Select(ModuleProject).Append(Abstractions).Append(Storage).Order(StringComparer.Ordinal), host.ProjectReferences);
        foreach (var project in projects.Where(p => p.Name != Host)) Assert.DoesNotContain(Host, project.ProjectReferences);
        // Every module is referenced by the host and by no other project of src.
        foreach (var module in ExpectedModules.Select(ModuleProject))
            Assert.Equal([Host], projects.Where(p => p.ProjectReferences.Contains(module)).Select(p => p.Name));
    }

    [Fact]
    public void TheSolutionAndTheLicenceBoundaryListEveryProject()
    {
        var root = T.RepoRoot().FullName;
        var solution = XDocument.Load(Path.Combine(root, "Cloud.slnx")).Descendants("Project").Select(item => ((string)item.Attribute("Path")!).Replace('\\', '/')).ToHashSet();
        using var boundary = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "eng", "policy", "licence-boundary.json")));
        var licensed = boundary.RootElement.GetProperty("projects").EnumerateArray().Select(row => row.GetProperty("path").GetString()!).ToHashSet();
        foreach (var project in SourceProjects())
        {
            var relative = "src/" + project.Name + "/" + project.Name + ".csproj";
            Assert.Contains(relative, solution);
            Assert.Contains(relative, licensed);
        }
    }

    [GeneratedRegex("\\bArcForges\\.Cloud\\.(Modules(?:\\.[A-Za-z]+)?|Composition|Ingress|Foundation|Storage|Hmac)\\b")]
    private static partial Regex CloudNamespaces();

    [Fact]
    public void NoSourceFileCrossesAModuleBoundary()
    {
        var root = T.RepoRoot().FullName;
        foreach (var module in ExpectedModules)
        {
            foreach (var file in CsFiles(Path.Combine(root, "src", ModuleProject(module))))
            {
                foreach (Match match in CloudNamespaces().Matches(File.ReadAllText(file)))
                {
                    // A module may use its own namespace and the Abstractions namespace; nothing else of Cloud, in particular no other module,
                    // no storage layer (persistence goes through Storage.D1 by the module's plans) and nothing of the host.
                    var allowed = match.Value == "ArcForges.Cloud.Modules" || match.Value == "ArcForges.Cloud.Modules." + module;
                    Assert.True(allowed, Path.GetRelativePath(root, file) + " references " + match.Value);
                }
            }
        }

        foreach (var shared in new[] { Abstractions, Storage })
        {
            foreach (var file in CsFiles(Path.Combine(root, "src", shared)))
            {
                foreach (Match match in CloudNamespaces().Matches(File.ReadAllText(file)))
                {
                    var own = shared == Abstractions ? match.Value == "ArcForges.Cloud.Modules" : match.Value is "ArcForges.Cloud.Storage" or "ArcForges.Cloud.Hmac";
                    Assert.True(own, Path.GetRelativePath(root, file) + " references " + match.Value);
                }
            }
        }
    }

    private static IEnumerable<string> CsFiles(string directory) =>
        Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories).Where(file => !file.Contains("/obj/", StringComparison.Ordinal) && !file.Contains("\\obj\\", StringComparison.Ordinal)
            && !file.Contains("/bin/", StringComparison.Ordinal) && !file.Contains("\\bin\\", StringComparison.Ordinal));

    [Fact]
    public void EachCompiledModuleAssemblyReferencesOnlyTheAbstractions()
    {
        Assert.Equal(19, ModuleBoundaries.All.Count);
        foreach (var boundary in ModuleBoundaries.All)
        {
            var assembly = boundary.GetType().Assembly;
            Assert.Equal(ModuleProject(boundary.Descriptor.Name), assembly.GetName().Name);
            var firstParty = assembly.GetReferencedAssemblies().Select(name => name.Name!).Where(name => name.StartsWith("ArcForges.", StringComparison.Ordinal)).ToArray();
            Assert.Equal([Abstractions], firstParty);
            // Public surface: the boundary type and nothing that exposes persistence or another module.
            Assert.All(assembly.GetExportedTypes(), type => Assert.StartsWith("ArcForges.Cloud.Modules." + boundary.Descriptor.Name, type.Namespace, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void DescriptorsMatchTheOwnerRegistryAndAreDisjoint()
    {
        using var registry = JsonDocument.Parse(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "storage", "plans", "owners.json")));
        var modules = registry.RootElement.GetProperty("owners").EnumerateArray().Where(row => row.GetProperty("kind").GetString() == "module").ToArray();
        Assert.Equal(19, modules.Length);
        var descriptors = ModuleBoundaries.All.Select(boundary => boundary.Descriptor).ToArray();
        Assert.Equal(ExpectedModules.Order(StringComparer.Ordinal), descriptors.Select(d => d.Name).Order(StringComparer.Ordinal));
        foreach (var descriptor in descriptors)
        {
            var row = Assert.Single(modules, entry => entry.GetProperty("className").GetString() == descriptor.Name);
            Assert.Equal(descriptor.PlanOwner, row.GetProperty("owner").GetString());
            Assert.Equal(descriptor.TablePrefix, row.GetProperty("tablePrefix").GetString());
            Assert.Equal(descriptor.Schema + "_", descriptor.TablePrefix);
            Assert.Equal(descriptor.Schema.Replace('_', '-'), descriptor.PlanOwner);
        }

        // No table prefix may be a prefix of another (including the shared platform and the proof prefixes), or ownership would be ambiguous.
        var prefixes = descriptors.Select(d => d.TablePrefix).Append("platform_").Append("probe_").ToArray();
        Assert.Equal(prefixes.Length, prefixes.Distinct(StringComparer.Ordinal).Count());
        foreach (var a in prefixes)
        {
            foreach (var b in prefixes) Assert.True(a == b || !b.StartsWith(a, StringComparison.Ordinal), a + " contains " + b);
        }

        Assert.Equal(descriptors.Length, descriptors.Select(d => d.PlanOwner).Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [InlineData("identity", "identity")]
    [InlineData("", "identity")]
    [InlineData("Identity", "Identity")]
    [InlineData("Identity", "package-catalog")]
    [InlineData("Identity", "_identity")]
    [InlineData("Identity", "identity_")]
    [InlineData("Identity", "")]
    [InlineData("Identity Module", "identity")]
    public void AMalformedDescriptorCannotBeCreated(string name, string schema) =>
        Assert.Throws<ArgumentException>(() => ModuleDescriptor.Create(name, schema));

    [Fact]
    public void DescriptorsDeriveTheOwnerAndThePrefixFromTheSchemaOnly()
    {
        var descriptor = ModuleDescriptor.Create("PackageCatalog", "package_catalog");
        Assert.Equal("package-catalog", descriptor.PlanOwner);
        Assert.Equal("package_catalog_", descriptor.TablePrefix);
        Assert.Equal(descriptor, ModuleDescriptor.Create("PackageCatalog", "package_catalog"));
        Assert.Same(ModuleBoundaries.All[0], ModuleBoundaries.All[0]);
    }

    [Fact]
    public void TheHostListsEveryBoundaryOnceAndAListedBoundaryServesNothing()
    {
        var identity = BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly);
        var listed = HostModules.All(identity).OfType<ModuleBoundaryHost>().ToArray();
        Assert.Equal(ModuleBoundaries.All, listed.Select(host => host.Boundary));
        Assert.Equal(19, listed.Select(host => host.Boundary.Descriptor.Name).Distinct(StringComparer.Ordinal).Count());
        foreach (IHostModule host in listed)
        {
            Assert.Empty(host.RpcPolicies);
            Assert.Empty(host.PlainPaths);
            Assert.Empty(host.PlainPrefixes);
        }
    }

    [Fact]
    public async Task TheComposedHostStillServesOnlyHelloAndHealthAndRefusesEveryModulePath()
    {
        var identity = BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly);
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Limits.MaxRequestBodySize = 4096;
            kestrel.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1);
        });
        var modules = HostModules.All(identity);
        foreach (var module in modules) module.Register(builder);
        var app = builder.Build();
        foreach (var module in modules) module.Map(app);
        await app.StartAsync(T.Ct);
        try
        {
            var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var client = new HttpClient { BaseAddress = new Uri(address) };
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz", T.Ct)).StatusCode);
            foreach (var module in ExpectedModules)
            {
                // A path that is not shaped like a method is simply not served; a method-shaped path without a policy gets the gRPC status
                // UNIMPLEMENTED (12) and reaches no endpoint.
                foreach (var path in new[] { "/" + module.ToLowerInvariant(), "/internal/" + module.ToLowerInvariant() + "/v1/get" })
                {
                    using var content = new ByteArrayContent([0, 0, 0, 0, 0]);
                    content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc-web+proto");
                    using var response = await client.PostAsync(path, content, T.Ct);
                    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
                }

                using var rpc = new ByteArrayContent([0, 0, 0, 0, 0]);
                rpc.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc-web+proto");
                using var refused = await client.PostAsync("/arcforges." + module.ToLowerInvariant() + ".v1." + module + "Service/Get", rpc, T.Ct);
                Assert.Equal(HttpStatusCode.OK, refused.StatusCode);
                Assert.Contains("grpc-status: 12", await refused.Content.ReadAsStringAsync(T.Ct), StringComparison.Ordinal);
            }
        }
        finally
        {
            await app.StopAsync(T.Ct);
            await app.DisposeAsync();
        }
    }
}
