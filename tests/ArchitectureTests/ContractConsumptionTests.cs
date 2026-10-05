// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>Contract consumption and generated RPC descriptor fixtures (WP-05.03, Cloud slice).</summary>
public sealed class ContractConsumptionTests
{
    private const string Candidate = "1.0.0-ci.287.1";

    private const string GrpcSource = """
        namespace Grpc.Core { public sealed class BindServiceMethodAttribute : System.Attribute { public BindServiceMethodAttribute(System.Type type, string method) { } } }
        """;

    private static string Props(string publicApi = Candidate, string cloudInternal = Candidate) => $$"""
        <Project><ItemGroup>
          <PackageVersion Include="ArcForges.Build.Policy" Version="1.0.0-ci.94.1" />
          <PackageVersion Include="ArcForges.Contracts.PublicApi" Version="{{publicApi}}" />
          <PackageVersion Include="ArcForges.Contracts.CloudInternal" Version="{{cloudInternal}}" />
        </ItemGroup></Project>
        """;

    private static string Manifest(string client = Candidate, string proto = Candidate) => $$"""
        { "dependencies": { "@arcforges/ai-internal": "{{Candidate}}", "@cloudflare/containers": "0.3.7" },
          "devDependencies": { "@arcforges/api-client": "{{client}}", "@arcforges/proto": "{{proto}}" } }
        """;

    [Fact]
    public void OneExactCandidateAcrossNuGetAndNpmIsAccepted()
    {
        Assert.Empty(ContractConsumptionPolicy.CheckPins(Props(), Manifest()));
    }

    [Theory]
    [InlineData("1.0.0-ci.286.1", "nuget")]
    [InlineData("1.0.*", "nuget")]
    [InlineData("[1.0.0,2.0.0)", "nuget")]
    [InlineData("1.0.0-ci.286.1", "npm")]
    [InlineData("^1.0.0-ci.287.1", "npm")]
    public void FloatingOrMixedContractCandidatesAreRejected(string version, string ecosystem)
    {
        var problems = ecosystem == "nuget"
            ? ContractConsumptionPolicy.CheckPins(Props(publicApi: version), Manifest())
            : ContractConsumptionPolicy.CheckPins(Props(), Manifest(client: version));
        Assert.NotEmpty(problems);
    }

    [Fact]
    public void AMissingNuGetContractPinSetIsRejectedWhileNpmMayBeAbsent()
    {
        Assert.NotEmpty(ContractConsumptionPolicy.CheckPins("<Project />", Manifest()));
        Assert.Empty(ContractConsumptionPolicy.CheckPins(Props(), "{ \"scripts\": {} }"));
    }

    [Fact]
    public void PackageOnlyConsumptionInsideTheRepositoryIsAccepted()
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "cloud-root"));
        var projects = new Dictionary<string, string>
        {
            ["src/Service/Service.csproj"] = """
                <Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
                  <PackageReference Include="ArcForges.Contracts.PublicApi" GeneratePathProperty="true" />
                  <EmbeddedResource Include="../../eng/version-sources.json" LogicalName="Cloud.VersionSources" />
                  <EmbeddedResource Include="$(PkgArcForges_Contracts_PublicApi)/source.json" LogicalName="Cloud.ContractsSource" />
                  <InternalsVisibleTo Include="Service.Tests" />
                </ItemGroup></Project>
                """,
            ["tests/Tests/Tests.csproj"] = """<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../../src/Service/Service.csproj" /></ItemGroup></Project>""",
        };
        Assert.Empty(ContractConsumptionPolicy.CheckProjectInputs(root, projects));
    }

    [Theory]
    [InlineData("<ProjectReference Include=\"../../../Contracts/src/public/dotnet/PublicApi/PublicApi.csproj\" />")]
    [InlineData("<ProjectReference Include=\"..\\..\\..\\..\\Contracts\\x.csproj\" />")]
    [InlineData("<Reference Include=\"ArcForges.Contracts.PublicApi\"><HintPath>../../lib/ArcForges.Contracts.PublicApi.dll</HintPath></Reference>")]
    [InlineData("<Protobuf Include=\"proto/hello.proto\" />")]
    [InlineData("<Compile Include=\"../../../Contracts/gen/Hello.cs\" />")]
    [InlineData("<Compile Include=\"Generated/Hello.cs\" />")]
    [InlineData("<EmbeddedResource Include=\"../../../Sibling/data.json\" />")]
    public void SiblingSourceSchemasAndPathReferencesAreRejected(string item)
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "cloud-root"));
        var projects = new Dictionary<string, string>
        {
            ["src/Service/Service.csproj"] = $"<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup>{item}</ItemGroup></Project>",
        };
        Assert.NotEmpty(ContractConsumptionPolicy.CheckProjectInputs(root, projects));
    }

    [Fact]
    public void LocalContractAuthorityFilesAreRejected()
    {
        Assert.Empty(ContractConsumptionPolicy.CheckTrackedFiles(["src/ArcForges.Cloud/Program.cs", "src/ArcForges.Cloud/Storage/PlanManifest.g.cs", "worker/router.ts"]));
        foreach (string file in new[] { "proto/hello.proto", "src/Generated/Hello.cs", "worker/gen/hello_pb.ts", ".gitmodules" })
        {
            Assert.NotEmpty(ContractConsumptionPolicy.CheckTrackedFiles([file]));
        }
    }

    [Fact]
    public void AServiceDerivedFromAGeneratedContractsBaseIsAccepted()
    {
        using var contracts = ContractsAssembly.Emit("ArcForges.Contracts.Hello", GrpcSource + """
            namespace Hello { public static class HelloService { [Grpc.Core.BindServiceMethod(typeof(HelloService), "BindService")] public abstract class HelloServiceBase { public abstract int Say(int value); } } }
            """);
        var compilation = Service(contracts, "sealed class Endpoint : Hello.HelloService.HelloServiceBase { public override int Say(int value) => value; }");
        Assert.Empty(ContractConsumptionPolicy.CheckServiceBases(compilation));
    }

    [Fact]
    public void AServiceMappedThroughTheGeneratedBaseIsAccepted()
    {
        using var contracts = ContractsAssembly.Emit("ArcForges.Contracts.Hello", GrpcSource + """
            namespace Hello { public static class HelloService { [Grpc.Core.BindServiceMethod(typeof(HelloService), "BindService")] public abstract class HelloServiceBase { } } }
            """);
        var compilation = Service(contracts, MapSource("Endpoint", "sealed class Endpoint : Hello.HelloService.HelloServiceBase { }"));
        Assert.Empty(ContractConsumptionPolicy.CheckServiceBases(compilation));
    }

    [Fact]
    public void AHandWrittenServiceBaseInTheCompilingProjectIsRejected()
    {
        using var contracts = ContractsAssembly.Emit("ArcForges.Contracts.Hello", "namespace Hello { public static class Unused { } }");
        var compilation = Service(contracts, GrpcSource + """
            static class HelloService { [Grpc.Core.BindServiceMethod(typeof(HelloService), "BindService")] public abstract class HelloServiceBase { } }
            sealed class Endpoint : HelloService.HelloServiceBase { }
            """);
        Assert.NotEmpty(ContractConsumptionPolicy.CheckServiceBases(compilation));
    }

    [Fact]
    public void AGeneratedBaseFromAForeignAssemblyIsRejected()
    {
        using var foreign = ContractsAssembly.Emit("Third.Party.Rpc", GrpcSource + """
            namespace Hello { public static class HelloService { [Grpc.Core.BindServiceMethod(typeof(HelloService), "BindService")] public abstract class HelloServiceBase { } } }
            """);
        var compilation = Service(foreign, "sealed class Endpoint : Hello.HelloService.HelloServiceBase { }");
        Assert.NotEmpty(ContractConsumptionPolicy.CheckServiceBases(compilation));
    }

    [Fact]
    public void AServiceBaseWithoutTheGeneratedBindIdentityIsRejected()
    {
        using var contracts = ContractsAssembly.Emit("ArcForges.Contracts.Hello", "namespace Hello { public abstract class PingServiceBase { } }");
        var compilation = Service(contracts, "sealed class Endpoint : Hello.PingServiceBase { }");
        Assert.NotEmpty(ContractConsumptionPolicy.CheckServiceBases(compilation));
    }

    [Fact]
    public void MappingATypeWithoutAGeneratedBaseIsRejected()
    {
        using var contracts = ContractsAssembly.Emit("ArcForges.Contracts.Hello", "namespace Hello { public static class Unused { } }");
        var compilation = Service(contracts, MapSource("Handwritten", "sealed class Handwritten { }"));
        Assert.NotEmpty(ContractConsumptionPolicy.CheckServiceBases(compilation));
    }

    [Fact]
    public void PlainClassesAreNotServicesAndNeedNoGeneratedBase()
    {
        using var contracts = ContractsAssembly.Emit("ArcForges.Contracts.Hello", "namespace Hello { public static class Unused { } }");
        Assert.Empty(ContractConsumptionPolicy.CheckServiceBases(Service(contracts, "class Helper { } sealed class Derived : Helper { }")));
    }

    [Fact]
    public void AuthoredProtobufMessagesAreRejectedAndGeneratedUseIsNot()
    {
        const string stub = "namespace Google.Protobuf { public interface IMessage { } public interface IMessage<T> : IMessage { } }";
        Assert.NotEmpty(ContractConsumptionPolicy.CheckNoAuthoredWireMessages(Compile(stub + " public sealed class Wire : Google.Protobuf.IMessage<Wire> { }")));
        Assert.NotEmpty(ContractConsumptionPolicy.CheckNoAuthoredWireMessages(Compile(stub + " public sealed record Wire : Google.Protobuf.IMessage { }")));
        Assert.Empty(ContractConsumptionPolicy.CheckNoAuthoredWireMessages(Compile(stub + " public sealed class Handler { public void Use(Google.Protobuf.IMessage message) { } }")));
    }

    private const string GrpcStubs = """
        namespace Grpc.Core
        {
            public sealed class Method<TRequest, TResponse> { }
            public sealed class Marshaller<T> { }
            public static class Marshallers { public static Marshaller<T> Create<T>() => null!; }
            public abstract class ClientBase<T> { }
        }
        namespace Grpc.Net.Client.Web { public enum GrpcWebMode { GrpcWeb, GrpcWebText } }
        """;

    [Theory]
    [InlineData("class U { object M() => new Grpc.Core.Method<string, string>(); }")]
    [InlineData("class U { object M() { Grpc.Core.Method<int, int> m = new(); return m; } }")]
    [InlineData("class U { object M() => new Grpc.Core.Marshaller<string>(); }")]
    [InlineData("class U { object M() => Grpc.Core.Marshallers.Create<string>(); }")]
    [InlineData("using static Grpc.Core.Marshallers; class U { object M() => Create<int>(); }")]
    public void HandBuiltRpcDescriptorsAndMarshallersAreRejected(string source)
    {
        Assert.NotEmpty(ContractConsumptionPolicy.FindHandBuiltRpcDescriptors(Compile(GrpcStubs + "\n" + source)));
    }

    [Fact]
    public void GeneratedServiceUseWithoutDescriptorConstructionIsAccepted()
    {
        Assert.Empty(ContractConsumptionPolicy.FindHandBuiltRpcDescriptors(Compile(GrpcStubs + " class U { object? M(Grpc.Core.Method<int, int>? generated) => generated; }")));
    }

    [Fact]
    public void AHandWrittenGrpcClientIsRejected()
    {
        Assert.NotEmpty(ContractConsumptionPolicy.CheckNoAuthoredWireMessages(Compile(GrpcStubs + " sealed class Hand : Grpc.Core.ClientBase<Hand> { }")));
        Assert.Empty(ContractConsumptionPolicy.CheckNoAuthoredWireMessages(Compile(GrpcStubs + " sealed class Plain { }")));
    }

    [Fact]
    public void TextEncodedGrpcWebIsRejectedAndBinaryIsAccepted()
    {
        Assert.NotEmpty(ContractConsumptionPolicy.FindTextEncodedGrpcWeb(Compile(GrpcStubs + " class U { object M() => Grpc.Net.Client.Web.GrpcWebMode.GrpcWebText; }")));
        Assert.Empty(ContractConsumptionPolicy.FindTextEncodedGrpcWeb(Compile(GrpcStubs + " class U { object M() => Grpc.Net.Client.Web.GrpcWebMode.GrpcWeb; }")));
    }

    [Fact]
    public void AProjectItemNamingTheEvaluationOwnedDirectoryIsRejected()
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "cloud-root"));
        var projects = new Dictionary<string, string>
        {
            ["src/Service/Service.csproj"] = "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"obj/arcforges-policy/Release/generated/Evil.cs\" /></ItemGroup></Project>",
        };
        Assert.NotEmpty(ContractConsumptionPolicy.CheckProjectInputs(root, projects));
    }
    private static string MapSource(string service, string declaration) => $$"""
        static class Mapper { public static void MapGrpcService<T>(this object app) where T : class { } }
        {{declaration}}
        static class Use { static void Run() => new object().MapGrpcService<{{service}}>(); }
        """;

    private static CSharpCompilation Service(ContractsAssembly contracts, string source) =>
        FixtureCompiler.Create("Service", new Dictionary<string, string> { ["service.cs"] = source }, [contracts.Path]);

    private static CSharpCompilation Compile(string source) =>
        FixtureCompiler.Create("Fixture", new Dictionary<string, string> { ["fixture.cs"] = source });

    private sealed class ContractsAssembly : IDisposable
    {
        private ContractsAssembly(string path) => Path = path;

        public string Path { get; }

        public static ContractsAssembly Emit(string name, string source)
        {
            string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-contracts-" + Guid.NewGuid().ToString("N") + ".dll");
            var result = FixtureCompiler.Create(name, new Dictionary<string, string> { ["contracts.cs"] = source }).Emit(path);
            Assert.True(result.Success, string.Join(Environment.NewLine, result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
            return new ContractsAssembly(path);
        }

        public void Dispose() => File.Delete(Path);
    }
}
