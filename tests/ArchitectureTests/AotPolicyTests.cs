// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>Native AOT posture fixtures (BR-07): project settings, source suppressions and the JSON serialization path.</summary>
public sealed class AotPolicyTests
{
    private const string CommonProps = "<Project><PropertyGroup><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression></PropertyGroup></Project>";

    private static string Project(string extra = "", params (string Name, string Value)[] overrides)
    {
        var settings = new Dictionary<string, string>
        {
            ["PublishAot"] = "true",
            ["JsonSerializerIsReflectionEnabledByDefault"] = "false",
            ["IlcTreatWarningsAsErrors"] = "true",
            ["ILLinkTreatWarningsAsErrors"] = "true",
        };
        foreach (var (name, value) in overrides)
        {
            settings[name] = value;
        }

        return "<Project Sdk=\"Microsoft.NET.Sdk.Web\"><PropertyGroup>"
            + string.Concat(settings.Select(setting => $"<{setting.Key}>{setting.Value}</{setting.Key}>")) + extra
            + "</PropertyGroup></Project>";
    }
    [Fact]
    public void TheDeclaredAotSettingsAreAccepted()
    {
        Assert.Empty(CloudAotPolicy.CheckProject(Project(), CommonProps));
        Assert.Empty(CloudAotPolicy.CheckProject(Project("<NoWarn>CS1591;CA1707</NoWarn>"), CommonProps));
    }

    [Theory]
    [InlineData("PublishAot", "false")]
    [InlineData("JsonSerializerIsReflectionEnabledByDefault", "true")]
    [InlineData("IlcTreatWarningsAsErrors", "false")]
    [InlineData("ILLinkTreatWarningsAsErrors", "false")]
    public void WeakenedCoreSettingsAreRejected(string name, string value)
    {
        Assert.NotEmpty(CloudAotPolicy.CheckProject(Project(string.Empty, (name, value)), CommonProps));
    }

    [Theory]
    [InlineData("<SuppressTrimAnalysisWarnings>true</SuppressTrimAnalysisWarnings>")]
    [InlineData("<TrimmerSingleWarn>true</TrimmerSingleWarn>")]
    [InlineData("<EnableTrimAnalyzer>false</EnableTrimAnalyzer>")]
    [InlineData("<EnableAotAnalyzer>false</EnableAotAnalyzer>")]
    [InlineData("<NoWarn>$(NoWarn);IL2026</NoWarn>")]
    [InlineData("<NoWarn>IL3050,CS1591</NoWarn>")]
    [InlineData("<NoWarn>$(NoWarn);IL3*</NoWarn>")]
    [InlineData("<NoWarn>IL*</NoWarn>")]
    [InlineData("<WarningsNotAsErrors>IL2104</WarningsNotAsErrors>")]
    public void AddedDiagnosticSuppressionsAreRejected(string change)
    {
        Assert.NotEmpty(CloudAotPolicy.CheckProject(Project(change), CommonProps));
    }
    [Theory]
    [InlineData("<PublishAot>")]
    [InlineData("<IlcTreatWarningsAsErrors>")]
    public void MissingAotSettingsAreRejected(string element)
    {
        string project = Project().Replace(element + "true</" + element[1..], string.Empty, StringComparison.Ordinal);
        Assert.NotEmpty(CloudAotPolicy.CheckProject(project, CommonProps));
    }

    [Theory]
    [InlineData("<ItemGroup><TrimmerRootAssembly Include=\"Example\" /></ItemGroup>")]
    [InlineData("<ItemGroup><TrimmerRootDescriptor Include=\"roots.xml\" /></ItemGroup>")]
    [InlineData("<ItemGroup><RdXmlFile Include=\"rd.xml\" /></ItemGroup>")]
    public void TrimmerRootsAreRejected(string items)
    {
        Assert.NotEmpty(CloudAotPolicy.CheckProject(Project().Replace("</Project>", items + "</Project>", StringComparison.Ordinal), CommonProps));
    }

    [Theory]
    [InlineData("#pragma warning disable IL2026\nclass C { }")]
    [InlineData("#pragma warning disable CS8618, IL3050\nclass C { }")]
    [InlineData("[System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage(\"Trimming\", \"IL2026\")] class C { }")]
    [InlineData("[UnconditionalSuppressMessage(\"AOT\", \"IL3050\", Justification = \"x\")] class C { }")]
    [InlineData("[System.Diagnostics.CodeAnalysis.SuppressMessage(\"Trimming\", \"IL2026:Members\")] class C { }")]
    public void SourceLevelTrimAndAotSuppressionsAreRejected(string source)
    {
        Assert.NotEmpty(CloudAotPolicy.FindSuppressions(Syntax(source)));
    }

    [Theory]
    [InlineData("#pragma warning disable CS8618\nclass C { }")]
    [InlineData("[System.Diagnostics.CodeAnalysis.SuppressMessage(\"Style\", \"IDE0005\")] class C { }")]
    [InlineData("class C { string M() => \"#pragma warning disable IL2026\"; } // IL3050 in a comment")]
    public void UnrelatedPragmasAndTextAreNotSuppressions(string source)
    {
        Assert.Empty(CloudAotPolicy.FindSuppressions(Syntax(source)));
    }

    [Theory]
    [InlineData("static class C { static object? M(string json) => System.Text.Json.JsonSerializer.Deserialize<Wire>(json); }")]
    [InlineData("static class C { static string M(Wire value) => System.Text.Json.JsonSerializer.Serialize(value); }")]
    [InlineData("static class C { static byte[] M(Wire value) => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value, new System.Text.Json.JsonSerializerOptions()); }")]
    [InlineData("static class C { static object? M(string json) => System.Text.Json.JsonSerializer.Deserialize(json, typeof(Wire)); }")]
    [InlineData("static class C { static object M(Wire value) => Microsoft.AspNetCore.Http.Results.Json(value); }")]
    public void SerializerCallsWithoutCompileTimeMetadataAreRejected(string source)
    {
        Assert.NotEmpty(CloudAotPolicy.FindUnregisteredJsonSerialization(Json(source)));
    }

    [Theory]
    [InlineData("static class C { static object? M(string json, System.Text.Json.Serialization.Metadata.JsonTypeInfo<Wire> info) => System.Text.Json.JsonSerializer.Deserialize(json, info); }")]
    [InlineData("static class C { static byte[] M(Wire value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<Wire> info) => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value, info); }")]
    [InlineData("static class C { static object? M(string json, System.Text.Json.Serialization.JsonSerializerContext context) => System.Text.Json.JsonSerializer.Deserialize(json, typeof(Wire), context); }")]
    [InlineData("static class C { static object M(Wire value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<Wire> info) => Microsoft.AspNetCore.Http.Results.Json(value, info); }")]
    [InlineData("static class C { static string M() => System.Text.Json.Nodes.JsonNode.Parse(\"{}\")!.ToJsonString(); }")]
    public void SerializerCallsWithRegisteredMetadataAreAccepted(string source)
    {
        Assert.Empty(CloudAotPolicy.FindUnregisteredJsonSerialization(Json(source)));
    }

    private static CSharpCompilation Syntax(string source) =>
        CSharpCompilation.Create("Syntax", [CSharpSyntaxTree.ParseText(source)]);

    private static CSharpCompilation Json(string source) => FixtureCompiler.Create("Json", new Dictionary<string, string>
    {
        ["fixture.cs"] = """
            namespace Microsoft.AspNetCore.Http
            {
                public static class Results
                {
                    public static object Json<T>(T value) => value!;
                    public static object Json<T>(T value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info) => value!;
                }
            }
            public sealed record Wire(int Value);
            """ + "\n" + source,
    });
}
