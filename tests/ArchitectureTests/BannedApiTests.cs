// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// Banned-API fixtures (WP-05.04). Cloud is the Native AOT host, so reflection and runtime code generation carry the most cases;
/// all seven shared categories still get a compiled valid/violating pair. Fixtures resolve real symbols, never text.
/// </summary>
public sealed class BannedApiTests
{
    [Theory]
    [InlineData("BAN-REFLECTION", "class C { object? M() => typeof(string); }", "class C { object? M() => System.Type.GetType(\"Example\"); }", "Shell")]
    [InlineData("BAN-CODEGEN", "class C { object M() => System.Linq.Expressions.Expression.Constant(1); }", "class C { object M() => new System.Reflection.Emit.DynamicMethod(\"example\", typeof(void), System.Type.EmptyTypes); }", "Shell")]
    [InlineData("BAN-BLOCKING", "class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Delay(1); } }", "class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Yield(); System.Threading.Tasks.Task.Delay(1).Wait(); } }", "Shell")]
    [InlineData("BAN-PROVIDER", "class C { int M() => 1; }", "namespace OpenAI { public static class Client { public static int Call() => 1; } } class C { int M() => OpenAI.Client.Call(); }", "Shell")]
    [InlineData("BAN-LOGGING", "class C { void M() { System.Console.WriteLine(42); } }", "class SecretValue {} class C { void M(SecretValue secret) { System.Console.WriteLine(secret); } }", "Shell")]
    [InlineData("BAN-MONEY", "class Money { decimal Add(decimal value) => value + 1m; }", "class Money { double Add(double value) => value + 1d; }", "Shell")]
    [InlineData("BAN-POINTER", "class C { internal System.Runtime.InteropServices.SafeHandle? Handle; }", "class C { internal System.IntPtr Handle; }", "NativeAdapter")]
    public void EveryCategoryAcceptsItsValidFixtureAndRejectsItsViolation(string rule, string valid, string violation, string role)
    {
        Assert.Empty(Scan(valid, Enum.Parse<ProjectRole>(role)));
        Assert.Contains(Scan(violation, Enum.Parse<ProjectRole>(role)), finding => finding.Rule == rule);
    }

    [Theory]
    [InlineData("class C { object? M() => System.Activator.CreateInstance(typeof(string)); }")]
    [InlineData("class C { object? M() => System.Activator.CreateInstance(System.Type.GetType(\"System.Object\")!); }")]
    [InlineData("using static System.Activator; class C { object? M() => CreateInstance(typeof(string)); }")]
    [InlineData("using T = System.Type; class C { object? M() => T.GetType(\"Example\"); }")]
    [InlineData("class C { object? M() => typeof(string).GetMethod(\"Trim\"); }")]
    [InlineData("class C { object? M() => typeof(string).GetProperty(\"Length\"); }")]
    [InlineData("class C { object? M() => typeof(string).GetField(\"Empty\"); }")]
    [InlineData("class C { object? M() => typeof(string).GetConstructor(System.Type.EmptyTypes); }")]
    [InlineData("class C { object? M() => typeof(string).GetMembers(); }")]
    [InlineData("class C { object? M() => typeof(string).InvokeMember(\"Trim\", System.Reflection.BindingFlags.InvokeMethod, null, \"\", null); }")]
    [InlineData("class C { object? M(System.Reflection.MethodInfo method) => method.Invoke(null, null); }")]
    [InlineData("class C { object? M(System.Reflection.PropertyInfo property, object value) => property.GetValue(value); }")]
    [InlineData("class C { void M(System.Reflection.FieldInfo field, object value) => field.SetValue(value, null); }")]
    [InlineData("class C { System.Type M(System.Type type) => type.MakeGenericType(typeof(int)); }")]
    [InlineData("class C { System.Reflection.MethodInfo M(System.Reflection.MethodInfo method) => method.MakeGenericMethod(typeof(int)); }")]
    [InlineData("class C { object? M() => System.Reflection.Assembly.Load(\"Example\"); }")]
    [InlineData("class C { object? M(System.Reflection.Assembly assembly) => assembly.GetTypes(); }")]
    [InlineData("class C { object M(dynamic value) => value.Run(); }")]
    public void ReflectionIsRejectedOnTheNativeAotPath(string source)
    {
        Assert.Contains(Scan(source, ProjectRole.Shell), finding => finding.Rule == "BAN-REFLECTION");
        Assert.Contains(Scan(source, ProjectRole.Shell), finding => finding.Rule == "BAN-REFLECTION");
    }

    [Theory]
    [InlineData("class C { object? M() => System.Activator.CreateInstance(typeof(string)); }")]
    [InlineData("class C { object? M() => typeof(string).GetMethod(\"Trim\"); }")]
    public void ReflectionIsOnlyAnAotPathRuleSoTheServiceMustStayClassifiedAsAot(string source)
    {
        // The engine reports reflection only for projects classified as AOT. The Cloud inventory therefore pins the service as AOT.
        Assert.DoesNotContain(Scan(source, ProjectRole.Shell, aot: false), finding => finding.Rule == "BAN-REFLECTION");
        var service = Assert.Single(CloudRepository.Classifications, project => project.Path == CloudRepository.Service);
        Assert.True(service.Aot && service.Production);
        Assert.All(CloudRepository.Classifications.Where(project => project.Path != CloudRepository.Service), project => Assert.False(project.Production));
    }

    [Theory]
    [InlineData("class C { object M() => new System.Reflection.Emit.DynamicMethod(\"example\", typeof(void), System.Type.EmptyTypes); }")]
    [InlineData("class C { object M() => System.Reflection.Emit.AssemblyBuilder.DefineDynamicAssembly(new System.Reflection.AssemblyName(\"example\"), System.Reflection.Emit.AssemblyBuilderAccess.Run); }")]
    [InlineData("class C { object M() => System.Linq.Expressions.Expression.Lambda<System.Func<int>>(System.Linq.Expressions.Expression.Constant(1)).Compile(); }")]
    [InlineData("class C { object M() => System.Linq.Expressions.Expression.Lambda(System.Linq.Expressions.Expression.Constant(1)).Compile(); }")]
    public void RuntimeCodeGenerationIsRejectedEverywhereInProduction(string source)
    {
        Assert.Contains(Scan(source, ProjectRole.Shell), finding => finding.Rule == "BAN-CODEGEN");
        Assert.Contains(Scan(source, ProjectRole.Shell, aot: false), finding => finding.Rule == "BAN-CODEGEN");
    }

    [Theory]
    [InlineData("class C { System.Linq.Expressions.Expression M() => System.Linq.Expressions.Expression.Constant(1); }")]
    [InlineData("class C { string M() => \"System.Activator.CreateInstance OpenAI.Client.Call secret\"; /* System.Reflection.Emit */ }")]
    [InlineData("class C { string M() => nameof(System.Activator.CreateInstance); }")]
    [InlineData("class C { System.Type M() => typeof(string); }")]
    public void ExpressionTreesWithoutCompilationAndTextAreNotBannedSymbols(string source)
    {
        Assert.Empty(Scan(source, ProjectRole.Shell));
    }

    [Theory]
    [InlineData("class C { void M() { System.Threading.Tasks.Task.Run(async () => { System.Threading.Tasks.Task.Delay(1).Wait(); await System.Threading.Tasks.Task.Yield(); }); } }")]
    [InlineData("class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Yield(); System.Threading.Tasks.Task.Delay(1).ConfigureAwait(false).GetAwaiter().GetResult(); } }")]
    [InlineData("class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Yield(); var value = System.Threading.Tasks.Task.FromResult(1).Result; } }")]
    [InlineData("class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Yield(); System.Threading.Thread.Sleep(1); } }")]
    [InlineData("class C { async System.Threading.Tasks.Task M() { await System.Threading.Tasks.Task.Yield(); System.Threading.Tasks.Task.WaitAll(System.Threading.Tasks.Task.CompletedTask); } }")]
    [InlineData("class C { void Start() { async System.Threading.Tasks.Task Local() { await System.Threading.Tasks.Task.Yield(); System.Threading.Tasks.Task.Delay(1).Wait(); } _ = Local(); } }")]
    public void BlockingWaitsAreRejectedOnAsynchronousPaths(string source)
    {
        Assert.Contains(Scan(source, ProjectRole.Shell), finding => finding.Rule == "BAN-BLOCKING");
    }

    [Fact]
    public void TheBlockingRuleIsLimitedToAsynchronousPathsAsTheEngineDefinesThem()
    {
        // Documented engine scope: a synchronous start-up path may still wait. The Cloud host has no such call (see the real graph gate).
        Assert.Empty(Scan("class C { void M() { System.Threading.Tasks.Task.Delay(1).Wait(); } }", ProjectRole.Shell));
    }

    [Theory]
    [InlineData("Azure")]
    [InlineData("Amazon")]
    [InlineData("OpenAI")]
    [InlineData("Cloudflare")]
    public void ProviderSdkCallsAndConstructionAreRejectedBecauseCloudIsTheShellNotAnAdapter(string provider)
    {
        string call = $"namespace {provider}.Sdk {{ public static class Client {{ public static int Call() => 1; }} }} class C {{ int M() => {provider}.Sdk.Client.Call(); }}";
        string construction = $"namespace {provider}.Sdk {{ public sealed class Client {{ }} }} class C {{ object M() => new {provider}.Sdk.Client(); }}";
        Assert.Equal(ProjectRole.Shell, Assert.Single(CloudRepository.Classifications, project => project.Path == CloudRepository.Service).Role);
        Assert.Contains(Scan(call, ProjectRole.Shell), finding => finding.Rule == "BAN-PROVIDER");
        Assert.Contains(Scan(construction, ProjectRole.Shell), finding => finding.Rule == "BAN-PROVIDER");
        // The same code would be admitted inside an adapter project, which is why the service must not be classified as one.
        Assert.DoesNotContain(Scan(call, ProjectRole.PublicApiAdapter), finding => finding.Rule == "BAN-PROVIDER");
    }

    [Theory]
    [InlineData("class C { void M(string secret) { var value = secret; System.Console.WriteLine(value); } }")]
    [InlineData("class C { void M(string password) { System.Diagnostics.Debug.WriteLine(password); } }")]
    [InlineData("class C { void M(string credential) { System.Diagnostics.Trace.WriteLine(credential); } }")]
    [InlineData("class C { void M(string accessToken) { System.Console.WriteLine(\"token {0}\", accessToken); } }")]
    [InlineData("class C { void M(string prompt) { System.Console.Write(prompt); } }")]
    public void SecretAndContentValuesCannotReachLoggingCalls(string source)
    {
        Assert.Contains(Scan(source, ProjectRole.Shell), finding => finding.Rule == "BAN-LOGGING");
    }

    [Theory]
    [InlineData("class Price { float Cost() => 1f; }")]
    [InlineData("class C { double balance = 1d; }")]
    [InlineData("class C { double CreditTotal(double a) => a; }")]
    public void BinaryFloatingPointIsRejectedInMoneyPaths(string source)
    {
        Assert.Contains(Scan(source, ProjectRole.Shell), finding => finding.Rule == "BAN-MONEY");
    }

    [Theory]
    [InlineData("unsafe class C { internal int* Pointer; }")]
    [InlineData("class C { internal System.UIntPtr Handle; }")]
    public void RawNativePointerFieldsAreRejectedOutsideTheNativeLifetimeAdapter(string source)
    {
        Assert.Contains(Scan(source, ProjectRole.Shell), finding => finding.Rule == "BAN-POINTER");
        Assert.Contains(Scan(source, ProjectRole.NativeAdapter), finding => finding.Rule == "BAN-POINTER");
    }

    [Fact]
    public void UnresolvableInvocationsFailClosedInsteadOfBeingSkipped()
    {
        var compilation = FixtureCompiler.Create("Unresolved", new Dictionary<string, string> { ["fixture.cs"] = "class C { void M() { Missing(); } }" });
        Assert.Throws<InvalidOperationException>(() => BannedSymbolScanner.Scan(compilation, Project(ProjectRole.PublicApiAdapter, aot: true)));
    }

    private static List<PolicyFinding> Scan(string source, ProjectRole role, bool aot = true) =>
        [.. BannedSymbolScanner.Scan(Compile(source), Project(role, aot))];

    private static ProjectClassification Project(ProjectRole role, bool aot) => new("fixture.csproj", role, CloudRepository.Owner, Aot: aot);

    private static Microsoft.CodeAnalysis.CSharp.CSharpCompilation Compile(string source) =>
        FixtureCompiler.Compile("Fixture", new Dictionary<string, string> { ["fixture.cs"] = source });
}
