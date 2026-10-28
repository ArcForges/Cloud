// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Nodes;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Generation;
using ArcForges.Cloud.Ingress;
using ArcForges.Cloud.Tools.Generation;
using Xunit;

namespace ArcForges.Cloud.Tests.Generation;

/// <summary>
/// CLOUD.84 S34 and D2: the Worker's method table, its transport budgets and its edge guards are generated from the C# registrations.
/// These tests replace the TypeScript regex comparison with the C# host one-for-one: the committed table must be exactly what the
/// registrations generate, the anonymous and owner-scope rule is enforced where the policy is built, and every budget is in range.
/// AF-CTR-02 moved the production rows (the Hello method, the health route and their budgets) to the Go center's registrations,
/// generated into center-tables.generated.ts; the C# HelloModule stays as the proof environment's host and the Hello rollback, so
/// its production rows must still be exactly the rows the Go center generates (TheGoCenterProductionTableEqualsTheCSharpRegistrations).
/// </summary>
public sealed class GeneratedTablesTests
{
    private const string TablesPath = "worker/tables/cloud-tables.generated.ts";
    private const string CenterTablesPath = "worker/tables/center-tables.generated.ts";

    [Fact]
    public void CommittedWorkerTableIsExactlyWhatTheRegistrationsGenerate()
    {
        var committed = File.ReadAllText(Path.Combine(T.RepoRoot().FullName, TablesPath));
        Assert.Equal(TypeScriptTables.Render(HostReader.Read()), committed);
    }

    [Fact]
    public void TheGoCenterProductionTableEqualsTheCSharpRegistrations()
    {
        // The same values from their new source: the Go center generates the production rows; the C# rollback host must agree with
        // them byte for byte, so switching ARCFORGES_HELLO_RUNTIME changes no Worker behaviour.
        var center = File.ReadAllText(Path.Combine(T.RepoRoot().FullName, CenterTablesPath)).ReplaceLineEndings("\n");
        var production = TypeScriptTables.RenderProduction(HostReader.Read());
        Assert.EndsWith(production, center, StringComparison.Ordinal);
        Assert.Contains("export interface ApiRoute {", center, StringComparison.Ordinal);
        var proof = File.ReadAllText(Path.Combine(T.RepoRoot().FullName, TablesPath));
        Assert.DoesNotContain("productionRoutes", proof, StringComparison.Ordinal);
        Assert.Contains("import type { ApiRoute } from \"./center-tables.generated.ts\";", proof, StringComparison.Ordinal);
    }

    [Fact]
    public void GenerateCheckPassesOnTheCommittedOutputs()
    {
        Assert.Equal(0, ArcForges.Cloud.Tools.Generation.Program.Main(["check"]));
    }

    [Fact]
    public void ProductionServesExactlyTheAnonymousHelloMethodAndTheHealthRoute()
    {
        var model = HostReader.Read();
        Assert.Equal(new[] { "/arcforges.hello.v1.HelloService/SayHello" }, model.Production.Select(row => row.Path));
        var hello = model.Production[0];
        Assert.Equal("anonymous", hello.Auth);
        Assert.Equal("unary", hello.Kind);
        Assert.Equal("hello", hello.Instance);
        Assert.False(hello.RequestMeta);
        Assert.Equal(4096, hello.MaxRequestBytes);
        Assert.Equal("/api/healthz", model.HealthPath);
        Assert.Equal("/healthz", model.Health.Path);
        Assert.Equal("anonymous", model.Health.Auth);
    }

    [Fact]
    public void ProofMethodsAreSessionMethodsAndNeverAppearInTheProductionTable()
    {
        var model = HostReader.Read();
        Assert.Equal(3, model.Proof.Count);
        Assert.All(model.Proof, row => Assert.Equal("session", row.Auth));
        Assert.All(model.Proof, row => Assert.True(row.RequestMeta, row.Path));
        Assert.DoesNotContain(model.Production, row => row.Path.StartsWith("/arcforges.proof.", StringComparison.Ordinal));
    }

    [Fact]
    public void AnAnonymousMethodHasNoOwnerScope()
    {
        Assert.Throws<ArgumentException>(() =>
            RpcPolicy.Unary("/arcforges.test.v1.Probe/Ping", RpcAuthentication.Anonymous, RpcScope.Workspace));
        var registered = new HelloModule(new JsonObject()).RpcPolicies.Concat(PipelineProbe.Policies);
        foreach (var policy in registered)
        {
            Assert.False(policy.Authentication == RpcAuthentication.Anonymous && policy.Scope != RpcScope.None, policy.FullName);
        }
    }

    [Fact]
    public void EveryTransportBudgetIsWithinItsDeclaredLimits()
    {
        Assert.InRange(TransportBudgets.MaxBodyBytes, 1, RpcPolicy.AbsoluteMaxRequestBytes);
        Assert.InRange(TransportBudgets.ColdStartMilliseconds, 1, TransportBudgets.StreamLifetimeMilliseconds);
        foreach (var budget in TransportBudgets.ByMethod.Values)
        {
            Assert.InRange(budget.MaxFrameBytes, 1, 1_048_576);
            Assert.InRange(budget.MaxUnaryResponseBytes, 1, 1_048_576);
            Assert.InRange(budget.MaxDurationMilliseconds, 1, TransportBudgets.StreamLifetimeMilliseconds);
        }
    }

    [Fact]
    public void TheHelloRequestBoundIsTheBodyBoundTheWorkerApplies()
    {
        var model = HostReader.Read();
        Assert.Equal(TransportBudgets.MaxBodyBytes, model.MaxBodyBytes);
        Assert.Equal(TransportBudgets.StreamLifetimeMilliseconds, model.StreamLifetimeMilliseconds);
        Assert.Equal(TransportBudgets.ColdStartMilliseconds, model.ColdStartMilliseconds);
        Assert.Equal("__Host-af_session", model.SessionCookieName);
        Assert.Equal("x-af-csrf", model.CsrfHeader);
        Assert.Equal(IngressPipeline.SessionCookieName, model.SessionCookieName);
    }
}
