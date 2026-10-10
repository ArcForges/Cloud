// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections;
using System.Reflection;
using System.Text.Json.Nodes;

namespace ArcForges.Cloud.Tools.Generation;

/// <summary>One public method as the Worker's table lists it: the fields of worker/ingress/routes.ts ApiRoute.</summary>
public sealed record RouteRow(
    string Path,
    string Kind,
    string Auth,
    int MaxRequestBytes,
    int MaxFrameBytes,
    int MaxUnaryResponseBytes,
    int MaxDurationMilliseconds,
    string Instance,
    bool RequestMeta);

/// <summary>The correlation guards of the Worker (CR-01, CR-03): the identity shape, where it lives in a request and the traceparent form.</summary>
public sealed record CorrelationGuardRow(
    string UuidPattern,
    string NilUuid,
    int RequestMetaField,
    int CorrelationIdField,
    int IdValueField,
    int IdByteLength,
    string TraceparentVersion,
    string TraceparentFlags);

/// <summary>One declared binding of the readiness vocabulary: the component, the name and the environments that declare it.</summary>
public sealed record ReadinessBindingRow(string Component, string Name, IReadOnlyList<string> Environments);

/// <summary>The readiness vocabulary the Worker names (WP-21.07, cloud.readiness.v1; CLOUD.84 S34 and S39(1)), read from ReadinessVocabulary.</summary>
public sealed record ReadinessRow(
    string Schema,
    int RetryAfterSeconds,
    int WaitMilliseconds,
    IReadOnlyList<string> Environments,
    IReadOnlyList<string> Components,
    IReadOnlyList<string> States,
    IReadOnlyList<string> Statuses,
    IReadOnlyList<string> RetryableStatuses,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> KeyBindings,
    IReadOnlyList<string> ProbeOutcomes,
    IReadOnlyList<ReadinessBindingRow> Bindings);

/// <summary>Everything the Worker's transport tables are generated from, read from the C# host and its declarations.</summary>
public sealed record TableModel(
    string HelloPath,
    string HealthPath,
    RouteRow Health,
    IReadOnlyList<RouteRow> Production,
    IReadOnlyList<RouteRow> Proof,
    int MaxBodyBytes,
    int ColdStartMilliseconds,
    int StreamLifetimeMilliseconds,
    string SessionCookieName,
    string CsrfHeader,
    CorrelationGuardRow Correlation,
    ReadinessRow Readiness);

/// <summary>
/// Reads the transport tables by reflection over the host's registrations: HelloModule (the production policies and the plain health
/// path), PipelineProbe (the proof policies, registered only when the foundation proof is enabled) and the declarations in
/// ArcForges.Cloud.Generation.TransportBudgets. The reading is fail-closed: a registered method without a budget, a budget that names no
/// registered method, a missing declaration or a health path other than /healthz stops the generator instead of producing a partial table.
/// </summary>
public static class HostReader
{
    private const string HelloModuleType = "ArcForges.Cloud.Composition.HelloModule";
    private const string PipelineProbeType = "ArcForges.Cloud.Ingress.PipelineProbe";
    private const string IngressPipelineType = "ArcForges.Cloud.Ingress.IngressPipeline";
    private const string BudgetsType = "ArcForges.Cloud.Generation.TransportBudgets";
    private const string GuardsType = "ArcForges.Cloud.Generation.CorrelationGuards";
    private const string ApiPrefix = "/api";
    private const string HelloMethod = "/arcforges.hello.v1.HelloService/SayHello";
    private const BindingFlags AnyMember = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;

    /// <summary>Reads the model from the ArcForges.Cloud assembly this tool references.</summary>
    public static TableModel Read()
    {
        var assembly = typeof(ArcForges.Cloud.HelloEndpoint).Assembly;
        var budgets = LoadType(assembly, BudgetsType);
        var declared = DeclaredBudgets(budgets);

        var hello = CreateHelloModule(assembly);
        var helloType = hello.GetType();
        var production = Routes(Enumerate(Member(hello, helloType, "RpcPolicies")), declared, "production");
        var proof = Routes(Enumerate(Member(null, LoadType(assembly, PipelineProbeType), "Policies")), declared, "proof");

        var used = production.Concat(proof).Select(row => row.Path).ToHashSet(StringComparer.Ordinal);
        foreach (var name in declared.Keys)
        {
            if (!used.Contains(name)) throw new InvalidOperationException($"The transport budget {name} names no registered method.");
        }

        var plainPaths = Enumerate(Member(hello, helloType, "PlainPaths")).Select(item => (string)item).ToList();
        if (plainPaths.Count != 1 || plainPaths[0] != "/healthz")
            throw new InvalidOperationException("The Hello module must declare exactly one plain health path, /healthz.");
        var health = new RouteRow(
            Path: "/healthz",
            Kind: "unary",
            Auth: "anonymous",
            MaxRequestBytes: 0,
            MaxFrameBytes: 0,
            MaxUnaryResponseBytes: Constant(budgets, "HealthMaxUnaryResponseBytes"),
            MaxDurationMilliseconds: Constant(budgets, "HealthMaxDurationMilliseconds"),
            Instance: Text(budgets, "HealthInstance"),
            RequestMeta: false);

        var maxBodyBytes = Constant(budgets, "MaxBodyBytes");
        var helloRow = production.SingleOrDefault(row => row.Path == HelloMethod)
            ?? throw new InvalidOperationException("The production table must serve the Hello method.");
        if (helloRow.MaxRequestBytes != maxBodyBytes)
            throw new InvalidOperationException("TransportBudgets.MaxBodyBytes must equal the Hello policy's request bound.");

        var ingress = LoadType(assembly, IngressPipelineType);
        var guards = LoadType(assembly, GuardsType);
        return new TableModel(
            HelloPath: ApiPrefix + helloRow.Path,
            HealthPath: ApiPrefix + health.Path,
            Health: health,
            Production: production,
            Proof: proof,
            MaxBodyBytes: maxBodyBytes,
            ColdStartMilliseconds: Constant(budgets, "ColdStartMilliseconds"),
            StreamLifetimeMilliseconds: Constant(budgets, "StreamLifetimeMilliseconds"),
            SessionCookieName: Text(ingress, "SessionCookieName"),
            CsrfHeader: Text(ingress, "CsrfHeader").ToLowerInvariant(),
            Readiness: ReadReadiness(assembly),
            Correlation: new CorrelationGuardRow(
                UuidPattern: Text(guards, "UuidPattern"),
                NilUuid: Text(guards, "NilUuid"),
                RequestMetaField: Constant(guards, "RequestMetaField"),
                CorrelationIdField: Constant(guards, "CorrelationIdField"),
                IdValueField: Constant(guards, "IdValueField"),
                IdByteLength: Constant(guards, "IdByteLength"),
                TraceparentVersion: Text(guards, "TraceparentVersion"),
                TraceparentFlags: Text(guards, "TraceparentFlags")));
    }

    private const string ReadinessVocabularyType = "ArcForges.Cloud.Readiness.ReadinessVocabulary";

    /// <summary>Reads the readiness vocabulary and its binding declarations; a missing member stops the generator.</summary>
    private static ReadinessRow ReadReadiness(Assembly assembly)
    {
        var vocabulary = LoadType(assembly, ReadinessVocabularyType);
        var bindings = Enumerate(Member(null, vocabulary, "Bindings")).Select(item =>
        {
            var itemType = item.GetType();
            return new ReadinessBindingRow(Text(item, itemType, "Component"), Text(item, itemType, "Name"), Strings(Member(item, itemType, "Environments")));
        }).ToList();
        return new ReadinessRow(
            Schema: Text(vocabulary, "Schema"),
            RetryAfterSeconds: Constant(vocabulary, "RetryAfterSeconds"),
            WaitMilliseconds: Constant(vocabulary, "ReadinessWaitMilliseconds"),
            Environments: Strings(Member(null, vocabulary, "Environments")),
            Components: Strings(Member(null, vocabulary, "Components")),
            States: Strings(Member(null, vocabulary, "States")),
            Statuses: Strings(Member(null, vocabulary, "Statuses")),
            RetryableStatuses: Strings(Member(null, vocabulary, "RetryableStatuses")),
            Evidence: Strings(Member(null, vocabulary, "Evidence")),
            Reasons: Strings(Member(null, vocabulary, "Reasons")),
            KeyBindings: Strings(Member(null, vocabulary, "KeyBindings")),
            ProbeOutcomes: Strings(Member(null, vocabulary, "ProbeOutcomes")),
            Bindings: bindings);
    }

    private static IReadOnlyList<string> Strings(object value) => Enumerate(value).Select(item => (string)item).ToList();

    private static Type LoadType(Assembly assembly, string name) =>
        assembly.GetType(name, throwOnError: true) ?? throw new InvalidOperationException($"Missing type {name}.");

    private static object CreateHelloModule(Assembly assembly)
    {
        var type = LoadType(assembly, HelloModuleType);
        var constructor = type.GetConstructors(AnyMember).Single(candidate => candidate.GetParameters().Length == 1);
        // The identity is read only when the host maps its endpoints; the policies and the plain paths need no identity.
        return constructor.Invoke([new JsonObject()]);
    }

    private static IReadOnlyList<RouteRow> Routes(IEnumerable<object> policies, IReadOnlyDictionary<string, object> declared, string table)
    {
        var rows = new List<RouteRow>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var policy in policies)
        {
            var policyType = policy.GetType();
            var name = Text(policy, policyType, "FullName");
            if (!names.Add(name)) throw new InvalidOperationException($"Duplicate {table} policy {name}.");
            if (!declared.TryGetValue(name, out var budget))
                throw new InvalidOperationException($"The {table} method {name} has no transport budget in TransportBudgets.ByMethod.");
            var budgetType = budget.GetType();
            rows.Add(new RouteRow(
                Path: name,
                Kind: KindName(Member(policy, policyType, "Kind").ToString()),
                Auth: AuthName(Member(policy, policyType, "Authentication").ToString()),
                MaxRequestBytes: Constant(policy, policyType, "MaxRequestBytes"),
                MaxFrameBytes: Constant(budget, budgetType, "MaxFrameBytes"),
                MaxUnaryResponseBytes: Constant(budget, budgetType, "MaxUnaryResponseBytes"),
                MaxDurationMilliseconds: Constant(budget, budgetType, "MaxDurationMilliseconds"),
                Instance: Text(budget, budgetType, "Instance"),
                RequestMeta: (bool)Member(policy, policyType, "ReadsRequestMeta")));
        }

        if (rows.Count == 0) throw new InvalidOperationException($"The {table} table is empty.");
        return rows;
    }

    private static string KindName(string? kind) => kind switch
    {
        "Unary" => "unary",
        "ServerStream" => "serverStream",
        _ => throw new InvalidOperationException($"Unsupported RPC kind {kind}."),
    };

    private static string AuthName(string? authentication) => authentication switch
    {
        "Anonymous" => "anonymous",
        "Session" => "session",
        _ => throw new InvalidOperationException($"Unsupported authentication {authentication}."),
    };

    /// <summary>The declared budgets by method path, read from the public static dictionary of the declarations.</summary>
    private static Dictionary<string, object> DeclaredBudgets(Type budgets)
    {
        var result = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var pair in Enumerate(Member(null, budgets, "ByMethod")))
        {
            var pairType = pair.GetType();
            result.Add((string)Member(pair, pairType, "Key"), Member(pair, pairType, "Value"));
        }

        return result;
    }

    private static IEnumerable<object> Enumerate(object value) => ((IEnumerable)value).Cast<object>();

    private static int Constant(Type type, string name) => (int)Member(null, type, name);

    private static int Constant(object target, Type type, string name) => (int)Member(target, type, name);

    private static string Text(Type type, string name) => (string)Member(null, type, name);

    private static string Text(object target, Type type, string name) => (string)Member(target, type, name);

    private static object Member(object? target, Type type, string name)
    {
        var property = type.GetProperty(name, AnyMember);
        if (property is not null)
            return property.GetValue(target) ?? throw new InvalidOperationException($"{type.FullName}.{name} is null.");
        var field = type.GetField(name, AnyMember) ?? throw new InvalidOperationException($"Missing {type.FullName}.{name}.");
        return field.GetValue(target) ?? throw new InvalidOperationException($"{type.FullName}.{name} is null.");
    }
}
