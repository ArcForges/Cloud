// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Tests.SharedFamilies;

/// <summary>
/// The fixture family of <c>Vectors/family-lock-order.json</c>, the same plan the TypeScript generator tests generate from SQL and
/// the SQLite oracle runs. Here it is rebuilt from the vector's roles and parameter kinds, so the C# engine is exercised on exactly
/// the statement shape the generator produced.
/// </summary>
internal static class FamilyFixture
{
    public const string Workspace = "0198a7c0-1c3e-7d4a-9b1f-0000000a0001";
    public const string User = "0198a7c0-1c3e-7d4a-9b1f-0000000a0002";
    public const string Job = "0198a7c0-1c3e-7d4a-9b1f-0000000a0003";
    public const string ConfigRevision = "0198a7c0-1c3e-7d4a-9b1f-0000000a0004";
    public const string PolicyTarget = "0198a7c0-1c3e-7d4a-9b1f-0000000a0005";
    public const long NowMicros = 1_790_000_000_000_000;

    private static readonly Lazy<JsonDocument> Document = new(() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "tests", "ArcForges.Cloud.Tests", "Vectors", "family-lock-order.json"))));

    public static JsonElement Vectors => Document.Value.RootElement;

    public static FamilyStatementRole ParseRole(string text, out bool known)
    {
        var parts = text.Split(' ');
        known = ModuleLockOrder.TryFromOwner(parts[1], out var module);
        var phase = Enum.Parse<FamilyPhase>(parts[0], ignoreCase: true);
        var kind = Enum.Parse<FamilyClass>(parts[2], ignoreCase: true);
        return new FamilyStatementRole(module, phase, kind, parts[3]);
    }

    public static PlanParam ParseKind(string kind) => new(kind switch
    {
        "text" => PlanKind.Text,
        "int64" => PlanKind.Int64,
        "uint64" => PlanKind.Uint64,
        "decimal" => PlanKind.Decimal,
        "bytes" => PlanKind.Bytes,
        "bool" => PlanKind.Bool,
        "scope" => PlanKind.Scope,
        _ => throw new InvalidOperationException(kind),
    });

    public static FamilyDefinition Definition()
    {
        var plan = Vectors.GetProperty("fixturePlan");
        return new FamilyDefinition(
            plan.GetProperty("family").GetString()!,
            "Fixture family",
            "test vector",
            plan.GetProperty("participants").EnumerateArray()
                .Select(participant =>
                {
                    ModuleLockOrder.TryFromOwner(participant.GetProperty("module").GetString()!, out var module);
                    var required = participant.GetProperty("required").GetBoolean();
                    return new FamilyParticipant(module, required, required ? null : "when it applies");
                })
                .ToArray());
    }

    public static FamilyPlanDefinition Plan()
    {
        var plan = Vectors.GetProperty("fixturePlan");
        var statements = plan.GetProperty("statements").EnumerateArray().ToArray();
        var roles = statements.Select(statement => ParseRole(statement.GetProperty("role").GetString()!, out _)).ToArray();
        var definition = new PlanDefinition(
            plan.GetProperty("id").GetString()!,
            1,
            PlanAccess.Write,
            0,
            statements.Select(statement => new PlanStatement(statement.GetProperty("params").EnumerateArray().Select(kind => ParseKind(kind.GetString()!)).ToArray(), null)).ToArray());
        return new FamilyPlanDefinition(definition, plan.GetProperty("family").GetString()!, roles);
    }

    /// <summary>Every contribution of the fixture plan built through the typed primitives, in an arbitrary (not plan) order.</summary>
    public static IReadOnlyList<FamilyContribution> Contributions(Guid command, long revision = 7, long budgetRevision = 3, long used = 10, long held = 2)
    {
        var workspace = D1Values.Text(Workspace);
        return
        [
            FamilyGuards.Mutation(FamilyModule.Platform, FamilyClass.Record, "receipt", [D1Values.Text(command.ToString("D")), workspace, D1Values.Text("actor"), D1Values.Text("fixture.commit"), D1Values.Text("hash"), D1Values.Int64(2), D1Values.Int64(revision + 1), D1Values.Int64(NowMicros), D1Values.Int64(NowMicros + 86_400_000_000)]),
            FamilyGuards.Mutation(FamilyModule.Notification, FamilyClass.Record, "suppression", [D1Values.Text("recipient"), D1Values.Int64(1), D1Values.Int64(1), D1Values.Int64(NowMicros)]),
            FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Record, "revision", [D1Values.Int64(NowMicros), workspace]),
            FamilyGuards.Mutation(FamilyModule.Entitlement, FamilyClass.Bucket, "quota", [D1Values.Int64(used + 3), D1Values.Int64(held), D1Values.Int64(1), workspace, D1Values.Text("storage"), D1Values.Text("gauge")]),
            FamilyGuards.Revision(FamilyModule.Notification, "suppression", [D1Values.Text("recipient"), D1Values.Int64(1)], 0),
            FamilyGuards.Policy(FamilyModule.Policy, "source-policy", [workspace, D1Values.Text("project"), D1Values.Text(PolicyTarget)], [D1Values.Int64(4)]),
            FamilyGuards.Balance(FamilyModule.Entitlement, "quota", [D1Values.Int64(1), workspace, D1Values.Text("storage"), D1Values.Text("gauge")], budgetRevision, [D1Values.Int64(used), D1Values.Int64(held)]),
            FamilyGuards.Revision(FamilyModule.Entitlement, "workspace-revision", [workspace], revision),
            FamilyGuards.Authorization(FamilyModule.Workspace, "owner", [workspace], [D1Values.Text(User), D1Values.Int64(1)]),
            FamilyGuards.Policy(FamilyModule.Configuration, "active-config", [D1Values.Text(ConfigRevision)], [D1Values.Int64(2), D1Values.Bytes(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray())]),
            FamilyGuards.Lease(FamilyModule.Platform, "job-lease", [D1Values.Text(Job)], "container-a", 5, NowMicros),
        ];
    }

    public static FamilyUnitOfWork Unit(Guid? command = null, ulong generation = 0, string scope = Workspace)
    {
        var id = command ?? Guid.NewGuid();
        var unit = FamilyUnitOfWork.Begin(Plan(), id, scope, generation, Definition());
        foreach (var contribution in Contributions(id)) unit.Contribute(contribution);
        return unit;
    }

    public static string Text(D1Scalar scalar) => D1Values.TryGetText(scalar, out var value) ? value : throw new InvalidOperationException("not text");

    public static long Int(D1Scalar scalar) => D1Values.TryGetInt64(scalar, out var value) ? value : throw new InvalidOperationException("not int64");

    /// <summary>A comparable text of one scalar: its kind and exact value.</summary>
    public static string Render(D1Scalar scalar) => scalar switch
    {
        D1ScalarD1TextValue text => "text:" + text.Value.Value,
        D1ScalarD1Int64Value number => "int64:" + number.Value.Value,
        D1ScalarD1BytesValue bytes => "bytes:" + bytes.Value.Value,
        D1ScalarD1NullValue => "null",
        _ => scalar.GetType().Name,
    };

    public static string Format(long value) => value.ToString(CultureInfo.InvariantCulture);
}

/// <summary>A plan bridge the test scripts: each call is recorded and answered (or failed) by the script.</summary>
internal sealed class ScriptedExecutor : IPlanExecutor
{
    private readonly Func<PlanCall, int, PlanResult> script;

    public ScriptedExecutor(Func<PlanCall, int, PlanResult> script) => this.script = script;

    public List<PlanCall> Calls { get; } = [];

    public static ScriptedExecutor Failing(params PlanFailureKind?[] sequence) => new((_, call) =>
        sequence[Math.Min(call, sequence.Length) - 1] is { } kind ? throw new PlanFailureException(kind) : new PlanResult([], 12));

    public Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
    {
        Calls.Add(call);
        return Task.FromResult(script(call, Calls.Count));
    }
}
