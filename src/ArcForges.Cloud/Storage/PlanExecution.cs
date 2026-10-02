// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage;

internal enum PlanFailureKind
{
    InvalidPlan,
    StaleGeneration,
    Precondition,
    Constraint,
    Overloaded,
    Unavailable,
    UnknownOutcome,
    ManifestMismatch,
    Transport,
}

/// <summary>A refused or failed plan; the message never carries SQL, values or transport text.</summary>
internal sealed class PlanFailureException(PlanFailureKind kind) : Exception("Storage plan failed: " + kind)
{
    public PlanFailureKind Kind { get; } = kind;
}

/// <summary>One plan invocation: arguments per statement, the owner scope and the recovery generation it must match.</summary>
internal sealed record PlanCall(
    PlanDefinition Plan,
    D1Scalar[][] Arguments,
    string OwnerScope,
    Guid RequestId,
    ulong RecoveryGeneration,
    TimeSpan? Timeout = null)
{
    public static PlanCall New(PlanDefinition plan, string ownerScope, ulong recoveryGeneration, D1Scalar[][] arguments) =>
        new(plan, arguments, ownerScope, Guid.NewGuid(), recoveryGeneration);
}

internal sealed record PlanResult(IReadOnlyList<IReadOnlyList<D1Scalar>> Rows, ulong Changes);

internal interface IPlanExecutor
{
    /// <summary>Executes one plan once; there is no automatic retry anywhere on this path.</summary>
    Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken);
}

/// <summary>Argument and result checks against the typed plan definition, shared by the executor and test doubles.</summary>
internal static class PlanArguments
{
    public const int MaxTextLength = 262144;
    public const int MaxBytesLength = 262144;

    /// <summary>Counts, kinds, nullability, exact numeric forms and the scope rule; throws InvalidPlan before anything is sent.</summary>
    public static void Validate(PlanCall call)
    {
        var plan = call.Plan;
        if (call.OwnerScope.Length is 0 or > 256 || call.RequestId == Guid.Empty || call.Arguments.Length != plan.Statements.Count)
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        for (var statement = 0; statement < plan.Statements.Count; statement++)
        {
            var parameters = plan.Statements[statement].Params;
            var arguments = call.Arguments[statement];
            if (arguments.Length != parameters.Count) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
            for (var index = 0; index < parameters.Count; index++)
            {
                if (!Matches(arguments[index], parameters[index], call.OwnerScope)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
            }
        }
    }

    private static bool Matches(D1Scalar? scalar, PlanParam param, string ownerScope)
    {
        if (scalar is null) return false;
        if (D1Values.IsNull(scalar)) return param.Nullable && param.Kind != PlanKind.Scope;
        return param.Kind switch
        {
            PlanKind.Int64 => D1Values.TryGetInt64(scalar, out _),
            PlanKind.Uint64 => D1Values.TryGetUint64(scalar, out _),
            PlanKind.Decimal => D1Values.TryGetDecimal(scalar, out _),
            PlanKind.Text => D1Values.TryGetText(scalar, out var text) && ValidText(text),
            PlanKind.Scope => D1Values.TryGetText(scalar, out var scope) && string.Equals(scope, ownerScope, StringComparison.Ordinal),
            PlanKind.Bytes => D1Values.TryGetBytes(scalar, out var bytes) && bytes.Length <= MaxBytesLength,
            PlanKind.Bool => D1Values.TryGetBool(scalar, out _),
            _ => false,
        };
    }

    /// <summary>Text is bounded and free of unpaired surrogates, which JSON cannot carry.</summary>
    public static bool ValidText(string text)
    {
        if (text.Length > MaxTextLength) return false;
        for (var index = 0; index < text.Length; index++)
        {
            if (char.IsHighSurrogate(text[index]))
            {
                if (++index == text.Length || !char.IsLowSurrogate(text[index])) return false;
            }
            else if (char.IsLowSurrogate(text[index])) return false;
        }

        return true;
    }

    /// <summary>The returned rows must match the plan's declared result kinds and its row bound.</summary>
    public static bool RowsMatch(PlanDefinition plan, IReadOnlyList<IReadOnlyList<D1Scalar>> rows)
    {
        var returns = plan.Statements.FirstOrDefault(s => s.Returns is not null)?.Returns;
        if (returns is null) return rows.Count == 0;
        if (rows.Count > plan.MaxRows) return false;
        foreach (var row in rows)
        {
            if (row.Count != returns.Count) return false;
            for (var index = 0; index < returns.Count; index++)
            {
                if (!Matches(row[index], returns[index], "")) return false;
            }
        }

        return true;
    }
}
