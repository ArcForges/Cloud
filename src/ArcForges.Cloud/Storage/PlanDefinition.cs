// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage;

/// <summary>Typed bind and result kinds of a reviewed named plan.</summary>
internal enum PlanKind
{
    Int64,
    Uint64,
    Decimal,
    Text,
    Bytes,
    Bool,
    /// <summary>A text parameter that must equal the request owner scope.</summary>
    Scope,
}

internal enum PlanAccess
{
    Read,
    Write,
}

internal readonly record struct PlanParam(PlanKind Kind, bool Nullable = false);

internal sealed record PlanStatement(IReadOnlyList<PlanParam> Params, IReadOnlyList<PlanParam>? Returns);

/// <summary>One versioned named plan; the generated manifest binds the SQL by hash to the Worker dictionary.</summary>
internal sealed record PlanDefinition(
    string Id,
    int Version,
    PlanAccess Access,
    int MaxRows,
    IReadOnlyList<PlanStatement> Statements);
