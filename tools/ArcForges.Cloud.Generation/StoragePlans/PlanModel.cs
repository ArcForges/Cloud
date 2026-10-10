// SPDX-License-Identifier: AGPL-3.0-only
// The data model of the storage-plan generator (CLOUD.84 U7, D3): the reviewed named plans, the owner and family registries and the
// physical columns the guard primitives are expanded against. The generator is a non-published tool; these types never ship.
namespace ArcForges.Cloud.Tools.Generation.StoragePlans;

/// <summary>A plan, registry or manifest input is refused. The message names the file and the rule, as the Node generator did.</summary>
public sealed class PlanRefusal(string message) : Exception(message);

/// <summary>One bound or returned column: the kind name (int64, uint64, decimal, text, bytes, bool or scope) and nullability.</summary>
public readonly record struct PlanParameter(string Kind, bool Nullable);

/// <summary>The role of a family statement in its guarded batch (SU-04).</summary>
public sealed record FamilyStatementMeta(string Module, string Phase, string Class, string Key);

/// <summary>One statement of a plan. <see cref="Returns"/> is null for every statement except the one a read plan returns rows from.</summary>
public sealed record PlanStatement(
    string Sql,
    IReadOnlyList<PlanParameter> Params,
    IReadOnlyList<PlanParameter>? Returns,
    FamilyStatementMeta? Family = null);

/// <summary>One versioned plan with the identity the manifest hashes. <see cref="Family"/> is set only for shared family plans.</summary>
public sealed record PlanDefinition(
    string Id,
    int Version,
    string Access,
    int MaxRows,
    IReadOnlyList<PlanStatement> Statements,
    string Sha256,
    string? Tail,
    string? Family);

public sealed record PlanOwner(string Owner, string ClassName, string Kind, string TablePrefix);

public sealed record OwnerRegistry(IReadOnlyList<PlanOwner> Owners);

/// <summary>A module that may take part in a family. A conditional participant states the condition.</summary>
public sealed record FamilyParticipant(string Module, string Requirement, string? When);

public sealed record FamilyDefinition(string Family, string Title, string Source, IReadOnlyList<FamilyParticipant> Participants);

public sealed record FamilyRegistry(IReadOnlyList<FamilyDefinition> Families);

/// <summary>The whole plan set in manifest order, with the one SHA-256 identity both sides compare.</summary>
public sealed record PlanManifest(
    string ManifestHash,
    IReadOnlyList<PlanDefinition> Plans,
    OwnerRegistry Registry,
    FamilyRegistry Families);

/// <summary>A physical column as the guard primitives see it: its name and its logical kind (physical-schema.ts PhysicalKind).</summary>
public sealed record PhysicalColumnInfo(string Name, string Kind);

public sealed record PhysicalTableInfo(string Name, IReadOnlyList<PhysicalColumnInfo> Columns);

/// <summary>The physical tables of every committed manifest file, with the money and aggregate columns expanded.</summary>
public sealed record PhysicalManifest(IReadOnlyList<PhysicalTableInfo> Tables);
