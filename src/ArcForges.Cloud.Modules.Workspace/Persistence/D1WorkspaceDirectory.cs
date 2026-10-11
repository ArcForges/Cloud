// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Modules.Workspace.Persistence;

/// <summary>The named read plans of the Workspace owner (<c>storage/plans/workspace</c>); the only strings this module hands to the plan port.</summary>
internal static class WorkspacePlans
{
    public const string Get = "workspace.workspace-get";
    public const string ByOwner = "workspace.workspace-by-owner";

    /// <summary>The columns every workspace read returns, in plan order.</summary>
    public const int ColumnCount = 9;
}

/// <summary>
/// The production <see cref="IWorkspaceDirectory"/>: the Workspace module's own reads over D1, written only against the Abstractions plan
/// port (a module reaches storage through its own named plans and nothing else). Every read is scoped by realm; the read by identifier
/// binds the workspace identifier as the owner scope. A stored row is decoded strictly: a column of the wrong kind, an identifier that is
/// not the one asked for, or a value outside the data model's closed lists is a defect and is never returned as a workspace.
/// </summary>
internal sealed partial class D1WorkspaceDirectory(IModulePlanPort plans) : IWorkspaceDirectory
{
    /// <summary>The protection profiles the data model admits (<c>workspace_workspace.protection_profile IN (1)</c>).</summary>
    private static readonly long[] KnownProtectionProfiles = [1];

    public async ValueTask<WorkspaceDirectoryResult> FindAsync(string realmId, string workspaceId, CancellationToken cancellationToken)
    {
        if (!IsCanonical(realmId) || !IsCanonical(workspaceId)) return Invalid();
        var outcome = await plans.ReadAsync(
            new ModulePlanRead(WorkspacePlans.Get, workspaceId, [PlanValue.FromText(realmId), PlanValue.FromText(workspaceId)]), cancellationToken).ConfigureAwait(false);
        return Decode(outcome, realmId, workspaceId, ownerUserId: null);
    }

    public async ValueTask<WorkspaceDirectoryResult> FindByOwnerAsync(string realmId, string ownerUserId, CancellationToken cancellationToken)
    {
        if (!IsCanonical(realmId) || !IsCanonical(ownerUserId)) return Invalid();

        // The plan carries no scope parameter (a realm-level read, S54(6)); the realm names the call.
        var outcome = await plans.ReadAsync(
            new ModulePlanRead(WorkspacePlans.ByOwner, realmId, [PlanValue.FromText(realmId), PlanValue.FromText(ownerUserId)]), cancellationToken).ConfigureAwait(false);
        return Decode(outcome, realmId, workspaceId: null, ownerUserId);
    }

    internal static bool IsCanonical([NotNullWhen(true)] string? value) => value is not null && Canonical().IsMatch(value);

    private static WorkspaceDirectoryResult Decode(ModulePlanOutcome outcome, string realmId, string? workspaceId, string? ownerUserId)
    {
        switch (outcome.Status)
        {
            case ModulePlanStatus.Succeeded:
                break;
            case ModulePlanStatus.Unavailable or ModulePlanStatus.StaleGeneration:
                return new(WorkspaceDirectoryStatus.Unavailable, null, "The workspace read was not served: " + outcome.Status + ".");
            default:
                return Defect("The workspace read was refused: " + outcome.Status + ".");
        }

        if (outcome.Rows.Count == 0) return new(WorkspaceDirectoryStatus.NotFound, null, null);
        if (outcome.Rows.Count > 1) return Defect("The workspace read returned more than one row.");
        var record = Read(outcome.Rows[0]);
        if (record is null) return Defect("The stored workspace row cannot be interpreted.");
        if (!string.Equals(record.RealmId, realmId, StringComparison.Ordinal)
            || (workspaceId is not null && !string.Equals(record.WorkspaceId, workspaceId, StringComparison.Ordinal))
            || (ownerUserId is not null && !string.Equals(record.OwnerUserId, ownerUserId, StringComparison.Ordinal)))
        {
            return Defect("The workspace read returned a row that was not asked for.");
        }

        return new(WorkspaceDirectoryStatus.Found, record, null);
    }

    /// <summary>The record of one row, or null when any column is not exactly what the data model stores.</summary>
    internal static WorkspaceRecord? Read(IReadOnlyList<PlanValue> row)
    {
        if (row.Count != WorkspacePlans.ColumnCount) return null;
        if (!Identifier(row[0], out var workspace) || !Identifier(row[1], out var realm) || !Identifier(row[2], out var owner)) return null;
        if (row[3].Kind != PlanValueKind.Text || row[4].Kind != PlanValueKind.Text) return null;
        if (row[5].Kind != PlanValueKind.Int64 || row[6].Kind != PlanValueKind.Int64 || row[7].Kind != PlanValueKind.Int64 || row[8].Kind != PlanValueKind.Int64) return null;
        var profile = row[5].AsInt64();
        if (Array.IndexOf(KnownProtectionProfiles, profile) < 0) return null;
        WorkspaceRecordState? state = row[6].AsInt64() switch
        {
            1 => WorkspaceRecordState.Active,
            2 => WorkspaceRecordState.Suspended,
            3 => WorkspaceRecordState.PendingDeletion,
            _ => null,
        };
        var createdAt = row[7].AsInt64();
        var revision = row[8].AsInt64();
        if (state is null || createdAt < 0 || revision < 0) return null;
        return new WorkspaceRecord(workspace, realm, owner, row[3].AsText(), row[4].AsText(), profile, state.Value, createdAt, revision);
    }

    private static bool Identifier(PlanValue value, [NotNullWhen(true)] out string? text)
    {
        text = value.Kind == PlanValueKind.Text && IsCanonical(value.AsText()) ? value.AsText() : null;
        return text is not null;
    }

    private static WorkspaceDirectoryResult Invalid() =>
        new(WorkspaceDirectoryStatus.InvalidRequest, null, "A realm, workspace or owner identifier is a canonical lower-case UUID.");

    private static WorkspaceDirectoryResult Defect(string detail) => new(WorkspaceDirectoryStatus.Defect, null, detail);

    // \z, not $: a trailing line feed is not part of a canonical identifier.
    [GeneratedRegex(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Canonical();
}
