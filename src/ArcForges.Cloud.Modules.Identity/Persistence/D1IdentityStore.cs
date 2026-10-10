// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;

namespace ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;

/// <summary>
/// The production <see cref="IIdentityStore"/>: the Identity module's persistence over D1, written only against the Abstractions ports (a
/// module reaches storage through named plans of its own owner and nothing else). It names no SQL and no table.
/// <list type="bullet">
/// <item>Reads: the Identity read plans through the module's plan port, every one scoped by realm (the realm is also the owner scope of
/// these realm-level reads); a credential lookup is the one statement <c>identity.credential-get</c>, so the credential and its user are
/// read at one moment. Workspaces are read through the Workspace module's published directory, because each module reads only its own
/// tables.</item>
/// <item>Commits: the arguments and the tail are exactly what IdentityStatements builds (the shared vector holds them byte for byte). A
/// module write plan goes through the plan port, an enrollment through the family port as the family <c>account-enrollment</c>; the
/// commit context gives the instant from the clock, a random outbox identifier, the command identifier as the correlation (no edge
/// correlation reaches the module yet) and change-record schema version 1.</item>
/// <item>Outcomes: a false guard is <see cref="CommitOutcome.Refused"/>; a key collision of a random identifier (the credential identifier of
/// an added credential, or a user identifier held in another realm) is refused the same way so the service retries with fresh identifiers;
/// a replay, a reused identifier, an expired receipt and an unknown outcome are the typed outcomes of the receipt. An unavailable store
/// throws <see cref="IdentityStoreFailure.Unavailable"/>; anything else (a refused plan, a constraint of another commit, an undecodable row)
/// throws <see cref="IdentityStoreFailure.Defect"/>. Nothing is coerced, and no message carries a value.</item>
/// </list>
/// </summary>
internal sealed class D1IdentityStore : IIdentityStore
{
    /// <summary>The version of the Identity change records: the schema version the change archive stores for every Identity commit.</summary>
    public const long ChangeRecordSchemaVersion = 1;

    private readonly IModulePlanPort plans;
    private readonly IModuleFamilyPort families;
    private readonly IWorkspaceDirectory workspaces;
    private readonly Func<IdentityCommit, CommitContext> context;

    public D1IdentityStore(IModulePlanPort plans, IModuleFamilyPort families, IWorkspaceDirectory workspaces, IIdentityIdSource ids, TimeProvider time)
        : this(plans, families, workspaces, ProductionContext(ids, time))
    {
    }

    /// <summary>The commit context is a parameter so that a test can hold the store to the shared vector's fixed context.</summary>
    internal D1IdentityStore(IModulePlanPort plans, IModuleFamilyPort families, IWorkspaceDirectory workspaces, Func<IdentityCommit, CommitContext> context)
    {
        this.plans = plans ?? throw new ArgumentNullException(nameof(plans));
        this.families = families ?? throw new ArgumentNullException(nameof(families));
        this.workspaces = workspaces ?? throw new ArgumentNullException(nameof(workspaces));
        this.context = context ?? throw new ArgumentNullException(nameof(context));
    }

    private static Func<IdentityCommit, CommitContext> ProductionContext(IIdentityIdSource ids, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(ids);
        ArgumentNullException.ThrowIfNull(time);
        return commit => new CommitContext(UtcMicros.FromDateTimeOffset(time.GetUtcNow()), ids.NewId(), commit.CommandId, null, ChangeRecordSchemaVersion);
    }

    public async ValueTask<User?> FindUserAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        var rows = await ReadAsync(IdentityPlans.UserLoad, realm, [PlanValue.FromText(realm.Value), PlanValue.FromText(id.Value)], cancellationToken).ConfigureAwait(false);
        if (rows.Count == 0) return null;
        var row = Single(rows, IdentityPlans.UserLoad);
        if (row.Count != IdentityPlans.UserColumns || row[0].Kind != PlanValueKind.Text || !string.Equals(row[0].AsText(), id.Value, StringComparison.Ordinal))
            throw Defect(IdentityPlans.UserLoad, "returned a row that is not the user asked for");
        return IdentityRowCodec.ReadUser(id, realm, row, 1) ?? throw Defect(IdentityPlans.UserLoad, "returned a user row that cannot be interpreted");
    }

    public async ValueTask<CredentialLookup?> FindCredentialAsync(RealmId realm, string providerId, string subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(providerId);
        ArgumentNullException.ThrowIfNull(subject);
        var rows = await ReadAsync(
            IdentityPlans.CredentialGet, realm, [PlanValue.FromText(realm.Value), PlanValue.FromText(providerId), PlanValue.FromText(subject)], cancellationToken).ConfigureAwait(false);
        if (rows.Count == 0) return null;
        var row = Single(rows, IdentityPlans.CredentialGet);
        if (row.Count != IdentityPlans.CredentialColumns + IdentityPlans.JoinedUserColumns) throw Defect(IdentityPlans.CredentialGet, "returned a row of the wrong width");
        var credential = IdentityRowCodec.ReadCredential(row) ?? throw Defect(IdentityPlans.CredentialGet, "returned a credential row that cannot be interpreted");
        if (credential.Realm != realm || !string.Equals(credential.ProviderId, providerId, StringComparison.Ordinal) || !string.Equals(credential.Subject, subject, StringComparison.Ordinal))
            throw Defect(IdentityPlans.CredentialGet, "returned a credential that is not the one asked for");
        var user = IdentityRowCodec.ReadUser(credential.UserId, realm, row, IdentityPlans.CredentialColumns)
            ?? throw Defect(IdentityPlans.CredentialGet, "returned a user row that cannot be interpreted");
        return new CredentialLookup(credential, user);
    }

    public async ValueTask<IReadOnlyList<AuthIdentity>> ListCredentialsAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        var rows = await ReadAsync(IdentityPlans.CredentialRows, realm, [PlanValue.FromText(realm.Value), PlanValue.FromText(id.Value)], cancellationToken).ConfigureAwait(false);
        if (rows.Count > IdentityPlans.MaxCredentialRows) throw Defect(IdentityPlans.CredentialRows, "returned more rows than its bound");
        var credentials = new List<AuthIdentity>(rows.Count);
        foreach (var row in rows)
        {
            if (row.Count != IdentityPlans.CredentialColumns) throw Defect(IdentityPlans.CredentialRows, "returned a row of the wrong width");
            var credential = IdentityRowCodec.ReadCredential(row) ?? throw Defect(IdentityPlans.CredentialRows, "returned a credential row that cannot be interpreted");
            if (credential.Realm != realm || credential.UserId != id) throw Defect(IdentityPlans.CredentialRows, "returned a credential of another user");
            credentials.Add(credential);
        }

        return credentials;
    }

    public async ValueTask<Workspace?> FindWorkspaceAsync(RealmId realm, WorkspaceId id, CancellationToken cancellationToken)
    {
        var result = await workspaces.FindAsync(realm.Value, id.Value, cancellationToken).ConfigureAwait(false);
        var workspace = FromDirectory(result, "read by identifier");
        if (workspace is not null && (workspace.Realm != realm || workspace.Id != id)) throw new IdentityStoreException(IdentityStoreFailure.Defect, "The workspace directory returned a workspace that was not asked for.");
        return workspace;
    }

    public async ValueTask<Workspace?> FindWorkspaceByOwnerAsync(RealmId realm, UserId owner, CancellationToken cancellationToken)
    {
        var result = await workspaces.FindByOwnerAsync(realm.Value, owner.Value, cancellationToken).ConfigureAwait(false);
        var workspace = FromDirectory(result, "read by owner");
        if (workspace is not null && (workspace.Realm != realm || workspace.OwnerUserId != owner)) throw new IdentityStoreException(IdentityStoreFailure.Defect, "The workspace directory returned a workspace that was not asked for.");
        return workspace;
    }

    public async ValueTask<bool> HasActiveRecoveryPathAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        var rows = await ReadAsync(IdentityPlans.RecoveryActive, realm, [PlanValue.FromText(realm.Value), PlanValue.FromText(id.Value)], cancellationToken).ConfigureAwait(false);

        // No row: the user is not in this realm, so it has no recovery path here.
        if (rows.Count == 0) return false;
        var row = Single(rows, IdentityPlans.RecoveryActive);
        if (row.Count != 1 || row[0].Kind != PlanValueKind.Bool) throw Defect(IdentityPlans.RecoveryActive, "returned an answer that is not one flag");
        return row[0].AsBool();
    }

    public async ValueTask<CommitOutcome> CommitAsync(IdentityCommit commit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commit);
        var values = context(commit);
        ModulePlanOutcome outcome;
        string planId;
        if (commit is IdentityCommit.Enroll enroll)
        {
            var call = IdentityStatements.Enroll(enroll, values);
            planId = IdentityStatements.EnrollmentPlan;
            var family = new ModuleFamilyCall(
                IdentityPlans.EnrollmentFamily, planId, call.Scope.Value, [.. call.Contributions.Select(IdentityRowCodec.ToStatement)], IdentityRowCodec.ToCommit(call.Tail));
            outcome = await families.ExecuteAsync(family, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var call = commit switch
            {
                IdentityCommit.AddCredential add => IdentityStatements.CredentialAdd(add, values),
                IdentityCommit.RevokeCredential revoke => IdentityStatements.CredentialRevoke(revoke, values),
                IdentityCommit.RelabelCredential relabel => IdentityStatements.CredentialRelabel(relabel, values),
                IdentityCommit.RenameUser rename => IdentityStatements.UserRename(rename, values),
                _ => throw new ArgumentOutOfRangeException(nameof(commit)),
            };
            planId = call.PlanId;
            var write = new ModulePlanWrite(
                call.PlanId, call.Scope.Value, [.. call.OwnerStatements.Select(IdentityRowCodec.ToValues)], IdentityRowCodec.ToCommit(call.Tail));
            outcome = await plans.WriteAsync(write, cancellationToken).ConfigureAwait(false);
        }

        return Map(commit, outcome.Status, planId);
    }

    /// <summary>The commit outcome of a plan status (the table in the type comment).</summary>
    internal static CommitOutcome Map(IdentityCommit commit, ModulePlanStatus status, string planId) => status switch
    {
        ModulePlanStatus.Succeeded => CommitOutcome.Committed,
        ModulePlanStatus.Replayed => CommitOutcome.Replayed,
        ModulePlanStatus.GuardRefused => CommitOutcome.Refused,
        ModulePlanStatus.ConstraintRefused when commit is IdentityCommit.Enroll or IdentityCommit.AddCredential => CommitOutcome.Refused,
        ModulePlanStatus.ReusedIdentifier => CommitOutcome.IdentifierConflict,
        ModulePlanStatus.ReceiptExpired => CommitOutcome.ReceiptExpired,
        ModulePlanStatus.UnknownOutcome => CommitOutcome.Unknown,
        ModulePlanStatus.Unavailable or ModulePlanStatus.StaleGeneration =>
            throw new IdentityStoreException(IdentityStoreFailure.Unavailable, "The plan '" + planId + "' was not executed: " + status + "."),
        _ => throw Defect(planId, "was refused: " + status),
    };

    private async Task<IReadOnlyList<IReadOnlyList<PlanValue>>> ReadAsync(string planId, RealmId realm, IReadOnlyList<PlanValue> arguments, CancellationToken cancellationToken)
    {
        // The identity reads carry no workspace scope (realm-level reads, S54(6)); the realm names the call.
        var outcome = await plans.ReadAsync(new ModulePlanRead(planId, realm.Value, arguments), cancellationToken).ConfigureAwait(false);
        return outcome.Status switch
        {
            ModulePlanStatus.Succeeded => outcome.Rows,
            ModulePlanStatus.Unavailable or ModulePlanStatus.StaleGeneration =>
                throw new IdentityStoreException(IdentityStoreFailure.Unavailable, "The plan '" + planId + "' was not served: " + outcome.Status + "."),
            _ => throw Defect(planId, "was refused: " + outcome.Status),
        };
    }

    private static IReadOnlyList<PlanValue> Single(IReadOnlyList<IReadOnlyList<PlanValue>> rows, string planId) =>
        rows.Count == 1 ? rows[0] : throw Defect(planId, "returned more than one row");

    private static Workspace? FromDirectory(WorkspaceDirectoryResult result, string what)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.Status switch
        {
            WorkspaceDirectoryStatus.Found => (result.Workspace is null ? null : IdentityRowCodec.ReadWorkspace(result.Workspace))
                ?? throw new IdentityStoreException(IdentityStoreFailure.Defect, "The workspace " + what + " returned a record that cannot be interpreted."),
            WorkspaceDirectoryStatus.NotFound => null,
            WorkspaceDirectoryStatus.Unavailable => throw new IdentityStoreException(IdentityStoreFailure.Unavailable, "The workspace " + what + " was not served."),
            _ => throw new IdentityStoreException(IdentityStoreFailure.Defect, "The workspace " + what + " was refused: " + result.Status + "."),
        };
    }

    private static IdentityStoreException Defect(string planId, string reason) =>
        new(IdentityStoreFailure.Defect, "The plan '" + planId + "' " + reason + ".");
}
