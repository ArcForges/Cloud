// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Text;
using System.Globalization;
using System.Text.Json;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;

namespace ArcForges.Cloud.Modules.Identity.Persistence;

/// <summary>The live Identity owner store. Named plans and exact primitive values are its entire storage boundary.</summary>
internal sealed class D1IdentityStore(IModulePlanPort plans, IModuleFamilyPort families, IIdentityIdSource ids, TimeProvider time) : IIdentityStore
{
    private const string EnrollmentFamily = "account-enrollment";
    private const int PageSize = 64;
    private const int ReadAttempts = 3;

    public async ValueTask<User?> FindUserAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        var rows = await Read("identity.user-load", realm.Value, [Text(realm.Value), Text(id.Value)], false, cancellationToken).ConfigureAwait(false);
        return One(rows, row => IdentityRowCodec.User(realm, id, row));
    }

    public async ValueTask<CredentialLookup?> FindCredentialAsync(RealmId realm, string providerId, string subject, CancellationToken cancellationToken)
    {
        var rows = await Read("identity.credential-find", realm.Value, [Text(realm.Value), Text(providerId), Text(subject)], false, cancellationToken).ConfigureAwait(false);
        return One(rows, row => IdentityRowCodec.Credential(realm, providerId, subject, row));
    }

    public async ValueTask<IReadOnlyList<AuthIdentity>> ListCredentialsAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        var output = new List<AuthIdentity>();
        var afterInstant = long.MinValue;
        var afterId = "";
        while (true)
        {
            var rows = await Read("identity.credential-list", realm.Value, [Text(realm.Value), Text(id.Value), PlanValue.FromInt64(afterInstant), Text(afterId)], false, cancellationToken).ConfigureAwait(false);
            if (rows.Count > PageSize) throw Defect();
            foreach (var row in rows)
            {
                var credential = Decode(() => IdentityRowCodec.Credential(realm, id, row));
                if (credential.CreatedAt.Value < afterInstant || (credential.CreatedAt.Value == afterInstant && string.CompareOrdinal(credential.Id.Value, afterId) <= 0)) throw Defect();
                output.Add(credential);
                afterInstant = credential.CreatedAt.Value;
                afterId = credential.Id.Value;
            }
            if (rows.Count < PageSize) return output;
        }
    }

    public async ValueTask<Workspace?> FindWorkspaceAsync(RealmId realm, WorkspaceId id, CancellationToken cancellationToken)
    {
        var rows = await Read("workspace.workspace-load", id.Value, [Text(realm.Value), Text(id.Value)], true, cancellationToken).ConfigureAwait(false);
        return One(rows, row => IdentityRowCodec.Workspace(realm, id, null, row));
    }

    public async ValueTask<Workspace?> FindWorkspaceByOwnerAsync(RealmId realm, UserId owner, CancellationToken cancellationToken)
    {
        var rows = await Read("workspace.workspace-by-owner", realm.Value, [Text(realm.Value), Text(owner.Value)], true, cancellationToken).ConfigureAwait(false);
        return One(rows, row => IdentityRowCodec.Workspace(realm, null, owner, row));
    }

    public async ValueTask<bool> HasActiveRecoveryPathAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        var rows = await Read("identity.recovery-active", realm.Value, [Text(realm.Value), Text(id.Value)], false, cancellationToken).ConfigureAwait(false);
        if (rows.Count != 1) throw Defect();
        return Decode(() => IdentityRowCodec.Recovery(rows[0]));
    }

    public async ValueTask<EnrollmentReceipt?> InspectEnrollmentAsync(EnrollmentRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await families.InspectAsync(EnrollmentFamily, EnrollmentReceiptIdentity.For(request), cancellationToken).ConfigureAwait(false);
        if (result.Status == ModulePlanStatus.Succeeded) return null;
        var outcome = Outcome(result.Status);
        if (outcome != CommitOutcome.Replayed) return new EnrollmentReceipt(outcome);
        return Decode(() => Receipt(result.StoredResultJson));
    }

    public async ValueTask<CommitOutcome> CommitAsync(IdentityCommit commit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(commit);
        var now = UtcMicros.FromDateTimeOffset(time.GetUtcNow());
        if (now.Value > long.MaxValue - CommitContext.ReceiptRetentionMicros) throw Defect();
        var context = new CommitContext(now, ids.NewId(), ids.NewId(), commit.CommandId, 1);
        ModulePlanOutcome result;
        if (commit is IdentityCommit.Enroll enrollment)
        {
            var call = IdentityStatements.Enroll(enrollment, context);
            result = await families.WriteAsync(new ModuleFamilyWrite(EnrollmentFamily, IdentityStatements.EnrollmentPlan, call.Scope.Value,
                [.. call.Contributions.Select(item => new ModuleFamilyContribution(item.Module, item.Kind, item.Key, [.. item.Arguments.Select(Value)]))],
                Tail(call.Tail, call.Scope)), cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var call = commit switch
            {
                IdentityCommit.AddCredential item => IdentityStatements.CredentialAdd(item, context),
                IdentityCommit.RevokeCredential item => IdentityStatements.CredentialRevoke(item, context),
                IdentityCommit.RelabelCredential item => IdentityStatements.CredentialRelabel(item, context),
                IdentityCommit.RenameUser item => IdentityStatements.UserRename(item, context),
                _ => throw Defect(),
            };
            result = await plans.WriteAsync(new ModulePlanWrite(call.PlanId, call.Scope.Value,
                [.. call.OwnerStatements.Select(items => (IReadOnlyList<PlanValue>)[.. items.Select(Value)])], Tail(call.Tail, call.Scope)), cancellationToken).ConfigureAwait(false);
        }
        return Outcome(result.Status);
    }

    private async Task<IReadOnlyList<IReadOnlyList<PlanValue>>> Read(string name, string scope, IReadOnlyList<PlanValue> arguments, bool participant, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = new ModulePlanRead(name, scope, arguments);
            var result = participant
                ? await families.ReadAsync(EnrollmentFamily, read, cancellationToken).ConfigureAwait(false)
                : await plans.ReadAsync(read, cancellationToken).ConfigureAwait(false);
            if (result.Status == ModulePlanStatus.Succeeded) return result.Rows;
            if (attempt + 1 < ReadAttempts && result.Status is ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50 * (1 << attempt)), time, cancellationToken).ConfigureAwait(false);
                continue;
            }
            Outcome(result.Status);
            throw Defect(); // A read cannot return a commit/receipt status.
        }
    }

    private static CommitOutcome Outcome(ModulePlanStatus status) => status switch
    {
        ModulePlanStatus.Succeeded => CommitOutcome.Committed,
        ModulePlanStatus.GuardRefused or ModulePlanStatus.ConstraintRefused => CommitOutcome.Refused,
        ModulePlanStatus.Replayed => CommitOutcome.Replayed,
        ModulePlanStatus.ReusedIdentifier => CommitOutcome.IdentifierConflict,
        ModulePlanStatus.ReceiptExpired => CommitOutcome.ReceiptExpired,
        ModulePlanStatus.ReplayedFailure => CommitOutcome.ReplayedFailure,
        ModulePlanStatus.UnknownOutcome => throw new IdentityStorageException(IdentityStorageFailure.OutcomeUnknown),
        ModulePlanStatus.Unavailable => throw new IdentityStorageException(IdentityStorageFailure.Unavailable),
        ModulePlanStatus.StaleGeneration => throw new IdentityStorageException(IdentityStorageFailure.StaleGeneration),
        _ => throw Defect(),
    };

    private static EnrollmentReceipt Receipt(string? json)
    {
        if (json is null || json.Length > 1024) throw Defect();
        using var document = JsonDocument.Parse(json);
        var value = document.RootElement;
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != 4 || value.GetProperty("schemaVersion").GetInt32() != 1) throw Defect();
        return new EnrollmentReceipt(CommitOutcome.Replayed, UserId.Parse(value.GetProperty("userId").GetString()!),
            AuthIdentityId.Parse(value.GetProperty("authIdentityId").GetString()!), WorkspaceId.Parse(value.GetProperty("workspaceId").GetString()!));
    }

    private static T? One<T>(IReadOnlyList<IReadOnlyList<PlanValue>> rows, Func<IReadOnlyList<PlanValue>, T> decode) where T : class
    {
        if (rows.Count > 1) throw Defect();
        return rows.Count == 0 ? null : Decode(() => decode(rows[0]));
    }

    private static T Decode<T>(Func<T> decode)
    {
        try { return decode(); }
        catch (Exception failure) when (failure is ArgumentException or FormatException or JsonException or KeyNotFoundException or InvalidOperationException or OverflowException)
        { throw Defect(); }
    }

    private static ModuleCommit Tail(TailContent tail, WorkspaceId scope) => new(Guid.Parse(tail.CommandId), tail.WorkspaceId is { } id ? Guid.Parse(id) : null,
        tail.ActorRef, tail.Operation, tail.RequestHash, tail.ResultPayloadJson, tail.ResultRevision, tail.CreatedAt, tail.ExpiresAt,
        [.. tail.Events.Select(item => new ModuleOutboxEvent(Guid.Parse(item.OutboxId), item.AggregateKind, Guid.Parse(item.AggregateId), item.AggregateRevision,
            item.EventType, item.PayloadJson, Guid.Parse(scope.Value), Guid.Parse(item.CorrelationId), item.CausationId is { } cause ? Guid.Parse(cause) : null))],
        tail.SchemaVersion, tail.ChangeRecordJson);

    private static PlanValue Value(PlanArgument argument) => argument.Kind switch
    {
        PlanArgumentKind.Null => PlanValue.Null,
        PlanArgumentKind.Text => Text(argument.Value!),
        PlanArgumentKind.Int64 => PlanValue.FromInt64(long.Parse(argument.Value!, CultureInfo.InvariantCulture)),
        PlanArgumentKind.Bytes => PlanValue.FromBytes(Base64Url.DecodeFromChars(argument.Value!)),
        _ => throw Defect(),
    };
    private static PlanValue Text(string value) => PlanValue.FromText(value);
    private static IdentityStorageException Defect() => new(IdentityStorageFailure.InvalidPlan);
}
