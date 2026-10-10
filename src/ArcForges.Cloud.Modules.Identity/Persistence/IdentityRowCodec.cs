// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Text;
using System.Collections.Immutable;
using System.Globalization;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;

namespace ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;

/// <summary>
/// Converts between the core model and the primitives of the Abstractions ports: plan rows into users and credentials, the statement
/// arguments and commit tail that IdentityStatements builds into plan values and a <see cref="ModuleCommit"/>, and directory records into
/// workspaces. A row is decoded strictly: a column of the wrong kind, a non-canonical identifier, a value outside the data model's closed
/// lists or a credential the model could not have written is answered with null (the store reports a defect), never coerced.
/// </summary>
internal static class IdentityRowCodec
{
    /// <summary>
    /// The credential that starts at <paramref name="offset"/> (the 18 credential columns of <c>identity.credential-rows</c>, which are also
    /// the first columns of <c>identity.credential-get</c>), or null when any column is not what the model stores.
    /// </summary>
    public static AuthIdentity? ReadCredential(IReadOnlyList<PlanValue> row, int offset = 0)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (row.Count < offset + IdentityPlans.CredentialColumns) return null;
        PlanValue At(int index) => row[offset + index];
        if (!AuthIdentityId.TryParse(Text(At(0)), out var id) || !UserId.TryParse(Text(At(1)), out var user) || !RealmId.TryParse(Text(At(14)), out var realm)) return null;
        if (Int64(At(2)) is not { } methodNumber || methodNumber is < 1 or > 4) return null;
        var method = (AuthMethod)methodNumber;
        if (Text(At(3)) is not { } subject || Text(At(15)) is not { } provider) return null;
        if (!OptionalBytes(At(4), out var publicKey) || !OptionalBytes(At(5), out var userHandle)) return null;
        if (!OptionalFlag(At(6), out var backupEligible) || !OptionalFlag(At(7), out var backupState)) return null;
        if (!OptionalText(At(8), out var transports) || !OptionalText(At(10), out var label) || !OptionalText(At(16), out var password)) return null;
        if (!OptionalInt64(At(9), out var signCount) || !OptionalInt64(At(12), out var lastUsed) || !OptionalInt64(At(13), out var revoked)) return null;
        if (Int64(At(11)) is not { } created || Int64(At(17)) is not { } revision || revision < 0) return null;

        PasskeyMaterial? passkey = null;
        if (method == AuthMethod.Passkey)
        {
            passkey = new PasskeyMaterial(publicKey, userHandle, backupEligible, backupState, transports, signCount);
        }
        else if (!publicKey.IsDefault || !userHandle.IsDefault || backupEligible is not null || backupState is not null || transports is not null || signCount is not null)
        {
            // Passkey material on another method would be dropped by the model; the row is not one the store wrote.
            return null;
        }

        var credential = new AuthIdentity(
            id, user, realm, provider, method, subject, label, passkey, password, new UtcMicros(created),
            lastUsed is { } used ? new UtcMicros(used) : null, revoked is { } at ? new UtcMicros(at) : null, revision);
        return IdentityRules.HasValidShape(credential) ? credential : null;
    }

    /// <summary>
    /// The user whose five columns (display name, state, created, deletion requested, revision) start at <paramref name="offset"/>; the
    /// identifier and the realm come from the request or from the joined credential, which the plans match.
    /// </summary>
    public static User? ReadUser(UserId id, RealmId realm, IReadOnlyList<PlanValue> row, int offset)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (row.Count < offset + IdentityPlans.JoinedUserColumns) return null;
        if (Text(row[offset]) is not { } displayName) return null;
        if (Int64(row[offset + 1]) is not { } state || state is < 1 or > 5) return null;
        if (Int64(row[offset + 2]) is not { } created || created < 0) return null;
        if (!OptionalInt64(row[offset + 3], out var deletion) || deletion < 0) return null;
        if (Int64(row[offset + 4]) is not { } revision || revision < 0) return null;
        return new User(id, realm, displayName, (UserState)state, new UtcMicros(created), deletion is { } at ? new UtcMicros(at) : null, revision);
    }

    /// <summary>A workspace of the Workspace module's directory as the core model holds it (the protection profile is not part of the model).</summary>
    public static Workspace? ReadWorkspace(WorkspaceRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!WorkspaceId.TryParse(record.WorkspaceId, out var id) || !RealmId.TryParse(record.RealmId, out var realm) || !UserId.TryParse(record.OwnerUserId, out var owner)) return null;
        WorkspaceState? state = record.State switch
        {
            WorkspaceRecordState.Active => WorkspaceState.Active,
            WorkspaceRecordState.Suspended => WorkspaceState.Suspended,
            WorkspaceRecordState.PendingDeletion => WorkspaceState.PendingDeletion,
            _ => null,
        };
        if (state is null || record.Name is null || record.DataRegion is null || record.CreatedAtMicros < 0 || record.Revision < 0) return null;
        return new Workspace(id, realm, owner, record.Name, record.DataRegion, state.Value, new UtcMicros(record.CreatedAtMicros), record.Revision);
    }

    /// <summary>One statement argument as an exact plan value: the integer from its canonical decimal text, the bytes from base64url.</summary>
    public static PlanValue ToValue(PlanArgument argument) => argument.Kind switch
    {
        PlanArgumentKind.Text => PlanValue.FromText(argument.Value!),
        PlanArgumentKind.Int64 => PlanValue.FromInt64(long.Parse(argument.Value!, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture)),
        PlanArgumentKind.Bytes => PlanValue.FromBytes(Base64Url.DecodeFromChars(argument.Value!)),
        PlanArgumentKind.Null => PlanValue.Null,
        _ => throw new ArgumentOutOfRangeException(nameof(argument)),
    };

    public static IReadOnlyList<PlanValue> ToValues(ImmutableArray<PlanArgument> arguments) => [.. arguments.Select(ToValue)];

    /// <summary>The class of an enrollment contribution: a revision guard or a record mutation (the only two the family statements use).</summary>
    public static FamilyStatementClass ToClass(string kind) => kind switch
    {
        "revision" => FamilyStatementClass.Revision,
        "record" => FamilyStatementClass.Record,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), "An enrollment contribution is a revision guard or a record."),
    };

    public static FamilyStatement ToStatement(StatementContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(contribution);
        return new FamilyStatement(contribution.Module, ToClass(contribution.Kind), contribution.Key, ToValues(contribution.Arguments));
    }

    /// <summary>
    /// The commit tail as the Abstractions commit: the receipt identity and result, the outbox events (each in the commit's workspace, as
    /// the shared vector binds them) and the change record. Every identifier is a canonical UUID, so the conversion is exact.
    /// </summary>
    public static ModuleCommit ToCommit(TailContent tail)
    {
        ArgumentNullException.ThrowIfNull(tail);
        Guid? workspace = tail.WorkspaceId is null ? null : Guid.ParseExact(tail.WorkspaceId, "D");
        var events = tail.Events.Select(e => new ModuleOutboxEvent(
            Guid.ParseExact(e.OutboxId, "D"), e.AggregateKind, Guid.ParseExact(e.AggregateId, "D"), e.AggregateRevision, e.EventType, e.PayloadJson, workspace,
            Guid.ParseExact(e.CorrelationId, "D"), e.CausationId is null ? null : Guid.ParseExact(e.CausationId, "D"))).ToArray();
        return new ModuleCommit(
            Guid.ParseExact(tail.CommandId, "D"), workspace, tail.ActorRef, tail.Operation, tail.RequestHash, tail.ResultPayloadJson, tail.ResultRevision,
            tail.CreatedAt, tail.ExpiresAt, events, tail.SchemaVersion, tail.ChangeRecordJson);
    }

    private static string? Text(PlanValue value) => value.Kind == PlanValueKind.Text ? value.AsText() : null;

    private static long? Int64(PlanValue value) => value.Kind == PlanValueKind.Int64 ? value.AsInt64() : null;

    private static bool OptionalText(PlanValue value, out string? text)
    {
        text = value.Kind == PlanValueKind.Text ? value.AsText() : null;
        return value.Kind is PlanValueKind.Text or PlanValueKind.Null;
    }

    private static bool OptionalInt64(PlanValue value, out long? integer)
    {
        integer = value.Kind == PlanValueKind.Int64 ? value.AsInt64() : null;
        return value.Kind is PlanValueKind.Int64 or PlanValueKind.Null;
    }

    private static bool OptionalFlag(PlanValue value, out bool? flag)
    {
        flag = value.Kind == PlanValueKind.Int64 && value.AsInt64() is 0 or 1 ? value.AsInt64() == 1 : null;
        return value.IsNull || flag is not null;
    }

    private static bool OptionalBytes(PlanValue value, out ImmutableArray<byte> bytes)
    {
        bytes = value.Kind == PlanValueKind.Bytes ? ImmutableArray.Create(value.AsBytes()) : default;
        return value.Kind is PlanValueKind.Bytes or PlanValueKind.Null;
    }
}
