// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;

namespace ArcForges.Cloud.Modules.Identity.Core.Infrastructure;

/// <summary>
/// Turns one <see cref="IdentityCommit"/> into the arguments of the named plan that applies it (<c>storage/plans/identity</c>, and the
/// family <c>account-enrollment</c> for an enrollment). The argument order of every statement is the order of its placeholders in the
/// checked-in plan, and the tests hold each statement to the plan's parameter kinds and to shared vectors. Nothing here names SQL.
/// </summary>
internal static class IdentityStatements
{
    public const string CredentialAddPlan = "identity.credential-add";
    public const string CredentialRevokePlan = "identity.credential-revoke";
    public const string CredentialRelabelPlan = "identity.credential-relabel";
    public const string UserRenamePlan = "identity.user-rename";
    public const string EnrollmentPlan = "families.account-enrollment.create-user";

    private static readonly UTF8Encoding Utf8 = new(false);

    public static IdentityPlanCall CredentialAdd(IdentityCommit.AddCredential commit, CommitContext context)
    {
        ArgumentNullException.ThrowIfNull(commit);
        var user = commit.Caller.User.Value;
        var realm = commit.Caller.Realm.Value;
        var credential = commit.Credential;
        ImmutableArray<ImmutableArray<PlanArgument>> own =
        [
            [Text(commit.CommandId), Text(realm), Text(user), Int64(commit.ExpectedUserRevision), Text(realm), Text(credential.ProviderId), Text(credential.Subject)],
            [.. CredentialRow(credential)],
            [Text(realm), Text(user), Int64(commit.ExpectedUserRevision)],
        ];
        var tail = Tail(
            commit, context, "identity.credential.add", commit.Caller, commit.ExpectedUserRevision + 1,
            [Event(context, "identity.auth_identity.added", "identity.user", user, commit.ExpectedUserRevision + 1, Payload(credential.UserId, credential.Id, (int)credential.Method))],
            writer =>
            {
                writer.WriteString("authIdentityId", credential.Id.Value);
                writer.WriteNumber("method", (int)credential.Method);
                writer.WriteNumber("userRevision", commit.ExpectedUserRevision + 1);
            });
        return new IdentityPlanCall(CredentialAddPlan, commit.Scope, own, tail);
    }

    public static IdentityPlanCall CredentialRevoke(IdentityCommit.RevokeCredential commit, CommitContext context)
    {
        ArgumentNullException.ThrowIfNull(commit);
        var user = commit.Caller.User.Value;
        var realm = commit.Caller.Realm.Value;
        var target = commit.Target.Value;
        ImmutableArray<ImmutableArray<PlanArgument>> own =
        [
            [
                Text(commit.CommandId), Text(realm), Text(target), Text(user), Int64(commit.ExpectedCredentialRevision),
                Text(realm), Text(user), Int64(commit.ExpectedUserRevision),
                Text(realm), Text(user), Text(target), Text(user),
            ],
            [Int64(commit.At.Value), Text(realm), Text(target), Text(user), Int64(commit.ExpectedCredentialRevision)],
            [Text(realm), Text(user), Int64(commit.ExpectedUserRevision)],
        ];
        var tail = Tail(
            commit, context, "identity.credential.revoke", commit.Caller, commit.ExpectedUserRevision + 1,
            [Event(context, "identity.auth_identity.revoked", "identity.user", user, commit.ExpectedUserRevision + 1, Payload(commit.Caller.User, commit.Target, null))],
            writer =>
            {
                writer.WriteString("authIdentityId", target);
                writer.WriteNumber("credentialRevision", commit.ExpectedCredentialRevision + 1);
                writer.WriteNumber("userRevision", commit.ExpectedUserRevision + 1);
            });
        return new IdentityPlanCall(CredentialRevokePlan, commit.Scope, own, tail);
    }

    public static IdentityPlanCall CredentialRelabel(IdentityCommit.RelabelCredential commit, CommitContext context)
    {
        ArgumentNullException.ThrowIfNull(commit);
        var user = commit.Caller.User.Value;
        var realm = commit.Caller.Realm.Value;
        var target = commit.Target.Value;
        ImmutableArray<ImmutableArray<PlanArgument>> own =
        [
            [Text(commit.CommandId), Text(realm), Text(target), Text(user), Int64(commit.ExpectedCredentialRevision), Text(realm), Text(user)],
            [PlanArgument.NullableText(commit.Label), Text(realm), Text(target), Text(user), Int64(commit.ExpectedCredentialRevision)],
        ];
        var tail = Tail(
            commit, context, "identity.credential.relabel", commit.Caller, commit.ExpectedCredentialRevision + 1,
            [Event(context, "identity.auth_identity.relabeled", "identity.auth_identity", target, commit.ExpectedCredentialRevision + 1, Payload(commit.Caller.User, commit.Target, null))],
            writer =>
            {
                writer.WriteString("authIdentityId", target);
                writer.WriteNumber("credentialRevision", commit.ExpectedCredentialRevision + 1);
            });
        return new IdentityPlanCall(CredentialRelabelPlan, commit.Scope, own, tail);
    }

    public static IdentityPlanCall UserRename(IdentityCommit.RenameUser commit, CommitContext context)
    {
        ArgumentNullException.ThrowIfNull(commit);
        var user = commit.Caller.User.Value;
        var realm = commit.Caller.Realm.Value;
        ImmutableArray<ImmutableArray<PlanArgument>> own =
        [
            [Text(commit.CommandId), Text(realm), Text(user), Int64(commit.ExpectedUserRevision)],
            [Text(commit.DisplayName), Text(realm), Text(user), Int64(commit.ExpectedUserRevision)],
        ];
        var tail = Tail(
            commit, context, "identity.user.rename", commit.Caller, commit.ExpectedUserRevision + 1,
            [Event(context, "identity.user.renamed", "identity.user", user, commit.ExpectedUserRevision + 1, UserPayload(commit.Caller.User))],
            writer => writer.WriteNumber("userRevision", commit.ExpectedUserRevision + 1));
        return new IdentityPlanCall(UserRenamePlan, commit.Scope, own, tail);
    }

    /// <summary>
    /// The enrollment family: guards that the user, the credential (by identifier and by realm, provider and subject), the owner's
    /// workspace and the workspace identifier are all absent (revision zero), then the three records and the tail.
    /// </summary>
    public static EnrollmentPlanCall Enroll(IdentityCommit.Enroll commit, CommitContext context)
    {
        ArgumentNullException.ThrowIfNull(commit);
        var user = commit.User;
        var credential = commit.Credential;
        var workspace = commit.Workspace;
        var realm = user.Realm.Value;
        var caller = new Principal(user.Realm, user.Id);
        ImmutableArray<StatementContribution> contributions =
        [
            new("identity", "revision", "credential-id", [Text(credential.Id.Value), Int64(0)]),
            new("identity", "revision", "credential-subject", [Text(realm), Text(credential.ProviderId), Text(credential.Subject), Int64(0)]),
            new("identity", "revision", "user", [Text(realm), Text(user.Id.Value), Int64(0)]),
            new("workspace", "revision", "owner", [Text(realm), Text(user.Id.Value), Int64(0)]),
            new("workspace", "revision", "workspace", [Text(workspace.Id.Value), Int64(0)]),
            new("identity", "record", "credential", [.. CredentialRow(credential)]),
            new("identity", "record", "account", [Text(user.Id.Value), Text(realm), Text(user.DisplayName), Int64(user.CreatedAt.Value)]),
            new("workspace", "record", "workspace",
                [Text(workspace.Id.Value), Text(realm), Text(user.Id.Value), Text(workspace.Name), Text(workspace.DataRegion), Int64(workspace.CreatedAt.Value)]),
        ];
        var tail = Tail(
            commit, context, "identity.account.enroll", caller, 1,
            [Event(context, "identity.user.enrolled", "identity.user", user.Id.Value, 1, Payload(user.Id, credential.Id, (int)credential.Method))],
            writer =>
            {
                writer.WriteString("workspaceId", workspace.Id.Value);
                writer.WriteString("authIdentityId", credential.Id.Value);
                writer.WriteNumber("method", (int)credential.Method);
            });
        return new EnrollmentPlanCall(commit.Scope, contributions, tail);
    }

    /// <summary>The arguments of the credential insert, in the placeholder order of the plan (shared by the add plan and the enrollment family).</summary>
    public static ImmutableArray<PlanArgument> CredentialRow(AuthIdentity credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var passkey = credential.Passkey;
        return
        [
            Text(credential.Id.Value),
            Text(credential.UserId.Value),
            Int64((int)credential.Method),
            Text(credential.Subject),
            passkey is null ? PlanArgument.Null : PlanArgument.OptionalBytes(passkey.PublicKey),
            passkey is null ? PlanArgument.Null : PlanArgument.OptionalBytes(passkey.UserHandle),
            PlanArgument.Flag(passkey?.BackupEligible),
            PlanArgument.Flag(passkey?.BackupState),
            PlanArgument.NullableText(passkey?.TransportsJson),
            PlanArgument.OptionalInt64(passkey?.SignCount),
            PlanArgument.NullableText(credential.Label),
            Int64(credential.CreatedAt.Value),
            Text(credential.Realm.Value),
            Text(credential.ProviderId),
            PlanArgument.NullableText(credential.Password),
        ];
    }

    private static PlanArgument Text(string value) => PlanArgument.Text(value);

    private static PlanArgument Int64(long value) => PlanArgument.Int64(value);

    private static string Payload(UserId user, AuthIdentityId credential, int? method)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("authIdentityId", credential.Value);
            if (method is { } m) writer.WriteNumber("method", m);
            writer.WriteString("userId", user.Value);
            writer.WriteEndObject();
        }

        return Utf8.GetString(stream.ToArray());
    }

    private static OutboxEventContent Event(CommitContext context, string eventType, string aggregateKind, string aggregateId, long revision, string payload) =>
        new(context.OutboxId, aggregateKind, aggregateId, revision, eventType, payload, context.CorrelationId, context.CausationId);

    private static string UserPayload(UserId user)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("userId", user.Value);
            writer.WriteEndObject();
        }

        return Utf8.GetString(stream.ToArray());
    }

    /// <summary>
    /// The receipt, the events and the change record. The request hash is the SHA-256 of the canonical operation text, so a reused command
    /// identifier with a different request is told apart from a replay; the change record names identifiers and revisions and nothing else.
    /// </summary>
    private static TailContent Tail(
        IdentityCommit commit, CommitContext context, string operation, Principal caller, long resultRevision,
        ImmutableArray<OutboxEventContent> events, Action<Utf8JsonWriter> change)
    {
        var requestText = operation + "\n" + commit.GetType().Name + "\n" + commit.Scope.Value + "\n" + caller.Realm.Value + "\n" + caller.User.Value + "\n" + RequestShape(commit);
        var hash = Convert.ToHexString(SHA256.HashData(Utf8.GetBytes(requestText))).ToLowerInvariant();
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("operation", operation);
            writer.WriteString("realmId", caller.Realm.Value);
            writer.WriteString("userId", caller.User.Value);
            change(writer);
            writer.WriteEndObject();
        }

        var record = Utf8.GetString(stream.ToArray());
        var result = "{\"ok\":true}";
        return new TailContent(
            commit.CommandId, commit.Scope.Value, "user:" + caller.User.Value, operation, hash, result, resultRevision,
            context.Now.Value, context.Now.Value + CommitContext.ReceiptRetentionMicros, events, context.SchemaVersion, record);
    }

    /// <summary>Every request field that changes the effect, so two different requests never share a hash. Secrets are hashed into the request hash only.</summary>
    private static string RequestShape(IdentityCommit commit) => commit switch
    {
        IdentityCommit.AddCredential add => string.Join('\n', add.Credential.ProviderId, (int)add.Credential.Method, add.Credential.Subject, add.Credential.Label ?? "\u0001", add.ExpectedUserRevision),
        IdentityCommit.RevokeCredential revoke => string.Join('\n', revoke.Target.Value, revoke.ExpectedCredentialRevision, revoke.ExpectedUserRevision),
        IdentityCommit.RelabelCredential relabel => string.Join('\n', relabel.Target.Value, relabel.Label ?? "\u0001", relabel.ExpectedCredentialRevision),
        IdentityCommit.RenameUser rename => string.Join('\n', rename.DisplayName, rename.ExpectedUserRevision),
        IdentityCommit.Enroll enroll => string.Join('\n', enroll.User.Id.Value, enroll.Workspace.Id.Value, enroll.Credential.Id.Value, enroll.Credential.ProviderId, enroll.Credential.Subject),
        _ => throw new ArgumentOutOfRangeException(nameof(commit)),
    };
}
