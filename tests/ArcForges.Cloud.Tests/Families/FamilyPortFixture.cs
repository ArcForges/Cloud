// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Text;
using System.Globalization;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;
using ArcForges.Cloud.Tests.Receipts;

namespace ArcForges.Cloud.Tests.Families;

internal static class FamilyPortFixture
{
    public static ModuleFamilyWrite Enrollment()
    {
        var realm = RealmId.Parse(Samples.Id(10).ToString("D"));
        var user = new User(UserId.Parse(Samples.Id(11).ToString("D")), realm, "Ada", UserState.Active, new UtcMicros(Samples.NowMicros), null, 1);
        var credential = new AuthIdentity(AuthIdentityId.Parse(Samples.Id(12).ToString("D")), user.Id, realm, "official-email", AuthMethod.EmailCode, "ada@example.test",
            null, null, null, user.CreatedAt, null, null, 1);
        var workspace = new Workspace(WorkspaceId.Parse(Samples.Id(13).ToString("D")), realm, user.Id, "Personal", "eu", WorkspaceState.Active, user.CreatedAt, 1);
        var call = IdentityStatements.Enroll(new IdentityCommit.Enroll(Samples.Id(1).ToString("D"), user, credential, workspace),
            new CommitContext(user.CreatedAt, Samples.Id(14).ToString("D"), Samples.Id(15).ToString("D"), null, 1));
        var tail = call.Tail;
        var commit = new ModuleCommit(Guid.Parse(tail.CommandId), tail.WorkspaceId is { } id ? Guid.Parse(id) : null,
            tail.ActorRef, tail.Operation, tail.RequestHash, tail.ResultPayloadJson, tail.ResultRevision, tail.CreatedAt, tail.ExpiresAt,
            [.. tail.Events.Select(item => new ModuleOutboxEvent(Guid.Parse(item.OutboxId), item.AggregateKind, Guid.Parse(item.AggregateId), item.AggregateRevision,
                item.EventType, item.PayloadJson, workspace.Id == default ? null : Guid.Parse(workspace.Id.Value), Guid.Parse(item.CorrelationId), null))], tail.SchemaVersion, tail.ChangeRecordJson);
        return new ModuleFamilyWrite("account-enrollment", IdentityStatements.EnrollmentPlan, call.Scope.Value,
            [.. call.Contributions.Select(item => new ModuleFamilyContribution(item.Module, item.Kind, item.Key, [.. item.Arguments.Select(Value)]))], commit);
    }

    private static PlanValue Value(PlanArgument argument) => argument.Kind switch
    {
        PlanArgumentKind.Null => PlanValue.Null,
        PlanArgumentKind.Text => PlanValue.FromText(argument.Value!),
        PlanArgumentKind.Int64 => PlanValue.FromInt64(long.Parse(argument.Value!, CultureInfo.InvariantCulture)),
        PlanArgumentKind.Bytes => PlanValue.FromBytes(Base64Url.DecodeFromChars(argument.Value!)),
        _ => throw new InvalidOperationException(),
    };
}
