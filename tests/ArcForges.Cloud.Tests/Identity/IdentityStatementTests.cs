// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Text;
using System.Collections.Immutable;
using System.Text.Json;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Archive;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// The module builds the arguments of its named plans without naming SQL or referencing the plan bridge. These tests hold that builder to
/// the bridge from the outside: the shared vector (the same file the SQLite oracle runs, built there by an independent TypeScript
/// implementation) must equal the module's arguments exactly, every statement must have the checked-in plan's parameter kinds, and the
/// enrollment contributions must be accepted and sealed by the real guarded-batch unit of work.
/// </summary>
public sealed class IdentityStatementTests
{
    private static readonly JsonElement Vector = JsonDocument.Parse(File.ReadAllText(
        Path.Combine(T.RepoRoot().FullName, "tests", "ArcForges.Cloud.Tests", "Vectors", "identity-plan-calls.json"))).RootElement;

    public static TheoryData<int> StepIndexes()
    {
        var data = new TheoryData<int>();
        for (var i = 0; i < Vector.GetProperty("steps").GetArrayLength(); i++) data.Add(i);
        return data;
    }

    private static string S(JsonElement e, string name) => e.GetProperty(name).GetString()!;

    private static string? N(JsonElement e, string name) => e.GetProperty(name).ValueKind == JsonValueKind.Null ? null : e.GetProperty(name).GetString();

    private static long L(JsonElement e, string name) => e.GetProperty(name).GetInt64();

    private static AuthIdentity Credential(JsonElement input)
    {
        PasskeyMaterial? passkey = null;
        if (input.GetProperty("passkey").ValueKind != JsonValueKind.Null)
        {
            var p = input.GetProperty("passkey");
            bool? Flag(string name) => p.GetProperty(name).ValueKind == JsonValueKind.Null ? null : p.GetProperty(name).GetBoolean();
            passkey = new PasskeyMaterial(
                [.. Base64Url.DecodeFromChars(S(p, "publicKey"))], [.. Base64Url.DecodeFromChars(S(p, "userHandle"))],
                Flag("backupEligible"), Flag("backupState"), N(p, "transports"),
                p.GetProperty("signCount").ValueKind == JsonValueKind.Null ? null : p.GetProperty("signCount").GetInt64());
        }

        return new AuthIdentity(
            AuthIdentityId.Parse(S(input, "credentialId")), UserId.Parse(S(input, "user")), RealmId.Parse(S(input, "realm")),
            S(input, "provider"), (AuthMethod)input.GetProperty("method").GetInt32(), S(input, "subject"), N(input, "label"), passkey, N(input, "password"),
            new UtcMicros(L(input, "createdAt")), null, null, 1);
    }

    private static CommitContext Context(JsonElement input) =>
        new(new UtcMicros(L(input, "now")), S(input, "outbox"), S(input, "correlation"), N(input, "causation"), L(input, "schema"));

    private static Principal Caller(JsonElement input) => new(RealmId.Parse(S(input, "realm")), UserId.Parse(S(input, "user")));

    private static (IdentityCommit Commit, CommitContext Context) Commit(string op, JsonElement input)
    {
        var context = Context(input);
        var command = S(input, "command");
        switch (op)
        {
            case "enroll":
                {
                    var credential = Credential(input.GetProperty("credential"));
                    var user = new User(credential.UserId, credential.Realm, S(input, "displayName"), UserState.Active, new UtcMicros(L(input, "now")), null, 1);
                    var workspace = new Workspace(WorkspaceId.Parse(S(input, "workspace")), user.Realm, user.Id, S(input, "workspaceName"), S(input, "region"), WorkspaceState.Active, user.CreatedAt, 1);
                    return (new IdentityCommit.Enroll(command, user, credential, workspace), context);
                }

            case "add":
                return (new IdentityCommit.AddCredential(command, WorkspaceId.Parse(S(input, "scope")), Caller(input), L(input, "expectedUserRevision"), Credential(input.GetProperty("credential"))), context);
            case "relabel":
                return (new IdentityCommit.RelabelCredential(command, WorkspaceId.Parse(S(input, "scope")), Caller(input), AuthIdentityId.Parse(S(input, "target")), L(input, "expectedCredentialRevision"), N(input, "label")), context);
            case "rename":
                return (new IdentityCommit.RenameUser(command, WorkspaceId.Parse(S(input, "scope")), Caller(input), L(input, "expectedUserRevision"), S(input, "displayName")), context);
            case "revoke":
                return (new IdentityCommit.RevokeCredential(command, WorkspaceId.Parse(S(input, "scope")), Caller(input), AuthIdentityId.Parse(S(input, "target")),
                    L(input, "expectedCredentialRevision"), L(input, "expectedUserRevision"), new UtcMicros(L(input, "at"))), context);
            default:
                throw new InvalidOperationException(op);
        }
    }

    private static D1Scalar Scalar(PlanArgument argument) => argument.Kind switch
    {
        PlanArgumentKind.Text => D1Values.Text(argument.Value!),
        PlanArgumentKind.Int64 => D1Values.Int64(long.Parse(argument.Value!, System.Globalization.CultureInfo.InvariantCulture)),
        PlanArgumentKind.Bytes => D1Values.Bytes(Base64Url.DecodeFromChars(argument.Value!)),
        PlanArgumentKind.Null => D1Values.Null(),
        _ => throw new InvalidOperationException(),
    };

    private static CommitTailValues TailValues(TailContent tail, WorkspaceId eventScope)
    {
        var identity = new CommandIdentity(Guid.Parse(tail.CommandId), tail.WorkspaceId is null ? null : Guid.Parse(tail.WorkspaceId), tail.ActorRef, tail.Operation, tail.RequestHash);
        var receipt = new CommandReceipt(identity, tail.ResultPayloadJson, tail.ResultRevision, tail.CreatedAt, tail.ExpiresAt);
        var events = tail.Events.Select(e => new OutboxEvent(
            Guid.Parse(e.OutboxId), e.AggregateKind, Guid.Parse(e.AggregateId), e.AggregateRevision, e.EventType, e.PayloadJson,
            Guid.Parse(eventScope.Value), Guid.Parse(e.CorrelationId), e.CausationId is null ? null : Guid.Parse(e.CausationId))).ToArray();
        return new CommitTailValues(receipt, events, new ChangeRecord(tail.SchemaVersion, tail.ChangeRecordJson));
    }

    private static string Describe(D1Scalar scalar) => scalar switch
    {
        D1ScalarD1NullValue => "null",
        D1ScalarD1TextValue t => "text:" + t.Value.Value,
        D1ScalarD1Int64Value i => "int64:" + i.Value.Value,
        D1ScalarD1BytesValue b => "bytes:" + b.Value.Value,
        _ => scalar.GetType().Name,
    };

    private static string[][] Expected(JsonElement step) =>
        [.. step.GetProperty("expected").EnumerateArray().Select(statement => statement.EnumerateArray()
            .Select(a => a.GetProperty("kind").GetString() switch
            {
                "null" => "null",
                var kind => kind + ":" + a.GetProperty("value").GetString(),
            }).ToArray())];

    private static PlanDefinition Plan(string id) => PlanManifest.All.Single(plan => plan.Id == id);

    [Theory]
    [MemberData(nameof(StepIndexes))]
    public void EveryPlanCallEqualsTheSharedVectorAndFitsTheCheckedInPlan(int index)
    {
        var step = Vector.GetProperty("steps")[index];
        var op = S(step, "op");
        var (commit, context) = Commit(op, step.GetProperty("input"));
        D1Scalar[][] sealedArguments;
        if (commit is IdentityCommit.Enroll enroll)
        {
            var call = IdentityStatements.Enroll(enroll, context);
            var tail = TailValues(call.Tail, call.Scope);
            var plan = PlanManifest.FamilyPlans.Single(candidate => candidate.Plan.Id == IdentityStatements.EnrollmentPlan);
            var definition = PlanManifest.FamilyCatalog.Single(family => family.Id == plan.Family);
            var unit = FamilyUnitOfWork.Begin(plan, Guid.Parse(call.Tail.CommandId), call.Scope.Value, 0, definition);
            foreach (var contribution in call.Contributions)
            {
                var module = contribution.Module == "identity" ? FamilyModule.Identity : FamilyModule.Workspace;
                var arguments = contribution.Arguments.Select(Scalar).ToArray();
                if (contribution.Kind == "revision")
                    unit.For(module).Revision(contribution.Key, arguments[..^1], long.Parse(contribution.Arguments[^1].Value!, System.Globalization.CultureInfo.InvariantCulture));
                else
                    unit.For(module).Mutation(FamilyClass.Record, contribution.Key, arguments);
            }

            var platform = CommitTail.Arguments(call.Scope.Value, tail);
            string[] keys = ["a-receipt", "b-stream", "c-outbox", "d-position", "e-archive-stream", "f-archive"];
            Assert.Equal(keys.Length, platform.Length);
            for (var i = 0; i < keys.Length; i++) unit.For(FamilyModule.Platform).Mutation(FamilyClass.Record, keys[i], platform[i]);
            sealedArguments = unit.Seal().Arguments;
        }
        else
        {
            var call = commit switch
            {
                IdentityCommit.AddCredential add => IdentityStatements.CredentialAdd(add, context),
                IdentityCommit.RevokeCredential revoke => IdentityStatements.CredentialRevoke(revoke, context),
                IdentityCommit.RelabelCredential relabel => IdentityStatements.CredentialRelabel(relabel, context),
                IdentityCommit.RenameUser rename => IdentityStatements.UserRename(rename, context),
                _ => throw new InvalidOperationException(),
            };
            Assert.Equal(S(step, "plan"), call.PlanId);
            var plan = Plan(call.PlanId);
            var own = call.OwnerStatements.Select(statement => statement.Select(Scalar).ToArray()).ToArray();
            // CommitTail.Bind refuses a plan whose statements do not have the canonical kinds or whose first guard names another command.
            sealedArguments = CommitTail.Bind(plan, call.Scope.Value, own, TailValues(call.Tail, call.Scope));
        }

        Assert.Equal(Expected(step), sealedArguments.Select(statement => statement.Select(Describe).ToArray()).ToArray());
        var checkedIn = Plan(S(step, "plan"));
        Assert.Equal(checkedIn.Statements.Count, sealedArguments.Length);
        for (var statement = 0; statement < sealedArguments.Length; statement++)
        {
            var kinds = checkedIn.Statements[statement].Params;
            Assert.Equal(kinds.Count, sealedArguments[statement].Length);
            for (var position = 0; position < kinds.Count; position++)
            {
                var scalar = sealedArguments[statement][position];
                if (D1Values.IsNull(scalar)) Assert.True(kinds[position].Nullable, $"statement {statement + 1} parameter {position + 1} is not nullable");
                else Assert.Equal(kinds[position].Kind is PlanKind.Scope ? PlanKind.Text : kinds[position].Kind, scalar switch
                {
                    D1ScalarD1TextValue => PlanKind.Text,
                    D1ScalarD1Int64Value => PlanKind.Int64,
                    D1ScalarD1BytesValue => PlanKind.Bytes,
                    _ => PlanKind.Decimal,
                });
            }
        }
    }

    [Fact]
    public void TheVectorCoversEveryWritePlanOfTheModuleAndTheFamily()
    {
        var planned = Vector.GetProperty("steps").EnumerateArray().Select(step => S(step, "plan")).ToHashSet(StringComparer.Ordinal);
        var written = PlanManifest.All.Where(plan => plan.Access == PlanAccess.Write && (plan.Id.StartsWith("identity.", StringComparison.Ordinal) || plan.Id.StartsWith("families.account-enrollment.", StringComparison.Ordinal)))
            .Select(plan => plan.Id).Where(id => id != "identity.credential-touch").ToHashSet(StringComparer.Ordinal);
        Assert.Equal(written.Order(), planned.Order());
    }

    [Fact]
    public void ATailNeverCarriesASubjectADisplayNameALabelOrASecret()
    {
        var step = Vector.GetProperty("steps").EnumerateArray().First(s => S(s, "op") == "add");
        var (commit, context) = Commit("add", step.GetProperty("input"));
        var call = IdentityStatements.CredentialAdd((IdentityCommit.AddCredential)commit, context);
        var credential = ((IdentityCommit.AddCredential)commit).Credential;
        var text = JsonSerializer.Serialize(new object?[] { call.Tail.ResultPayloadJson, call.Tail.ChangeRecordJson, call.Tail.Events.Select(e => e.PayloadJson), call.Tail.ActorRef, call.Tail.Operation, call.Tail.RequestHash });
        Assert.DoesNotContain(credential.Subject, text, StringComparison.Ordinal);
        Assert.DoesNotContain(credential.Label!, text, StringComparison.Ordinal);
        Assert.DoesNotContain(credential.Password!, text, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRequestHashSeparatesDifferentRequestsAndIgnoresNothingThatChangesTheEffect()
    {
        var step = Vector.GetProperty("steps").EnumerateArray().First(s => S(s, "op") == "add");
        var (commit, context) = Commit("add", step.GetProperty("input"));
        var add = (IdentityCommit.AddCredential)commit;
        var baseline = IdentityStatements.CredentialAdd(add, context).Tail.RequestHash;
        Assert.Equal(baseline, IdentityStatements.CredentialAdd(add, context).Tail.RequestHash);
        Assert.NotEqual(baseline, IdentityStatements.CredentialAdd(add with { Credential = add.Credential with { Subject = add.Credential.Subject + "x" } }, context).Tail.RequestHash);
        Assert.NotEqual(baseline, IdentityStatements.CredentialAdd(add with { Credential = add.Credential with { Label = "other" } }, context).Tail.RequestHash);
        Assert.NotEqual(baseline, IdentityStatements.CredentialAdd(add with { ExpectedUserRevision = add.ExpectedUserRevision + 1 }, context).Tail.RequestHash);
        Assert.NotEqual(baseline, IdentityStatements.CredentialAdd(add with { Credential = add.Credential with { Method = AuthMethod.Oidc, Password = null } }, context).Tail.RequestHash);
    }

    [Fact]
    public void ABytesOrIntegerArgumentIsExactAndANullIsExplicit()
    {
        Assert.Equal("AQID-_8", PlanArgument.Bytes([1, 2, 3, 251, 255]).Value);
        Assert.Equal("9223372036854775807", PlanArgument.Int64(long.MaxValue).Value);
        Assert.Equal("-1", PlanArgument.OptionalInt64(null).Value);
        Assert.Equal("-1", PlanArgument.Flag(null).Value);
        Assert.Equal("1", PlanArgument.Flag(true).Value);
        Assert.Equal("0", PlanArgument.Flag(false).Value);
        Assert.Equal(PlanArgumentKind.Null, PlanArgument.NullableText(null).Kind);
        Assert.Equal(PlanArgumentKind.Null, PlanArgument.OptionalBytes(default(ImmutableArray<byte>)).Kind);
    }
}
