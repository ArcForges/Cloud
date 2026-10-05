// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;
using static ArcForges.Cloud.Tests.Receipts.Samples;

namespace ArcForges.Cloud.Tests.Receipts;

/// <summary>
/// The commit tail builder against the one definition shared with the plan generator (Vectors/commit-tail.json, written by
/// eng/verification/commit-tail.ts): the same statements in the same order with the same parameter kinds, and arguments of exactly those kinds.
/// </summary>
public sealed class CommitTailTests
{
    private const string Scope = "workspace:fixture-a";

    private static JsonElement Vectors() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "tests", "ArcForges.Cloud.Tests", "Vectors", "commit-tail.json"))).RootElement;

    private static string Describe(PlanParam param) => param.Kind.ToString().ToLowerInvariant() + (param.Nullable ? "?" : "");

    /// <summary>A module write plan shaped as the generator requires: the guard, one owner statement and the tail.</summary>
    private static PlanDefinition PlanFor(int events, bool inbox, int owner = 2)
    {
        var statements = new List<PlanStatement>
        {
            new([new PlanParam(PlanKind.Text), new PlanParam(PlanKind.Scope)], null),
        };
        for (var index = 1; index < owner; index++) statements.Add(new([new PlanParam(PlanKind.Scope), new PlanParam(PlanKind.Text)], null));
        statements.AddRange(CommitTail.Kinds(events, inbox).Select(kinds => new PlanStatement([.. kinds.Params], null)));
        statements.Add(new PlanStatement([.. CommitTail.ReleaseKinds.Params], null));
        return new PlanDefinition("entitlement.fixture-store", 1, PlanAccess.Write, 0, statements);
    }

    private static D1Scalar[][] OwnerArguments(CommitTailValues values, int owner = 2)
    {
        var list = new List<D1Scalar[]> { new[] { D1Values.Text(values.Receipt.Identity.CommandId.ToString("D")), D1Values.Text(Scope) } };
        for (var index = 1; index < owner; index++) list.Add([D1Values.Text(Scope), D1Values.Text("x")]);
        return [.. list];
    }

    private static CommitTailValues Values(int events, bool inbox = false, long? revision = 3, Guid? workspace = null)
    {
        var list = Enumerable.Range(1, events).Select(n => Event(n, workspace: n == 1 ? workspace : null, causation: n == 2 ? Id(900) : null)).ToArray();
        var key = inbox ? new InboxKey("billing-consumer", "evt-1", 4) : null;
        return new CommitTailValues(Receipt(revision: revision, workspace: workspace), list, Change(), key, inbox ? NowMicros + InboxRetention.MinimumMicros : 0);
    }

    [Fact]
    public void TheStatementsAndKindsEqualTheVectorsOfTheGeneratorForEveryVariant()
    {
        var root = Vectors();
        Assert.Equal(StorageFormats.ArchiveStreamKey, root.GetProperty("archiveStreamKey").GetString());
        Assert.Equal(CommitTail.MaxEvents, root.GetProperty("maxEvents").GetInt32());
        var release = root.GetProperty("release");
        Assert.Equal(CommitTail.ReleaseKinds.Role, release.GetProperty("role").GetString());
        Assert.Equal(CommitTail.ReleaseKinds.Params.Select(Describe).ToArray(), release.GetProperty("params").EnumerateArray().Select(p => p.GetString()!).ToArray());
        var checkedVariants = 0;
        foreach (var variant in root.GetProperty("variants").EnumerateArray())
        {
            var events = variant.GetProperty("events").GetInt32();
            var inbox = variant.GetProperty("inbox").GetBoolean();
            var expected = variant.GetProperty("statements").EnumerateArray().Select(s => (Role: s.GetProperty("role").GetString()!, Params: s.GetProperty("params").EnumerateArray().Select(p => p.GetString()!).ToArray())).ToArray();
            var actual = CommitTail.Kinds(events, inbox);
            Assert.Equal(expected.Length, actual.Count);
            Assert.Equal(expected.Length, CommitTail.StatementCount(events, inbox));
            for (var index = 0; index < expected.Length; index++)
            {
                Assert.Equal(expected[index].Role, actual[index].Role);
                Assert.Equal(expected[index].Params, actual[index].Params.Select(Describe).ToArray());
            }

            checkedVariants++;
        }

        Assert.Equal(10, checkedVariants);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(16, true)]
    public void TheArgumentsMatchTheKindsOfEveryStatementAndPassThePlanValidation(int events, bool inbox)
    {
        var values = Values(events, inbox);
        var plan = PlanFor(events, inbox);
        var arguments = CommitTail.Bind(plan, Scope, OwnerArguments(values), values);
        Assert.Equal(plan.Statements.Count, arguments.Length);
        // The last statement is the guard release of the same command.
        Assert.Equal(values.Receipt.Identity.CommandId.ToString("D"), ScriptedExecutor.Text(arguments[^1][0]));
        // The production validator checks counts, kinds, nullability, exact numeric forms and that a scope parameter equals the owner scope.
        PlanArguments.Validate(PlanCall.New(plan, Scope, 0, arguments));
    }

    [Fact]
    public void TheTailBindsTheValuesTheSqlExpects()
    {
        var workspace = Id(77);
        var values = Values(2, inbox: true, revision: null, workspace: workspace);
        var tail = CommitTail.Arguments(Scope, values);
        var command = values.Receipt.Identity.CommandId.ToString("D");
        var now = values.Receipt.CreatedAtMicros;
        // inbox: source, stored message id with the generation, received and processed at the commit instant, expiry.
        Assert.Equal(["billing-consumer", "evt-1@4"], new[] { ScriptedExecutor.Text(tail[0][0]), ScriptedExecutor.Text(tail[0][1]) });
        Assert.Equal([now, now, values.InboxExpiresAtMicros], new[] { ScriptedExecutor.Int(tail[0][2]), ScriptedExecutor.Int(tail[0][3]), ScriptedExecutor.Int(tail[0][4]) });
        // receipt: a null revision is the sentinel -1, the workspace is bound, the payload is the original response.
        var receipt = tail[1];
        Assert.Equal(command, ScriptedExecutor.Text(receipt[0]));
        Assert.Equal(workspace.ToString("D"), ScriptedExecutor.Text(receipt[1]));
        Assert.Equal(-1, ScriptedExecutor.Int(receipt[6]));
        Assert.Equal("{\"ok\":true}", ScriptedExecutor.Text(receipt[5]));
        Assert.Equal(now, ScriptedExecutor.Int(receipt[7]));
        Assert.Equal(values.Receipt.ExpiresAtMicros, ScriptedExecutor.Int(receipt[8]));
        // each event: the stream allocation names the owner scope; the outbox row carries its ids; the position repeats the scope for the key and the read.
        Assert.Equal(Scope, ScriptedExecutor.Text(tail[2][0]));
        Assert.Equal(Id(101).ToString("D"), ScriptedExecutor.Text(tail[3][0]));
        Assert.Equal(workspace.ToString("D"), ScriptedExecutor.Text(tail[3][6]));
        Assert.True(D1Values.IsNull(tail[3][8]));
        Assert.Equal([Id(101).ToString("D"), Scope, Scope], tail[4].Select(ScriptedExecutor.Text).ToArray());
        Assert.Equal(Id(900).ToString("D"), ScriptedExecutor.Text(tail[6][8]));
        // archive: the change record, its SHA-256 and the commit instant; the guard release names the same command.
        var archive = tail[^1];
        Assert.Equal(command, ScriptedExecutor.Text(archive[0]));
        Assert.Equal(23, ScriptedExecutor.Int(archive[1]));
        Assert.True(D1Values.TryGetBytes(archive[3], out var hash));
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("{\"row\":1}")), hash);
        Assert.Equal(command, ScriptedExecutor.Text(CommitTail.Release(values.Receipt.Identity.CommandId)[0]));
        Assert.Equal(CommitTail.StatementCount(2, true), tail.Length);
    }

    [Fact]
    public void ARevisionBeyondTwoToTheFiftyThreeIsBoundExactly()
    {
        var receipt = new CommandReceipt(Identity(), "{}", 9_007_199_254_740_993L, NowMicros, NowMicros + 10);
        var values = new CommitTailValues(receipt, [], Change());
        var tail = CommitTail.Arguments(Scope, values);
        Assert.Equal("9007199254740993", ((D1ScalarD1Int64Value)tail[0][6]).Value.Value);
    }

    [Fact]
    public void BindRefusesAPlanWhoseTailOrGuardIsNotTheCanonicalOne()
    {
        var values = Values(1);
        var owner = OwnerArguments(values);
        var good = PlanFor(1, false);

        // Too few and too many statements.
        Assert.Equal(PlanFailureKind.InvalidPlan, Kind(() => CommitTail.Bind(PlanFor(1, false, owner: 3), Scope, owner, values)));
        Assert.Equal(PlanFailureKind.InvalidPlan, Kind(() => CommitTail.Bind(PlanFor(2, false), Scope, owner, values)));

        // A tail statement with a different parameter kind.
        var changed = good.Statements.ToList();
        changed[^2] = new PlanStatement([new PlanParam(PlanKind.Text), new PlanParam(PlanKind.Int64), new PlanParam(PlanKind.Text), new PlanParam(PlanKind.Text), new PlanParam(PlanKind.Int64)], null);
        Assert.Equal(PlanFailureKind.InvalidPlan, Kind(() => CommitTail.Bind(good with { Statements = changed }, Scope, owner, values)));

        // A stream parameter that is plain text could name any stream: the plan must bind it as the owner scope.
        var unscoped = good.Statements.ToList();
        var streamAt = unscoped.FindIndex(2, s => s.Params.Count == 2 && s.Params[0].Kind == PlanKind.Scope);
        unscoped[streamAt] = new PlanStatement([new PlanParam(PlanKind.Text), new PlanParam(PlanKind.Int64)], null);
        Assert.Equal(PlanFailureKind.InvalidPlan, Kind(() => CommitTail.Bind(good with { Statements = unscoped }, Scope, owner, values)));

        // A read plan, a guard that names another command, and a missing guard.
        Assert.Equal(PlanFailureKind.InvalidPlan, Kind(() => CommitTail.Bind(good with { Access = PlanAccess.Read }, Scope, owner, values)));
        var other = new D1Scalar[][] { [D1Values.Text(Id(999).ToString("D")), D1Values.Text(Scope)], owner[1] };
        Assert.Equal(PlanFailureKind.InvalidPlan, Kind(() => CommitTail.Bind(good, Scope, other, values)));
        Assert.Equal(PlanFailureKind.InvalidPlan, Kind(() => CommitTail.Bind(good, Scope, [owner[0]], values)));
    }

    private static PlanFailureKind Kind(Action action) => Assert.Throws<PlanFailureException>(action).Kind;

    [Fact]
    public void ValuesRefuseWhatTheColumnsWouldRefuse()
    {
        Assert.Throws<ArgumentException>(() => new CommandIdentity(Guid.Empty, null, "a", "o", "h"));
        Assert.Throws<ArgumentException>(() => new CommandIdentity(Id(1), Guid.Empty, "a", "o", "h"));
        Assert.Throws<ArgumentException>(() => new CommandIdentity(Id(1), null, "", "o", "h"));
        Assert.Throws<ArgumentException>(() => new CommandIdentity(Id(1), null, "a", new string('x', 257), "h"));
        Assert.Throws<ArgumentException>(() => new CommandIdentity(Id(1), null, "a", "o", "bad\u0001hash"));
        Assert.Throws<ArgumentException>(() => new CommandIdentity(Id(1), null, "a", "o", "lone\ud800surrogate"));
        Assert.Throws<ArgumentException>(() => new CommandReceipt(Identity(), "{not json", 1, NowMicros, NowMicros + 1));
        Assert.Throws<ArgumentException>(() => new CommandReceipt(Identity(), "{}", 1, NowMicros, NowMicros));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CommandReceipt(Identity(), "{}", -1, NowMicros, NowMicros + 1));
        Assert.Throws<ArgumentException>(() => new CommandReceipt(Identity(), new string('a', StorageFormats.MaxJsonBytes + 1), 1, NowMicros, NowMicros + 1));

        Assert.Throws<ArgumentException>(() => Event(1, payload: "[1]"));
        Assert.Throws<ArgumentException>(() => Event(1, payload: "{\"x\":\"" + new string('y', StorageFormats.MaxEventPayloadBytes) + "\"}"));
        Assert.Throws<ArgumentException>(() => new ArcForges.Cloud.Storage.Outbox.OutboxEvent(Guid.Empty, "k", Id(1), 0, "e", "{}", null, Id(2), null));
        Assert.Throws<ArgumentException>(() => new ArcForges.Cloud.Storage.Outbox.OutboxEvent(Id(1), "k", Id(1), 0, "e", "{}", null, Guid.Empty, null));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ArcForges.Cloud.Storage.Outbox.OutboxEvent(Id(1), "k", Id(1), -1, "e", "{}", null, Id(2), null));

        Assert.Throws<ArgumentException>(() => new ArcForges.Cloud.Storage.Archive.ChangeRecord(1, "[1]"));
        Assert.Throws<ArgumentException>(() => new ArcForges.Cloud.Storage.Archive.ChangeRecord(1, "{\"a\":\"" + new string('y', StorageFormats.MaxChangeRecordBytes) + "\"}"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ArcForges.Cloud.Storage.Archive.ChangeRecord(-1, "{}"));
        Assert.Throws<ArgumentException>(() => new ArcForges.Cloud.Storage.Archive.ChangeRecord(1, "{} trailing"));

        Assert.Throws<ArgumentException>(() => new CommitTailValues(Receipt(), Enumerable.Range(1, 17).Select(n => Event(n)).ToArray(), Change()));
        Assert.Throws<ArgumentException>(() => new CommitTailValues(Receipt(), [Event(1), Event(1)], Change()));
        Assert.Throws<ArgumentException>(() => new CommitTailValues(Receipt(), [], Change(), new InboxKey("c", "m", 0), NowMicros));
        // The declared inbox retention is at least 30 days.
        Assert.Throws<ArgumentException>(() => new CommitTailValues(Receipt(), [], Change(), new InboxKey("c", "m", 0), NowMicros + InboxRetention.MinimumMicros - 1));
        Assert.NotNull(new CommitTailValues(Receipt(), [], Change(), new InboxKey("c", "m", 0), NowMicros + InboxRetention.MinimumMicros));
        Assert.Throws<ArgumentException>(() => CommitTail.Arguments("platform:change-archive", Values(1)));
        Assert.Throws<ArgumentException>(() => CommitTail.Arguments("bad scope", Values(1)));
        Assert.Throws<ArgumentException>(() => CommitTail.Arguments("", Values(1)));
    }

    [Theory]
    [InlineData("workspace:abc", true)]
    [InlineData("realm", true)]
    [InlineData("a.b_c/d-e:f", true)]
    [InlineData("platform:change-archive", false)]
    [InlineData("platform:anything", false)]
    [InlineData("with space", false)]
    [InlineData("naïve", false)]
    [InlineData("", false)]
    public void OnlyAKeyThatIsNotThePlatformNamespaceIsAnOutboxStream(string key, bool valid) => Assert.Equal(valid, StorageFormats.IsOwnerStreamScope(key));

    [Fact]
    public void TheKeyBoundIsOneHundredTwentyEightCharacters()
    {
        Assert.True(StorageFormats.IsKey(new string('a', 128)));
        Assert.False(StorageFormats.IsKey(new string('a', 129)));
    }

    [Fact]
    public void TheCommitInstantIsMicrosecondsSinceTheUnixEpoch()
    {
        Assert.Equal(1_791_201_600_000_000L, NowMicros);
        Assert.Equal(1_000_000L, StorageFormats.Micros(DateTimeOffset.UnixEpoch.AddSeconds(1)));
    }
}
