// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Tests.Entitlement;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>
/// CLOUD.84 U7: one-for-one C# replacement of tests/worker/storage-plan-vectors.test.ts. Each case runs the reviewed foundation plans
/// (the same named SQL, constraints and batch rollback) through the production plan executor over SQLite, using <see cref="SqliteBridgeExecutor"/>.
/// The TypeScript harness counted rollbacks on its own stand-in for D1; the C# bridge does not expose that counter, so the rollback is
/// asserted by the state the batch leaves behind (the revision, the receipt, the outbox and the guard table), which is the observable effect.
/// </summary>
public sealed class StoragePlanVectorTests
{
    private const string Scope = "proof/test";
    private const long NowMicros = 1_790_000_000_000_000L;
    private static readonly string Hash = new string('a', 64);

    private sealed record Outcome(PlanResult? Result, PlanFailureKind? Failure)
    {
        public bool Ok => Result is not null;
    }

    private static PlanDefinition Plan(string id) => PlanManifest.All.Single(plan => plan.Id == id);

    /// <summary>
    /// Opens a bridge over every committed migration and adds the foundation probe schema that the reviewed foundation plans run against
    /// (the schema the TypeScript harness used by default). The probe tables are disjoint from the product tables, so both can coexist.
    /// </summary>
    private static async Task<SqliteBridgeExecutor> OpenFoundation()
    {
        var db = new SqliteBridgeExecutor();
        var probe = Path.Combine(T.RepoRoot().FullName, "worker", "proof-migrations", "0001_foundation_probe.sql");
        await db.ExecAsync(File.ReadAllText(probe), CancellationToken.None);
        return db;
    }

    private static async Task<Outcome> Run(SqliteBridgeExecutor db, string id, D1Scalar[][] arguments, string ownerScope = Scope)
    {
        try
        {
            return new Outcome(await db.ExecuteAsync(PlanCall.New(Plan(id), ownerScope, 1, arguments), CancellationToken.None), null);
        }
        catch (PlanFailureException failure)
        {
            return new Outcome(null, failure.Kind);
        }
    }

    private static string Cell(D1Scalar scalar)
    {
        if (D1Values.IsNull(scalar)) return "null";
        if (D1Values.TryGetText(scalar, out var text)) return text;
        if (D1Values.TryGetInt64(scalar, out var integer)) return integer.ToString(CultureInfo.InvariantCulture);
        if (D1Values.TryGetUint64(scalar, out var unsigned)) return unsigned.ToString(CultureInfo.InvariantCulture);
        if (D1Values.TryGetDecimal(scalar, out var fixedPoint)) return fixedPoint.ToString(CultureInfo.InvariantCulture);
        if (D1Values.TryGetBytes(scalar, out var bytes)) return Convert.ToHexString(bytes);
        throw new InvalidOperationException("A result cell has no text form.");
    }

    private static string[][] Rows(Outcome outcome) =>
        outcome.Result is null ? [] : outcome.Result.Rows.Select(row => row.Select(Cell).ToArray()).ToArray();

    private static Guid Uuid() => Guid.NewGuid();

    private static D1Scalar Sc(string value = Scope) => D1Values.Text(value);

    private static D1Scalar Txt(string value) => D1Values.Text(value);

    /// <summary>An int64 argument from its exact text; text outside the signed range is kept as written so the refusal can be proven.</summary>
    private static D1Scalar I64(string text) => new D1ScalarD1Int64Value(new D1Int64Value { Kind = "int64", Value = text });

    private static D1Scalar U64(string text) => new D1ScalarD1Uint64Value(new D1Uint64Value { Kind = "uint64", Value = text });

    private static D1Scalar Dec(string text) => new D1ScalarD1DecimalValue(new D1DecimalValue { Kind = "decimal", Value = text });

    private static D1Scalar Bytes(byte[] value) => D1Values.Bytes(value);

    private static D1Scalar Nul() => D1Values.Null();

    private static D1Scalar[][] ExactStore(string id, string signed, string unsigned, string decimalText, byte[]? payload, string expectedRevision, Guid? command = null)
    {
        var commandId = (command ?? Uuid()).ToString("D");
        return
        [
            [Txt(commandId), Sc(), Txt(id), I64(expectedRevision)],
            [Sc(), Txt(id), I64(signed), U64(unsigned), Dec(decimalText), payload is null ? Nul() : Bytes(payload), I64(expectedRevision)],
            [Sc(), Txt(commandId), Txt(Hash), Txt("{\"stored\":true}")],
            [Txt(commandId)],
        ];
    }

    private static Task<Outcome> ExactLoad(SqliteBridgeExecutor db, string id) =>
        Run(db, "foundation.exact-load", [[Sc(), Txt(id)]]);

    private static Task<Outcome> SeedAccount(SqliteBridgeExecutor db, string id, string balance) =>
        Run(db, "foundation.account-seed", [[Sc(), Txt(id), I64(balance)]]);

    private static D1Scalar[][] Transfer(string from, string to, string amount, string expFrom, string expTo, Guid? command = null)
    {
        var commandId = (command ?? Uuid()).ToString("D");
        return
        [
            [Txt(commandId), Sc(), Txt(from), I64(expFrom), I64(amount), Sc(), Txt(to), I64(expTo)],
            [I64(amount), Sc(), Txt(from), I64(expFrom)],
            [I64(amount), Sc(), Txt(to), I64(expTo)],
            [Sc(), Txt(commandId), Txt(Hash), Txt("{\"moved\":true}")],
            [Sc(), Txt(commandId), Txt("transfer.committed"), Txt("{}")],
            [Txt(commandId)],
        ];
    }

    private static async Task<string[][]> Account(SqliteBridgeExecutor db, string id) =>
        Rows(await Run(db, "foundation.account-load", [[Sc(), Txt(id)]]));

    private static async Task<string[][]> Outbox(SqliteBridgeExecutor db) =>
        Rows(await Run(db, "foundation.outbox-state", [[Sc()]]));

    private static async Task<long> Count(SqliteBridgeExecutor db, string table, string where = "1 = 1") =>
        await db.CountAsync(table, where);

    private static async Task<string> Snapshot(SqliteBridgeExecutor db)
    {
        static string Flat(string[][] rows) => string.Join(";", rows.Select(row => string.Join(",", row)));
        return string.Join("|", Flat(await Account(db, "a")), Flat(await Account(db, "b")), Flat(await Outbox(db)));
    }

    private static byte[] EveryByte() => Enumerable.Range(0, 256).Select(index => (byte)index).ToArray();

    [Fact]
    public async Task ReadinessReportsTheSchemaVersionThroughAnExactInt64Text()
    {
        using var db = await OpenFoundation();
        var outcome = await Run(db, "foundation.readiness", [[]]);
        Assert.True(outcome.Ok);
        Assert.Equal(new[] { new[] { "1" } }, Rows(outcome));
        Assert.Equal(0UL, outcome.Result!.Changes);
    }

    [Fact]
    public async Task SixtyFourBitAndDecimalValuesRoundTripExactlyIncludingValuesADoubleCannotHold()
    {
        var vectors = new[]
        {
            ("-9223372036854775808", "18446744073709551615", "-1234567890123456789.123456789"),
            ("9223372036854775807", "9007199254740993", "9999999999999999999.999999999"),
            ("9007199254740993", "0", "0"),
            ("-9007199254740993", "9223372036854775808", "-0.000000001"),
            ("0", "1", "123456789012345678901234567"),
        };
        for (var index = 0; index < vectors.Length; index++)
        {
            var (signed, unsigned, decimalText) = vectors[index];
            using var db = await OpenFoundation();
            var id = $"vector-{index}";
            var stored = await Run(db, "foundation.exact-store", ExactStore(id, signed, unsigned, decimalText, EveryByte(), "0"));
            Assert.True(stored.Ok);
            var loaded = Rows(await ExactLoad(db, id));
            Assert.Equal(new[] { signed, unsigned, decimalText }, loaded[0][..3]);
            Assert.Equal("1", loaded[0][4]);
            // The bytes survive too, and SQLite really stored an integer, not a rounded real.
            var direct = await db.QueryAsync("SELECT typeof(signed_value), CAST(signed_value AS TEXT), length(payload) FROM probe_exact", CancellationToken.None);
            Assert.Equal(new string?[] { "integer", signed, "256" }, direct[0]);
            Assert.Equal(0, await Count(db, "probe_guard"));
        }
    }

    [Fact]
    public async Task AnInt64OutsideTheSignedRangeIsRefusedBeforeSqlCanSaturateIt()
    {
        using var db = await OpenFoundation();
        // SQLite CAST would silently store 9223372036854775807 for this text.
        var result = await Run(db, "foundation.exact-store", ExactStore("big", "9223372036854775808", "1", "1", null, "0"));
        Assert.Equal(PlanFailureKind.InvalidPlan, result.Failure);
        Assert.Equal(0, await Count(db, "probe_exact"));
        Assert.Equal(0, await Count(db, "probe_receipt"));
        var below = await Run(db, "foundation.exact-store", ExactStore("big", "-9223372036854775809", "1", "1", null, "0"));
        Assert.Equal(PlanFailureKind.InvalidPlan, below.Failure);
        var unsigned = await Run(db, "foundation.exact-store", ExactStore("big", "1", "18446744073709551616", "1", null, "0"));
        Assert.Equal(PlanFailureKind.InvalidPlan, unsigned.Failure);
    }

    [Fact]
    public async Task AStaleRevisionViolatesTheGuardAndRollsTheWholeBatchBack()
    {
        using var db = await OpenFoundation();
        Assert.True((await Run(db, "foundation.exact-store", ExactStore("r", "5", "5", "5", null, "0"))).Ok);
        var stale = await Run(db, "foundation.exact-store", ExactStore("r", "6", "6", "6", null, "0"));
        Assert.Equal(PlanFailureKind.Precondition, stale.Failure);
        var loaded = Rows(await ExactLoad(db, "r"));
        Assert.Equal(new[] { "5", "5", "5" }, loaded[0][..3]);
        Assert.Equal(1, await Count(db, "probe_receipt"));
        Assert.Equal(0, await Count(db, "probe_guard"));
        // The next legitimate revision succeeds and increments exactly once.
        Assert.True((await Run(db, "foundation.exact-store", ExactStore("r", "7", "7", "7", null, "1"))).Ok);
        Assert.Equal("2", Rows(await ExactLoad(db, "r"))[0][4]);
    }

    [Fact]
    public async Task ADuplicateCommandReceiptIsAConstraintFailureThatUndoesTheMutation()
    {
        using var db = await OpenFoundation();
        var command = Uuid();
        Assert.True((await Run(db, "foundation.exact-store", ExactStore("d", "1", "1", "1", null, "0", command))).Ok);
        var replay = await Run(db, "foundation.exact-store", ExactStore("d", "2", "2", "2", null, "1", command));
        Assert.Equal(PlanFailureKind.Constraint, replay.Failure);
        var loaded = Rows(await ExactLoad(db, "d"));
        Assert.Equal(new[] { "1", "1", "1" }, loaded[0][..3]);
        Assert.Equal("1", loaded[0][4]);
    }

    [Fact]
    public async Task AGuardedTransferCommitsBalancesReceiptAndOutboxAtomicallyWithExact64BitArithmetic()
    {
        using var db = await OpenFoundation();
        Assert.True((await SeedAccount(db, "a", "9223372036854775000")).Ok);
        Assert.True((await SeedAccount(db, "b", "100")).Ok);
        // Seeding again is idempotent and never overwrites.
        Assert.True((await SeedAccount(db, "a", "5")).Ok);
        Assert.Equal(new[] { new[] { "9223372036854775000", "1" } }, await Account(db, "a"));
        var moved = await Run(db, "foundation.transfer", Transfer("a", "b", "9223372036854774900", "1", "1"));
        Assert.True(moved.Ok);
        Assert.Equal(new[] { new[] { "100", "2" } }, await Account(db, "a"));
        Assert.Equal(new[] { new[] { "9223372036854775000", "2" } }, await Account(db, "b"));
        Assert.Equal(new[] { new[] { "1", "1" } }, await Outbox(db));
    }

    [Fact]
    public async Task AFailedTransferGuardRollsBackBothBalancesTheReceiptAndTheOutboxRow()
    {
        using var db = await OpenFoundation();
        await SeedAccount(db, "a", "50");
        await SeedAccount(db, "b", "10");
        var attempts = new[]
        {
            ("stale source revision", "5", "9", "1"),
            ("stale target revision", "5", "1", "9"),
            ("insufficient balance", "51", "1", "1"),
        };
        foreach (var (label, amount, expFrom, expTo) in attempts)
        {
            var command = Uuid();
            var before = await Snapshot(db);
            var result = await Run(db, "foundation.transfer", Transfer("a", "b", amount, expFrom, expTo, command));
            Assert.Equal(PlanFailureKind.Precondition, result.Failure);
            Assert.Equal(before, await Snapshot(db));
            Assert.Equal(0, await Count(db, "probe_receipt", $"command_id = '{command:D}'"));
            Assert.Equal(0, await Count(db, "probe_guard"));
            Assert.False(string.IsNullOrEmpty(label));
        }
    }

    [Fact]
    public async Task ACreditThatWouldOverflowInt64IsAConstraintFailureAndTheDebitIsUndone()
    {
        using var db = await OpenFoundation();
        await SeedAccount(db, "a", "10");
        await SeedAccount(db, "b", "9223372036854775807");
        var result = await Run(db, "foundation.transfer", Transfer("a", "b", "1", "1", "1"));
        Assert.Equal(PlanFailureKind.Constraint, result.Failure);
        Assert.Equal(new[] { new[] { "10", "1" } }, await Account(db, "a"));
        Assert.Equal(new[] { new[] { "9223372036854775807", "1" } }, await Account(db, "b"));
        Assert.Equal(new[] { new[] { "0", "0" } }, await Outbox(db));
    }

    [Fact]
    public async Task AReplayedTransferCommandIsAConstraintFailureAndMovesNothingASecondTime()
    {
        using var db = await OpenFoundation();
        await SeedAccount(db, "a", "100");
        await SeedAccount(db, "b", "0");
        var command = Uuid();
        Assert.True((await Run(db, "foundation.transfer", Transfer("a", "b", "10", "1", "1", command))).Ok);
        // The command id replay carries current revisions, so only the receipt key can stop it.
        var replay = await Run(db, "foundation.transfer", Transfer("a", "b", "10", "2", "2", command));
        Assert.Equal(PlanFailureKind.Constraint, replay.Failure);
        Assert.Equal(new[] { new[] { "90", "2" } }, await Account(db, "a"));
        var receipt = Rows(await Run(db, "foundation.receipt-load", [[Sc(), Txt(command.ToString("D"))]]));
        Assert.Equal(new[] { new[] { Hash, "{\"moved\":true}" } }, receipt);
    }

    [Fact]
    public async Task RowsAreVisibleOnlyThroughTheirOwnOwnerScope()
    {
        using var db = await OpenFoundation();
        await SeedAccount(db, "a", "5");
        const string other = "proof/other";
        var foreign = await Run(db, "foundation.account-load", [[Sc(other), Txt("a")]], ownerScope: other);
        Assert.True(foreign.Ok);
        Assert.Empty(Rows(foreign));
        // A scope argument that differs from the declared owner scope is refused outright.
        var forged = await Run(db, "foundation.account-load", [[Sc(other), Txt("a")]]);
        Assert.Equal(PlanFailureKind.InvalidPlan, forged.Failure);
    }

    private static byte[] HandleHashOf(int seed) =>
        Enumerable.Range(0, 32).Select(index => (byte)((index * 7 + seed) & 255)).ToArray();

    private static D1Scalar[][] SessionCreate(string sessionId, byte[] handleHash, long offset = 0)
    {
        return
        [
            [
                Sc(),
                Txt(sessionId),
                Bytes(handleHash),
                Txt("11111111-1111-4111-8111-111111111111"),
                Txt("22222222-2222-4222-8222-222222222222"),
                Txt("[\"33333333-3333-4333-8333-333333333333\"]"),
                I64("0"),
                I64("1"),
                I64((NowMicros + offset).ToString(CultureInfo.InvariantCulture)),
                I64((NowMicros + offset + 43_200_000_000L).ToString(CultureInfo.InvariantCulture)),
                I64((NowMicros + offset + 1_800_000_000L).ToString(CultureInfo.InvariantCulture)),
                I64((NowMicros + offset).ToString(CultureInfo.InvariantCulture)),
            ],
            [Sc(), Txt(Uuid().ToString("D")), Txt("session.created"), Txt("{}")],
        ];
    }

    private static Task<Outcome> LoadSession(SqliteBridgeExecutor db, byte[] handleHash) =>
        Run(db, "foundation.session-load", [[Sc(), Bytes(handleHash)]]);

    [Fact]
    public async Task ASessionIsStoredAndFoundOnlyByTheHashOfItsHandleAndRevocationIsGuarded()
    {
        using var db = await OpenFoundation();
        var hashed = HandleHashOf(1);
        Assert.True((await Run(db, "foundation.session-create", SessionCreate("s1", hashed))).Ok);
        var found = Rows(await LoadSession(db, hashed));
        Assert.Equal(
            new[] { "s1", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "[\"33333333-3333-4333-8333-333333333333\"]", "0", "1" },
            found[0][..6]);
        Assert.Equal(new[] { "null", "null" }, found[0][10..]);
        Assert.Empty(Rows(await LoadSession(db, HandleHashOf(2))));
        // The same handle hash cannot be registered twice.
        Assert.Equal(PlanFailureKind.Constraint, (await Run(db, "foundation.session-create", SessionCreate("s2", hashed))).Failure);
        Assert.Equal(1, await Count(db, "probe_session"));
        Assert.Equal(1, await Count(db, "probe_outbox")); // the failed batch must not leave its outbox row

        D1Scalar[][] Revoke(Guid? command = null)
        {
            var commandId = (command ?? Uuid()).ToString("D");
            return
            [
                [Txt(commandId), Sc(), Txt("s1")],
                [I64((NowMicros + 5).ToString(CultureInfo.InvariantCulture)), Txt("logout"), Sc(), Txt("s1")],
                [Sc(), Txt(commandId), Txt("session.revoked"), Txt("{}")],
                [Txt(commandId)],
            ];
        }

        Assert.True((await Run(db, "foundation.session-revoke", Revoke())).Ok);
        var revoked = Rows(await LoadSession(db, hashed));
        Assert.Equal(new[] { (NowMicros + 5).ToString(CultureInfo.InvariantCulture), "logout" }, revoked[0][10..]);
        // A second revoke finds no active session: the guard fails and nothing is written.
        Assert.Equal(PlanFailureKind.Precondition, (await Run(db, "foundation.session-revoke", Revoke())).Failure);
        Assert.Equal(1, await Count(db, "probe_outbox", "event_key = 'session.revoked'"));
        // An unknown session cannot be revoked either.
        var unknown = new D1Scalar[][]
        {
            [Txt(Uuid().ToString("D")), Sc(), Txt("missing")],
            [I64(NowMicros.ToString(CultureInfo.InvariantCulture)), Txt("logout"), Sc(), Txt("missing")],
            [Sc(), Txt(Uuid().ToString("D")), Txt("session.revoked"), Txt("{}")],
            [Txt(Uuid().ToString("D"))],
        };
        Assert.Equal(PlanFailureKind.Precondition, (await Run(db, "foundation.session-revoke", unknown)).Failure);
    }

    [Fact]
    public async Task IdleRenewalMovesOnlyAnActiveUnexpiredUnrevokedSession()
    {
        using var db = await OpenFoundation();
        var hashed = HandleHashOf(3);
        await Run(db, "foundation.session-create", SessionCreate("s1", hashed));

        async Task<Outcome> Touch(long now, long idle) =>
            await Run(db, "foundation.session-touch", [[I64(now.ToString(CultureInfo.InvariantCulture)), I64(idle.ToString(CultureInfo.InvariantCulture)), Sc(), Bytes(hashed), I64(now.ToString(CultureInfo.InvariantCulture)), I64(now.ToString(CultureInfo.InvariantCulture))]]);

        var renewed = await Touch(NowMicros + 60, NowMicros + 1_800_000_060);
        Assert.True(renewed.Ok);
        Assert.Empty(Rows(renewed));
        Assert.Equal(1UL, renewed.Result!.Changes);
        var row = Rows(await LoadSession(db, hashed));
        Assert.Equal(
            new[] { (NowMicros + 1_800_000_060).ToString(CultureInfo.InvariantCulture), (NowMicros + 60).ToString(CultureInfo.InvariantCulture) },
            row[0][8..10]);
        // After the idle expiry nothing changes (zero rows is reported as zero changes).
        var idleExpired = await Touch(NowMicros + 1_800_000_061, NowMicros + 9);
        Assert.True(idleExpired.Ok);
        Assert.Empty(Rows(idleExpired));
        Assert.Equal(0UL, idleExpired.Result!.Changes);
        // After the absolute expiry nothing changes.
        var absoluteExpired = await Touch(NowMicros + 43_200_000_001, NowMicros + 9);
        Assert.True(absoluteExpired.Ok);
        Assert.Equal(0UL, absoluteExpired.Result!.Changes);
    }

    private static string Items(long from, long to)
    {
        var builder = new StringBuilder("[");
        for (var index = from; index < to; index++)
        {
            if (index > from) builder.Append(',');
            builder.Append("{\"n\":\"").Append(index.ToString(CultureInfo.InvariantCulture))
                .Append("\",\"a\":\"").Append(((index + 1) * 4_611_686_018_427L).ToString(CultureInfo.InvariantCulture)).Append("\"}");
        }

        return builder.Append(']').ToString();
    }

    private static long Sum(long from, long to)
    {
        long total = 0;
        for (var index = from; index < to; index++) total += (index + 1) * 4_611_686_018_427L;
        return total;
    }

    private sealed record JobCommit(
        string Job,
        string Fence,
        string Owner,
        string Cursor,
        long Now,
        string Items,
        string Next,
        string Checksum,
        string Event,
        Guid? Command = null);

    private static D1Scalar[][] CommitJob(JobCommit opts)
    {
        var command = (opts.Command ?? Uuid()).ToString("D");
        return
        [
            [Txt(command), Sc(), Txt(opts.Job), I64(opts.Fence), Txt(opts.Owner), I64(opts.Cursor), I64(opts.Now.ToString(CultureInfo.InvariantCulture))],
            [Sc(), Txt(opts.Job), Txt(opts.Items)],
            [I64(opts.Next), U64(opts.Checksum), I64(opts.Next), Sc(), Txt(opts.Job), I64(opts.Fence)],
            [Sc(), Txt(opts.Event), I64("0")],
            [Sc(), Txt(command), Txt("job.slice"), Txt("{}")],
            [Txt(command)],
        ];
    }

    private static D1Scalar[][] ClaimJob(string job, string owner, long now, long leaseUntil)
    {
        var command = Uuid().ToString("D");
        return
        [
            [Txt(command), Sc(), Txt(job), I64(now.ToString(CultureInfo.InvariantCulture)), Txt(owner)],
            [Txt(owner), I64(leaseUntil.ToString(CultureInfo.InvariantCulture)), Sc(), Txt(job)],
            [Txt(command)],
        ];
    }

    private static async Task<string[]?> JobLoad(SqliteBridgeExecutor db, string job)
    {
        var rows = Rows(await Run(db, "foundation.job-load", [[Sc(), Txt(job)]]));
        return rows.Length == 0 ? null : rows[0];
    }

    [Fact]
    public async Task AJobSliceIsClaimedUnderALeaseFencedAndCommittedOnceWithExactSums()
    {
        using var db = await OpenFoundation();
        const string job = "job-1";
        var start = await Run(db, "foundation.job-start",
        [
            [Sc(), Txt(job), I64("10")],
            [Sc(), Txt(Uuid().ToString("D")), Txt("job.started"), Txt("{}")],
        ]);
        Assert.True(start.Ok);
        const long now = 1_000;
        const long lease = now + 60_000_000;
        Assert.True((await Run(db, "foundation.job-claim", ClaimJob(job, "worker-a", now, lease))).Ok);
        Assert.Equal(new[] { "10", "0", "1", "worker-a", lease.ToString(CultureInfo.InvariantCulture) }, (await JobLoad(db, job))![..5]);

        // A second holder cannot claim while the lease is live, but the same owner can renew.
        Assert.Equal(PlanFailureKind.Precondition, (await Run(db, "foundation.job-claim", ClaimJob(job, "worker-b", now + 1, lease + 1))).Failure);
        var before = await JobLoad(db, job);
        var wrong = new (string Label, Func<JobCommit, JobCommit> Override)[]
        {
            ("wrong fence", commit => commit with { Fence = "2" }),
            ("wrong owner", commit => commit with { Owner = "worker-b" }),
            ("wrong cursor", commit => commit with { Cursor = "1" }),
            ("expired lease", commit => commit with { Now = lease + 1 }),
        };
        foreach (var (label, apply) in wrong)
        {
            var result = await Run(db, "foundation.job-commit", CommitJob(apply(new JobCommit(job, "1", "worker-a", "0", 2_000, Items(0, 4), "4", Sum(0, 4).ToString(CultureInfo.InvariantCulture), Uuid().ToString("D")))));
            Assert.True(result.Failure == PlanFailureKind.Precondition, label);
            Assert.Equal(before, await JobLoad(db, job));
            Assert.Equal(0, await Count(db, "probe_job_item"));
            Assert.Equal(0, await Count(db, "probe_inbox"));
        }

        var eventId = Uuid().ToString("D");
        var good = CommitJob(new JobCommit(job, "1", "worker-a", "0", 2_000, Items(0, 4), "4", Sum(0, 4).ToString(CultureInfo.InvariantCulture), eventId));
        Assert.True((await Run(db, "foundation.job-commit", good)).Ok);
        var committed = await JobLoad(db, job);
        Assert.Equal("4", committed![1]);
        // A committed slice releases its lease, so the next holder (even a restarted process) can claim at once.
        Assert.Equal(new[] { "null", "null" }, committed[3..5]);
        Assert.Equal(new[] { new[] { "4", Sum(0, 4).ToString(CultureInfo.InvariantCulture) } }, Rows(await Run(db, "foundation.job-items", [[Sc(), Txt(job)]])));
        // Delivering the same event again (after a fresh claim) is stopped by the inbox row and undoes the whole slice.
        Assert.True((await Run(db, "foundation.job-claim", ClaimJob(job, "worker-a", 2_000, lease))).Ok);
        var duplicate = CommitJob(new JobCommit(job, "2", "worker-a", "4", 2_001, Items(4, 8), "8", Sum(0, 8).ToString(CultureInfo.InvariantCulture), eventId));
        Assert.Equal(PlanFailureKind.Constraint, (await Run(db, "foundation.job-commit", duplicate)).Failure);
        Assert.Equal("4", (await JobLoad(db, job))![1]);
        Assert.Equal(4, await Count(db, "probe_job_item"));
        Assert.Equal(new[] { new[] { "1" } }, Rows(await Run(db, "foundation.inbox-seen", [[Sc(), Txt(eventId), I64("0")]])));
    }

    [Fact]
    public async Task AStaleHolderCannotFinalizeAfterItsLeaseIsTakenOverAndTheJobCompletesExactlyOnce()
    {
        using var db = await OpenFoundation();
        const string job = "job-2";
        await Run(db, "foundation.job-start",
        [
            [Sc(), Txt(job), I64("3")],
            [Sc(), Txt(Uuid().ToString("D")), Txt("job.started"), Txt("{}")],
        ]);
        await Run(db, "foundation.job-claim", ClaimJob(job, "old", 10, 20));
        // The lease expired, so another worker takes over with a higher fence.
        Assert.True((await Run(db, "foundation.job-claim", ClaimJob(job, "new", 21, 90))).Ok);
        Assert.Equal("2", (await JobLoad(db, job))![2]);
        var stale = await Run(db, "foundation.job-commit", CommitJob(new JobCommit(job, "1", "old", "0", 15, Items(0, 3), "3", "1", Uuid().ToString("D"))));
        Assert.Equal(PlanFailureKind.Precondition, stale.Failure);
        var fresh = await Run(db, "foundation.job-commit", CommitJob(new JobCommit(job, "2", "new", "0", 30, Items(0, 3), "3", (4_611_686_018_427L * 6).ToString(CultureInfo.InvariantCulture), Uuid().ToString("D"))));
        Assert.True(fresh.Ok);
        var row = (await JobLoad(db, job))!;
        Assert.Equal(new[] { "3", "complete", (4_611_686_018_427L * 6).ToString(CultureInfo.InvariantCulture) }, new[] { row[1], row[5], row[6] });
        // A completed job can no longer be claimed or committed.
        Assert.Equal(PlanFailureKind.Precondition, (await Run(db, "foundation.job-claim", ClaimJob(job, "new", 31, 91))).Failure);
    }

    [Fact]
    public async Task ACursorBeyondTheJobTotalViolatesTheTableConstraintAndUndoesTheSlice()
    {
        using var db = await OpenFoundation();
        const string job = "job-3";
        await Run(db, "foundation.job-start",
        [
            [Sc(), Txt(job), I64("2")],
            [Sc(), Txt(Uuid().ToString("D")), Txt("job.started"), Txt("{}")],
        ]);
        await Run(db, "foundation.job-claim", ClaimJob(job, "w", 1, 1_000));
        var result = await Run(db, "foundation.job-commit", CommitJob(new JobCommit(job, "1", "w", "0", 2, Items(0, 3), "3", "1", Uuid().ToString("D"))));
        Assert.Equal(PlanFailureKind.Constraint, result.Failure);
        Assert.Equal(0, await Count(db, "probe_job_item"));
    }
}
