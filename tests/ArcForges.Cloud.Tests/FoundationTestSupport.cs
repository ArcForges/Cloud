// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests;

internal static class T
{
    public static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static DirectoryInfo RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(directory.FullName, "Cloud.slnx"))) directory = directory.Parent!;
        return directory;
    }

    /// <summary>A key with generated material: no key literal is ever committed.</summary>
    public static SigningKey Key(string id) => new(id, RandomNumberGenerator.GetBytes(32));

    public static string Sha256Hex(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    public static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text));

    public static string Uuid() => Guid.NewGuid().ToString("D");

    public static FoundationOptions Options(ulong generation = 0) => new(
        new Uri("http://storage.test"), new Uri("http://objects.test"), Key("c2w-1"), Key("w2c-1"), Key("w2c-0"),
        RandomNumberGenerator.GetBytes(32), "https://app.example.test", "proof", generation, "proof/sessions");

    /// <summary>The environment variables of a valid enabled configuration, with generated material.</summary>
    public static Dictionary<string, string?> Environment() => new()
    {
        ["ARCFORGES_FOUNDATION_PROOF"] = "enabled",
        ["AF_HMAC_C2W_KEY_ID"] = "c2w-1",
        ["AF_HMAC_C2W_SECRET"] = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)),
        ["AF_HMAC_W2C_KEY_ID"] = "w2c-1",
        ["AF_HMAC_W2C_SECRET"] = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)),
        ["AF_CSRF_SECRET"] = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)),
        ["AF_ALLOWED_ORIGIN"] = "https://app.example.test",
    };
}

/// <summary>A clock the test moves by hand; <see cref="Tick"/> also advances the monotonic timestamp on every read.</summary>
internal sealed class FakeTime(DateTimeOffset start) : TimeProvider
{
    private long timestamp;

    public DateTimeOffset Now { get; set; } = start;

    /// <summary>Each GetTimestamp read adds this much to the monotonic clock.</summary>
    public TimeSpan Tick { get; set; }

    public override DateTimeOffset GetUtcNow() => Now;

    public override long TimestampFrequency => 1_000_000;

    public override long GetTimestamp() => timestamp += (long)Tick.TotalMicroseconds;

    public void Advance(TimeSpan span) => Now += span;
}

internal sealed class StubHandler(Func<HttpRequestMessage, byte[], Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public int Count { get; private set; }

    public List<HttpRequestMessage> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Count++;
        Requests.Add(request);
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        return await respond(request, body);
    }
}

/// <summary>An in-memory model of the reviewed plans at the plan boundary: the same guards, constraints and atomicity as the SQL.</summary>
internal sealed class FakeStorage : IPlanExecutor
{
    internal sealed record SessionRow(string Scope, string Id, byte[] Hash, string User, string Device, string Workspaces, long Generation, long Epoch,
        long Created, long Absolute, long Idle, long Seen, long? Revoked, string? Reason);

    internal sealed record ExactRow(long Signed, string Unsigned, string Decimal, byte[]? Payload, long Revision);

    internal sealed record JobRow(long Total, long Cursor, long Fence, string? Owner, long? Until, string State, string Checksum, long Revision);

    private readonly object gate = new();
    private long sequence;

    public ulong ActiveGeneration { get; set; }

    /// <summary>Runs before a plan executes: lets a test interleave another actor between two plans.</summary>
    public Func<PlanCall, Task>? Before { get; set; }

    /// <summary>Returns a failure to inject for a plan id, or null.</summary>
    public Func<PlanCall, PlanFailureKind?>? Fault { get; set; }

    public List<string> Calls { get; } = [];

    public List<SessionRow> Sessions { get; } = [];

    public Dictionary<(string, string), ExactRow> Exact { get; } = [];

    public Dictionary<(string, string), (long Balance, long Revision)> Accounts { get; } = [];

    public Dictionary<(string, string), (string Hash, string Result)> Receipts { get; } = [];

    public List<(long Sequence, string Scope, string Command, string Key, string Payload)> Outbox { get; } = [];

    public Dictionary<(string, string), JobRow> Jobs { get; } = [];

    public Dictionary<(string, string, long), long> Items { get; } = [];

    public HashSet<(string, string, long)> Inbox { get; } = [];

    public int Executions(string planId) => Calls.Count(c => c == planId);

    public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
    {
        if (Before is not null) await Before(call);
        PlanArguments.Validate(call);
        lock (gate)
        {
            Calls.Add(call.Plan.Id);
            if (Fault?.Invoke(call) is { } kind) throw new PlanFailureException(kind);
            if (call.RecoveryGeneration != ActiveGeneration) throw new PlanFailureException(PlanFailureKind.StaleGeneration);
            var result = Run(call);
            if (call.Plan.Access == PlanAccess.Read && !PlanArguments.RowsMatch(call.Plan, result.Rows)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
            return result;
        }
    }

    private static PlanFailureException Failure(PlanFailureKind kind) => new(kind);

    private static string Text(D1Scalar scalar) => D1Values.TryGetText(scalar, out var value) ? value : throw new InvalidOperationException();

    private static long Int(D1Scalar scalar) => D1Values.TryGetInt64(scalar, out var value) ? value : throw new InvalidOperationException();

    private static bool ValidJson(string text)
    {
        try
        {
            using var _ = JsonDocument.Parse(text);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static PlanResult Rows(params D1Scalar[][] rows) => new(rows, 0);

    private static PlanResult Changed(ulong changes) => new([], changes);

    private void AddOutbox(D1Scalar[] arguments)
    {
        var (scope, command, key, payload) = (Text(arguments[0]), Text(arguments[1]), Text(arguments[2]), Text(arguments[3]));
        if (!ValidJson(payload) || Outbox.Any(o => o.Scope == scope && o.Command == command && o.Key == key)) throw Failure(PlanFailureKind.Constraint);
        Outbox.Add((++sequence, scope, command, key, payload));
    }

    private void CheckOutbox(D1Scalar[] arguments)
    {
        var (scope, command, key, payload) = (Text(arguments[0]), Text(arguments[1]), Text(arguments[2]), Text(arguments[3]));
        if (!ValidJson(payload) || Outbox.Any(o => o.Scope == scope && o.Command == command && o.Key == key)) throw Failure(PlanFailureKind.Constraint);
    }

    private static D1Scalar[] SessionColumns(SessionRow s) =>
    [
        D1Values.Text(s.Id), D1Values.Text(s.User), D1Values.Text(s.Device), D1Values.Text(s.Workspaces), D1Values.Int64(s.Generation), D1Values.Int64(s.Epoch),
        D1Values.Int64(s.Created), D1Values.Int64(s.Absolute), D1Values.Int64(s.Idle), D1Values.Int64(s.Seen),
        s.Revoked is { } revoked ? D1Values.Int64(revoked) : D1Values.Null(), s.Reason is { } reason ? D1Values.Text(reason) : D1Values.Null(),
    ];

    private PlanResult Run(PlanCall call)
    {
        var a = call.Arguments;
        switch (call.Plan.Id)
        {
            case "foundation.readiness":
                return Rows([D1Values.Int64(1)]);
            case "foundation.session-create":
            {
                var row = new SessionRow(Text(a[0][0]), Text(a[0][1]), D1Values.TryGetBytes(a[0][2], out var hash) ? hash : [], Text(a[0][3]), Text(a[0][4]), Text(a[0][5]),
                    Int(a[0][6]), Int(a[0][7]), Int(a[0][8]), Int(a[0][9]), Int(a[0][10]), Int(a[0][11]), null, null);
                if (hash.Length != 32 || !ValidJson(row.Workspaces) || Sessions.Any(s => s.Scope == row.Scope && (s.Id == row.Id || s.Hash.AsSpan().SequenceEqual(hash))))
                    throw Failure(PlanFailureKind.Constraint);
                CheckOutbox(a[1]);
                Sessions.Add(row);
                AddOutbox(a[1]);
                return Changed(2);
            }
            case "foundation.session-load":
            {
                D1Values.TryGetBytes(a[0][1], out var hash);
                var found = Sessions.FirstOrDefault(s => s.Scope == Text(a[0][0]) && s.Hash.AsSpan().SequenceEqual(hash));
                return found is null ? Rows() : Rows(SessionColumns(found));
            }
            case "foundation.session-load-by-id":
            {
                var found = Sessions.FirstOrDefault(s => s.Scope == Text(a[0][0]) && s.Id == Text(a[0][1]));
                return found is null ? Rows() : Rows(SessionColumns(found));
            }
            case "foundation.session-touch":
            {
                D1Values.TryGetBytes(a[0][3], out var hash);
                var index = Sessions.FindIndex(s => s.Scope == Text(a[0][2]) && s.Hash.AsSpan().SequenceEqual(hash) && s.Revoked is null && s.Idle > Int(a[0][4]) && s.Absolute > Int(a[0][5]));
                if (index < 0) return Changed(0);
                Sessions[index] = Sessions[index] with { Seen = Int(a[0][0]), Idle = Int(a[0][1]) };
                return Changed(1);
            }
            case "foundation.session-revoke":
            {
                var index = Sessions.FindIndex(s => s.Scope == Text(a[0][1]) && s.Id == Text(a[0][2]) && s.Revoked is null);
                if (index < 0) throw Failure(PlanFailureKind.Precondition);
                CheckOutbox(a[2]);
                Sessions[index] = Sessions[index] with { Revoked = Int(a[1][0]), Reason = Text(a[1][1]) };
                AddOutbox(a[2]);
                return Changed(4);
            }
            case "foundation.exact-store":
            {
                var key = (Text(a[0][1]), Text(a[0][2]));
                var current = Exact.TryGetValue(key, out var existing) ? existing.Revision : 0;
                if (current != Int(a[0][3])) throw Failure(PlanFailureKind.Precondition);
                if (Receipts.ContainsKey((Text(a[2][0]), Text(a[2][1]))) || !ValidJson(Text(a[2][3]))) throw Failure(PlanFailureKind.Constraint);
                D1Values.TryGetBytes(a[1][5], out var payload);
                Exact[key] = new ExactRow(Int(a[1][2]), Text(D1Values.Text(((D1ScalarD1Uint64Value)a[1][3]).Value.Value)), Text(D1Values.Text(((D1ScalarD1DecimalValue)a[1][4]).Value.Value)),
                    D1Values.IsNull(a[1][5]) ? null : payload, Int(a[1][6]) + 1);
                Receipts[(Text(a[2][0]), Text(a[2][1]))] = (Text(a[2][2]), Text(a[2][3]));
                return Changed(4);
            }
            case "foundation.exact-load":
            {
                if (!Exact.TryGetValue((Text(a[0][0]), Text(a[0][1])), out var row)) return Rows();
                return Rows([D1Values.Int64(row.Signed), D1Values.Uint64(ulong.Parse(row.Unsigned, System.Globalization.CultureInfo.InvariantCulture)),
                    D1Values.TryParseDecimal(row.Decimal, out var value) ? D1Values.Decimal(value) : throw new InvalidOperationException(),
                    row.Payload is null ? D1Values.Null() : D1Values.Bytes(row.Payload), D1Values.Int64(row.Revision)]);
            }
            case "foundation.account-seed":
            {
                var key = (Text(a[0][0]), Text(a[0][1]));
                if (Accounts.ContainsKey(key)) return Changed(0);
                Accounts[key] = (Int(a[0][2]), 1);
                return Changed(1);
            }
            case "foundation.account-load":
                return Accounts.TryGetValue((Text(a[0][0]), Text(a[0][1])), out var account) ? Rows([D1Values.Int64(account.Balance), D1Values.Int64(account.Revision)]) : Rows();
            case "foundation.transfer":
            {
                var scope = Text(a[0][1]);
                var (from, to) = ((scope, Text(a[0][2])), (scope, Text(a[0][6])));
                var amount = Int(a[0][4]);
                if (!Accounts.TryGetValue(from, out var source) || !Accounts.TryGetValue(to, out var target)
                    || source.Revision != Int(a[0][3]) || source.Balance < amount || target.Revision != Int(a[0][7])) throw Failure(PlanFailureKind.Precondition);
                if (Receipts.ContainsKey((Text(a[3][0]), Text(a[3][1]))) || !ValidJson(Text(a[3][3]))) throw Failure(PlanFailureKind.Constraint);
                CheckOutbox(a[4]);
                Accounts[from] = (source.Balance - amount, source.Revision + 1);
                Accounts[to] = (target.Balance + amount, target.Revision + 1);
                Receipts[(Text(a[3][0]), Text(a[3][1]))] = (Text(a[3][2]), Text(a[3][3]));
                AddOutbox(a[4]);
                return Changed(6);
            }
            case "foundation.outbox-state":
            {
                var scope = Text(a[0][0]);
                var mine = Outbox.Where(o => o.Scope == scope).ToList();
                return Rows([D1Values.Int64(mine.Count), D1Values.Int64(mine.Count == 0 ? 0 : mine.Max(o => o.Sequence))]);
            }
            case "foundation.receipt-load":
                return Receipts.TryGetValue((Text(a[0][0]), Text(a[0][1])), out var receipt) ? Rows([D1Values.Text(receipt.Hash), D1Values.Text(receipt.Result)]) : Rows();
            case "foundation.job-start":
            {
                var key = (Text(a[0][0]), Text(a[0][1]));
                var total = Int(a[0][2]);
                if (Jobs.ContainsKey(key) || total is < 1 or > 1000) throw Failure(PlanFailureKind.Constraint);
                CheckOutbox(a[1]);
                Jobs[key] = new JobRow(total, 0, 0, null, null, "running", "0", 1);
                AddOutbox(a[1]);
                return Changed(2);
            }
            case "foundation.job-load":
            {
                if (!Jobs.TryGetValue((Text(a[0][0]), Text(a[0][1])), out var job)) return Rows();
                return Rows([D1Values.Int64(job.Total), D1Values.Int64(job.Cursor), D1Values.Int64(job.Fence), job.Owner is null ? D1Values.Null() : D1Values.Text(job.Owner),
                    job.Until is { } until ? D1Values.Int64(until) : D1Values.Null(), D1Values.Text(job.State), D1Values.Uint64(ulong.Parse(job.Checksum, System.Globalization.CultureInfo.InvariantCulture)),
                    D1Values.Int64(job.Revision)]);
            }
            case "foundation.job-claim":
            {
                var key = (Text(a[0][1]), Text(a[0][2]));
                if (!Jobs.TryGetValue(key, out var job) || job.State != "running"
                    || !(job.Owner is null || job.Until <= Int(a[0][3]) || job.Owner == Text(a[0][4]))) throw Failure(PlanFailureKind.Precondition);
                Jobs[key] = job with { Owner = Text(a[1][0]), Until = Int(a[1][1]), Fence = job.Fence + 1 };
                return Changed(3);
            }
            case "foundation.job-commit":
            {
                var key = (Text(a[0][1]), Text(a[0][2]));
                if (!Jobs.TryGetValue(key, out var job) || job.State != "running" || job.Fence != Int(a[0][3]) || job.Owner != Text(a[0][4])
                    || job.Cursor != Int(a[0][5]) || !(job.Until > Int(a[0][6]))) throw Failure(PlanFailureKind.Precondition);
                var items = new List<(long N, long Amount)>();
                using (var document = JsonDocument.Parse(Text(a[1][2])))
                {
                    foreach (var element in document.RootElement.EnumerateArray())
                        items.Add((long.Parse(element.GetProperty("n").GetString()!, System.Globalization.CultureInfo.InvariantCulture),
                            long.Parse(element.GetProperty("a").GetString()!, System.Globalization.CultureInfo.InvariantCulture)));
                }

                var newCursor = Int(a[2][0]);
                var inbox = (Text(a[3][0]), Text(a[3][1]), Int(a[3][2]));
                if (items.Any(i => Items.ContainsKey((key.Item1, key.Item2, i.N))) || newCursor > job.Total || Inbox.Contains(inbox)) throw Failure(PlanFailureKind.Constraint);
                CheckOutbox(a[4]);
                foreach (var item in items) Items[(key.Item1, key.Item2, item.N)] = item.Amount;
                D1Values.TryGetUint64(a[2][1], out var checksum);
                Jobs[key] = job with { Cursor = newCursor, Checksum = checksum.ToString(System.Globalization.CultureInfo.InvariantCulture), State = newCursor >= job.Total ? "complete" : "running", Revision = job.Revision + 1 };
                Inbox.Add(inbox);
                AddOutbox(a[4]);
                return Changed((ulong)(items.Count + 5));
            }
            case "foundation.job-items":
            {
                var scope = Text(a[0][0]);
                var job = Text(a[0][1]);
                var mine = Items.Where(i => i.Key.Item1 == scope && i.Key.Item2 == job).ToList();
                return Rows([D1Values.Int64(mine.Count), D1Values.Int64(mine.Sum(i => i.Value))]);
            }
            case "foundation.inbox-seen":
                return Rows([D1Values.Int64(Inbox.Contains((Text(a[0][0]), Text(a[0][1]), Int(a[0][2]))) ? 1 : 0)]);
            default:
                throw new InvalidOperationException("Unmodelled plan " + call.Plan.Id);
        }
    }
}
