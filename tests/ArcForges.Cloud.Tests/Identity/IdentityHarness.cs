// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

internal sealed class IdentityClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset now = start;

    public override DateTimeOffset GetUtcNow() => now;

    public void Advance(TimeSpan by) => now += by;
}

internal sealed class SequentialIdentityIds : IIdentityIdSource
{
    private long next = 0x100;

    public string NewId() => $"00000000-0000-4000-8000-{Interlocked.Increment(ref next):x12}";
}

/// <summary>
/// A test-only substitute for the D1-backed identity store. It applies each <see cref="IdentityCommit"/> with exactly the guards of the
/// named plans (storage/plans/identity and the family account-enrollment) as one atomic step under a lock, and it can be told to
/// refuse the next commits to simulate a lost race. It proves the service and the rules against that contract; the SQL itself is proven
/// by the SQLite oracle (tests/worker/identity-core-oracle.test.ts), and neither says anything about real D1.
/// <para>
/// Command receipts are modelled as the platform receipt store classifies them (CommandReplay): a committed commit records its tail's
/// command identifier, workspace, actor, operation, request hash and expiry (the tail built by <see cref="IdentityStatements"/>, so the
/// identity is the real one); a later commit under a recorded identifier is never applied and answers IdentifierConflict when any part
/// differs, ReceiptExpired when the window has passed, and Replayed otherwise. Lost responses and forced outcomes are scripted.
/// </para>
/// </summary>
internal sealed class InMemoryIdentityStore(TimeProvider? time = null) : IIdentityStore
{
    private const string ProbeOutboxId = "00000000-0000-4000-8000-0000000000ff";

    private readonly TimeProvider clock = time ?? TimeProvider.System;
    private readonly Dictionary<string, TailContent> receipts = new(StringComparer.Ordinal);
    private readonly Queue<CommitOutcome> forced = new();
    private readonly List<IdentityCommit> sent = [];
    private int loseResponses;
    private readonly Lock gate = new();
    private readonly Dictionary<UserId, User> users = [];
    private readonly Dictionary<AuthIdentityId, AuthIdentity> credentials = [];
    private readonly Dictionary<WorkspaceId, Workspace> workspaces = [];
    private readonly HashSet<UserId> recoveryPaths = [];
    private int refuseNext;
    private Action? beforeCommit;

    public int Commits { get; private set; }

    public int Reads { get; private set; }

    public IReadOnlyList<IdentityCommit> Committed => committed;

    /// <summary>Every commit handed to the store, in order, whatever its outcome (resends and receipt probes included).</summary>
    public IReadOnlyList<IdentityCommit> Sent { get { lock (gate) return [.. sent]; } }

    public int Receipts { get { lock (gate) return receipts.Count; } }

    private readonly List<IdentityCommit> committed = [];

    /// <summary>The next <paramref name="count"/> commits are refused without effect, as a lost race would be.</summary>
    public void RefuseNext(int count) => refuseNext = count;

    /// <summary>The next commits answer these outcomes in order without any effect (no row, no receipt).</summary>
    public void ForceNext(params CommitOutcome[] outcomes)
    {
        lock (gate)
        {
            foreach (var outcome in outcomes) forced.Enqueue(outcome);
        }
    }

    /// <summary>The next <paramref name="count"/> commits are decided normally (applied with their receipt, replayed or refused) but answer Unknown, as a lost response would.</summary>
    public void LoseNextResponses(int count)
    {
        lock (gate) loseResponses = count;
    }

    /// <summary>Removes every receipt, as the retention purge eventually does.</summary>
    public void PurgeReceipts()
    {
        lock (gate) receipts.Clear();
    }

    /// <summary>Runs once, inside the next commit's critical section before its guards, to model a writer that wins the race.</summary>
    public void BeforeNextCommit(Action action) => beforeCommit = action;

    public void SetRecoveryPath(UserId user, bool active)
    {
        lock (gate)
        {
            if (active) recoveryPaths.Add(user);
            else recoveryPaths.Remove(user);
        }
    }

    public void SetUserState(UserId id, UserState state)
    {
        lock (gate) users[id] = users[id] with { State = state };
    }

    public IReadOnlyList<User> Users { get { lock (gate) return [.. users.Values]; } }

    public IReadOnlyList<Workspace> Workspaces { get { lock (gate) return [.. workspaces.Values]; } }

    public IReadOnlyList<AuthIdentity> Credentials { get { lock (gate) return [.. credentials.Values]; } }

    public ValueTask<User?> FindUserAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Reads++;
            return ValueTask.FromResult(users.TryGetValue(id, out var user) && user.Realm == realm ? user : null);
        }
    }

    public ValueTask<CredentialLookup?> FindCredentialAsync(RealmId realm, string providerId, string subject, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Reads++;
            var found = credentials.Values.FirstOrDefault(c => c.Realm == realm && c.ProviderId == providerId && c.Subject == subject);
            return ValueTask.FromResult(found is null ? null : new CredentialLookup(found, users[found.UserId]));
        }
    }

    public ValueTask<IReadOnlyList<AuthIdentity>> ListCredentialsAsync(RealmId realm, UserId id, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Reads++;
            return ValueTask.FromResult<IReadOnlyList<AuthIdentity>>([.. credentials.Values.Where(c => c.Realm == realm && c.UserId == id).OrderBy(c => c.CreatedAt).ThenBy(c => c.Id.Value, StringComparer.Ordinal)]);
        }
    }

    public ValueTask<Workspace?> FindWorkspaceAsync(RealmId realm, WorkspaceId id, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Reads++;
            return ValueTask.FromResult(workspaces.TryGetValue(id, out var workspace) && workspace.Realm == realm ? workspace : null);
        }
    }

    public ValueTask<Workspace?> FindWorkspaceByOwnerAsync(RealmId realm, UserId owner, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            Reads++;
            return ValueTask.FromResult(workspaces.Values.FirstOrDefault(w => w.Realm == realm && w.OwnerUserId == owner));
        }
    }

    public ValueTask<bool> HasActiveRecoveryPathAsync(UserId id, CancellationToken cancellationToken)
    {
        lock (gate) return ValueTask.FromResult(recoveryPaths.Contains(id));
    }

    public ValueTask<CommitOutcome> CommitAsync(IdentityCommit commit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commit);
        lock (gate)
        {
            sent.Add(commit);
            var hook = beforeCommit;
            beforeCommit = null;
            hook?.Invoke();
            if (refuseNext > 0)
            {
                refuseNext--;
                return ValueTask.FromResult(CommitOutcome.Refused);
            }

            if (forced.TryDequeue(out var scripted)) return ValueTask.FromResult(scripted);
            var outcome = Decide(commit);
            if (loseResponses > 0)
            {
                loseResponses--;
                return ValueTask.FromResult(CommitOutcome.Unknown);
            }

            return ValueTask.FromResult(outcome);
        }
    }

    /// <summary>The receipt decides first (the receipt insert of the tail conflicts whatever the guards say); otherwise the guards, and a committed change records its receipt in the same step.</summary>
    private CommitOutcome Decide(IdentityCommit commit)
    {
        var now = UtcMicros.FromDateTimeOffset(clock.GetUtcNow());
        var tail = TailOf(commit, new CommitContext(now, ProbeOutboxId, commit.CommandId, null, 1));
        if (receipts.TryGetValue(commit.CommandId, out var stored))
        {
            var same = string.Equals(stored.WorkspaceId, tail.WorkspaceId, StringComparison.Ordinal)
                && string.Equals(stored.ActorRef, tail.ActorRef, StringComparison.Ordinal)
                && string.Equals(stored.Operation, tail.Operation, StringComparison.Ordinal)
                && string.Equals(stored.RequestHash, tail.RequestHash, StringComparison.Ordinal);
            if (!same) return CommitOutcome.IdentifierConflict;
            return now.Value >= stored.ExpiresAt ? CommitOutcome.ReceiptExpired : CommitOutcome.Replayed;
        }

        var outcome = Apply(commit);
        if (outcome == CommitOutcome.Committed)
        {
            receipts[commit.CommandId] = tail;
            Commits++;
            committed.Add(commit);
        }

        return outcome;
    }

    private static TailContent TailOf(IdentityCommit commit, CommitContext context) => commit switch
    {
        IdentityCommit.Enroll enroll => IdentityStatements.Enroll(enroll, context).Tail,
        IdentityCommit.AddCredential add => IdentityStatements.CredentialAdd(add, context).Tail,
        IdentityCommit.RevokeCredential revoke => IdentityStatements.CredentialRevoke(revoke, context).Tail,
        IdentityCommit.RelabelCredential relabel => IdentityStatements.CredentialRelabel(relabel, context).Tail,
        IdentityCommit.RenameUser rename => IdentityStatements.UserRename(rename, context).Tail,
        _ => throw new ArgumentOutOfRangeException(nameof(commit)),
    };

    private CommitOutcome Apply(IdentityCommit commit)
    {
        switch (commit)
        {
            case IdentityCommit.Enroll enroll:
                if (users.ContainsKey(enroll.User.Id) || credentials.ContainsKey(enroll.Credential.Id) || workspaces.ContainsKey(enroll.Workspace.Id)) return CommitOutcome.Refused;
                if (credentials.Values.Any(c => c.Realm == enroll.Credential.Realm && c.ProviderId == enroll.Credential.ProviderId && c.Subject == enroll.Credential.Subject)) return CommitOutcome.Refused;
                if (workspaces.Values.Any(w => w.Realm == enroll.User.Realm && w.OwnerUserId == enroll.User.Id)) return CommitOutcome.Refused;
                if (enroll.Workspace.OwnerUserId != enroll.User.Id || enroll.Credential.UserId != enroll.User.Id || enroll.Credential.Realm != enroll.User.Realm) throw new InvalidOperationException("The commit is inconsistent.");
                users[enroll.User.Id] = enroll.User;
                credentials[enroll.Credential.Id] = enroll.Credential;
                workspaces[enroll.Workspace.Id] = enroll.Workspace;
                return CommitOutcome.Committed;

            case IdentityCommit.AddCredential add:
                {
                    if (!users.TryGetValue(add.Caller.User, out var user) || user.Realm != add.Caller.Realm || user.Revision != add.ExpectedUserRevision || user.State != UserState.Active) return CommitOutcome.Refused;
                    if (credentials.Values.Any(c => c.Realm == add.Caller.Realm && c.ProviderId == add.Credential.ProviderId && c.Subject == add.Credential.Subject)) return CommitOutcome.Refused;
                    credentials[add.Credential.Id] = add.Credential;
                    users[user.Id] = user with { Revision = user.Revision + 1 };
                    return CommitOutcome.Committed;
                }

            case IdentityCommit.RevokeCredential revoke:
                {
                    if (!credentials.TryGetValue(revoke.Target, out var target) || target.Realm != revoke.Caller.Realm || target.UserId != revoke.Caller.User || target.Revision != revoke.ExpectedCredentialRevision || target.IsRevoked) return CommitOutcome.Refused;
                    if (!users.TryGetValue(revoke.Caller.User, out var user) || user.Realm != revoke.Caller.Realm || user.Revision != revoke.ExpectedUserRevision || !IdentityRules.MayChangeCredentials(user)) return CommitOutcome.Refused;
                    var remaining = credentials.Values.Any(c => c.Realm == user.Realm && c.UserId == user.Id && c.Id != target.Id && !c.IsRevoked);
                    if (!remaining && !recoveryPaths.Contains(user.Id)) return CommitOutcome.Refused;
                    credentials[target.Id] = target with { RevokedAt = revoke.At, Revision = target.Revision + 1 };
                    users[user.Id] = user with { Revision = user.Revision + 1 };
                    return CommitOutcome.Committed;
                }

            case IdentityCommit.RelabelCredential relabel:
                {
                    if (!credentials.TryGetValue(relabel.Target, out var target) || target.Realm != relabel.Caller.Realm || target.UserId != relabel.Caller.User || target.Revision != relabel.ExpectedCredentialRevision || target.IsRevoked) return CommitOutcome.Refused;
                    if (!users.TryGetValue(relabel.Caller.User, out var user) || user.Realm != relabel.Caller.Realm || !IdentityRules.MayChangeCredentials(user)) return CommitOutcome.Refused;
                    credentials[target.Id] = target with { Label = relabel.Label, Revision = target.Revision + 1 };
                    return CommitOutcome.Committed;
                }

            case IdentityCommit.RenameUser rename:
                {
                    if (!users.TryGetValue(rename.Caller.User, out var user) || user.Realm != rename.Caller.Realm || user.Revision != rename.ExpectedUserRevision || !IdentityRules.MayChangeCredentials(user)) return CommitOutcome.Refused;
                    users[user.Id] = user with { DisplayName = rename.DisplayName, Revision = user.Revision + 1 };
                    return CommitOutcome.Committed;
                }

            default:
                throw new ArgumentOutOfRangeException(nameof(commit));
        }
    }
}

internal sealed class IdentityHarness
{
    public static readonly RealmId RealmA = RealmId.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    public static readonly RealmId RealmB = RealmId.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");

    public IdentityHarness()
    {
        Clock = new IdentityClock(new DateTimeOffset(2026, 10, 5, 12, 0, 0, TimeSpan.Zero));
        Store = new InMemoryIdentityStore(Clock);
        Ids = new SequentialIdentityIds();
        Service = new IdentityService(Store, Ids, Clock);
    }

    public IdentityClock Clock { get; }

    public InMemoryIdentityStore Store { get; }

    public SequentialIdentityIds Ids { get; }

    public IdentityService Service { get; }

    public string Command() => Ids.NewId();

    public static NewCredential Email(string subject, string? label = null) =>
        new("official-email", AuthMethod.EmailCode, subject, label, null, null);

    public static NewCredential Passkey(string subject) =>
        new("official-passkey", AuthMethod.Passkey, subject, "Phone",
            new PasskeyMaterial([1, 2, 3], [9, 8, 7], true, false, "[\"internal\"]", 0), null);

    public static NewCredential Password(string subject) =>
        new("self-host-password", AuthMethod.Password, subject, null, null, "verifier-example");

    public async Task<EnrollmentOutcome> EnrollAsync(RealmId realm, string subject, string name = "Ada", NewCredential? credential = null)
    {
        var result = await Service.CompleteEnrollmentAsync(new EnrollmentRequest(realm, Command(), name, credential ?? Email(subject)), TestContext.Current.CancellationToken);
        Assert.True(result.IsSuccess, "enrollment failed: " + result.Error);
        return result.Value!;
    }

    public static Principal Caller(EnrollmentOutcome account) => new(account.User.Realm, account.User.Id);
}
