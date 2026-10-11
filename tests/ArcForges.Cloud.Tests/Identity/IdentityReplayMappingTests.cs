// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// How the service maps the replay outcomes of a commit (CLOUD.72, S54(2) and (4)): an unknown outcome is resent only as the identical
/// command, a replay is the original success, a reused identifier and an expired receipt are typed refusals that write nothing, and the
/// enrollment receipt probe can replay or be refused but never write. The store substitute classifies receipts by the identity the real
/// commit tail carries (<see cref="IdentityStatements"/>), so the request hashes here are the production ones.
/// </summary>
public sealed class IdentityReplayMappingTests
{
    private static readonly RealmId RealmA = IdentityHarness.RealmA;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // ------------------------------------------------------------------------------------------------------------------------
    // The typed refusals and outcomes
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public void IdentityErrorGainsExactlyTheTwoReplayRefusalsAndKeepsEveryExistingMember()
    {
        Assert.Equal(
            new[] { "InvalidRequest", "NotFound", "CredentialUnavailable", "LastCredential", "NotPermitted", "Conflict", "IdentifierConflict", "ReceiptExpired" },
            Enum.GetNames<IdentityError>());
        Assert.Equal(
            new[] { "Committed", "Refused", "Replayed", "IdentifierConflict", "ReceiptExpired", "Unknown" },
            Enum.GetNames<CommitOutcome>());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Unknown outcomes: resend the identical command, never a new one
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AnEnrollmentWhoseResponseWasLostIsResentIdenticallyAndReplaysAsTheUserItCreated()
    {
        var h = new IdentityHarness();
        h.Store.LoseNextResponses(1);
        var result = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test")), Ct);
        Assert.True(result.IsSuccess);
        Assert.True(result.Value!.CreatedUser, "the replay is this attempt's own effect, so the created-user grants still apply once");
        var sent = h.Store.Sent;
        Assert.Equal(2, sent.Count);
        Assert.Same(sent[0], sent[1]);
        Assert.Equal(1, h.Store.Commits);
        Assert.Equal(1, h.Store.Receipts);
        Assert.Equal(result.Value.User, h.Store.Users.Single());
        Assert.Equal(result.Value.Workspace, h.Store.Workspaces.Single());
        Assert.Equal(result.Value.Credential, h.Store.Credentials.Single());
    }

    [Fact]
    public async Task AnOutcomeThatStaysUnknownIsResentOnlyAsTheIdenticalCommandAndThenReportedAsAConflict()
    {
        var h = new IdentityHarness();
        h.Store.ForceNext([.. Enumerable.Repeat(CommitOutcome.Unknown, IdentityService.MaxAttempts)]);
        var command = h.Command();
        var result = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, command, "Ada", IdentityHarness.Email("ada@example.test")), Ct);
        Assert.Equal(IdentityError.Conflict, result.Error);
        var sent = h.Store.Sent;
        Assert.Equal(IdentityService.MaxAttempts, sent.Count);
        Assert.All(sent, commit => Assert.Same(sent[0], commit));
        Assert.Equal(command, sent[0].CommandId);
        Assert.Empty(h.Store.Users);
        Assert.Equal(0, h.Store.Receipts);
    }

    [Fact]
    public async Task AnUnknownOutcomeFollowedByACommitCommitsTheIdenticalCommandOnce()
    {
        var h = new IdentityHarness();
        h.Store.ForceNext(CommitOutcome.Unknown, CommitOutcome.Unknown);
        var result = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test")), Ct);
        Assert.True(result.Value!.CreatedUser);
        var sent = h.Store.Sent;
        Assert.Equal(3, sent.Count);
        Assert.All(sent, commit => Assert.Same(sent[0], commit));
        Assert.Equal(1, h.Store.Commits);
    }

    [Fact]
    public async Task EveryWriteWhoseResponseWasLostReplaysItsOwnEffectExactlyOnce()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);

        h.Store.LoseNextResponses(1);
        var added = await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-2"), Ct);
        Assert.Equal(h.Store.Credentials.Single(c => c.Subject == "cred-2"), added.Value);

        h.Store.LoseNextResponses(1);
        var relabelled = await h.Service.RelabelCredentialAsync(caller, h.Command(), added.Value!.Id, "Work phone", Ct);
        Assert.Equal(h.Store.Credentials.Single(c => c.Subject == "cred-2"), relabelled.Value);

        h.Store.LoseNextResponses(1);
        var revoked = await h.Service.RevokeCredentialAsync(caller, h.Command(), account.Credential.Id, Ct);
        Assert.Equal(h.Store.Credentials.Single(c => c.Id == account.Credential.Id), revoked.Value);

        h.Store.LoseNextResponses(1);
        var renamed = await h.Service.RenameUserAsync(caller, h.Command(), "Ada Lovelace", Ct);
        Assert.Equal(h.Store.Users.Single(), renamed.Value);

        // Four writes after the enrollment, each sent twice (the lost response and the identical resend), each applied once.
        Assert.Equal(5, h.Store.Commits);
        Assert.Equal(9, h.Store.Sent.Count);
        Assert.Equal(4, h.Store.Users.Single().Revision); // the link, the revocation and the rename, each once
        Assert.Equal(2, h.Store.Credentials.Count);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // The same command with the same content: a replay of the original result
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task ConcurrentIdenticalEnrollmentsUnderOneCommandCreateOnceAndTheOtherReplaysAsAnExistingUser()
    {
        var h = new IdentityHarness();
        var request = new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test"));
        EnrollmentOutcome? winner = null;
        h.Store.BeforeNextCommit(() => winner = h.Service.CompleteEnrollmentAsync(request, Ct).AsTask().GetAwaiter().GetResult().Value);
        var loser = await h.Service.CompleteEnrollmentAsync(request, Ct);

        Assert.True(winner!.CreatedUser);
        Assert.True(loser.IsSuccess);
        Assert.False(loser.Value!.CreatedUser, "initial grants apply once, to the attempt that created the user");
        Assert.Equal(winner.User, loser.Value.User);
        Assert.Equal(winner.Credential, loser.Value.Credential);
        Assert.Equal(winner.Workspace, loser.Value.Workspace);
        Assert.Equal(1, h.Store.Commits);
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Credentials);
        Assert.Single(h.Store.Workspaces);

        // The loser's attempt, the winner's commit, then the probe: built from the winner's records under the same command.
        var sent = h.Store.Sent;
        Assert.Equal(3, sent.Count);
        var probe = Assert.IsType<IdentityCommit.Enroll>(sent[2]);
        Assert.Equal(request.CommandId, probe.CommandId);
        Assert.Equal(winner.User.Id, probe.User.Id);
        Assert.Equal(winner.Credential.Id, probe.Credential.Id);
        Assert.Equal(winner.Workspace.Id, probe.Workspace.Id);
        Assert.NotEqual(winner.User.Id, Assert.IsType<IdentityCommit.Enroll>(sent[0]).User.Id);
    }

    [Fact]
    public async Task ManyConcurrentRequestsOfOneCommandAndCredentialCommitOnceAndAllSucceed()
    {
        var h = new IdentityHarness();
        var request = new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("many@example.test"));
        var results = await Task.WhenAll(Enumerable.Range(0, 25).Select(_ => Task.Run(() => h.Service.CompleteEnrollmentAsync(request, Ct).AsTask())));
        Assert.All(results, r => Assert.True(r.IsSuccess, "refused: " + r.Error));
        Assert.Equal(1, results.Count(r => r.Value!.CreatedUser));
        Assert.Single(results.Select(r => r.Value!.User.Id).Distinct());
        Assert.Equal(1, h.Store.Commits);
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Workspaces);
        Assert.Single(h.Store.Credentials);
    }

    [Fact]
    public async Task AReplayedLinkReturnsTheStoredCredentialAndNotTheIdentifierThisAttemptAllocated()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        var command = h.Command();
        AuthIdentity? winner = null;
        h.Store.BeforeNextCommit(() => winner = h.Service.AddCredentialAsync(caller, command, IdentityHarness.Passkey("cred-2"), Ct).AsTask().GetAwaiter().GetResult().Value);
        var loser = await h.Service.AddCredentialAsync(caller, command, IdentityHarness.Passkey("cred-2"), Ct);
        Assert.True(loser.IsSuccess);
        Assert.Equal(winner, loser.Value);
        Assert.Equal(h.Store.Credentials.Single(c => c.Subject == "cred-2"), loser.Value);
        Assert.Equal(2, h.Store.Users.Single().Revision);
        Assert.Equal(2, h.Store.Commits);
    }

    [Fact]
    public async Task AReplayedRevocationReturnsTheStoredRevocationInstant()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        Assert.True((await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-2"), Ct)).IsSuccess);
        var command = h.Command();
        AuthIdentity? winner = null;
        h.Store.BeforeNextCommit(() =>
        {
            h.Clock.Advance(TimeSpan.FromSeconds(1));
            winner = h.Service.RevokeCredentialAsync(caller, command, account.Credential.Id, Ct).AsTask().GetAwaiter().GetResult().Value;
        });
        var loser = await h.Service.RevokeCredentialAsync(caller, command, account.Credential.Id, Ct);
        Assert.Equal(winner, loser.Value);
        Assert.Equal(h.Store.Credentials.Single(c => c.Id == account.Credential.Id), loser.Value);
        Assert.Equal(3, h.Store.Users.Single().Revision);
    }

    [Fact]
    public async Task ConcurrentIdenticalRelabelsAndRenamesReplayTheOriginalResult()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);

        var relabel = h.Command();
        AuthIdentity? relabelWinner = null;
        h.Store.BeforeNextCommit(() => relabelWinner = h.Service.RelabelCredentialAsync(caller, relabel, account.Credential.Id, "Mail", Ct).AsTask().GetAwaiter().GetResult().Value);
        var relabelLoser = await h.Service.RelabelCredentialAsync(caller, relabel, account.Credential.Id, "Mail", Ct);
        Assert.Equal(relabelWinner, relabelLoser.Value);
        Assert.Equal(h.Store.Credentials.Single(), relabelLoser.Value);

        var rename = h.Command();
        User? renameWinner = null;
        h.Store.BeforeNextCommit(() => renameWinner = h.Service.RenameUserAsync(caller, rename, "Ada L", Ct).AsTask().GetAwaiter().GetResult().Value);
        var renameLoser = await h.Service.RenameUserAsync(caller, rename, "Ada L", Ct);
        Assert.Equal(renameWinner, renameLoser.Value);
        Assert.Equal(h.Store.Users.Single(), renameLoser.Value);
        Assert.Equal(3, h.Store.Commits);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // The same command with different content: a reused identifier, nothing written
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AnEnrollmentCommandReusedForAnotherCredentialIsRefusedAndWritesNothing()
    {
        var h = new IdentityHarness();
        var command = h.Command();
        Assert.True((await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, command, "Ada", IdentityHarness.Email("ada@example.test")), Ct)).IsSuccess);
        var reused = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, command, "Bob", IdentityHarness.Email("bob@example.test")), Ct);
        Assert.Equal(IdentityError.IdentifierConflict, reused.Error);
        Assert.Null(reused.Value);
        Assert.Single(h.Store.Users);
        Assert.DoesNotContain(h.Store.Credentials, c => c.Subject == "bob@example.test");
        Assert.Equal(2, h.Store.Sent.Count); // no probe: the credential of the reused request does not exist
        Assert.Equal(1, h.Store.Commits);
    }

    [Fact]
    public async Task EveryWriteCommandReusedWithDifferentContentIsRefusedAndWritesNothing()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        var added = (await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-2"), Ct)).Value!;
        var link = h.Command();
        Assert.True((await h.Service.AddCredentialAsync(caller, link, IdentityHarness.Passkey("cred-3"), Ct)).IsSuccess);
        var credentials = h.Store.Credentials;
        Assert.Equal(IdentityError.IdentifierConflict, (await h.Service.AddCredentialAsync(caller, link, IdentityHarness.Passkey("cred-4"), Ct)).Error);
        Assert.Equal(IdentityError.IdentifierConflict, (await h.Service.RenameUserAsync(caller, link, "Other", Ct)).Error);
        Assert.Equal(IdentityError.IdentifierConflict, (await h.Service.RelabelCredentialAsync(caller, link, added.Id, "Other", Ct)).Error);
        Assert.Equal(IdentityError.IdentifierConflict, (await h.Service.RevokeCredentialAsync(caller, link, added.Id, Ct)).Error);
        // The identical rename sent again after it committed read a newer revision, so its request differs: reused, never re-executed.
        var rename = h.Command();
        Assert.True((await h.Service.RenameUserAsync(caller, rename, "Ada L", Ct)).IsSuccess);
        var users = h.Store.Users;
        var commits = h.Store.Commits;
        Assert.Equal(IdentityError.IdentifierConflict, (await h.Service.RenameUserAsync(caller, rename, "Ada L", Ct)).Error);

        Assert.Equal(users, h.Store.Users);
        Assert.Equal(credentials, h.Store.Credentials);
        Assert.Equal(commits, h.Store.Commits);
    }

    [Fact]
    public async Task AnotherUserPresentingAKnownCommandLearnsOnlyThatItIsReused()
    {
        var h = new IdentityHarness();
        var ada = await h.EnrollAsync(RealmA, "ada@example.test");
        var bob = await h.EnrollAsync(RealmA, "bob@example.test");
        var command = h.Command();
        Assert.True((await h.Service.RenameUserAsync(IdentityHarness.Caller(ada), command, "Ada L", Ct)).IsSuccess);
        var bobBefore = h.Store.Users.Single(u => u.Id == bob.User.Id);
        var reused = await h.Service.RenameUserAsync(IdentityHarness.Caller(bob), command, "Ada L", Ct);
        Assert.Equal(IdentityError.IdentifierConflict, reused.Error);
        Assert.Null(reused.Value);
        Assert.Equal(bobBefore, h.Store.Users.Single(u => u.Id == bob.User.Id));
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Expired receipts: refused, never executed as new
    // ------------------------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public async Task AnEnrollmentReplayPastTheReceiptWindowIsRefusedAndNeverExecutedAsNew(int extraMicros, bool insideWindow)
    {
        // extraMicros 0 lands exactly on the expiry instant (expired); 1 lands one microsecond before it (still a replay).
        var h = new IdentityHarness();
        var request = new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test"));
        var window = TimeSpan.FromTicks(CommitContext.ReceiptRetentionMicros * 10 - extraMicros * 10);
        h.Store.BeforeNextCommit(() =>
        {
            Assert.True(h.Service.CompleteEnrollmentAsync(request, Ct).AsTask().GetAwaiter().GetResult().IsSuccess);
            h.Clock.Advance(window);
        });
        var late = await h.Service.CompleteEnrollmentAsync(request, Ct);
        if (insideWindow)
        {
            Assert.True(late.IsSuccess);
            Assert.False(late.Value!.CreatedUser);
        }
        else
        {
            Assert.Equal(IdentityError.ReceiptExpired, late.Error);
        }

        Assert.Equal(1, h.Store.Commits);
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Workspaces);
    }

    [Fact]
    public async Task EveryWriteAnsweredWithAnExpiredReceiptIsRefusedWithoutAResendOrAReread()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        var added = (await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-2"), Ct)).Value!;
        var users = h.Store.Users;
        var credentials = h.Store.Credentials;
        var writes = new Func<Task<IdentityError?>>[]
        {
            async () => (await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Bob", IdentityHarness.Email("bob@example.test")), Ct)).Error,
            async () => (await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-3"), Ct)).Error,
            async () => (await h.Service.RevokeCredentialAsync(caller, h.Command(), added.Id, Ct)).Error,
            async () => (await h.Service.RelabelCredentialAsync(caller, h.Command(), added.Id, "Other", Ct)).Error,
            async () => (await h.Service.RenameUserAsync(caller, h.Command(), "Other", Ct)).Error,
        };
        foreach (var write in writes)
        {
            var before = h.Store.Sent.Count;
            h.Store.ForceNext(CommitOutcome.ReceiptExpired);
            Assert.Equal(IdentityError.ReceiptExpired, await write());
            Assert.Equal(before + 1, h.Store.Sent.Count);
        }

        Assert.Equal(users, h.Store.Users);
        Assert.Equal(credentials, h.Store.Credentials);
    }

    [Fact]
    public async Task EveryWriteAnsweredWithAReusedIdentifierIsRefusedWithoutAResend()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        var added = (await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-2"), Ct)).Value!;
        var writes = new Func<Task<IdentityError?>>[]
        {
            async () => (await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-3"), Ct)).Error,
            async () => (await h.Service.RevokeCredentialAsync(caller, h.Command(), added.Id, Ct)).Error,
            async () => (await h.Service.RelabelCredentialAsync(caller, h.Command(), added.Id, "Other", Ct)).Error,
            async () => (await h.Service.RenameUserAsync(caller, h.Command(), "Other", Ct)).Error,
        };
        foreach (var write in writes)
        {
            var before = h.Store.Sent.Count;
            h.Store.ForceNext(CommitOutcome.IdentifierConflict);
            Assert.Equal(IdentityError.IdentifierConflict, await write());
            Assert.Equal(before + 1, h.Store.Sent.Count);
        }
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // The enrollment receipt probe never writes
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AProbeWhoseReceiptIsGoneIsRefusedAndWritesNothing()
    {
        var h = new IdentityHarness();
        h.Store.BeforeNextCommit(() =>
        {
            // Another command created the credential, and the store then answers this attempt as a reused identifier.
            Assert.True(h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test")), Ct).AsTask().GetAwaiter().GetResult().IsSuccess);
            h.Store.ForceNext(CommitOutcome.IdentifierConflict);
        });
        var result = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test")), Ct);
        Assert.Equal(IdentityError.IdentifierConflict, result.Error);
        Assert.Equal(3, h.Store.Sent.Count); // the attempt, the other command's commit, the probe (refused by every guard)
        Assert.Equal(1, h.Store.Commits);
        Assert.Equal(1, h.Store.Receipts);
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Workspaces);
        Assert.Single(h.Store.Credentials);
    }

    [Fact]
    public async Task AProbeNeverAdoptsRecordsAnotherCommandCreated()
    {
        var h = new IdentityHarness();
        var command = h.Command();
        Assert.True((await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, command, "Bob", IdentityHarness.Email("bob@example.test")), Ct)).IsSuccess);
        h.Store.BeforeNextCommit(() =>
            Assert.True(h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test")), Ct).AsTask().GetAwaiter().GetResult().IsSuccess));
        var result = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, command, "Ada", IdentityHarness.Email("ada@example.test")), Ct);
        Assert.Equal(IdentityError.IdentifierConflict, result.Error);
        Assert.Null(result.Value);
        Assert.Equal(2, h.Store.Commits);
        Assert.Equal(2, h.Store.Users.Count);
        Assert.IsType<IdentityCommit.Enroll>(h.Store.Sent[^1]);
    }

    [Fact]
    public async Task AProbeIsNotSentForAnUnusableCredential()
    {
        var h = new IdentityHarness();
        var request = new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("ada@example.test"));
        h.Store.BeforeNextCommit(() =>
        {
            var created = h.Service.CompleteEnrollmentAsync(request, Ct).AsTask().GetAwaiter().GetResult().Value!;
            h.Store.SetUserState(created.User.Id, UserState.Suspended);
        });
        var result = await h.Service.CompleteEnrollmentAsync(request, Ct);
        Assert.Equal(IdentityError.IdentifierConflict, result.Error);
        Assert.Equal(2, h.Store.Sent.Count);
        Assert.Equal(1, h.Store.Commits);
    }

    [Fact]
    public async Task AProbeWhoseOutcomeStaysUnknownIsAConflictAndAProbeTheStoreAppliedIsADefect()
    {
        var h = new IdentityHarness();
        await h.EnrollAsync(RealmA, "ada@example.test");
        var request = new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("bob@example.test"));
        h.Store.BeforeNextCommit(() =>
        {
            Assert.True(h.Service.CompleteEnrollmentAsync(request with { CommandId = h.Command() }, Ct).AsTask().GetAwaiter().GetResult().IsSuccess);
            h.Store.ForceNext([CommitOutcome.IdentifierConflict, .. Enumerable.Repeat(CommitOutcome.Unknown, IdentityService.MaxAttempts)]);
        });
        Assert.Equal(IdentityError.Conflict, (await h.Service.CompleteEnrollmentAsync(request, Ct)).Error);
        Assert.Equal(2, h.Store.Commits);

        var other = new IdentityHarness();
        var broken = new EnrollmentRequest(RealmA, other.Command(), "Cy", IdentityHarness.Email("cy@example.test"));
        other.Store.BeforeNextCommit(() =>
        {
            Assert.True(other.Service.CompleteEnrollmentAsync(broken with { CommandId = other.Command() }, Ct).AsTask().GetAwaiter().GetResult().IsSuccess);
            other.Store.ForceNext(CommitOutcome.IdentifierConflict, CommitOutcome.Committed);
        });
        await Assert.ThrowsAsync<InvalidOperationException>(() => other.Service.CompleteEnrollmentAsync(broken, Ct).AsTask());
        Assert.Single(other.Store.Users);
    }
}
