// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

public sealed class IdentityServiceTests
{
    private static readonly RealmId RealmA = IdentityHarness.RealmA;
    private static readonly RealmId RealmB = IdentityHarness.RealmB;

    // ------------------------------------------------------------------------------------------------------------------------
    // Enrollment and the single-owner workspace
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AnEnrollmentCreatesTheUserTheCredentialAndExactlyOnePersonalWorkspaceOwnedByTheUser()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test", "Ada Lovelace");
        Assert.True(account.CreatedUser);
        Assert.Equal(account.User.Id, account.Workspace.OwnerUserId);
        Assert.Equal(RealmA, account.Workspace.Realm);
        Assert.Equal(UserState.Active, account.User.State);
        Assert.Equal(1, account.User.Revision);
        Assert.Equal(account.User.Id, account.Credential.UserId);
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Workspaces);
        Assert.Single(h.Store.Credentials);
        Assert.Equal(IdentityRules.PersonalWorkspaceName, account.Workspace.Name);
        Assert.Equal(h.Clock.GetUtcNow().ToUnixTimeMilliseconds() * 1000, account.User.CreatedAt.Value);
    }

    [Fact]
    public async Task ACompletionByAnExistingCredentialSignsTheSameUserInAndCreatesNothing()
    {
        var h = new IdentityHarness();
        var first = await h.EnrollAsync(RealmA, "ada@example.test");
        var again = await h.EnrollAsync(RealmA, "ada@example.test", "Another name");
        Assert.False(again.CreatedUser, "initial grants apply only to a created user");
        Assert.Equal(first.User.Id, again.User.Id);
        Assert.Equal(first.Workspace.Id, again.Workspace.Id);
        Assert.Equal("Ada", again.User.DisplayName);
        Assert.Equal(1, h.Store.Commits);
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Workspaces);
    }

    [Fact]
    public async Task TheSameSubjectInAnotherRealmIsAnotherIdentityWithItsOwnWorkspace()
    {
        var h = new IdentityHarness();
        var a = await h.EnrollAsync(RealmA, "ada@example.test");
        var b = await h.EnrollAsync(RealmB, "ada@example.test");
        Assert.NotEqual(a.User.Id, b.User.Id);
        Assert.NotEqual(a.Workspace.Id, b.Workspace.Id);
        Assert.Equal(2, h.Store.Users.Count);
        Assert.True(b.CreatedUser);
        // Neither realm can authorize the other's workspace, even with the other's identifiers.
        Assert.Equal(IdentityError.NotFound, (await h.Service.AuthorizeWorkspaceAsync(new Principal(RealmB, a.User.Id), a.Workspace.Id, TestContext.Current.CancellationToken)).Error);
        Assert.Equal(IdentityError.NotFound, (await h.Service.AuthorizeWorkspaceAsync(new Principal(RealmA, b.User.Id), b.Workspace.Id, TestContext.Current.CancellationToken)).Error);
    }

    [Fact]
    public async Task ALostEnrollmentRaceIsRereadAndEndsAsTheWinnersUserNotAsASecondUser()
    {
        var h = new IdentityHarness();
        var winner = (EnrollmentOutcome?)null;
        // The commit of the loser meets a winner that committed the same credential first.
        h.Store.BeforeNextCommit(() =>
        {
            var other = h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Winner", IdentityHarness.Email("race@example.test")), TestContext.Current.CancellationToken).AsTask().GetAwaiter().GetResult();
            winner = other.Value;
        });
        var loser = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Loser", IdentityHarness.Email("race@example.test")), TestContext.Current.CancellationToken);
        Assert.True(loser.IsSuccess);
        Assert.False(loser.Value!.CreatedUser);
        Assert.Equal(winner!.User.Id, loser.Value.User.Id);
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Workspaces);
    }

    [Fact]
    public async Task ManyConcurrentEnrollmentsOfOneCredentialCreateExactlyOneUserAndOneWorkspace()
    {
        var h = new IdentityHarness();
        var results = await Task.WhenAll(Enumerable.Range(0, 64).Select(i => Task.Run(() =>
            h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada " + i, IdentityHarness.Email("many@example.test")), TestContext.Current.CancellationToken).AsTask())));
        Assert.All(results, r => Assert.True(r.IsSuccess));
        Assert.Equal(1, results.Count(r => r.Value!.CreatedUser));
        Assert.Single(results.Select(r => r.Value!.User.Id).Distinct());
        Assert.Single(h.Store.Users);
        Assert.Single(h.Store.Workspaces);
        Assert.Single(h.Store.Credentials);
    }

    [Fact]
    public async Task ARefusedCommitIsRereadAtMostMaxAttemptsTimesAndThenReportedAsAConflict()
    {
        var h = new IdentityHarness();
        h.Store.RefuseNext(IdentityService.MaxAttempts);
        var result = await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("a@example.test")), TestContext.Current.CancellationToken);
        Assert.Equal(IdentityError.Conflict, result.Error);
        Assert.Empty(h.Store.Users);
        h.Store.RefuseNext(IdentityService.MaxAttempts - 1);
        Assert.True((await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Email("a@example.test")), TestContext.Current.CancellationToken)).IsSuccess);
    }

    [Fact]
    public async Task EnrollmentRefusesMalformedRequestsBeforeTouchingTheStore()
    {
        var h = new IdentityHarness();
        var good = IdentityHarness.Email("a@example.test");
        var cases = new[]
        {
            new EnrollmentRequest(default, h.Command(), "Ada", good),
            new EnrollmentRequest(RealmA, "not-a-uuid", "Ada", good),
            new EnrollmentRequest(RealmA, h.Command(), "", good),
            new EnrollmentRequest(RealmA, h.Command(), "Ada", good with { Subject = "" }),
            new EnrollmentRequest(RealmA, h.Command(), "Ada", good with { ProviderId = "BAD" }),
            new EnrollmentRequest(RealmA, h.Command(), "Ada", good with { Method = AuthMethod.Password }),
            new EnrollmentRequest(RealmA, h.Command(), "Ada", IdentityHarness.Passkey("x") with { Passkey = null }),
        };
        foreach (var request in cases) Assert.Equal(IdentityError.InvalidRequest, (await h.Service.CompleteEnrollmentAsync(request, TestContext.Current.CancellationToken)).Error);
        Assert.Equal(0, h.Store.Reads);
        Assert.Empty(h.Store.Users);
    }

    [Fact]
    public async Task APasskeyAndAPasswordUserEnrollWithTheirMethodData()
    {
        var h = new IdentityHarness();
        var passkey = await h.EnrollAsync(RealmA, "cred-1", credential: IdentityHarness.Passkey("cred-1"));
        Assert.Equal(AuthMethod.Passkey, passkey.Credential.Method);
        Assert.NotNull(passkey.Credential.Passkey);
        var password = await h.EnrollAsync(RealmA, "ada", credential: IdentityHarness.Password("ada"));
        Assert.Equal(AuthMethod.Password, password.Credential.Method);
        Assert.NotNull(password.Credential.Password);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Identity change continuity (BR-04)
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AddingRevokingAndRelabellingCredentialsNeverChangesTheUserTheUserIdentifierOrTheWorkspace()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test", "Ada");
        var caller = IdentityHarness.Caller(account);
        var workspaceBefore = h.Store.Workspaces.Single();
        var userBefore = h.Store.Users.Single();

        var passkey = (await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-2"), TestContext.Current.CancellationToken)).Value!;
        var oidc = (await h.Service.AddCredentialAsync(caller, h.Command(), new NewCredential("corp-oidc", AuthMethod.Oidc, "issuer|sub", null, null, null), TestContext.Current.CancellationToken)).Value!;
        Assert.True((await h.Service.RelabelCredentialAsync(caller, h.Command(), passkey.Id, "Work phone", TestContext.Current.CancellationToken)).IsSuccess);
        Assert.True((await h.Service.RevokeCredentialAsync(caller, h.Command(), account.Credential.Id, TestContext.Current.CancellationToken)).IsSuccess);
        Assert.True((await h.Service.RevokeCredentialAsync(caller, h.Command(), oidc.Id, TestContext.Current.CancellationToken)).IsSuccess);

        var userAfter = h.Store.Users.Single();
        Assert.Equal(userBefore.Id, userAfter.Id);
        Assert.Equal(userBefore with { Revision = userAfter.Revision }, userAfter);
        Assert.Equal(workspaceBefore, h.Store.Workspaces.Single());
        Assert.Equal(5, userAfter.Revision); // two links and two revocations advance the lifecycle revision; the relabel does not
        Assert.All(h.Store.Credentials, credential => Assert.Equal(userBefore.Id, credential.UserId));
        Assert.Equal(1, h.Store.Credentials.Count(credential => !credential.IsRevoked));
        var resolved = await h.Service.ResolveCredentialAsync(RealmA, "official-passkey", "cred-2", TestContext.Current.CancellationToken);
        Assert.Equal(userBefore.Id, resolved.Value!.User.Id);
        Assert.Equal("Work phone", resolved.Value.Credential.Label);
    }

    [Fact]
    public async Task ARevokedCredentialNoLongerResolvesButTheUserAndItsWorkspaceStillDo()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        Assert.True((await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("cred-2"), TestContext.Current.CancellationToken)).IsSuccess);
        Assert.True((await h.Service.RevokeCredentialAsync(caller, h.Command(), account.Credential.Id, TestContext.Current.CancellationToken)).IsSuccess);
        Assert.Equal(IdentityError.CredentialUnavailable, (await h.Service.ResolveCredentialAsync(RealmA, "official-email", "ada@example.test", TestContext.Current.CancellationToken)).Error);
        Assert.True((await h.Service.GetPersonalWorkspaceAsync(caller, TestContext.Current.CancellationToken)).IsSuccess);
        Assert.Equal(account.Workspace.Id, (await h.Service.GetPersonalWorkspaceAsync(caller, TestContext.Current.CancellationToken)).Value!.Id);
    }

    [Fact]
    public async Task ARenameChangesTheNameAndNothingElse()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test", "Ada");
        var renamed = await h.Service.RenameUserAsync(IdentityHarness.Caller(account), h.Command(), "Ada Lovelace", TestContext.Current.CancellationToken);
        Assert.Equal("Ada Lovelace", renamed.Value!.DisplayName);
        Assert.Equal(account.User.Id, renamed.Value.Id);
        Assert.Equal(account.User.CreatedAt, renamed.Value.CreatedAt);
        Assert.Equal(IdentityError.InvalidRequest, (await h.Service.RenameUserAsync(IdentityHarness.Caller(account), h.Command(), " ", TestContext.Current.CancellationToken)).Error);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Linking races and the last-credential rule
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task ACredentialLinkedToAnyoneInTheRealmCannotBeLinkedAndTheRefusalNamesNoOwner()
    {
        var h = new IdentityHarness();
        var ada = await h.EnrollAsync(RealmA, "ada@example.test");
        var bob = await h.EnrollAsync(RealmA, "bob@example.test");
        var stolen = await h.Service.AddCredentialAsync(IdentityHarness.Caller(bob), h.Command(), IdentityHarness.Email("ada@example.test"), TestContext.Current.CancellationToken);
        var own = await h.Service.AddCredentialAsync(IdentityHarness.Caller(ada), h.Command(), IdentityHarness.Email("ada@example.test"), TestContext.Current.CancellationToken);
        Assert.Equal(IdentityError.CredentialUnavailable, stolen.Error);
        Assert.Equal(stolen, own);
        Assert.Single(h.Store.Credentials, c => c.Subject == "ada@example.test");
    }

    [Fact]
    public async Task ALinkDecidedBeforeAConcurrentLinkCommittedIsRereadAndStillSucceedsOnTheCurrentRevision()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        h.Store.BeforeNextCommit(() => Assert.True(h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("winner"), TestContext.Current.CancellationToken).AsTask().GetAwaiter().GetResult().IsSuccess));
        var result = await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("loser"), TestContext.Current.CancellationToken);
        Assert.True(result.IsSuccess);
        Assert.Equal(3, h.Store.Credentials.Count);
        Assert.Equal(3, h.Store.Users.Single().Revision);
    }

    [Fact]
    public async Task TwoUsersLinkingTheSameCredentialConcurrentlyEndWithExactlyOneOwner()
    {
        var h = new IdentityHarness();
        var ada = await h.EnrollAsync(RealmA, "ada@example.test");
        var bob = await h.EnrollAsync(RealmA, "bob@example.test");
        var results = await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() =>
            h.Service.AddCredentialAsync(IdentityHarness.Caller(i % 2 == 0 ? ada : bob), h.Command(), IdentityHarness.Passkey("shared"), TestContext.Current.CancellationToken).AsTask())));
        Assert.Equal(1, results.Count(r => r.IsSuccess));
        Assert.All(results.Where(r => !r.IsSuccess), r => Assert.Equal(IdentityError.CredentialUnavailable, r.Error));
        Assert.Single(h.Store.Credentials, c => c.Subject == "shared");
    }

    [Fact]
    public async Task TheLastCredentialCannotBeRevokedWithoutARecoveryPathAndCanBeWithOne()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        Assert.Equal(IdentityError.LastCredential, (await h.Service.RevokeCredentialAsync(caller, h.Command(), account.Credential.Id, TestContext.Current.CancellationToken)).Error);
        Assert.False(h.Store.Credentials.Single().IsRevoked);
        h.Store.SetRecoveryPath(account.User.Id, true);
        Assert.True((await h.Service.RevokeCredentialAsync(caller, h.Command(), account.Credential.Id, TestContext.Current.CancellationToken)).IsSuccess);
    }

    [Fact]
    public async Task ConcurrentRevocationsOfAUsersCredentialsNeverLeaveItWithoutOne()
    {
        for (var round = 0; round < 25; round++)
        {
            var h = new IdentityHarness();
            var account = await h.EnrollAsync(RealmA, "ada@example.test");
            var caller = IdentityHarness.Caller(account);
            var extra = new List<AuthIdentity>();
            for (var i = 0; i < 3; i++) extra.Add((await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("c" + i), TestContext.Current.CancellationToken)).Value!);
            var targets = new[] { account.Credential.Id }.Concat(extra.Select(c => c.Id)).ToArray();
            var results = await Task.WhenAll(targets.Select(id => Task.Run(() => h.Service.RevokeCredentialAsync(caller, h.Command(), id, TestContext.Current.CancellationToken).AsTask())));
            Assert.True(h.Store.Credentials.Any(c => !c.IsRevoked), "the user keeps a usable credential");
            Assert.All(results.Where(r => !r.IsSuccess), r => Assert.Contains(r.Error, new IdentityError?[] { IdentityError.LastCredential, IdentityError.Conflict }));
        }
    }

    [Fact]
    public async Task ACredentialOfAnotherUserOrRealmCannotBeRevokedOrRelabelled()
    {
        var h = new IdentityHarness();
        var ada = await h.EnrollAsync(RealmA, "ada@example.test");
        var bob = await h.EnrollAsync(RealmA, "bob@example.test");
        var carol = await h.EnrollAsync(RealmB, "carol@example.test");
        Assert.True((await h.Service.AddCredentialAsync(IdentityHarness.Caller(bob), h.Command(), IdentityHarness.Passkey("b2"), TestContext.Current.CancellationToken)).IsSuccess);
        var before = h.Store.Credentials.ToArray();
        Assert.Equal(IdentityError.NotFound, (await h.Service.RevokeCredentialAsync(IdentityHarness.Caller(ada), h.Command(), bob.Credential.Id, TestContext.Current.CancellationToken)).Error);
        Assert.Equal(IdentityError.NotFound, (await h.Service.RevokeCredentialAsync(IdentityHarness.Caller(ada), h.Command(), carol.Credential.Id, TestContext.Current.CancellationToken)).Error);
        Assert.Equal(IdentityError.NotFound, (await h.Service.RelabelCredentialAsync(IdentityHarness.Caller(ada), h.Command(), bob.Credential.Id, "mine now", TestContext.Current.CancellationToken)).Error);
        Assert.Equal(IdentityError.NotFound, (await h.Service.RelabelCredentialAsync(new Principal(RealmB, ada.User.Id), h.Command(), ada.Credential.Id, "x", TestContext.Current.CancellationToken)).Error);
        Assert.Equal(before.OrderBy(c => c.Id.Value), h.Store.Credentials.OrderBy(c => c.Id.Value));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task OnlyAnActiveUserLinksAndOnlyAnActiveOrRestrictedUserChangesCredentials(int stored)
    {
        var state = (UserState)stored;
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        Assert.True((await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("c2"), TestContext.Current.CancellationToken)).IsSuccess);
        h.Store.SetUserState(account.User.Id, state);
        Assert.Equal(IdentityError.NotPermitted, (await h.Service.AddCredentialAsync(caller, h.Command(), IdentityHarness.Passkey("c3"), TestContext.Current.CancellationToken)).Error);
        var change = await h.Service.RelabelCredentialAsync(caller, h.Command(), account.Credential.Id, "x", TestContext.Current.CancellationToken);
        if (state == UserState.Restricted) Assert.True(change.IsSuccess);
        else Assert.Equal(IdentityError.NotPermitted, change.Error);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Ownership, tenant leakage and enumeration
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task OnlyTheOwnerAuthorizesTheWorkspaceAndEveryOtherCaseIsOneRefusal()
    {
        var h = new IdentityHarness();
        var ada = await h.EnrollAsync(RealmA, "ada@example.test");
        var bob = await h.EnrollAsync(RealmA, "bob@example.test");
        var owner = await h.Service.AuthorizeWorkspaceAsync(IdentityHarness.Caller(ada), ada.Workspace.Id, TestContext.Current.CancellationToken);
        Assert.Equal(ada.Workspace, owner.Value);
        var other = await h.Service.AuthorizeWorkspaceAsync(IdentityHarness.Caller(bob), ada.Workspace.Id, TestContext.Current.CancellationToken);
        var unknown = await h.Service.AuthorizeWorkspaceAsync(IdentityHarness.Caller(bob), WorkspaceId.Parse("00000000-0000-4000-8000-0000000000ff"), TestContext.Current.CancellationToken);
        var foreignRealm = await h.Service.AuthorizeWorkspaceAsync(new Principal(RealmB, ada.User.Id), ada.Workspace.Id, TestContext.Current.CancellationToken);
        var none = await h.Service.AuthorizeWorkspaceAsync(IdentityHarness.Caller(ada), default, TestContext.Current.CancellationToken);
        Assert.Equal(IdentityResult<Workspace>.Failure(IdentityError.NotFound), other);
        Assert.Equal(other, unknown);
        Assert.Equal(other, foreignRealm);
        Assert.Equal(other, none);
    }

    [Fact]
    public async Task ACredentialIdentifierIsNeverAUserIdentifier()
    {
        var h = new IdentityHarness();
        var account = await h.EnrollAsync(RealmA, "ada@example.test");
        // The only way to reuse the text of a credential as a user is to parse it as one: such a user does not exist.
        var asUser = new Principal(RealmA, UserId.Parse(account.Credential.Id.Value));
        Assert.Equal(IdentityError.NotFound, (await h.Service.AuthorizeWorkspaceAsync(asUser, account.Workspace.Id, TestContext.Current.CancellationToken)).Error);
        Assert.Equal(IdentityError.NotFound, (await h.Service.GetPersonalWorkspaceAsync(asUser, TestContext.Current.CancellationToken)).Error);
        Assert.Equal(IdentityError.NotFound, (await h.Service.RenameUserAsync(asUser, h.Command(), "Mallory", TestContext.Current.CancellationToken)).Error);
        Assert.Equal("Ada", h.Store.Users.Single().DisplayName);
    }

    [Fact]
    public async Task UnknownRevokedForeignRealmAndSuspendedSubjectsAreOneIndistinguishableRefusal()
    {
        var h = new IdentityHarness();
        var ada = await h.EnrollAsync(RealmA, "ada@example.test");
        var gone = await h.EnrollAsync(RealmA, "gone@example.test");
        var suspended = await h.EnrollAsync(RealmA, "suspended@example.test");
        Assert.True((await h.Service.AddCredentialAsync(IdentityHarness.Caller(gone), h.Command(), IdentityHarness.Passkey("g2"), TestContext.Current.CancellationToken)).IsSuccess);
        Assert.True((await h.Service.RevokeCredentialAsync(IdentityHarness.Caller(gone), h.Command(), gone.Credential.Id, TestContext.Current.CancellationToken)).IsSuccess);
        h.Store.SetUserState(suspended.User.Id, UserState.Suspended);

        var known = await h.Service.ResolveCredentialAsync(RealmA, "official-email", "ada@example.test", TestContext.Current.CancellationToken);
        Assert.Equal(ada.User.Id, known.Value!.User.Id);
        var refusals = new[]
        {
            await h.Service.ResolveCredentialAsync(RealmA, "official-email", "nobody@example.test", TestContext.Current.CancellationToken),
            await h.Service.ResolveCredentialAsync(RealmA, "official-email", "gone@example.test", TestContext.Current.CancellationToken),
            await h.Service.ResolveCredentialAsync(RealmB, "official-email", "ada@example.test", TestContext.Current.CancellationToken),
            await h.Service.ResolveCredentialAsync(RealmA, "official-email", "suspended@example.test", TestContext.Current.CancellationToken),
            await h.Service.ResolveCredentialAsync(RealmA, "official-passkey", "ada@example.test", TestContext.Current.CancellationToken),
            await h.Service.ResolveCredentialAsync(RealmA, "BAD PROVIDER", "ada@example.test", TestContext.Current.CancellationToken),
            await h.Service.ResolveCredentialAsync(default, "official-email", "ada@example.test", TestContext.Current.CancellationToken),
        };
        Assert.All(refusals, refusal => Assert.Equal(IdentityResult<CredentialResolution>.Failure(IdentityError.CredentialUnavailable), refusal));
        // The enrollment path says the same about a revoked or suspended credential.
        foreach (var subject in new[] { "gone@example.test", "suspended@example.test" })
            Assert.Equal(IdentityError.CredentialUnavailable, (await h.Service.CompleteEnrollmentAsync(new EnrollmentRequest(RealmA, h.Command(), "x", IdentityHarness.Email(subject)), TestContext.Current.CancellationToken)).Error);
    }

    [Fact]
    public async Task AWorkspaceHasNoMembersOrRolesAndTheOwnerRelationIsTheOnlyLinkToAUser()
    {
        var h = new IdentityHarness();
        var ada = await h.EnrollAsync(RealmA, "ada@example.test");
        var bob = await h.EnrollAsync(RealmA, "bob@example.test");
        // Every API that could grant a second principal access takes a Principal and decides by Owns; there is no other relation to add.
        var properties = typeof(Workspace).GetProperties().Select(p => p.Name).Order().ToArray();
        Assert.Equal(["CreatedAt", "DataRegion", "Id", "Name", "OwnerUserId", "Realm", "Revision", "State"], properties.Where(n => n != "EqualityContract"));
        Assert.Equal(ada.User.Id, h.Store.Workspaces.Single(w => w.Id == ada.Workspace.Id).OwnerUserId);
        Assert.Equal(bob.User.Id, h.Store.Workspaces.Single(w => w.Id == bob.Workspace.Id).OwnerUserId);
        Assert.Equal(2, h.Store.Workspaces.Select(w => w.OwnerUserId).Distinct().Count());
    }
}
