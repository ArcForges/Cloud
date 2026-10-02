// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Storage;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class SessionServiceTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] Workspaces = ["33333333-3333-4333-8333-333333333333"];

    private static (SessionService Service, FakeStorage Storage, FakeTime Time) Create(FoundationOptions? options = null)
    {
        var storage = new FakeStorage();
        var time = new FakeTime(Start);
        return (new SessionService(storage, options ?? T.Options(), time), storage, time);
    }

    private static Task<IssuedSession> Issue(SessionService service) =>
        service.IssueAsync(T.Uuid(), T.Uuid(), Workspaces, T.Ct);

    [Fact]
    public async Task OnlyTheHashOfTheHandleIsStoredAndTheHandleIsTheCookieValue()
    {
        var (service, storage, _) = Create();
        var issued = await Issue(service);
        Assert.Equal(43, issued.Handle.Length);
        Assert.True(SessionService.TryParseHandle(issued.Handle, out var handle));
        var stored = Assert.Single(storage.Sessions);
        Assert.Equal(System.Security.Cryptography.SHA256.HashData(handle), stored.Hash);
        Assert.DoesNotContain(issued.Handle, string.Join('|', storage.Outbox.Select(o => o.Payload)), StringComparison.Ordinal);
        Assert.Equal(Start.AddHours(12), SessionService.FromMicros(issued.AbsoluteExpiresAt));
        Assert.Equal(Start.AddMinutes(30), SessionService.FromMicros(issued.IdleExpiresAt));
        Assert.Equal(1, storage.Sessions[0].Epoch);
        var resolved = await service.ResolveAsync(issued.Handle, T.Ct);
        Assert.True(resolved.IsAuthenticated);
        Assert.Equal(issued.SessionId, resolved.Session!.SessionId);
        Assert.Equal(Workspaces, resolved.Session.WorkspaceIds);
    }

    [Fact]
    public async Task EveryMalformedOrUnknownHandleIsUnauthenticatedWithoutAnyReadForMalformedOnes()
    {
        var (service, storage, _) = Create();
        var issued = await Issue(service);
        foreach (var bad in new string?[] { null, "", issued.Handle[..42], issued.Handle + "A", issued.Handle + "=", "+" + issued.Handle[1..], new string(' ', 43) })
            Assert.False((await service.ResolveAsync(bad, T.Ct)).IsAuthenticated, bad);
        Assert.Equal(0, storage.Executions("foundation.session-load"));
        var other = Base64Url.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        Assert.False((await service.ResolveAsync(other, T.Ct)).IsAuthenticated);
        Assert.Equal(1, storage.Executions("foundation.session-load"));
    }

    [Fact]
    public async Task AbsoluteIdleAndRecoveryGenerationExpiriesAreEnforcedOnEveryResolve()
    {
        var (service, _, time) = Create();
        var issued = await Issue(service);
        time.Advance(TimeSpan.FromMinutes(29));
        Assert.True((await service.ResolveAsync(issued.Handle, T.Ct)).IsAuthenticated);
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.False((await service.ResolveAsync(issued.Handle, T.Ct)).IsAuthenticated, "idle expiry");

        var (renewing, _, clock) = Create();
        var kept = await Issue(renewing);
        for (var step = 0; step < 24; step++)
        {
            clock.Advance(TimeSpan.FromMinutes(29));
            var resolution = await renewing.ResolveAsync(kept.Handle, T.Ct);
            Assert.True(resolution.IsAuthenticated, "renewed at step " + step);
            await renewing.TouchAsync(resolution, T.Ct);
        }

        clock.Advance(TimeSpan.FromMinutes(29));
        Assert.False((await renewing.ResolveAsync(kept.Handle, T.Ct)).IsAuthenticated, "absolute expiry at twelve hours");

        var (other, storage, _) = Create(T.Options(7));
        storage.ActiveGeneration = 7;
        var issuedOther = await Issue(other);
        Assert.True((await other.ResolveAsync(issuedOther.Handle, T.Ct)).IsAuthenticated);
        storage.Sessions[0] = storage.Sessions[0] with { Generation = 6 };
        Assert.False((await other.ResolveAsync(issuedOther.Handle, T.Ct)).IsAuthenticated, "foreign recovery generation");
    }

    [Fact]
    public async Task TouchNeverExtendsPastTheAbsoluteExpiryAndZeroChangesIsNotAnError()
    {
        var (service, storage, time) = Create();
        var issued = await Issue(service);
        for (var step = 0; step < 24; step++)
        {
            time.Advance(TimeSpan.FromMinutes(29));
            await service.TouchAsync(await service.ResolveAsync(issued.Handle, T.Ct), T.Ct);
        }

        time.Advance(TimeSpan.FromMinutes(20));
        var resolution = await service.ResolveAsync(issued.Handle, T.Ct);
        Assert.True(resolution.IsAuthenticated);
        var touched = await service.TouchAsync(resolution, T.Ct);
        Assert.Equal(touched.Session!.AbsoluteExpiresAt, touched.Session.IdleExpiresAt);
        Assert.Equal(touched.Session.AbsoluteExpiresAt, storage.Sessions[0].Idle);
        Assert.Equal("happened", (await service.RevokeAsync(issued.SessionId, T.Ct)).Effect);
        // A revoked session matches zero rows: nothing is renewed and nothing fails.
        var after = await service.TouchAsync(touched, T.Ct);
        Assert.Equal(touched, after);
        Assert.Equal(SessionResolution.Unauthenticated, await service.TouchAsync(SessionResolution.Unauthenticated, T.Ct));
    }

    [Fact]
    public async Task RevocationIsDurableIdempotentAndSeenByAnotherContainer()
    {
        var (service, storage, time) = Create();
        var issued = await Issue(service);
        var receipt = await service.RevokeAsync(issued.SessionId, T.Ct);
        Assert.Equal("happened", receipt.Effect);
        Assert.NotEqual(Guid.Empty, receipt.CommandId);
        // A second Container instance over the same storage sees the revocation at once.
        var another = new SessionService(storage, T.Options(), time);
        Assert.False((await another.ResolveAsync(issued.Handle, T.Ct)).IsAuthenticated);
        Assert.Equal(2, storage.Outbox.Count);
        Assert.Contains(storage.Outbox, o => o.Key == "session.revoked");
        // Revoking again or an unknown id changes nothing and is reported honestly.
        var again = await service.RevokeAsync(issued.SessionId, T.Ct);
        Assert.Equal("didNotHappen", again.Effect);
        Assert.Equal("didNotHappen", (await service.RevokeAsync(T.Uuid(), T.Ct)).Effect);
        Assert.Equal(2, storage.Outbox.Count);
        Assert.Equal("logout", storage.Sessions[0].Reason);
    }

    [Fact]
    public async Task AnUnknownRevokeOutcomeIsReportedAsUnknownNotAsSafe()
    {
        var (service, storage, _) = Create();
        var issued = await Issue(service);
        storage.Fault = call => call.Plan.Id == "foundation.session-revoke" ? PlanFailureKind.UnknownOutcome : null;
        Assert.Equal("unknown", (await service.RevokeAsync(issued.SessionId, T.Ct)).Effect);
        storage.Fault = call => call.Plan.Id == "foundation.session-revoke" ? PlanFailureKind.Unavailable : null;
        await Assert.ThrowsAsync<PlanFailureException>(() => service.RevokeAsync(issued.SessionId, T.Ct));
    }

    [Fact]
    public async Task CsrfIsBoundToTheSessionAndTheAnonymousTokenNeverVerifies()
    {
        var (service, _, _) = Create();
        var first = await Issue(service);
        var second = await Issue(service);
        var resolved = await service.ResolveAsync(first.Handle, T.Ct);
        var other = await service.ResolveAsync(second.Handle, T.Ct);
        Assert.Equal(43, first.CsrfToken.Length);
        Assert.NotEqual(first.CsrfToken, second.CsrfToken);
        Assert.True(service.VerifyCsrf(resolved, first.CsrfToken));
        Assert.False(service.VerifyCsrf(resolved, second.CsrfToken));
        Assert.False(service.VerifyCsrf(other, first.CsrfToken));
        Assert.False(service.VerifyCsrf(resolved, service.AnonymousCsrf()));
        Assert.False(service.VerifyCsrf(SessionResolution.Unauthenticated, service.AnonymousCsrf()));
        Assert.False(service.VerifyCsrf(SessionResolution.Unauthenticated, first.CsrfToken));
        foreach (var bad in new string?[] { null, "", first.CsrfToken[..42], first.CsrfToken + "A", first.CsrfToken.ToUpperInvariant() })
            Assert.False(service.VerifyCsrf(resolved, bad), bad);
        Assert.Equal(first.CsrfToken, service.CsrfFor(System.Security.Cryptography.SHA256.HashData(Base64Url.TryDecode(first.Handle, out var handle) ? handle : [])));
        // A different deployment secret derives different tokens for the same session.
        var elsewhere = new SessionService(new FakeStorage(), T.Options(), new FakeTime(Start));
        Assert.NotEqual(first.CsrfToken, elsewhere.CsrfFor(System.Security.Cryptography.SHA256.HashData(handle)));
    }

    [Fact]
    public async Task IssueRefusesInvalidIdentitiesAndTooManyWorkspaces()
    {
        var (service, storage, _) = Create();
        await Assert.ThrowsAsync<ArgumentException>(() => service.IssueAsync("not-a-uuid", T.Uuid(), Workspaces, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => service.IssueAsync(T.Uuid(), "00000000-0000-0000-0000-000000000000", Workspaces, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => service.IssueAsync(T.Uuid(), T.Uuid(), [T.Uuid(), T.Uuid(), T.Uuid(), T.Uuid()], T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => service.IssueAsync(T.Uuid(), T.Uuid(), ["x"], T.Ct));
        Assert.Empty(storage.Sessions);
    }

    [Fact]
    public async Task ReadinessRequiresTheExactSchemaVersionAndAHealthyExecutor()
    {
        var (service, storage, _) = Create();
        Assert.True(await service.IsReadyAsync(T.Ct));
        storage.Fault = _ => PlanFailureKind.Unavailable;
        Assert.False(await service.IsReadyAsync(T.Ct));
        storage.Fault = _ => PlanFailureKind.ManifestMismatch;
        Assert.False(await service.IsReadyAsync(T.Ct));
    }

    [Fact]
    public async Task AFailedStorageReadNeverAuthenticates()
    {
        var (service, storage, _) = Create();
        var issued = await Issue(service);
        storage.Fault = call => call.Plan.Id == "foundation.session-load" ? PlanFailureKind.Unavailable : null;
        await Assert.ThrowsAsync<PlanFailureException>(() => service.ResolveAsync(issued.Handle, T.Ct));
    }
}
