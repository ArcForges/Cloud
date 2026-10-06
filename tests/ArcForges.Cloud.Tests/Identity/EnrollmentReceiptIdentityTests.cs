// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

public sealed class EnrollmentReceiptIdentityTests
{
    [Fact]
    public void StableIdentityBindsEveryCredentialAndProfileFieldAndDistinguishesNullAndEmpty()
    {
        var request = new EnrollmentRequest(IdentityHarness.RealmA, "00000000-0000-4000-8000-000000000001", "Ada", IdentityHarness.Passkey("credential"));
        var original = EnrollmentReceiptIdentity.For(request);
        Assert.Null(original.WorkspaceId);
        Assert.Equal("identity.account.enroll", original.Operation);
        Assert.Equal(original.RequestHash, EnrollmentReceiptIdentity.For(request with { CommandId = "00000000-0000-4000-8000-000000000002" }).RequestHash);
        Assert.Equal(original.ActorRef, EnrollmentReceiptIdentity.For(request with { DisplayName = "Grace" }).ActorRef);
        Assert.NotEqual(original.RequestHash, EnrollmentReceiptIdentity.For(request with { DisplayName = "Grace" }).RequestHash);
        Assert.NotEqual(original.RequestHash, EnrollmentReceiptIdentity.For(request with { Realm = IdentityHarness.RealmB }).RequestHash);
        var credential = request.Credential;
        var material = credential.Passkey!;
        NewCredential[] mutations = [
            credential with { ProviderId = "another-provider" }, credential with { Subject = "another-subject" }, credential with { Label = null },
            credential with { Label = "" }, credential with { Password = "verifier" }, credential with { Passkey = material with { PublicKey = [9, 9] } },
            credential with { Passkey = material with { UserHandle = [1, 1] } }, credential with { Passkey = material with { BackupEligible = null } },
            credential with { Passkey = material with { BackupState = true } }, credential with { Passkey = material with { TransportsJson = "[]" } },
            credential with { Passkey = material with { SignCount = 1 } }, credential with { Passkey = null },
        ];
        foreach (var mutation in mutations) Assert.NotEqual(original.RequestHash, EnrollmentReceiptIdentity.For(request with { Credential = mutation }).RequestHash);
        Assert.NotEqual(EnrollmentReceiptIdentity.For(request with { Credential = credential with { Label = null } }).RequestHash,
            EnrollmentReceiptIdentity.For(request with { Credential = credential with { Label = "" } }).RequestHash);
    }

    [Fact]
    public void FieldSeparatorsAndInvalidUnicodeCannotProduceTheSameFingerprint()
    {
        var request = new EnrollmentRequest(IdentityHarness.RealmA, "00000000-0000-4000-8000-000000000001", "Ada", IdentityHarness.Email("subject"));
        Assert.NotEqual(EnrollmentReceiptIdentity.For(request with { DisplayName = "a\nb", Credential = request.Credential with { Subject = "c" } }).RequestHash,
            EnrollmentReceiptIdentity.For(request with { DisplayName = "a", Credential = request.Credential with { Subject = "b\nc" } }).RequestHash);
        Assert.Throws<System.Text.EncoderFallbackException>(() => EnrollmentReceiptIdentity.For(request with { Credential = request.Credential with { Password = "\ud800" } }));
    }
}
