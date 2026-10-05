// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

public sealed class IdentityDomainTests
{
    private static readonly RealmId Realm = IdentityHarness.RealmA;
    private static readonly UserId UserOne = UserId.Parse("00000000-0000-4000-8000-0000000000a1");
    private static readonly UserId UserTwo = UserId.Parse("00000000-0000-4000-8000-0000000000a2");

    private static User User(UserId id, UserState state = UserState.Active) => new(id, Realm, "Ada", state, new UtcMicros(1), null, 1);

    private static AuthIdentity Credential(int n, UserId user, bool revoked = false, RealmId? realm = null) =>
        new(AuthIdentityId.Parse($"00000000-0000-4000-8000-{n:x12}"), user, realm ?? Realm, "official-email", AuthMethod.EmailCode, $"s{n}", null, null, null,
            new UtcMicros(n), null, revoked ? new UtcMicros(99) : null, 1);

    [Theory]
    [InlineData("00000000-0000-4000-8000-000000000001", true)]
    [InlineData("0198A7C0-1C3E-7D4A-9B1F-000000000001", false)]
    [InlineData("0198a7c0-1c3e-7d4a-9b1f-00000000000", false)]
    [InlineData("0198a7c0-1c3e-7d4a-9b1f-0000000000011", false)]
    [InlineData("{0198a7c0-1c3e-7d4a-9b1f-000000000001}", false)]
    [InlineData("0198a7c01c3e7d4a9b1f000000000001", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IdentifiersAreCanonicalLowerCaseUuidsOnly(string? text, bool valid)
    {
        Assert.Equal(valid, UserId.TryParse(text, out var user));
        Assert.Equal(valid, AuthIdentityId.TryParse(text, out _));
        Assert.Equal(valid, RealmId.TryParse(text, out _));
        Assert.Equal(valid, WorkspaceId.TryParse(text, out _));
        if (valid) Assert.Equal(text, user.Value);
        else Assert.Throws<ArgumentException>(() => UserId.Parse(text!));
    }

    [Fact]
    public void ADefaultIdentifierHoldsNothingAndNeverEqualsAParsedOne()
    {
        Assert.Throws<InvalidOperationException>(() => default(UserId).Value);
        Assert.NotEqual(default, UserOne);
    }

    [Fact]
    public void TheSameTextIsADifferentIdentifierForEachConcept()
    {
        const string text = "00000000-0000-4000-8000-0000000000a1";
        object user = UserId.Parse(text);
        object credential = AuthIdentityId.Parse(text);
        object workspace = WorkspaceId.Parse(text);
        object realm = RealmId.Parse(text);
        Assert.False(user.Equals(credential));
        Assert.False(workspace.Equals(realm));
        Assert.False(credential.Equals(workspace));
    }

    [Theory]
    [InlineData("Ada", true)]
    [InlineData("Ádá 😀", true)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("tab\there", false)]
    [InlineData("new\nline", false)]
    public void DisplayNamesArePlainBoundedText(string text, bool valid) => Assert.Equal(valid, IdentityRules.IsValidDisplayName(text));

    [Fact]
    public void UnpairedSurrogatesAreRefusedAndPairedOnesAreText()
    {
        Assert.False(IdentityRules.IsValidDisplayName("\ud800"));
        Assert.False(IdentityRules.IsValidDisplayName("a\ud800"));
        Assert.False(IdentityRules.IsValidDisplayName("\udc00x"));
        Assert.False(IdentityRules.IsValidDisplayName("\udc00\ud800"));
        Assert.True(IdentityRules.IsValidDisplayName("\ud83d\ude00"));
    }

    [Fact]
    public void TextBoundsAreExact()
    {
        Assert.True(IdentityRules.IsValidDisplayName(new string('a', IdentityRules.DisplayNameMaxLength)));
        Assert.False(IdentityRules.IsValidDisplayName(new string('a', IdentityRules.DisplayNameMaxLength + 1)));
        Assert.True(IdentityRules.IsValidSubject(new string('a', IdentityRules.SubjectMaxLength)));
        Assert.False(IdentityRules.IsValidSubject(new string('a', IdentityRules.SubjectMaxLength + 1)));
        Assert.False(IdentityRules.IsValidSubject(""));
        Assert.True(IdentityRules.IsValidLabel(null));
        Assert.False(IdentityRules.IsValidLabel(""));
        Assert.True(IdentityRules.IsValidLabel(new string('a', IdentityRules.LabelMaxLength)));
        Assert.False(IdentityRules.IsValidLabel(new string('a', IdentityRules.LabelMaxLength + 1)));
    }

    [Theory]
    [InlineData("official-email", true)]
    [InlineData("corp.oidc_1", true)]
    [InlineData("Official", false)]
    [InlineData("1abc", false)]
    [InlineData("", false)]
    [InlineData("has space", false)]
    public void ProviderIdsAreKeys(string provider, bool valid) => Assert.Equal(valid, IdentityRules.IsValidProvider(provider));

    [Fact]
    public void ACredentialHasTheShapeOfItsMethod()
    {
        var email = Credential(1, UserOne);
        Assert.True(IdentityRules.HasValidShape(email));
        Assert.False(IdentityRules.HasValidShape(email with { Password = "x" }), "only a password carries a verifier");
        Assert.False(IdentityRules.HasValidShape(email with { Passkey = new PasskeyMaterial([1], [1], null, null, null, null) }), "only a passkey carries passkey data");
        var password = email with { Method = AuthMethod.Password, Password = "verifier" };
        Assert.True(IdentityRules.HasValidShape(password));
        Assert.False(IdentityRules.HasValidShape(password with { Password = null }));
        Assert.False(IdentityRules.HasValidShape(password with { Password = "" }));
        var passkey = email with { Method = AuthMethod.Passkey, Passkey = new PasskeyMaterial([1, 2], [3, 4], true, false, null, 0) };
        Assert.True(IdentityRules.HasValidShape(passkey));
        Assert.False(IdentityRules.HasValidShape(passkey with { Passkey = null }));
        Assert.False(IdentityRules.HasValidShape(passkey with { Passkey = passkey.Passkey! with { UserHandle = [] } }), "a passkey needs its user handle");
        Assert.False(IdentityRules.HasValidShape(passkey with { Passkey = passkey.Passkey! with { PublicKey = default } }));
        Assert.False(IdentityRules.HasValidShape(passkey with { Passkey = passkey.Passkey! with { BackupEligible = null, BackupState = true } }), "backup state requires backup eligibility");
        Assert.False(IdentityRules.HasValidShape(passkey with { Passkey = passkey.Passkey! with { SignCount = -1 } }));
        Assert.False(IdentityRules.HasValidShape(email with { ProviderId = "Bad Provider" }));
        Assert.False(IdentityRules.HasValidShape(email with { Subject = "" }));
        Assert.False(IdentityRules.HasValidShape(email with { Label = "" }));
    }

    [Theory]
    [InlineData(1, true, true)]
    [InlineData(2, false, true)]
    [InlineData(3, false, false)]
    [InlineData(4, false, false)]
    [InlineData(5, false, false)]
    public void OnlyAnActiveUserMayAddAndOnlyAnActiveOrRestrictedUserMayChangeCredentials(int stored, bool mayAdd, bool mayChange)
    {
        var state = (UserState)stored;
        Assert.Equal(mayAdd, IdentityRules.MayAddCredential(User(UserOne, state)));
        Assert.Equal(mayChange, IdentityRules.MayChangeCredentials(User(UserOne, state)));
    }

    [Fact]
    public void TheLastCredentialRuleKeepsAUsableCredentialOrARecoveryPath()
    {
        var user = User(UserOne);
        var only = Credential(1, UserOne);
        var second = Credential(2, UserOne);
        Assert.Equal(IdentityError.LastCredential, IdentityRules.CheckRevocation(user, [only], only.Id, false));
        Assert.Null(IdentityRules.CheckRevocation(user, [only], only.Id, true));
        Assert.Null(IdentityRules.CheckRevocation(user, [only, second], only.Id, false));
        // A revoked credential is not a remaining one.
        Assert.Equal(IdentityError.LastCredential, IdentityRules.CheckRevocation(user, [only, Credential(2, UserOne, revoked: true)], only.Id, false));
        // A credential of another user or another realm is not the user's remaining one.
        Assert.Equal(IdentityError.LastCredential, IdentityRules.CheckRevocation(user, [only, Credential(3, UserTwo)], only.Id, false));
        Assert.Equal(IdentityError.LastCredential, IdentityRules.CheckRevocation(user, [only, Credential(4, UserOne, realm: IdentityHarness.RealmB)], only.Id, false));
    }

    [Fact]
    public void ARevocationNamesAnUnrevokedCredentialOfTheUserOrIsNotFound()
    {
        var user = User(UserOne);
        var mine = Credential(1, UserOne);
        var other = Credential(2, UserTwo);
        var gone = Credential(3, UserOne, revoked: true);
        Assert.Equal(IdentityError.NotFound, IdentityRules.CheckRevocation(user, [mine, other, gone], other.Id, true));
        Assert.Equal(IdentityError.NotFound, IdentityRules.CheckRevocation(user, [mine, other, gone], gone.Id, true));
        Assert.Equal(IdentityError.NotFound, IdentityRules.CheckRevocation(user, [mine], Credential(9, UserOne).Id, true));
        Assert.Equal(IdentityError.NotPermitted, IdentityRules.CheckRevocation(User(UserOne, UserState.Suspended), [mine, gone], mine.Id, true));
    }

    [Fact]
    public void OwnershipIsADirectCheckOfTheRealmAndTheOwnerUserAndNothingElse()
    {
        var workspace = IdentityRules.NewPersonalWorkspace(WorkspaceId.Parse("00000000-0000-4000-8000-0000000000b1"), User(UserOne));
        Assert.True(IdentityRules.Owns(new Principal(Realm, UserOne), workspace));
        Assert.False(IdentityRules.Owns(new Principal(Realm, UserTwo), workspace));
        Assert.False(IdentityRules.Owns(new Principal(IdentityHarness.RealmB, UserOne), workspace), "the same user identifier in another realm owns nothing");
        Assert.Equal(UserOne, workspace.OwnerUserId);
        Assert.Equal(WorkspaceState.Active, workspace.State);
        Assert.Equal("Automatic", workspace.DataRegion);
    }

    [Fact]
    public void UtcMicrosFloorsBelowTheEpochAndKeepsWholeMicroseconds()
    {
        Assert.Equal(0, UtcMicros.FromDateTimeOffset(DateTimeOffset.UnixEpoch).Value);
        Assert.Equal(1_500_000, UtcMicros.FromDateTimeOffset(DateTimeOffset.UnixEpoch.AddSeconds(1.5)).Value);
        Assert.Equal(-1, UtcMicros.FromDateTimeOffset(DateTimeOffset.UnixEpoch.AddTicks(-1)).Value);
        Assert.True(new UtcMicros(1) < new UtcMicros(2));
    }

    [Fact]
    public void TheEnumNumbersAreTheStoredPositionsOfThePhysicalEnums()
    {
        static string[] Values(string file, string name)
        {
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", "Physical", "manifest", file)));
            return [.. document.RootElement.GetProperty("enums").GetProperty(name).GetProperty("values").EnumerateArray().Select(value => value.GetString()!)];
        }

        static void Matches<TEnum>(string[] manifest) where TEnum : struct, Enum
        {
            var ordered = Enum.GetValues<TEnum>().OrderBy(value => Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            Assert.Equal(manifest.Length, ordered.Length);
            for (var i = 0; i < ordered.Length; i++)
            {
                Assert.Equal(i + 1, Convert.ToInt32(ordered[i], System.Globalization.CultureInfo.InvariantCulture));
                Assert.Equal(manifest[i], ordered[i].ToString(), ignoreCase: true);
            }
        }

        Matches<AuthMethod>(Values("identity.json", "identity.auth_method"));
        Matches<UserState>(Values("identity.json", "identity.user_state"));
        Matches<WorkspaceState>(Values("workspace.json", "workspace.workspace_state"));
    }
}
