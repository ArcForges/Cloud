// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;

namespace ArcForges.Cloud.Modules.Identity.Persistence;

internal static class IdentityRowCodec
{
    public static User User(RealmId realm, UserId id, IReadOnlyList<PlanValue> row)
    {
        Count(row, 7);
        if (Text(row[0]) != id.Value || Text(row[6]) != realm.Value) throw Defect();
        return ReadUser(id, realm, row[1], row[2], row[3], row[4], row[5]);
    }

    public static CredentialLookup Credential(RealmId realm, string provider, string subject, IReadOnlyList<PlanValue> row)
    {
        Count(row, 23);
        if (Text(row[10]) != realm.Value || Text(row[11]) != provider || Text(row[12]) != subject) throw Defect();
        var user = UserId.Parse(Text(row[1]));
        var credential = ReadCredential(row[0], user, realm, provider, row[2], subject, row[3], row[4], row[5], row[6], row[7],
            row[13], row[14], row[15], row[16], row[17], row[18], row[19]);
        return new CredentialLookup(credential, ReadUser(user, realm, row[20], row[8], row[21], row[22], row[9]));
    }

    public static AuthIdentity Credential(RealmId realm, UserId user, IReadOnlyList<PlanValue> row)
    {
        Count(row, 18);
        if (Text(row[8]) != user.Value || Text(row[9]) != realm.Value) throw Defect();
        return ReadCredential(row[0], user, realm, Text(row[2]), row[1], Text(row[10]), row[3], row[4], row[5], row[6], row[7],
            row[11], row[12], row[13], row[14], row[15], row[16], row[17]);
    }

    public static Workspace Workspace(RealmId realm, WorkspaceId? id, UserId? owner, IReadOnlyList<PlanValue> row)
    {
        Count(row, 8);
        if (Text(row[1]) != realm.Value || (id is { } expected && Text(row[0]) != expected.Value)
            || (owner is { } principal && Text(row[2]) != principal.Value)) throw Defect();
        var state = Integer(row[5]);
        if (state is < 1 or > 3 || Integer(row[7]) < 0) throw Defect();
        return new Workspace(WorkspaceId.Parse(Text(row[0])), realm, UserId.Parse(Text(row[2])), Text(row[3]), Text(row[4]),
            (WorkspaceState)state, new UtcMicros(Integer(row[6])), Integer(row[7]));
    }

    public static bool Recovery(IReadOnlyList<PlanValue> row)
    {
        Count(row, 1);
        return Flag(row[0]) ?? throw Defect();
    }

    private static User ReadUser(UserId id, RealmId realm, PlanValue name, PlanValue state, PlanValue created, PlanValue deleted, PlanValue revision)
    {
        var display = Text(name);
        var status = Integer(state);
        var rev = Integer(revision);
        if (!IdentityRules.IsValidDisplayName(display) || status is < 1 or > 5 || rev < 0) throw Defect();
        return new User(id, realm, display, (UserState)status, new UtcMicros(Integer(created)), Instant(deleted), rev);
    }

    private static AuthIdentity ReadCredential(PlanValue id, UserId user, RealmId realm, string provider, PlanValue method, string subject,
        PlanValue label, PlanValue created, PlanValue used, PlanValue revoked, PlanValue revision,
        PlanValue key, PlanValue handle, PlanValue eligible, PlanValue backedUp, PlanValue transports, PlanValue counter, PlanValue password)
    {
        var kind = Integer(method);
        var rev = Integer(revision);
        if (kind is < 1 or > 4 || rev < 0) throw Defect();
        PasskeyMaterial? passkey = null;
        if (kind == 1)
            passkey = new PasskeyMaterial(Bytes(key), Bytes(handle), Flag(eligible), Flag(backedUp), OptionalText(transports), OptionalInteger(counter));
        else if (key.Kind != PlanValueKind.Null || handle.Kind != PlanValueKind.Null || eligible.Kind != PlanValueKind.Null
            || backedUp.Kind != PlanValueKind.Null || transports.Kind != PlanValueKind.Null || counter.Kind != PlanValueKind.Null) throw Defect();
        var credential = new AuthIdentity(AuthIdentityId.Parse(Text(id)), user, realm, provider, (AuthMethod)kind, subject, OptionalText(label),
            passkey, OptionalText(password), new UtcMicros(Integer(created)), Instant(used), Instant(revoked), rev);
        if (!IdentityRules.HasValidShape(credential)) throw Defect();
        return credential;
    }

    private static void Count(IReadOnlyList<PlanValue> row, int expected)
    {
        if (row.Count != expected) throw Defect();
    }

    private static string Text(PlanValue value) => value.Kind == PlanValueKind.Text ? value.AsText() : throw Defect();
    private static long Integer(PlanValue value) => value.Kind == PlanValueKind.Int64 ? value.AsInt64() : throw Defect();
    private static string? OptionalText(PlanValue value) => value.Kind == PlanValueKind.Null ? null : Text(value);
    private static long? OptionalInteger(PlanValue value) => value.Kind == PlanValueKind.Null ? null : Integer(value);
    private static UtcMicros? Instant(PlanValue value) => OptionalInteger(value) is { } instant ? new UtcMicros(instant) : null;
    private static bool? Flag(PlanValue value) => value.Kind switch { PlanValueKind.Null => null, PlanValueKind.Bool => value.AsBool(), _ => throw Defect() };
    private static ImmutableArray<byte> Bytes(PlanValue value) => value.Kind == PlanValueKind.Bytes ? [.. value.AsBytes()] : throw Defect();
    private static IdentityStorageException Defect() => new(IdentityStorageFailure.InvalidPlan);
}
