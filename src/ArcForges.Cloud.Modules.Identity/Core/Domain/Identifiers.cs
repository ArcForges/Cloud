// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Modules.Identity.Core.Domain;

/// <summary>
/// The canonical form of every identifier of the identity model: a lower-case UUID, the form the physical schema checks (model 01,
/// ID-01). The four identifier types below are distinct and never convert to each other, so no member can accept the identifier of one
/// concept where another is meant (BR-04): a credential is never a user, and a realm is never a workspace.
/// </summary>
internal static partial class IdentifierText
{
    public static bool IsCanonical([NotNullWhen(true)] string? value) => value is not null && Canonical().IsMatch(value);

    public static string Require(string? value, string name) =>
        IsCanonical(value) ? value : throw new ArgumentException("An identifier is a canonical lower-case UUID.", name);

    [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.CultureInvariant)]
    private static partial Regex Canonical();
}

/// <summary>The identifier of a realm: the configured authority one D1 database serves (ID-10).</summary>
internal readonly record struct RealmId
{
    private readonly string? value;

    private RealmId(string value) => this.value = value;

    public string Value => value ?? throw new InvalidOperationException("The default RealmId holds no value.");

    public static RealmId Parse(string text) => new(IdentifierText.Require(text, nameof(text)));

    public static bool TryParse(string? text, out RealmId id)
    {
        id = IdentifierText.IsCanonical(text) ? new RealmId(text) : default;
        return IdentifierText.IsCanonical(text);
    }

    public override string ToString() => Value;
}

/// <summary>The identifier of a user, meaningful only together with its realm (ID-10).</summary>
internal readonly record struct UserId
{
    private readonly string? value;

    private UserId(string value) => this.value = value;

    public string Value => value ?? throw new InvalidOperationException("The default UserId holds no value.");

    public static UserId Parse(string text) => new(IdentifierText.Require(text, nameof(text)));

    public static bool TryParse(string? text, out UserId id)
    {
        id = IdentifierText.IsCanonical(text) ? new UserId(text) : default;
        return IdentifierText.IsCanonical(text);
    }

    public override string ToString() => Value;
}

/// <summary>The identifier of one authentication identity (a credential of a user). It never names a user.</summary>
internal readonly record struct AuthIdentityId
{
    private readonly string? value;

    private AuthIdentityId(string value) => this.value = value;

    public string Value => value ?? throw new InvalidOperationException("The default AuthIdentityId holds no value.");

    public static AuthIdentityId Parse(string text) => new(IdentifierText.Require(text, nameof(text)));

    public static bool TryParse(string? text, out AuthIdentityId id)
    {
        id = IdentifierText.IsCanonical(text) ? new AuthIdentityId(text) : default;
        return IdentifierText.IsCanonical(text);
    }

    public override string ToString() => Value;
}

/// <summary>The identifier of a workspace: the scope everything else attaches to (BR-05).</summary>
internal readonly record struct WorkspaceId
{
    private readonly string? value;

    private WorkspaceId(string value) => this.value = value;

    public string Value => value ?? throw new InvalidOperationException("The default WorkspaceId holds no value.");

    public static WorkspaceId Parse(string text) => new(IdentifierText.Require(text, nameof(text)));

    public static bool TryParse(string? text, out WorkspaceId id)
    {
        id = IdentifierText.IsCanonical(text) ? new WorkspaceId(text) : default;
        return IdentifierText.IsCanonical(text);
    }

    public override string ToString() => Value;
}