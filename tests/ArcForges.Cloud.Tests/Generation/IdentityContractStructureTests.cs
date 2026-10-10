// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Text.RegularExpressions;
using ArcForges.Contracts.Hello.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Generation;

/// <summary>
/// The contract half of WP-22.00 (CLOUD.11), replacing one-for-one the scan that tests/worker/identity-structure.test.ts ran over the
/// npm proto package (CLOUD.84 S33(3)(c)). The names of the generated public contracts, read from the restored NuGet
/// ArcForges.Contracts.PublicApi types, carry no membership, role, invitation, seat or shared-editor concept (WO-05). The allowlist is
/// the reviewed exception set that the TypeScript scan held, in the C# spellings of the same generated names.
/// </summary>
public sealed partial class IdentityContractStructureTests
{
    private static readonly Assembly Contracts = typeof(SayHelloRequest).Assembly;

    /// <summary>Words that name a collaboration concept the product excludes (P2-006), after splitting camel case.</summary>
    private static readonly HashSet<string> ForbiddenWords = new(StringComparer.Ordinal)
    {
        "membership", "memberships", "member", "members", "role", "roles", "invitation", "invitations", "invite", "invites", "invited",
        "seat", "seats", "collaborator", "collaborators", "collaboration", "collaborative", "organisation", "organisations", "organization",
        "organizations", "teammate", "teammates",
    };

    /// <summary>Adjacent word pairs that name a shared editor or a team workspace.</summary>
    private static readonly (string First, string Second)[] ForbiddenPairs =
    [
        ("shared", "editor"), ("shared", "editing"), ("co", "editor"), ("team", "workspace"),
    ];

    /// <summary>
    /// The reviewed exceptions. Each names a generated contract identifier and why it is not a customer workspace concept: the chat
    /// message author is a conversation role, not a workspace role.
    /// </summary>
    private static readonly (string Identifier, bool Prefix, string Reason)[] Allowed =
    [
        ("TranscriptRole", true, "the author of a chat message in the public API, and the values of its enum, not a workspace role"),
        ("Role", false, "the author role of a content part or transcript message (chat), not a workspace role"),
    ];

    [GeneratedRegex("([a-z0-9])([A-Z])|([A-Z]+)([A-Z][a-z])", RegexOptions.CultureInvariant)]
    private static partial Regex Boundary();

    private static string[] Words(string identifier) =>
        Regex.Split(Boundary().Replace(identifier, "$1$3 $2$4"), "[^A-Za-z0-9]+")
            .Where(word => word.Length > 0)
            .Select(word => word.ToLowerInvariant())
            .ToArray();

    private static string[] Violations(string identifier)
    {
        var parts = Words(identifier);
        var found = parts.Where(ForbiddenWords.Contains).ToList();
        foreach (var (first, second) in ForbiddenPairs)
            if (parts.Where((word, index) => word == first && index + 1 < parts.Length && parts[index + 1] == second).Any())
                found.Add($"{first} {second}");
        return found.ToArray();
    }

    private static bool IsAllowed(string identifier) =>
        Allowed.Any(entry => entry.Prefix ? identifier.StartsWith(entry.Identifier, StringComparison.Ordinal) : identifier == entry.Identifier);

    /// <summary>
    /// The identifiers that the proto declarations produce in the restored Contracts assembly: exported type names, enum values, field
    /// properties and the rpc methods of the generated service clients. Protobuf accessors (Has, Clear and the field-number constants)
    /// are excluded only when they derive from a field that is listed, so they name no new concept.
    /// </summary>
    private static IEnumerable<string> ContractNames()
    {
        const BindingFlags Declared = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (var type in Contracts.GetExportedTypes())
        {
            yield return type.Name;
            if (type.IsEnum)
            {
                foreach (var value in Enum.GetNames(type)) yield return value;
                continue;
            }

            var properties = type.GetProperties(Declared).Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
            var service = type.Name.EndsWith("Client", StringComparison.Ordinal) || type.Name.EndsWith("Base", StringComparison.Ordinal);
            foreach (var member in type.GetMembers(Declared))
            {
                if (member.MemberType is MemberTypes.Method)
                {
                    if (service) yield return member.Name;
                    continue;
                }

                if (IsAccessor(member.Name, properties)) continue;
                if (member.MemberType is MemberTypes.Property or MemberTypes.Field) yield return member.Name;
            }
        }
    }

    private static bool IsAccessor(string name, HashSet<string> properties) =>
        (name.StartsWith("Has", StringComparison.Ordinal) && properties.Contains(name[3..]))
        || (name.StartsWith("Clear", StringComparison.Ordinal) && properties.Contains(name[5..]))
        || (name.EndsWith("FieldNumber", StringComparison.Ordinal) && properties.Contains(name[..^"FieldNumber".Length]));

    [Fact]
    public void TheGeneratedPublicContractsDeclareNoMembershipRoleInvitationSeatOrSharedEditorConcept()
    {
        var names = ContractNames().Distinct().ToArray();
        Assert.True(names.Length > 100, "the scan reads the generated declarations");
        var hits = names.Where(name => Violations(name).Length > 0 && !IsAllowed(name)).ToArray();
        Assert.Empty(hits);
    }

    [Fact]
    public void EveryReviewedExceptionMatchesAGeneratedIdentifierAndHasAReason()
    {
        var names = ContractNames().Distinct().ToArray();
        foreach (var entry in Allowed)
        {
            Assert.True(entry.Reason.Length > 20, $"a reason is stated for {entry.Identifier}");
            Assert.True(names.Any(name => entry.Prefix ? name.StartsWith(entry.Identifier, StringComparison.Ordinal) : name == entry.Identifier), $"{entry.Identifier} is not a generated identifier");
        }
    }

    [Fact]
    public void TheScannerFlagsTheExcludedVocabularyInAllItsSpellingsAndNothingElse()
    {
        foreach (var name in new[] { "WorkspaceMembership", "AddMember", "workspace_role", "InviteUser", "SeatCount", "SharedEditor", "TeamWorkspace", "OrganizationId", "isCollaborator" })
            Assert.NotEmpty(Violations(name));
        foreach (var name in new[] { "OwnerUserId", "Workspace", "AuthIdentity", "Revoke", "Reserve", "Controller", "Preserve" })
            Assert.Empty(Violations(name));
        // A word that merely contains an excluded one is not flagged.
        Assert.Equal(new[] { "member" }, Violations("memberOf2"));
    }
}
