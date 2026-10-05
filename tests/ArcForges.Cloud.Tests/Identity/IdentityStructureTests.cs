// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Text.RegularExpressions;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.Identity;

/// <summary>
/// The structural half of WP-22.00 on the compiled Identity assembly: no member carries a membership, role, invitation, seat or
/// shared-editor concept (WO-05), an authentication identity is never a user (BR-04), and ownership is the single owner relation. The
/// schema and contract halves are in tests/worker/identity-structure.test.ts.
/// </summary>
public sealed partial class IdentityStructureTests
{
    private static readonly Assembly Module = typeof(IdentityModule).Assembly;
    private const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    private static readonly HashSet<string> Forbidden = new(StringComparer.Ordinal)
    {
        "membership", "memberships", "member", "members", "role", "roles", "invitation", "invitations", "invite", "invites", "seat", "seats",
        "collaborator", "collaborators", "collaboration", "organisation", "organisations", "organization", "organizations", "teammate",
    };

    [GeneratedRegex("([a-z0-9])([A-Z])|([A-Z]+)([A-Z][a-z])", RegexOptions.CultureInvariant)]
    private static partial Regex Boundary();

    private static IEnumerable<string> Words(string identifier) =>
        Boundary().Replace(identifier, "$1$3 $2$4").Split([' ', '_', '-', '.', '<', '>', '`', '+'], StringSplitOptions.RemoveEmptyEntries).Select(word => word.ToLowerInvariant());

    private static IEnumerable<Type> ModuleTypes() => Module.GetTypes().Where(type => !Attribute.IsDefined(type, typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute)));

    [Fact]
    public void NoTypeOrMemberOfTheIdentityAssemblyNamesAMembershipRoleInvitationSeatOrSharedEditorConcept()
    {
        var names = new List<string>();
        foreach (var type in ModuleTypes())
        {
            names.Add(type.Name);
            names.AddRange(type.GetMembers(All).Where(member => member.MemberType is not MemberTypes.NestedType).Select(member => member.Name));
            names.AddRange(type.GetMethods(All).SelectMany(method => method.GetParameters()).Select(parameter => parameter.Name ?? ""));
            if (type.IsEnum) names.AddRange(Enum.GetNames(type));
        }

        Assert.True(names.Count > 200, "the scan reads the assembly");
        var hits = names.Where(name => Words(name).Any(Forbidden.Contains) || Words(name).Zip(Words(name).Skip(1)).Any(pair => pair is ("shared", "editor" or "editing") or ("team", "workspace"))).Distinct().ToArray();
        Assert.Empty(hits);
    }

    [Fact]
    public void TheScannerFlagsTheExcludedVocabularyInAllItsSpellings()
    {
        foreach (var name in new[] { "WorkspaceMembership", "AddMember", "workspace_role", "InviteUser", "SeatCount", "SharedEditor", "TeamWorkspace", "OrganizationId" })
            Assert.True(Words(name).Any(Forbidden.Contains) || Words(name).Zip(Words(name).Skip(1)).Any(pair => pair is ("shared", "editor") or ("team", "workspace")), name);
        foreach (var name in new[] { "OwnerUserId", "Workspace", "AuthIdentity", "Revoke", "Reserve" })
            Assert.False(Words(name).Any(Forbidden.Contains), name);
    }

    [Fact]
    public void TheFourIdentifiersAreDistinctValueTypesWithNoConversionBetweenThem()
    {
        Type[] ids = [typeof(RealmId), typeof(UserId), typeof(AuthIdentityId), typeof(WorkspaceId)];
        Assert.Equal(4, ids.Distinct().Count());
        foreach (var type in ids)
        {
            Assert.True(type.IsValueType);
            var conversions = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static).Where(method => method.Name is "op_Implicit" or "op_Explicit");
            Assert.Empty(conversions);
            Assert.All(ids.Where(other => other != type), other => Assert.False(type.IsAssignableFrom(other)));
        }
    }

    [Fact]
    public void NoAuthorizationDecisionOfTheCoreTakesACredentialIdentifier()
    {
        var service = typeof(IdentityService).GetMethods(All | BindingFlags.Public).Where(method => method.DeclaringType == typeof(IdentityService) && method.ReturnType.Name.StartsWith("ValueTask", StringComparison.Ordinal)).ToArray();
        Assert.True(service.Length >= 8);
        var authorization = service.Where(method => method.Name is nameof(IdentityService.AuthorizeWorkspaceAsync) or nameof(IdentityService.GetPersonalWorkspaceAsync)).ToArray();
        Assert.Equal(2, authorization.Length);
        foreach (var method in authorization)
        {
            Assert.Contains(method.GetParameters(), parameter => parameter.ParameterType == typeof(Principal));
            Assert.DoesNotContain(method.GetParameters(), parameter => parameter.ParameterType == typeof(AuthIdentityId));
        }

        // A credential identifier is accepted only where a credential is the thing acted on.
        var acceptsCredential = service.Where(method => method.GetParameters().Any(parameter => parameter.ParameterType == typeof(AuthIdentityId))).Select(method => method.Name).Order().ToArray();
        Assert.Equal([nameof(IdentityService.RelabelCredentialAsync), nameof(IdentityService.RevokeCredentialAsync)], acceptsCredential);
        // The principal is a realm and a user; a credential cannot stand in for it.
        Assert.Equal([typeof(RealmId), typeof(UserId)], typeof(Principal).GetProperties().Select(property => property.PropertyType).Where(type => type != typeof(Principal)).ToArray());
        // The use cases that return a user never take a credential as the caller.
        Assert.DoesNotContain(typeof(IdentityService).GetMethods(All).SelectMany(method => method.GetParameters()), parameter => parameter.ParameterType == typeof(AuthIdentityId) && parameter.Name is "caller" or "user");
    }

    [Fact]
    public void AWorkspaceNamesExactlyOneUserAndEveryCredentialExactlyOneUser()
    {
        var workspace = typeof(Workspace).GetProperties().Where(property => property.PropertyType == typeof(UserId)).Select(property => property.Name).ToArray();
        Assert.Equal(["OwnerUserId"], workspace);
        Assert.DoesNotContain(typeof(Workspace).GetProperties(), property => property.PropertyType.IsGenericType && property.PropertyType.GetGenericArguments().Contains(typeof(UserId)));
        Assert.Equal(["UserId"], typeof(AuthIdentity).GetProperties().Where(property => property.PropertyType == typeof(UserId)).Select(property => property.Name).ToArray());
        Assert.DoesNotContain(typeof(User).GetProperties(), property => property.PropertyType == typeof(AuthIdentityId));
        Assert.DoesNotContain(typeof(User).GetProperties(), property => property.PropertyType.IsGenericType && property.PropertyType.GetGenericArguments().Contains(typeof(AuthIdentityId)));
    }

    [Fact]
    public void TheModuleListsTheServiceAndNeedsAStoreItDoesNotProvide()
    {
        var services = new ServiceCollection();
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        Assert.Contains(services, descriptor => descriptor.ServiceType == typeof(IdentityService));
        using var provider = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IdentityService>());
        Assert.Equal("identity_", IdentityModule.Instance.Descriptor.TablePrefix);
    }

    [Fact]
    public void EveryTypeOfTheCoreIsInternalAndLivesInALayerNamespace()
    {
        var core = ModuleTypes().Where(type => type.Namespace?.StartsWith("ArcForges.Cloud.Modules.Identity.Core", StringComparison.Ordinal) == true).ToArray();
        Assert.NotEmpty(core);
        Assert.All(core, type => Assert.False(type.IsPublic, type.FullName));
        Assert.All(core, type => Assert.Matches(@"\.Core\.(Domain|Application|Infrastructure)$", type.Namespace!));
        Assert.All(ModuleTypes().Where(type => type.IsPublic), type => Assert.Equal("ArcForges.Cloud.Modules.Identity", type.Namespace));
    }
}