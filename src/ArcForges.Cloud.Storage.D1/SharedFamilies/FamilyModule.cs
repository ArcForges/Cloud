// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage.SharedFamilies;

/// <summary>
/// A contributor to one guarded family batch: the seventeen modules of the fixed order of Design SU-04 (the declaration order
/// below is that order) and the shared infrastructure, which lies outside it.
/// </summary>
internal enum FamilyModule
{
    Configuration,
    Identity,
    Workspace,
    Device,
    Entitlement,
    Commerce,
    Policy,
    Agent,
    Chat,
    Scope,
    Task,
    Search,
    PackageCatalog,
    Notification,
    Resource,
    Sync,
    Audit,

    /// <summary>Receipts, outbox rows and leases (<c>platform_</c> tables). Its guards come first and its receipt and outbox statements last.</summary>
    Platform,
}

/// <summary>The three phases of a family batch: every guard, then every mutation, then the one generated release of the guard rows.</summary>
internal enum FamilyPhase
{
    Guard,
    Mutation,
    Release,
}

/// <summary>
/// The class of one statement inside its module and phase. Guards run authorization, revision, policy, balance, lease; mutations
/// run quota buckets before reservations (SU-04), then every other record.
/// </summary>
internal enum FamilyClass
{
    Authorization,
    Revision,
    Policy,
    Balance,
    Lease,
    Bucket,
    Reservation,
    Record,
    Release,
}

/// <summary>The fixed module lock order of Design SU-04, the one place C# knows it.</summary>
internal static class ModuleLockOrder
{
    private static readonly FamilyModule[] Ordered =
    [
        FamilyModule.Configuration,
        FamilyModule.Identity,
        FamilyModule.Workspace,
        FamilyModule.Device,
        FamilyModule.Entitlement,
        FamilyModule.Commerce,
        FamilyModule.Policy,
        FamilyModule.Agent,
        FamilyModule.Chat,
        FamilyModule.Scope,
        FamilyModule.Task,
        FamilyModule.Search,
        FamilyModule.PackageCatalog,
        FamilyModule.Notification,
        FamilyModule.Resource,
        FamilyModule.Sync,
        FamilyModule.Audit,
    ];

    /// <summary>Config, Identity, Workspace, Device, Entitlement, Commerce, Policy, Agent, Chat, Scope, Task, Search, PackageCatalog, Notification, Resource, Sync, Audit.</summary>
    public static IReadOnlyList<FamilyModule> Order => Ordered;

    /// <summary>A position in the order exists for these modules only; Support and TrustSafety have none and are not <see cref="FamilyModule"/> values.</summary>
    public static bool HasPosition(FamilyModule module) => module != FamilyModule.Platform && Array.IndexOf(Ordered, module) >= 0;

    /// <summary>
    /// The sort position of a statement of <paramref name="module"/> in <paramref name="phase"/>: platform guards precede every module
    /// guard and platform receipts and outbox rows follow every module mutation.
    /// </summary>
    public static int Rank(FamilyModule module, FamilyPhase phase)
    {
        if (module == FamilyModule.Platform) return phase == FamilyPhase.Guard ? -1 : Ordered.Length;
        var index = Array.IndexOf(Ordered, module);
        return index >= 0 ? index : throw new ArgumentOutOfRangeException(nameof(module));
    }

    /// <summary>The owner name of the module in <c>storage/plans/owners.json</c> (the plan owner and the table prefix without its underscore).</summary>
    public static string Owner(FamilyModule module) => module switch
    {
        FamilyModule.Configuration => "config",
        FamilyModule.Identity => "identity",
        FamilyModule.Workspace => "workspace",
        FamilyModule.Device => "device",
        FamilyModule.Entitlement => "entitlement",
        FamilyModule.Commerce => "commerce",
        FamilyModule.Policy => "policy",
        FamilyModule.Agent => "agent",
        FamilyModule.Chat => "chat",
        FamilyModule.Scope => "scope",
        FamilyModule.Task => "task",
        FamilyModule.Search => "search",
        FamilyModule.PackageCatalog => "package-catalog",
        FamilyModule.Notification => "notification",
        FamilyModule.Resource => "resource",
        FamilyModule.Sync => "sync",
        FamilyModule.Audit => "audit",
        FamilyModule.Platform => "platform",
        _ => throw new ArgumentOutOfRangeException(nameof(module)),
    };

    /// <summary>Resolves an owner name to its module; an owner with no position in the order (support, trustsafety) is not resolved.</summary>
    public static bool TryFromOwner(string owner, out FamilyModule module)
    {
        foreach (var candidate in Ordered)
        {
            if (string.Equals(Owner(candidate), owner, StringComparison.Ordinal))
            {
                module = candidate;
                return true;
            }
        }

        module = FamilyModule.Platform;
        return string.Equals(owner, "platform", StringComparison.Ordinal);
    }
}
