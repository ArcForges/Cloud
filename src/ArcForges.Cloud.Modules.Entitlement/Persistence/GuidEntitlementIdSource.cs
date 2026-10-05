// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;

namespace ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;

/// <summary>
/// The production identifier source: a random version 4 UUID in the canonical lower-case form every <c>id</c> column of the physical
/// schema requires. Tests supply their own deterministic source through the port.
/// </summary>
internal sealed class GuidEntitlementIdSource : IEntitlementIdSource
{
    public string NewId() => Guid.NewGuid().ToString("D");
}
