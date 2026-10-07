// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArcForges.Cloud.Composition;

/// <summary>Lazy required policy input, isolated from existing-row reads and anonymous health. Identity owns parsing and persistence.</summary>
internal sealed class IdentityDeletionModule : IHostModule
{
    public void Register(WebApplicationBuilder builder) => builder.Services.TryAddSingleton(_ => new IdentityDeletionPolicyInput(
        Environment.GetEnvironmentVariable("AF_IDENTITY_DELETION_POLICY_VERSION"), Environment.GetEnvironmentVariable("AF_IDENTITY_DELETION_GRACE_SECONDS")));

    public void Map(WebApplication app)
    {
        // The owning public recovery transport activates only after CLOUD17's complete real participant composition.
    }
}
