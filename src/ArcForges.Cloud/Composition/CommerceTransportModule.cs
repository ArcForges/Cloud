// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Infrastructure;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArcForges.Cloud.Composition;

/// <summary>Host-owned transport only. Commerce registers its provider from approved configuration and
/// consumes the keyed factory; this module publishes no RPC, credential, merchant policy or business service.</summary>
internal sealed class CommerceTransportModule : IHostModule
{
    private readonly Func<string, string?> environment;
    private readonly Func<HttpMessageHandler>? authorityFactory;

    public CommerceTransportModule() : this(Environment.GetEnvironmentVariable) { }
    internal CommerceTransportModule(Func<string, string?> environment, Func<HttpMessageHandler>? authorityFactory = null)
    {
        this.environment = environment;
        this.authorityFactory = authorityFactory;
    }

    public void Register(WebApplicationBuilder builder)
    {
        var enabled = environment("ARCFORGES_COMMERCE_EGRESS");
        if (enabled is not null && enabled != "enabled")
            throw new InvalidOperationException("Invalid commerce transport configuration.");
        // Lazy trust loading preserves the existing Hello host even when no merchant service is configured.
        // Resolving/using the transport fails closed without explicit enablement and a valid platform CA.
        builder.Services.TryAddKeyedSingleton<Func<HttpMessageHandler>>(CommerceHttpTransport.ServiceKey, (_, _) =>
            () => enabled == "enabled" && authorityFactory is not null ? authorityFactory() : CommerceHttpTransport.Create(enabled));
    }

    public void Map(WebApplication app) { }
}
