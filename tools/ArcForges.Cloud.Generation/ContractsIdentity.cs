// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;

namespace ArcForges.Cloud.Tools.Generation;

/// <summary>
/// The restored ArcForges.Contracts.PublicApi identity (source.json) exactly as the Cloud assembly embeds it (CLOUD.84 S33(3)(a)). The copy
/// committed at eng/generated/contracts-identity.json is byte-identical to it, and the Node tooling reads the committed copy.
/// </summary>
public static class ContractsIdentity
{
    /// <summary>The manifest resource name the Cloud project gives the restored source.json.</summary>
    public const string ResourceName = "Cloud.ContractsSource";

    public static byte[] Read(Assembly assembly)
    {
        using var stream = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"The Cloud assembly embeds no {ResourceName} resource.");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
}
