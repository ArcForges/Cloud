// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

/// <summary>
/// The model and tariff snapshot a run was pinned to. A dispatch is allowed only against exactly this pair; a missing, empty or
/// changed pin is refused before any dispatch (HAR.40 validation (f)).
/// </summary>
internal sealed record PinnedSnapshot(string ModelId, string TariffSnapshotId)
{
    internal bool IsPinned => IsToken(ModelId) && IsToken(TariffSnapshotId);

    /// <summary>True when this run's pin and the requested pair are the same non-empty pair.</summary>
    internal bool Matches(PinnedSnapshot requested) =>
        IsPinned && requested.IsPinned
        && string.Equals(ModelId, requested.ModelId, StringComparison.Ordinal)
        && string.Equals(TariffSnapshotId, requested.TariffSnapshotId, StringComparison.Ordinal);

    private static bool IsToken(string value) =>
        value.Length is >= 1 and <= 128
        && value.All(character => character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or ':' or '/' or '-');
}

/// <summary>
/// The identity of one run execution: the C# claim epoch and recovery generation, the Cloud build identity and the Cloudflare Worker
/// version identifier (HAR.40 validation (g)). A change in any component yields a different digest, and the digest is bound into every
/// dispatch intent, so the Worker version is never replaced by the Cloud build identity.
/// </summary>
internal sealed record RunIdentity(Guid RunId, string CloudBuildIdentity, string WorkerVersion, long RecoveryGeneration, PinnedSnapshot Pinned)
{
    /// <summary>The Workflow-compatible identifier of this generation, as contracts 05 names it.</summary>
    internal string WorkflowId => "af-" + RunId.ToString("D") + "-" + RecoveryGeneration.ToString(CultureInfo.InvariantCulture);

    /// <summary>Lower-case hex SHA-256 over the canonical identity lines, for one claim epoch.</summary>
    internal string DigestForEpoch(long epoch)
    {
        var canonical = string.Join(
            "\n",
            "af.run-identity.v1",
            RunId.ToString("D"),
            CloudBuildIdentity,
            WorkerVersion,
            RecoveryGeneration.ToString(CultureInfo.InvariantCulture),
            epoch.ToString(CultureInfo.InvariantCulture),
            Pinned.ModelId,
            Pinned.TariffSnapshotId);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
