// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Ingress;

namespace ArcForges.Cloud.Generation;

/// <summary>
/// The production transport limits and identifier shapes that the Worker applies before it forwards a call (CLOUD.84 S34 and S43(3)).
/// They are declarations only: tools/ArcForges.Cloud.Generation reads every public constant of this class and emits it into
/// worker/tables/cloud-tables.generated.ts, so the Worker holds no limit or shape literal of its own. A constant whose name ends in Pattern
/// is emitted as a regular expression literal; every other string is emitted as a string. A value the host already declares is referenced,
/// not copied, so there is one source for it.
/// </summary>
internal static class WorkerWireLimits
{
    /// <summary>The Worker abandons a request body that is not read within this long (the production pipeline's body timer).</summary>
    public const int BodyReadMilliseconds = 5000;

    /// <summary>The Worker abandons a discarded upload that is not read within this long (the production router's cleanup timer).</summary>
    public const int RouterBodyReadMilliseconds = 1000;

    /// <summary>The idle time after which the production Container may sleep (the Containers library's sleepAfter).</summary>
    public const string ContainerSleepAfter = "60s";

    /// <summary>The gRPC-Web frame header: one flag byte and a four-byte length (the host's framing).</summary>
    public const int GrpcFrameHeaderBytes = GrpcWebFraming.HeaderLength;

    /// <summary>The W3C parent id of one hop: eight random bytes, never all zero.</summary>
    public const int SpanIdByteLength = 8;

    /// <summary>The canonical lowercase hyphenated UUID, the one identity shape every importer shares (CR-01, CR-03).</summary>
    public const string CanonicalUuidPattern = CorrelationGuards.UuidPattern;

    /// <summary>A lowercase hexadecimal SHA-256 digest (64 characters).</summary>
    public const string Sha256HexPattern = "^[0-9a-f]{64}$";

    /// <summary>Lowercase hexadecimal bytes: an even number of hexadecimal characters, possibly none.</summary>
    public const string HexBytesPattern = "^(?:[0-9a-f]{2})*$";

    /// <summary>The session cookie value and the CSRF token: 43 base64url characters (256 random bits, unpadded).</summary>
    public const string SessionTokenPattern = "^[A-Za-z0-9_-]{43}$";

    /// <summary>A bearer credential: the scheme word and 16 to 4096 token characters.</summary>
    public const string BearerCredentialPattern = "^Bearer ([A-Za-z0-9._~+/=-]{16,4096})$";
}
