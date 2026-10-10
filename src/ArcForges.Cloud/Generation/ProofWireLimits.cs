// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;

namespace ArcForges.Cloud.Generation;

/// <summary>
/// The limits and identifier shapes of the isolated proof composition (FOUNDATION_PROOF): the foundation objects, container, operator and
/// signing paths, the readiness report and the named-plan deadline and integer grammar (CLOUD.84 S39(3) and S43(3)). The generator emits
/// them into the same generated module; the production bundle does not import them, so they are tree-shaken out of it. As with
/// <see cref="WorkerWireLimits"/>, a value the host already declares is referenced rather than copied.
/// </summary>
internal static class ProofWireLimits
{
    /// <summary>The largest object part the objects facade accepts (the host's ObjectsClient bound).</summary>
    public const int MaxPartBytes = ObjectsClient.MaxBytes;

    /// <summary>The SHA-256 of an empty body: the hash a signed GET of a body-less request carries.</summary>
    public const string EmptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// <summary>A realm identifier: lowercase letters and digits, a hyphen after the first character, at most 32 more characters.</summary>
    public const string RealmPattern = "^[a-z0-9][a-z0-9-]{0,31}$";

    /// <summary>A byte range with both ends present: bytes=start-end, each end at most twelve digits.</summary>
    public const string ObjectsRangePattern = "^bytes=(\\d{1,12})-(\\d{1,12})$";

    /// <summary>A declared content length: a positive decimal number of at most nine digits.</summary>
    public const string ObjectsContentLengthPattern = "^[1-9][0-9]{0,8}$";

    /// <summary>The largest request body of a proof route (the host's foundation endpoint bound).</summary>
    public const int MaxRequestBytes = FoundationEndpoints.MaxBodyBytes;

    /// <summary>The largest reply the Worker reads from the Container (the proof container client bound).</summary>
    public const int MaxReplyBytes = 65_536;

    /// <summary>A proof scope: the literal proof/ and at most 200 characters of path.</summary>
    public const string ScopePattern = "^proof\\/[A-Za-z0-9._/-]{1,200}$";

    /// <summary>The shortest proof token that enables the proof credential path.</summary>
    public const int ProofMinimumTokenBytes = 32;

    /// <summary>The retry delay the proof queue consumer asks for when the proof environment is not enabled.</summary>
    public const int ProofRetryDelaySeconds = 60;

    /// <summary>The largest clock difference an operator signature may carry.</summary>
    public const int OperatorMaxSkewSeconds = 60;

    /// <summary>An operator authorization header: the scheme, the time, the nonce and the signature.</summary>
    public const string OperatorHeaderPattern = "^AF-Operator t=(\\d{10}),n=([A-Za-z0-9_-]{22}),s=([A-Za-z0-9_-]{86})$";

    /// <summary>An Ed25519 public key is 32 bytes.</summary>
    public const int OperatorPublicKeyBytes = 32;

    /// <summary>An Ed25519 signature is 64 bytes.</summary>
    public const int OperatorSignatureBytes = 64;

    /// <summary>The largest clock difference of a private request signature (the host's PrivateRequestSigning bound).</summary>
    public const int MaxSkewSeconds = PrivateRequestSigning.MaxSkewSeconds;

    /// <summary>A deployment signing secret is this many bytes (the host's PrivateRequestSigning length).</summary>
    public const int SecretByteLength = SigningKey.SecretLength;

    /// <summary>A signing key identifier: an alphanumeric character followed by at most 63 identifier characters.</summary>
    public const string KeyIdPattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$";

    /// <summary>A signing epoch in seconds: a positive decimal number of at most sixteen digits.</summary>
    public const string EpochSecondsPattern = "^[1-9][0-9]{0,15}$";

    /// <summary>A signing nonce: 22 base64url characters (128 random bits, unpadded).</summary>
    public const string NoncePattern = "^[A-Za-z0-9_-]{22}$";

    /// <summary>An HMAC-SHA256 tag is 32 bytes.</summary>
    public const int MacBytes = 32;

    /// <summary>The random bytes a new nonce is made from.</summary>
    public const int NonceRandomBytes = 16;

    /// <summary>More than the longest library opening of a Container reply is never read.</summary>
    public const int ClassifiedPrefixBytes = 128;

    /// <summary>The longest worker revision the readiness report accepts (the host's readiness bound).</summary>
    public const int MaxRevisionLength = 80;

    /// <summary>The longest schema version the readiness report accepts.</summary>
    public const int MaxSchemaVersionLength = 8;

    /// <summary>The longest elapsed time the readiness report accepts, in milliseconds.</summary>
    public const int MaxElapsedMs = 60_000;

    /// <summary>A named-plan deadline: an RFC 3339 UTC timestamp with at most seven fractional digits.</summary>
    public const string DeadlinePattern = "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d{1,7}))?Z$";

    /// <summary>A canonical int64 argument: zero, or an optional minus sign and a non-zero leading digit.</summary>
    public const string Int64TextPattern = "^(?:0|-?[1-9][0-9]*)$";

    /// <summary>A canonical uint64 argument: zero, or a non-zero leading digit.</summary>
    public const string Uint64TextPattern = "^(?:0|[1-9][0-9]*)$";

    /// <summary>A readiness binding's uint64 text, at most twenty digits.</summary>
    public const string BindingUint64TextPattern = "^(0|[1-9][0-9]{0,19})$";
}
