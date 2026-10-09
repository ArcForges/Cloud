// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Generation;

/// <summary>
/// The correlation guards the Worker applies before it forwards a call (CLOUD.69, CLOUD.84 S34(3); Design CR-01 and CR-03). The identity
/// shape, the fields that carry it in a request and the traceparent form the Worker writes are declared here and generated into
/// worker/tables/cloud-tables.generated.ts. The Worker refuses a malformed identity before any Container wakes, and copies no client value
/// into a header. The host's own rule (CorrelationContext.IsValidId) is unchanged, and GeneratedTablesTests checks that these declarations
/// accept exactly the identities the host accepts.
/// </summary>
internal static class CorrelationGuards
{
    /// <summary>A canonical lowercase hyphenated UUID: the only accepted spelling of a correlation or causation id.</summary>
    public const string UuidPattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

    /// <summary>The nil UUID, which is never a correlation identity.</summary>
    public const string NilUuid = "00000000-0000-0000-0000-000000000000";

    /// <summary>RequestMeta is field 1 of every generated request message (wire registry 04).</summary>
    public const int RequestMetaField = 1;

    /// <summary>RequestMeta.correlationId is field 3 of RequestMeta.</summary>
    public const int CorrelationIdField = 3;

    /// <summary>The value of an Id message is its field 1.</summary>
    public const int IdValueField = 1;

    /// <summary>An Id value is exactly this many bytes, and never all zero.</summary>
    public const int IdByteLength = 16;

    /// <summary>The W3C traceparent version the Worker writes.</summary>
    public const string TraceparentVersion = "00";

    /// <summary>The W3C traceparent flags the Worker writes (sampled).</summary>
    public const string TraceparentFlags = "01";
}
