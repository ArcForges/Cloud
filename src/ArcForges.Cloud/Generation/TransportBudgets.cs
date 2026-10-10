// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Generation;

/// <summary>
/// One method's transport budget as the Worker applies it before it forwards a call (CLOUD.84 S34(1)). These are declarations only: the
/// host keeps its own enforcement and these values do not change it. tools/ArcForges.Cloud.Generation reads them with the RPC policies
/// and emits worker/tables/cloud-tables.generated.ts, so the Worker holds no budget literal of its own.
/// </summary>
/// <param name="MaxFrameBytes">The bound of one response frame.</param>
/// <param name="MaxUnaryResponseBytes">The bound of a whole unary response, buffered before any byte is returned.</param>
/// <param name="MaxDurationMilliseconds">The cap of the RPC deadline (unary) or of the stream lifetime (server stream).</param>
/// <param name="Instance">The Container instance (Durable Object name) that serves the method.</param>
internal sealed record TransportBudget(int MaxFrameBytes, int MaxUnaryResponseBytes, int MaxDurationMilliseconds, string Instance);

/// <summary>
/// The transport budgets of the public ingress. The generator refuses a registered public method that has no budget here, and a budget
/// that names no registered method, so the two lists cannot drift apart.
/// </summary>
internal static class TransportBudgets
{
    /// <summary>The bound of a whole request body, frame header included. It equals the Hello policy's bound, which the generator checks.</summary>
    public const int MaxBodyBytes = 4096;

    /// <summary>The Container may take at most this long to start before a stream's response headers arrive.</summary>
    public const int ColdStartMilliseconds = 15_000;

    /// <summary>A server stream's lifetime when the client states no shorter deadline: the annex 10 server close after five minutes plus slack.</summary>
    public const int StreamLifetimeMilliseconds = 310_000;

    /// <summary>The health route is a small plain reply: its bound of the whole response.</summary>
    public const int HealthMaxUnaryResponseBytes = 8192;

    /// <summary>The health route's own cap on its duration.</summary>
    public const int HealthMaxDurationMilliseconds = 15_000;

    /// <summary>The Container instance that answers the health route.</summary>
    public const string HealthInstance = "hello";

    /// <summary>The budget of each public method, keyed by its exact method path.</summary>
    public static IReadOnlyDictionary<string, TransportBudget> ByMethod { get; } = new Dictionary<string, TransportBudget>(StringComparer.Ordinal)
    {
        ["/arcforges.hello.v1.HelloService/SayHello"] = new(MaxFrameBytes: 8192, MaxUnaryResponseBytes: 8192, MaxDurationMilliseconds: 10_000, Instance: "hello"),
        ["/arcforges.proof.v1.PipelineProbe/Whoami"] = new(MaxFrameBytes: 65_536, MaxUnaryResponseBytes: 8192, MaxDurationMilliseconds: 10_000, Instance: "foundation"),
        ["/arcforges.proof.v1.PipelineProbe/Stream"] = new(MaxFrameBytes: 65_536, MaxUnaryResponseBytes: 8192, MaxDurationMilliseconds: 60_000, Instance: "foundation"),
        ["/arcforges.proof.v1.PipelineProbe/Observation"] = new(MaxFrameBytes: 65_536, MaxUnaryResponseBytes: 8192, MaxDurationMilliseconds: 10_000, Instance: "foundation"),
    };
}
