// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;

namespace ArcForges.Cloud.Ingress;

/// <summary>Counters of the probe streams of this process; an observation of what the host saw, never an authority.</summary>
internal sealed class PipelineProbeState
{
    private long started;
    private long completed;
    private long canceled;
    private long deadlineExceeded;

    public long Started => Interlocked.Read(ref started);

    public long Completed => Interlocked.Read(ref completed);

    public long Canceled => Interlocked.Read(ref canceled);

    public long DeadlineExceeded => Interlocked.Read(ref deadlineExceeded);

    public void Start() => Interlocked.Increment(ref started);

    public void Complete() => Interlocked.Increment(ref completed);

    public void Cancel() => Interlocked.Increment(ref canceled);

    public void Expire() => Interlocked.Increment(ref deadlineExceeded);
}

/// <summary>
/// The proof-only gRPC-Web probe that lets the deployed ingress be observed end to end without a business service: an authenticated
/// workspace-scoped unary call that reports the admitted caller and current owner, a server stream that emits timed frames and a custom
/// trailer, and an observation of how the host saw its streams end. It is registered only when the foundation proof is enabled, so the
/// production host and Worker route table do not contain it. The messages are hand-framed proof bytes, not Contracts records: the pinned
/// generated surface carries no authenticated unary or server-streaming method that fits, and no wire meaning is invented for product use.
/// Request messages follow the envelope convention (field 1 is <c>RequestMeta</c>). Every reply the probe builds carries the call's
/// correlation identity the way a business reply does (CLOUD.69): field 10 is <c>ResponseMeta</c> (a unary reply and every stream frame)
/// and, for an acknowledged domain refusal, field 11 is an <c>ArcError</c> in a reply with an OK status. Whoami asks for that refusal with
/// request field 10 set to 1; it is the one place the host builds an <c>ArcError</c> today.
/// </summary>
internal static partial class PipelineProbe
{
    public const string WhoamiPath = "/arcforges.proof.v1.PipelineProbe/Whoami";
    public const string StreamPath = "/arcforges.proof.v1.PipelineProbe/Stream";
    public const string ObservationPath = "/arcforges.proof.v1.PipelineProbe/Observation";
    public const int MaxFrames = 50;
    public const int MaxIntervalMilliseconds = 2000;
    public const int MaxTotalMilliseconds = 30_000;
    public const int DefaultFrames = 3;
    public const int DefaultIntervalMilliseconds = 100;
    public const int MetaField = 10;
    public const int ErrorField = 11;
    public const int RefuseField = 10;
    public const string RefusalCode = "state.not_found";
    public const string TrailerName = "x-af-probe";
    public const string TrailerValue = "done";

    public static IEnumerable<RpcPolicy> Policies =>
    [
        RpcPolicy.Unary(WhoamiPath, RpcAuthentication.Session, RpcScope.Workspace),
        RpcPolicy.ServerStream(StreamPath, RpcAuthentication.Session, RpcScope.Workspace),
        RpcPolicy.Unary(ObservationPath, RpcAuthentication.Session, RpcScope.Workspace),
    ];

    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost(WhoamiPath, WhoamiAsync);
        app.MapPost(StreamPath, StreamAsync);
        app.MapPost(ObservationPath, ObservationAsync);
    }

    private static async Task WhoamiAsync(HttpContext context)
    {
        var call = context.Features.Get<IngressCall>()!;
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, context.RequestAborted);
        if (WantsRefusal(body.ToArray()))
        {
            // An acknowledged domain refusal: gRPC OK, and the outcome is an ArcError that carries the call's correlation identity.
            var refusal = new ProtoBuilder()
                .Bytes(MetaField, CorrelationReplies.Meta(call.Correlation).ToByteArray())
                .Bytes(ErrorField, CorrelationReplies.Error(call.Correlation, RefusalCode, ErrorCategory.State, RefusalCode).ToByteArray());
            await WriteUnaryAsync(context, refusal.ToArray());
            return;
        }

        var message = new ProtoBuilder()
            .String(1, call.Caller.SessionId ?? "")
            .String(2, call.Caller.UserId ?? "")
            .String(3, call.Owner?.WorkspaceId ?? "")
            .Varint(4, call.Owner?.RecoveryGeneration ?? 0)
            .Bytes(MetaField, CorrelationReplies.Meta(call.Correlation).ToByteArray());
        await WriteUnaryAsync(context, message.ToArray());
    }

    /// <summary>The pipeline already read this envelope strictly; here only the proof's own request field is looked at.</summary>
    private static bool WantsRefusal(byte[] body)
    {
        if (!GrpcWebFraming.TryReadSingleMessage(body, out var message)) return false;
        var position = 0;
        while (position < message.Length)
        {
            if (!ProtoWire.TryReadTag(message, ref position, out var field, out var wire)) return false;
            if (field == RefuseField && wire == 0)
            {
                return ProtoWire.TryReadVarint(message, ref position, out var value) && value == 1;
            }

            if (!ProtoWire.TrySkip(message, ref position, wire)) return false;
        }

        return false;
    }

    private static async Task ObservationAsync(HttpContext context)
    {
        var state = context.RequestServices.GetRequiredService<PipelineProbeState>();
        var call = context.Features.Get<IngressCall>()!;
        var message = new ProtoBuilder()
            .Varint(1, (ulong)state.Started)
            .Varint(2, (ulong)state.Completed)
            .Varint(3, (ulong)state.Canceled)
            .Varint(4, (ulong)state.DeadlineExceeded)
            .Bytes(MetaField, CorrelationReplies.Meta(call.Correlation).ToByteArray());
        await WriteUnaryAsync(context, message.ToArray());
    }

    private static async Task WriteUnaryAsync(HttpContext context, byte[] message)
    {
        var response = context.Response;
        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = "application/grpc-web+proto";
        var frame = GrpcWebFraming.Frame(message);
        var trailer = GrpcWebFraming.TrailerFrame(GrpcWebFraming.Ok);
        await response.Body.WriteAsync(frame, context.RequestAborted);
        await response.Body.WriteAsync(trailer, context.RequestAborted);
    }

    private static async Task StreamAsync(HttpContext context)
    {
        var state = context.RequestServices.GetRequiredService<PipelineProbeState>();
        var meta = CorrelationReplies.Meta(context.Features.Get<IngressCall>()!.Correlation).ToByteArray();
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, context.RequestAborted);
        if (!TryReadStreamRequest(body.ToArray(), out var frames, out var interval))
        {
            await IngressPipeline.RefuseAsync(context, GrpcWebFraming.InvalidArgument, "validation.invalid_request");
            return;
        }

        state.Start();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        if (TryParseTimeout(context.Request.Headers["grpc-timeout"].ToString(), out var deadline)) linked.CancelAfter(deadline);
        var response = context.Response;
        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = "application/grpc-web+proto";
        try
        {
            await response.StartAsync(linked.Token);
            for (var sequence = 0; sequence < frames; sequence++)
            {
                if (sequence > 0 && interval > 0) await Task.Delay(interval, linked.Token);
                var message = new ProtoBuilder().Varint(1, (ulong)sequence).Bytes(2, Payload(sequence)).Bytes(MetaField, meta);
                await response.Body.WriteAsync(GrpcWebFraming.Frame(message.ToArray()), linked.Token);
                await response.Body.FlushAsync(linked.Token);
            }

            await response.Body.WriteAsync(GrpcWebFraming.TrailerFrame(GrpcWebFraming.Ok, null, (TrailerName, TrailerValue)), linked.Token);
            await response.Body.FlushAsync(linked.Token);
            state.Complete();
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // The client or the Worker went away: nothing can be written, and the stream must stop producing at once.
            state.Cancel();
        }
        catch (OperationCanceledException)
        {
            state.Expire();
            await response.Body.WriteAsync(GrpcWebFraming.TrailerFrame(GrpcWebFraming.DeadlineExceeded, "dependency.timeout"), CancellationToken.None);
        }
    }

    /// <summary>A deterministic 32-byte payload per sequence, so a client can detect a reordered, duplicated or altered frame.</summary>
    internal static byte[] Payload(int sequence)
    {
        var bytes = new byte[32];
        for (var i = 0; i < bytes.Length; i++) bytes[i] = (byte)((sequence * 31) + i);
        return bytes;
    }

    private static bool TryReadStreamRequest(byte[] body, out int frames, out int interval)
    {
        frames = DefaultFrames;
        interval = DefaultIntervalMilliseconds;
        if (!GrpcWebFraming.TryReadSingleMessage(body, out var message)) return false;
        var position = 0;
        while (position < message.Length)
        {
            if (!ProtoWire.TryReadTag(message, ref position, out var field, out var wire)) return false;
            if (field is 10 or 11)
            {
                if (wire != 0 || !ProtoWire.TryReadVarint(message, ref position, out var value) || value > int.MaxValue) return false;
                if (field == 10) frames = (int)value;
                else interval = (int)value;
            }
            else if (!ProtoWire.TrySkip(message, ref position, wire))
            {
                return false;
            }
        }

        return frames is >= 1 and <= MaxFrames && interval is >= 0 and <= MaxIntervalMilliseconds
            && (long)frames * interval <= MaxTotalMilliseconds;
    }

    /// <summary>The gRPC <c>grpc-timeout</c> header: up to eight digits and a unit; a malformed value means no deadline here (the Worker already bounds it).</summary>
    internal static bool TryParseTimeout(string header, out TimeSpan timeout)
    {
        timeout = default;
        var match = TimeoutPattern().Match(header);
        if (!match.Success) return false;
        var amount = long.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
        timeout = match.Groups[2].Value switch
        {
            "H" => TimeSpan.FromHours(amount),
            "M" => TimeSpan.FromMinutes(amount),
            "S" => TimeSpan.FromSeconds(amount),
            "m" => TimeSpan.FromMilliseconds(amount),
            "u" => TimeSpan.FromTicks(amount * 10),
            _ => TimeSpan.FromTicks(Math.Max(1, amount / 100)),
        };
        return true;
    }

    [GeneratedRegex(@"^(\d{1,8})([HMSmun])\z")]
    private static partial Regex TimeoutPattern();

    /// <summary>Just enough protobuf writing for the probe replies.</summary>
    private sealed class ProtoBuilder
    {
        private readonly MemoryStream buffer = new();

        public ProtoBuilder Varint(int field, ulong value)
        {
            WriteVarint(((ulong)field << 3) | 0);
            WriteVarint(value);
            return this;
        }

        public ProtoBuilder String(int field, string value) => Bytes(field, Encoding.UTF8.GetBytes(value));

        public ProtoBuilder Bytes(int field, byte[] value)
        {
            WriteVarint(((ulong)field << 3) | 2);
            WriteVarint((ulong)value.Length);
            buffer.Write(value);
            return this;
        }

        public byte[] ToArray() => buffer.ToArray();

        private void WriteVarint(ulong value)
        {
            while (value >= 0x80)
            {
                buffer.WriteByte((byte)(value | 0x80));
                value >>= 7;
            }

            buffer.WriteByte((byte)value);
        }
    }
}
