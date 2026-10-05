// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Text;

namespace ArcForges.Cloud.Ingress;

/// <summary>The gRPC-Web wire framing the pipeline reads and writes by hand: one flag byte, a big-endian length and the payload.</summary>
internal static class GrpcWebFraming
{
    public const byte DataFlag = 0x00;
    public const byte TrailerFlag = 0x80;
    public const int HeaderLength = 5;

    /// <summary>The standard gRPC status codes the pipeline itself produces.</summary>
    public const int Ok = 0;
    public const int Canceled = 1;
    public const int InvalidArgument = 3;
    public const int DeadlineExceeded = 4;
    public const int PermissionDenied = 7;
    public const int ResourceExhausted = 8;
    public const int FailedPrecondition = 9;
    public const int Unimplemented = 12;
    public const int Internal = 13;
    public const int Unavailable = 14;
    public const int Unauthenticated = 16;

    public static byte[] Frame(ReadOnlySpan<byte> message)
    {
        var frame = new byte[HeaderLength + message.Length];
        frame[0] = DataFlag;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)message.Length);
        message.CopyTo(frame.AsSpan(HeaderLength));
        return frame;
    }

    /// <summary>A trailer frame: one <c>name: value</c> CRLF line per trailer, names already lowercase.</summary>
    public static byte[] TrailerFrame(int status, string? message = null, params (string Name, string Value)[] extra)
    {
        var text = new StringBuilder().Append("grpc-status: ").Append(status).Append("\r\n");
        if (message is not null) text.Append("grpc-message: ").Append(Uri.EscapeDataString(message)).Append("\r\n");
        foreach (var (name, value) in extra) text.Append(name).Append(": ").Append(value).Append("\r\n");
        var payload = Encoding.ASCII.GetBytes(text.ToString());
        var frame = new byte[HeaderLength + payload.Length];
        frame[0] = TrailerFlag;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)payload.Length);
        payload.CopyTo(frame, HeaderLength);
        return frame;
    }

    /// <summary>
    /// The one message of a unary or server-streaming request: exactly one uncompressed data frame whose declared length matches
    /// the rest of the body. Anything else (no frame, a second frame, the compressed flag, a trailer flag, a length mismatch) is refused.
    /// </summary>
    public static bool TryReadSingleMessage(ReadOnlySpan<byte> body, out ReadOnlySpan<byte> message)
    {
        message = default;
        if (body.Length < HeaderLength || body[0] != DataFlag) return false;
        var length = BinaryPrimitives.ReadUInt32BigEndian(body[1..]);
        if (length != (uint)(body.Length - HeaderLength)) return false;
        message = body[HeaderLength..];
        return true;
    }
}
