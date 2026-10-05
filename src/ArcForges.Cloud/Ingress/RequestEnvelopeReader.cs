// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Ingress;

/// <summary>What the pipeline needs from the request envelope: the addressed workspace and the caller-stated recovery generation.</summary>
internal readonly record struct RequestEnvelope(string? WorkspaceId, ulong? RecoveryGeneration);

/// <summary>
/// Reads <c>RequestMeta</c> (field 1 of every generated request message, wire registry 04) straight from the protobuf bytes, so the
/// owner gate needs no per-method generated type and no reflection. It is strict: a repeated meta, a repeated workspace or generation,
/// an <c>Id</c> that is not exactly 16 nonzero bytes, a group, a truncated field or a wrong wire type is malformed. Other fields are skipped.
/// </summary>
internal static class RequestEnvelopeReader
{
    private const int MetaField = 1;
    private const int WorkspaceField = 4;
    private const int RecoveryGenerationField = 7;
    private const int IdValueField = 1;

    public static bool TryRead(ReadOnlySpan<byte> message, out RequestEnvelope envelope)
    {
        envelope = default;
        var seenMeta = false;
        var position = 0;
        while (position < message.Length)
        {
            if (!ProtoWire.TryReadTag(message, ref position, out var field, out var wire)) return false;
            if (field == MetaField)
            {
                if (wire != 2 || seenMeta || !ProtoWire.TryReadLengthDelimited(message, ref position, out var meta) || !TryReadMeta(meta, out envelope)) return false;
                seenMeta = true;
            }
            else if (!ProtoWire.TrySkip(message, ref position, wire))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Canonical lowercase UUID text of 16 bytes in canonical order (not the .NET Guid layout).</summary>
    public static string FormatId(ReadOnlySpan<byte> id)
    {
        var hex = Convert.ToHexStringLower(id);
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }

    private static bool TryReadMeta(ReadOnlySpan<byte> meta, out RequestEnvelope envelope)
    {
        envelope = default;
        string? workspace = null;
        ulong? generation = null;
        var position = 0;
        while (position < meta.Length)
        {
            if (!ProtoWire.TryReadTag(meta, ref position, out var field, out var wire)) return false;
            switch (field)
            {
                case WorkspaceField:
                    if (wire != 2 || workspace is not null || !ProtoWire.TryReadLengthDelimited(meta, ref position, out var id) || !TryReadId(id, out workspace)) return false;
                    break;
                case RecoveryGenerationField:
                    if (wire != 0 || generation is not null || !ProtoWire.TryReadVarint(meta, ref position, out var value)) return false;
                    generation = value;
                    break;
                default:
                    if (!ProtoWire.TrySkip(meta, ref position, wire)) return false;
                    break;
            }
        }

        envelope = new RequestEnvelope(workspace, generation);
        return true;
    }

    private static bool TryReadId(ReadOnlySpan<byte> id, out string? text)
    {
        text = null;
        byte[]? value = null;
        var position = 0;
        while (position < id.Length)
        {
            if (!ProtoWire.TryReadTag(id, ref position, out var field, out var wire)) return false;
            if (field == IdValueField)
            {
                if (wire != 2 || value is not null || !ProtoWire.TryReadLengthDelimited(id, ref position, out var bytes)) return false;
                value = bytes.ToArray();
            }
            else if (!ProtoWire.TrySkip(id, ref position, wire))
            {
                return false;
            }
        }

        if (value is not { Length: 16 } || value.All(b => b == 0)) return false;
        text = FormatId(value);
        return true;
    }
}
