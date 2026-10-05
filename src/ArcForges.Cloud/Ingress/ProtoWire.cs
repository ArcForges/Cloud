// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Ingress;

/// <summary>Minimal strict protobuf wire reading shared by the envelope reader and the proof probe; groups and truncation are refused.</summary>
internal static class ProtoWire
{
    internal static bool TryReadTag(ReadOnlySpan<byte> data, ref int position, out int field, out int wire)
    {
        field = 0;
        wire = 0;
        if (!TryReadVarint(data, ref position, out var tag) || tag >> 3 is 0 or > int.MaxValue) return false;
        field = (int)(tag >> 3);
        wire = (int)(tag & 7);
        return true;
    }

    internal static bool TryReadVarint(ReadOnlySpan<byte> data, ref int position, out ulong value)
    {
        value = 0;
        for (var shift = 0; shift < 70; shift += 7)
        {
            if (position >= data.Length) return false;
            var b = data[position++];
            if (shift == 63 && b > 1) return false;
            value |= (ulong)(b & 0x7f) << shift;
            if ((b & 0x80) == 0) return true;
        }

        return false;
    }

    internal static bool TryReadLengthDelimited(ReadOnlySpan<byte> data, ref int position, out ReadOnlySpan<byte> body)
    {
        body = default;
        if (!TryReadVarint(data, ref position, out var length) || length > (ulong)(data.Length - position)) return false;
        body = data.Slice(position, (int)length);
        position += (int)length;
        return true;
    }

    internal static bool TrySkip(ReadOnlySpan<byte> data, ref int position, int wire)
    {
        switch (wire)
        {
            case 0:
                return TryReadVarint(data, ref position, out _);
            case 1:
                return Advance(data, ref position, 8);
            case 2:
                return TryReadLengthDelimited(data, ref position, out _);
            case 5:
                return Advance(data, ref position, 4);
            default:
                return false;
        }
    }

    internal static bool Advance(ReadOnlySpan<byte> data, ref int position, int count)
    {
        if (data.Length - position < count) return false;
        position += count;
        return true;
    }
}
