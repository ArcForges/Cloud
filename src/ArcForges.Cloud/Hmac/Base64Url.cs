// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;

namespace ArcForges.Cloud.Hmac;

/// <summary>Strict unpadded base64url: one accepted text form per byte string.</summary>
internal static class Base64Url
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        var output = new StringBuilder((bytes.Length * 4 + 2) / 3);
        var index = 0;
        for (; index + 2 < bytes.Length; index += 3)
        {
            var value = (bytes[index] << 16) | (bytes[index + 1] << 8) | bytes[index + 2];
            output.Append(Alphabet[(value >> 18) & 63]).Append(Alphabet[(value >> 12) & 63])
                .Append(Alphabet[(value >> 6) & 63]).Append(Alphabet[value & 63]);
        }

        switch (bytes.Length - index)
        {
            case 1:
                output.Append(Alphabet[bytes[index] >> 2]).Append(Alphabet[(bytes[index] & 3) << 4]);
                break;
            case 2:
                var pair = (bytes[index] << 8) | bytes[index + 1];
                output.Append(Alphabet[pair >> 10]).Append(Alphabet[(pair >> 4) & 63]).Append(Alphabet[(pair & 15) << 2]);
                break;
        }

        return output.ToString();
    }

    /// <summary>Only the 64 URL-safe characters, no padding or whitespace, and zero trailing bits.</summary>
    public static bool TryDecode(ReadOnlySpan<char> text, out byte[] bytes)
    {
        bytes = [];
        if (text.Length % 4 == 1) return false;
        var values = new int[text.Length];
        for (var index = 0; index < text.Length; index++)
        {
            var value = text[index] < 128 ? Alphabet.IndexOf(text[index], StringComparison.Ordinal) : -1;
            if (value < 0) return false;
            values[index] = value;
        }

        var output = new List<byte>(text.Length * 3 / 4);
        for (var index = 0; index < values.Length; index += 4)
        {
            var count = Math.Min(4, values.Length - index);
            var packed = 0;
            for (var offset = 0; offset < 4; offset++) packed = (packed << 6) | (offset < count ? values[index + offset] : 0);
            output.Add((byte)(packed >> 16));
            if (count > 2) output.Add((byte)(packed >> 8));
            if (count > 3) output.Add((byte)packed);
            if (count == 2 && (packed & 0xffff) != 0) return false;
            if (count == 3 && (packed & 0xff) != 0) return false;
        }

        bytes = [.. output];
        return true;
    }
}
