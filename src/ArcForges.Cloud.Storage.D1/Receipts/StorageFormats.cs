// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.Json;

namespace ArcForges.Cloud.Storage.Receipts;

/// <summary>Exact formats of the values the commit tail and the platform plans bind (Design model 01 section 2, physical conventions).</summary>
internal static class StorageFormats
{
    /// <summary>The change archive is the one stream whose key starts with this prefix; an owner scope never does.</summary>
    public const string PlatformPrefix = "platform:";

    public const string ArchiveStreamKey = "platform:change-archive";
    public const int MaxKeyLength = 128;
    public const int MaxShortTextLength = 256;
    public const int MaxJsonBytes = 131072;
    public const int MaxEventPayloadBytes = 4096;
    public const int MaxChangeRecordBytes = 65536;

    private const long UnixEpochTicks = 621355968000000000L;

    /// <summary>The Key alphabet and length of the physical manifest.</summary>
    public static bool IsKey(string? value)
    {
        if (value is null || value.Length is 0 or > MaxKeyLength) return false;
        foreach (var c in value)
        {
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or ':' or '/' or '-')) return false;
        }

        return true;
    }

    /// <summary>The key of an outbox stream: a Key that is not the platform's own namespace.</summary>
    public static bool IsOwnerStreamScope(string? value) => IsKey(value) && !value!.StartsWith(PlatformPrefix, StringComparison.Ordinal);

    public static string Id(Guid value)
    {
        if (value == Guid.Empty) throw new ArgumentException("A nil identifier is not a valid identifier.", nameof(value));
        return value.ToString("D");
    }

    public static string? Id(Guid? value) => value is { } guid ? Id(guid) : null;

    /// <summary>UTC microseconds since the Unix epoch, the stored form of every instant.</summary>
    public static long Micros(DateTimeOffset instant) => checked((instant.UtcTicks - UnixEpochTicks) / 10);

    /// <summary>Short free text: non-empty, bounded, well-formed Unicode and no control character.</summary>
    public static string ShortText(string? value, string name)
    {
        if (value is null || value.Length is 0 or > MaxShortTextLength || !PlanArguments.ValidText(value)) throw new ArgumentException($"{name} is empty, too long or not well-formed text.", name);
        foreach (var c in value)
        {
            if (char.IsControl(c)) throw new ArgumentException($"{name} holds a control character.", name);
        }

        return value;
    }

    /// <summary>Well-formed JSON of at most <paramref name="maxBytes"/> UTF-8 bytes, with an object root when <paramref name="objectRoot"/>.</summary>
    public static bool IsJson(string? value, int maxBytes, bool objectRoot)
    {
        if (value is null || value.Length == 0 || !PlanArguments.ValidText(value)) return false;
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length > maxBytes) return false;
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 32 });
            var first = true;
            while (reader.Read())
            {
                if (first && objectRoot && reader.TokenType != JsonTokenType.StartObject) return false;
                first = false;
            }

            return !first;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
