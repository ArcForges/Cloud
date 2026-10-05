// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Storage.Receipts;

namespace ArcForges.Cloud.Storage.Archive;

/// <summary>
/// The bounded replay record of one committed batch (D1 profile section 7): its schema version and the resulting row revisions,
/// after-images and deletion keys as one JSON object. It never carries a temporary body or a credential; that is the caller's
/// duty, and the bound here (64 KiB) makes an oversized record a refusal instead of a silently truncated one.
/// </summary>
internal sealed record ChangeRecord
{
    public ChangeRecord(long schemaVersion, string recordJson)
    {
        if (schemaVersion < 0) throw new ArgumentOutOfRangeException(nameof(schemaVersion), "A schema version is never negative.");
        if (!StorageFormats.IsJson(recordJson, StorageFormats.MaxChangeRecordBytes, objectRoot: true)) throw new ArgumentException("A change record is one well-formed JSON object of at most 64 KiB.", nameof(recordJson));
        SchemaVersion = schemaVersion;
        RecordJson = recordJson;
    }

    public long SchemaVersion { get; }

    public string RecordJson { get; }

    /// <summary>SHA-256 of the UTF-8 bytes of the record text, the tamper evidence a reader verifies before it copies the record.</summary>
    public byte[] Hash() => HashOf(RecordJson);

    public static byte[] HashOf(string recordJson) => SHA256.HashData(Encoding.UTF8.GetBytes(recordJson));
}
