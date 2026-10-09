// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Text.Json;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

/// <summary>
/// A checkpoint of a run: references and identifiers only (a receipt hash, an ordinal, an optional wait key and the selected worker
/// version). It holds no prompt, output, tool body or other content, and its JSON form is bounded to 128 KiB (contracts 05 line 151).
/// </summary>
internal sealed record CheckpointRef(long Ordinal, byte[] ReceiptSha256, string? WaitKey, string WorkerVersion)
{
    internal const int ReceiptLength = 32;

    /// <summary>The canonical JSON form of the reference. Refused when a field is out of range or the form exceeds the limit.</summary>
    internal byte[] ToCanonicalJson()
    {
        if (Ordinal is < 0 or > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(Ordinal));
        if (ReceiptSha256 is null || ReceiptSha256.Length != ReceiptLength)
            throw new ArgumentException("A checkpoint receipt is a 32-byte hash.", nameof(ReceiptSha256));
        if (WaitKey is not null && !IsKey(WaitKey)) throw new ArgumentException("A wait key is a bounded key.", nameof(WaitKey));
        if (!IsKey(WorkerVersion)) throw new ArgumentException("A worker version is a bounded key.", nameof(WorkerVersion));
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("ordinal", Ordinal);
            writer.WriteString("receiptSha256", Convert.ToHexStringLower(ReceiptSha256));
            if (WaitKey is null) writer.WriteNull("waitKey");
            else writer.WriteString("waitKey", WaitKey);
            writer.WriteString("workerVersion", WorkerVersion);
            writer.WriteEndObject();
        }

        if (buffer.WrittenCount > BudgetPolicy.CheckpointLimitBytes)
            throw new ArgumentException("A checkpoint exceeds its limit.", nameof(WaitKey));
        return buffer.WrittenSpan.ToArray();
    }

    private static bool IsKey(string value) =>
        value.Length is >= 1 and <= 128
        && value.All(character => character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or ':' or '/' or '-');
}
