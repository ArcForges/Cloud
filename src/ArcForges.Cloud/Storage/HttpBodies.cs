// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage;

internal static class HttpBodies
{
    /// <summary>Reads a bounded body; null when it exceeds the limit.</summary>
    public static async Task<byte[]?> ReadLimitedAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is { } length && length > limit) return null;
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[16384];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > limit) return null;
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
