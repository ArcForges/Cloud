// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.Capacity;

namespace ArcForges.Cloud.Capacity;

/// <summary>The actual fixed private Container-to-Worker scheduling adapter. Every retry keeps exact
/// immutable wake/command IDs; D1 job authority is consulted before a hint can be scheduled.</summary>
internal sealed class CapacityWakeScheduler(HttpClient client, SigningKey signer, ICapacityJobPort jobs, TimeProvider time) : ICapacityWakeScheduler, IDisposable
{
    private const string Path = "/internal/capacity/v1/schedule";
    private readonly CancellationTokenSource lifetime = new();
    private int disposed;
    private readonly SemaphoreSlim permits = new(2, 2);
    private int admitted;
    private readonly object signingGate = new();
    private readonly SigningKey ownedSigner = new(signer.Id, signer.Secret.ToArray());
    public async Task<CapacityScheduleResult> ScheduleAsync(CapacityScheduleCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref disposed) != 0) return new(CapacityScheduleStatus.Unavailable);
        if (command is null || command.CommandId == Guid.Empty || command.JobId == Guid.Empty || !CapacityJobCodec.Owner(command.Owner) || command.AvailableAtMicros < 0)
            return new(CapacityScheduleStatus.Invalid);
        if (Interlocked.Increment(ref admitted) > 4)
        { Interlocked.Decrement(ref admitted); return new(CapacityScheduleStatus.Unavailable); }
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
        bounded.CancelAfter(TimeSpan.FromSeconds(15));
        var entered = false; var dispatched = false;
        try
        {
            await permits.WaitAsync(bounded.Token).ConfigureAwait(false); entered = true;
            var read = await jobs.ReadAsync(command.Owner, command.JobId, bounded.Token).ConfigureAwait(false);
            bounded.Token.ThrowIfCancellationRequested();
            if (read.Status != CapacityJobStatus.Succeeded) return new(read.Status switch
            {
                CapacityJobStatus.Denied => CapacityScheduleStatus.Denied,
                CapacityJobStatus.Unavailable => CapacityScheduleStatus.Unavailable,
                _ => CapacityScheduleStatus.Conflict,
            });
            if (read.Job!.State is CapacityJobState.Succeeded or CapacityJobState.DeadLettered) return new(CapacityScheduleStatus.AlreadyScheduled);
            var wake = new CapacityWake(command.CommandId, command.Owner, command.JobId, "capacity-" + command.CommandId.ToString("D"),
                Derived(command.CommandId, "claim"), Derived(command.CommandId, "checkpoint"));
            var body = Body(wake, command.AvailableAtMicros);
            for (var attempt = 0; attempt < 3; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (Volatile.Read(ref disposed) != 0) return new(dispatched ? CapacityScheduleStatus.UnknownOutcome : CapacityScheduleStatus.Unavailable);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(bounded.Token);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, "http://capacity.internal" + Path);
                    request.Content = new ByteArrayContent(body);
                    request.Content.Headers.ContentType = new("application/json");
                    lock (signingGate)
                    {
                        bounded.Token.ThrowIfCancellationRequested();
                        PrivateRequestSigner.Sign("POST", Path, Convert.ToHexStringLower(SHA256.HashData(body)), command.CommandId.ToString("D"), ownedSigner, time)
                            .CopyTo((name, value) => request.Headers.TryAddWithoutValidation(name, value));
                    }
                    dispatched = true;
                    using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                    deadline.Token.ThrowIfCancellationRequested();
                    if (response.StatusCode == HttpStatusCode.Conflict) return new(CapacityScheduleStatus.Conflict);
                    if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) return new(CapacityScheduleStatus.Denied);
                    if (response.StatusCode == HttpStatusCode.BadRequest) return new(CapacityScheduleStatus.Invalid);
                    if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != "application/json"
                        || response.Content.Headers.ContentEncoding.Count != 0) throw new HttpRequestException("Capacity scheduling receipt unavailable");
                    await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                    var bytes = new byte[1025]; var count = 0;
                    while (count < bytes.Length)
                    {
                        var received = await stream.ReadAsync(bytes.AsMemory(count), deadline.Token).ConfigureAwait(false);
                        if (received == 0) break;
                        count += received;
                    }
                    if (count > 1024) throw new HttpRequestException("Capacity scheduling receipt too large");
                    deadline.Token.ThrowIfCancellationRequested();
                    using var parsed = JsonDocument.Parse(bytes.AsMemory(0, count), new() { MaxDepth = 4 });
                    var root = parsed.RootElement;
                    if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1
                        || !root.TryGetProperty("status", out var status) || status.ValueKind != JsonValueKind.String)
                        throw new HttpRequestException("Invalid capacity scheduling receipt");
                    return status.GetString() switch
                    {
                        "scheduled" => new(CapacityScheduleStatus.Scheduled),
                        "duplicate" => new(CapacityScheduleStatus.AlreadyScheduled),
                        _ => new(CapacityScheduleStatus.UnknownOutcome),
                    };
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
                catch (ObjectDisposedException) when (Volatile.Read(ref disposed) != 0) { }
                catch (Exception error) when (error is HttpRequestException or JsonException or IOException) { }
                if (Volatile.Read(ref disposed) != 0) return new(CapacityScheduleStatus.UnknownOutcome);
                if (attempt < 2) await Task.Delay(TimeSpan.FromMilliseconds(25 * (attempt + 1)), bounded.Token).ConfigureAwait(false);
            }
            return new(CapacityScheduleStatus.UnknownOutcome);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return new(dispatched ? CapacityScheduleStatus.UnknownOutcome : CapacityScheduleStatus.Unavailable); }
        finally { if (entered) permits.Release(); Interlocked.Decrement(ref admitted); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        lifetime.Cancel(); client.Dispose();
        lock (signingGate) CryptographicOperations.ZeroMemory(ownedSigner.Secret);
        // Concurrent linked registrations may still be unwinding; keep this tiny cancellation
        // source valid rather than race its disposal against an active dispatch.
    }

    internal static Guid Derived(Guid id, string operation) => new(SHA256.HashData(Encoding.ASCII.GetBytes("capacity-wake-v1\n" + operation + "\n" + id.ToString("D"))).AsSpan(0, 16));
    private static byte[] Body(CapacityWake wake, long dueAt)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject(); writer.WritePropertyName("wake");
            JsonSerializer.Serialize(writer, wake, CapacityHttpJson.Default.CapacityWake);
            writer.WriteString("dueAtMicros", dueAt.ToString(CultureInfo.InvariantCulture)); writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}
