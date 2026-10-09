// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Text;
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Modules.Task.Harness.Wake;

/// <summary>
/// The C# side of the run alarm (HAR.40 alarm arming). It sends one closed JSON request per call to the outbound virtual host
/// <c>harness.internal</c>: a POST to the schedule path with <c>{runId, wakeAtMs, workspaceId}</c>, or a POST to the cancel path with the
/// run key <c>{runId, workspaceId}</c>. The Worker validates the shape again and calls the run's Durable Object; the C# side decides only
/// whether it asks for the wake. Every failure to arm is a refusal, so a run is never parked without a wake that was confirmed armed.
/// </summary>
public sealed class HarnessAlarmClient(HttpClient http, TimeSpan timeout) : IHarnessAlarmPort
{
    /// <summary>The only outbound virtual host of the alarm; the container reaches nothing else through it.</summary>
    public const string Host = "harness.internal";

    /// <summary>The path that arms or re-arms the run's wake.</summary>
    public const string SchedulePath = "/v1/schedule";

    /// <summary>The path that cancels the run's armed wake.</summary>
    public const string CancelPath = "/v1/cancel";

    /// <summary>The only body the Worker answers with 200 for a schedule: the exact reply of the Durable Object's accepted schedule.</summary>
    private const string ScheduledReply = "{\"scheduled\":true}";

    private readonly HttpClient http = http ?? throw new ArgumentNullException(nameof(http));

    /// <inheritdoc />
    public async Task<HarnessAlarmReply> ScheduleAsync(HarnessAlarmSchedule schedule, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        var body = "{\"runId\":\"" + schedule.RunId.ToString("D") + "\",\"wakeAtMs\":" + schedule.WakeAtMs.ToString(CultureInfo.InvariantCulture)
            + ",\"workspaceId\":\"" + schedule.WorkspaceId.ToString("D") + "\"}";
        try
        {
            // One deadline covers the headers and the body, so a stalled body is bounded by the alarm deadline as well.
            using var deadline = Deadline(cancellationToken);
            using var reply = await PostAsync(SchedulePath, body, deadline.Token).ConfigureAwait(false);
            if (reply.StatusCode != HttpStatusCode.OK) return HarnessAlarmReply.Refused;
            var text = await reply.Content.ReadAsStringAsync(deadline.Token).ConfigureAwait(false);
            return string.Equals(text, ScheduledReply, StringComparison.Ordinal) ? HarnessAlarmReply.Armed : HarnessAlarmReply.Refused;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Fail closed: a transport failure, a timeout or a cancelled caller is not armed, so the run is not parked.
            _ = exception;
            return HarnessAlarmReply.Refused;
        }
    }

    /// <inheritdoc />
    public async global::System.Threading.Tasks.Task CancelAsync(Guid workspaceId, Guid runId, CancellationToken cancellationToken)
    {
        var body = "{\"runId\":\"" + runId.ToString("D") + "\",\"workspaceId\":\"" + workspaceId.ToString("D") + "\"}";
        try
        {
            using var deadline = Deadline(cancellationToken);
            (await PostAsync(CancelPath, body, deadline.Token).ConfigureAwait(false)).Dispose();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Best effort: a cancel that does not arrive leaves a wake that the fenced claim treats as stray and harmless.
            _ = exception;
        }
    }

    /// <summary>The caller's cancellation linked to the client's own deadline. The caller disposes it after the reply body is read.</summary>
    private CancellationTokenSource Deadline(CancellationToken cancellationToken)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        return deadline;
    }

    private async Task<HttpResponseMessage> PostAsync(string path, string body, CancellationToken deadline)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("http://" + Host + path))
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline).ConfigureAwait(false);
    }
}
