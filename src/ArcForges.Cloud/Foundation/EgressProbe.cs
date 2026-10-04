// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Http;

namespace ArcForges.Cloud.Foundation;

/// <summary>Result of one outbound attempt: only the host (never a path or a body), a closed outcome and the elapsed time.</summary>
internal sealed record EgressAttempt(string Host, string Outcome, int? Status, long ElapsedMs);

/// <summary>
/// The blocked-egress proof of the proof Container. It makes harmless outbound attempts to stable public names and reports whether any of them
/// got an answer. The Container's only permitted outbound paths are the interception hosts; with Internet access disabled every other
/// destination must fail to connect. A probe cannot pass vacuously: the verdict is "blocked" only when every target failed with a connection
/// error (a timeout or any HTTP response is not a block) and the allowed control path, which uses the same HTTP stack to reach the private
/// storage host, answered in the same call. Nothing is sent that carries data, and no redirect is followed.
/// </summary>
internal sealed class EgressProbe(Func<HttpClient> newClient, IReadOnlyList<Uri> targets, Func<CancellationToken, Task<bool>> control, TimeSpan? attemptTimeout = null)
{
    private readonly TimeSpan timeout = attemptTimeout ?? TimeSpan.FromSeconds(8);

    /// <summary>A stable public name and a literal address, so a DNS-only block cannot hide an open route to the address.</summary>
    public static IReadOnlyList<Uri> PublicTargets { get; } = [new("http://example.com/"), new("http://1.1.1.1/")];

    public async Task<(bool Blocked, bool ControlOk, IReadOnlyList<EgressAttempt> Attempts)> RunAsync(CancellationToken cancellationToken)
    {
        var controlOk = await control(cancellationToken);
        var attempts = new List<EgressAttempt>();
        foreach (var target in targets) attempts.Add(await AttemptAsync(target, cancellationToken));
        return (controlOk && attempts.Count > 0 && attempts.All(attempt => attempt.Outcome == "connection_failed"), controlOk, attempts);
    }

    private async Task<EgressAttempt> AttemptAsync(Uri target, CancellationToken cancellationToken)
    {
        var timer = Stopwatch.StartNew();
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(timeout);
        using var client = newClient();
        using var request = new HttpRequestMessage(HttpMethod.Head, target);
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, bounded.Token);
            return new EgressAttempt(target.Host, "http_response", (int)response.StatusCode, timer.ElapsedMilliseconds);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new EgressAttempt(target.Host, "timeout", null, timer.ElapsedMilliseconds);
        }
        catch (HttpRequestException)
        {
            return new EgressAttempt(target.Host, "connection_failed", null, timer.ElapsedMilliseconds);
        }
    }
}
