// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Http;

namespace ArcForges.Cloud.Foundation;

/// <summary>Result of one outbound attempt: only the host (never a path or a body), a closed outcome and the elapsed time.</summary>
internal sealed record EgressAttempt(string Host, string Outcome, int? Status, long ElapsedMs);

/// <summary>
/// The blocked-egress proof of the proof Container. It makes harmless outbound attempts to a stable public name and to a literal address and
/// reports whether any of them got an HTTP answer. With Internet access disabled the platform does not refuse connections: a hostname times
/// out and a literal address is accepted and dropped within about a millisecond (both observed on Cloudflare). The accepted criterion is
/// therefore "no HTTP response at all" (no status line, whatever the code, including a 520 from a proxy), not "connection refused". The
/// verdict is "blocked" only when every attempt got no response, at least two attempts ran (name and address), and the allowed control path,
/// which uses the same HTTP stack to reach the private storage host, answered in the same call. This cannot tell a silent drop from a very
/// slow open route; elapsed times are reported so a reader can see the hostname attempt used its whole window. A response body is never
/// read, nothing carrying data is sent and no redirect is followed.
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
        return (controlOk && attempts.Count >= 2 && attempts.All(attempt => attempt.Outcome != "http_response"), controlOk, attempts);
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
        catch (HttpRequestException exception)
        {
            // No HTTP response came back. A refused or unresolvable destination is "connection_failed"; a peer that accepted the connection
            // and then closed or reset it without a status line is "reached_then_failed" (the platform's behavior for a literal address).
            var refused = exception.HttpRequestError is HttpRequestError.ConnectionError or HttpRequestError.NameResolutionError;
            return new EgressAttempt(target.Host, refused ? "connection_failed" : "reached_then_failed", null, timer.ElapsedMilliseconds);
        }
        catch (Exception exception) when (exception is System.Net.Sockets.SocketException or System.IO.IOException)
        {
            // The HTTP stack can surface a socket error unwrapped when the peer resets a connection that was already established (seen on
            // Linux as "Transport endpoint is not connected"). It is still no HTTP response, and it must never escape as a server error:
            // only a refusal or an unreachable destination is "connection_failed", everything else was reached and then dropped.
            var socket = exception as System.Net.Sockets.SocketException ?? exception.InnerException as System.Net.Sockets.SocketException;
            var refused = socket?.SocketErrorCode is System.Net.Sockets.SocketError.ConnectionRefused or System.Net.Sockets.SocketError.HostUnreachable
                or System.Net.Sockets.SocketError.NetworkUnreachable or System.Net.Sockets.SocketError.HostNotFound or System.Net.Sockets.SocketError.NoData
                or System.Net.Sockets.SocketError.TryAgain;
            return new EgressAttempt(target.Host, refused ? "connection_failed" : "reached_then_failed", null, timer.ElapsedMilliseconds);
        }
    }
}
