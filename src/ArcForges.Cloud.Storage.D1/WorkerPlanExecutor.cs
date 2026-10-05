// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using ArcForges.Cloud.Hmac;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using ArcForges.Contracts.Foundation.Serialization;

namespace ArcForges.Cloud.Storage;

/// <summary>
/// Executes named plans through the private storage Worker handler. Arguments are validated before anything is
/// sent; a transport failure of a write is an unknown outcome and nothing is ever retried automatically.
/// </summary>
internal sealed class WorkerPlanExecutor(HttpClient client, Uri storageBaseUrl, SigningKey signingKey, TimeProvider time) : IPlanExecutor
{
    public const string ExecutePath = "/internal/storage/v1/execute-plan";
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(8);
    public static readonly TimeSpan MaxTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan Grace = TimeSpan.FromSeconds(2);

    private readonly Uri url = new(storageBaseUrl, ExecutePath);

    public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        PlanArguments.Validate(call);
        var write = call.Plan.Access == PlanAccess.Write;
        var timeout = call.Timeout ?? DefaultTimeout;
        if (timeout <= TimeSpan.Zero) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        if (timeout > MaxTimeout) timeout = MaxTimeout;
        var requestId = call.RequestId.ToString("D");
        byte[] body;
        try
        {
            body = ExecutePlanRequestJson.Serialize(new ExecutePlanRequest
            {
                PlanId = call.Plan.Id,
                PlanVersion = call.Plan.Version,
                ManifestHash = PlanManifest.Hash,
                RequestId = requestId,
                RecoveryGeneration = call.RecoveryGeneration.ToString(CultureInfo.InvariantCulture),
                OwnerScope = call.OwnerScope,
                Arguments = call.Arguments,
                DeadlineUtc = (time.GetUtcNow() + timeout).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture),
            });
        }
        catch (ContractSerializationException)
        {
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        PrivateRequestSigner.Sign("POST", url.PathAndQuery, Convert.ToHexStringLower(SHA256.HashData(body)), requestId, signingKey, time)
            .CopyTo((name, value) => request.Headers.TryAddWithoutValidation(name, value));
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(timeout + Grace);
        HttpStatusCode status;
        byte[]? reply;
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, bounded.Token);
            status = response.StatusCode;
            reply = status == HttpStatusCode.OK ? await HttpBodies.ReadLimitedAsync(response.Content, ExecutePlanResponseJson.MaxBytes, bounded.Token) : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The request may already have reached the Worker.
            if (write) throw new PlanFailureException(PlanFailureKind.UnknownOutcome);
            throw;
        }
        catch (Exception exception) when (exception is OperationCanceledException or HttpRequestException or IOException)
        {
            throw Uncertain(write);
        }

        if (status == HttpStatusCode.Unauthorized) throw new PlanFailureException(PlanFailureKind.Transport);
        if (status != HttpStatusCode.OK || reply is null || !ExecutePlanResponseJson.TryParse(reply, out var parsed, out _) || parsed is null)
            throw Uncertain(write);
        return parsed switch
        {
            ExecutePlanResponseExecutePlanSuccess success => Accept(call, requestId, write, success.Value),
            ExecutePlanResponseExecutePlanFailure failure => Reject(requestId, write, failure.Value),
            _ => throw Uncertain(write),
        };
    }

    private static PlanFailureException Uncertain(bool write) =>
        new(write ? PlanFailureKind.UnknownOutcome : PlanFailureKind.Unavailable);

    private static PlanResult Accept(PlanCall call, string requestId, bool write, ExecutePlanSuccess success)
    {
        if (success.RequestId != requestId) throw Uncertain(write);
        if (success.ManifestHash != PlanManifest.Hash) throw new PlanFailureException(PlanFailureKind.ManifestMismatch);
        if (!D1Values.TryParseUint64(success.Changes, out var changes)) throw Uncertain(write);
        var rows = new IReadOnlyList<D1Scalar>[success.Rows.Length];
        for (var index = 0; index < rows.Length; index++) rows[index] = success.Rows[index];
        if (!PlanArguments.RowsMatch(call.Plan, rows)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new PlanResult(rows, changes);
    }

    private static PlanResult Reject(string requestId, bool write, ExecutePlanFailure failure)
    {
        if (failure.RequestId != requestId) throw Uncertain(write);
        if (failure.ManifestHash != PlanManifest.Hash) throw new PlanFailureException(PlanFailureKind.ManifestMismatch);
        throw new PlanFailureException(failure.Failure switch
        {
            "invalidPlan" => PlanFailureKind.InvalidPlan,
            "staleGeneration" => PlanFailureKind.StaleGeneration,
            "precondition" => PlanFailureKind.Precondition,
            "constraint" => PlanFailureKind.Constraint,
            "overloaded" => PlanFailureKind.Overloaded,
            "unavailable" => PlanFailureKind.Unavailable,
            "unknownOutcome" => PlanFailureKind.UnknownOutcome,
            _ => PlanFailureKind.InvalidPlan,
        });
    }
}
