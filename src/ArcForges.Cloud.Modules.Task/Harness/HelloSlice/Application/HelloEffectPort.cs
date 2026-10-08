// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Application;

/// <summary>The three steps of the Hello slice, named as the AI slice names them. The names are the recorded operation of each reservation.</summary>
internal static class HelloSteps
{
    internal const string RequestTool = "request-tool";
    internal const string SayHello = "say-hello";
    internal const string FinishGreeting = "finish-greeting";
}

/// <summary>
/// The one external I/O port of the Hello slice. A model step goes to the Agent dispatch port; the say_hello tool runs locally and has no
/// external effect. While a model call is outstanding the port renews the lease on the executor's own schedule (every 20 seconds, the
/// renewal is due check), so a call of up to 90 seconds keeps its fence. Response bodies stay in this process: the executor records only a
/// content-addressed reference, so no prompt or answer is persisted (checkpoints are references only).
/// </summary>
internal sealed class HelloEffectPort(IModelDispatchPort models, HelloModelSettings settings, TimeSpan keepaliveInterval) : IEffectPort
{
    private readonly Dictionary<Guid, string> bodies = [];
    private string? stagedOperation;
    private string? stagedBody;
    private int stagedToolCount;

    /// <summary>Renews the lease when due. Set by the slice once the claim exists; the result is false when the lease is lost.</summary>
    internal Func<CancellationToken, Task<bool>>? RenewLease { get; set; }

    /// <summary>Stages the request of the next effect. The slice stages one step at a time, before each reservation.</summary>
    internal void Stage(string operation, string body, int toolCount)
    {
        stagedOperation = operation;
        stagedBody = body;
        stagedToolCount = toolCount;
    }

    /// <summary>The answer body of a settled command, removed on read. Null when the command produced no body in this process.</summary>
    internal string? TakeBody(Guid commandId) => bodies.Remove(commandId, out var body) ? body : null;

    public async Task<EffectResult> DispatchAsync(EffectCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        // An effect for an operation that was not staged cannot have been requested: nothing is sent.
        if (stagedOperation != call.Operation || stagedBody is null) return new EffectResult(EffectResultKind.FailedDidNotHappen, null);
        var body = stagedBody;

        if (call.Operation == HelloSteps.SayHello)
        {
            var greeting = HelloNames.Greeting(body);
            bodies[call.CommandId] = greeting;
            return new EffectResult(EffectResultKind.Succeeded, Reference(greeting));
        }

        var outcome = await DispatchModelAsync(call, body, cancellationToken).ConfigureAwait(false);
        if (outcome.Status != ModelDispatchStatus.Succeeded)
        {
            return outcome.Status switch
            {
                ModelDispatchStatus.RefusedBeforeDispatch => new EffectResult(EffectResultKind.RefusedBeforeDispatch, null),
                ModelDispatchStatus.FailedDidNotHappen => new EffectResult(EffectResultKind.FailedDidNotHappen, null),
                _ => new EffectResult(EffectResultKind.Unknown, null),
            };
        }

        if (outcome.ResponseJson is null) return new EffectResult(EffectResultKind.Unknown, null);
        bodies[call.CommandId] = outcome.ResponseJson;
        return new EffectResult(EffectResultKind.Succeeded, Reference(outcome.ResponseJson));
    }

    private async Task<ModelCallResult> DispatchModelAsync(EffectCall call, string body, CancellationToken cancellationToken)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var keeper = KeepLeaseAsync(stop.Token);
        try
        {
            return await models.DispatchAsync(
                new ModelCallRequest(call.Pinned.ModelId, call.Pinned.TariffSnapshotId, body, settings.MaxOutputTokens, stagedToolCount, settings.Deadline),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(false);
            try
            {
                await keeper.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The keepalive ends when the call ends; its cancellation is the expected stop.
            }
        }
    }

    /// <summary>
    /// Renews on the keepalive schedule until the call ends or the lease is lost. A renewal that fails in the store ends the keepalive without
    /// throwing, so the model outcome is never lost to the keepalive; the lease is then decided by the fenced outcome write.
    /// </summary>
    private async global::System.Threading.Tasks.Task KeepLeaseAsync(CancellationToken cancellationToken)
    {
        while (RenewLease is { } renew)
        {
            await global::System.Threading.Tasks.Task.Delay(keepaliveInterval, cancellationToken).ConfigureAwait(false);
            bool renewed;
            try
            {
                renewed = await renew(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException and not OutOfMemoryException)
            {
                return;
            }

            if (!renewed) return;
        }
    }

    /// <summary>A content-addressed reference of an answer: bounded, and it reveals nothing of the content.</summary>
    private static string Reference(string content) => "sha256-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
}
