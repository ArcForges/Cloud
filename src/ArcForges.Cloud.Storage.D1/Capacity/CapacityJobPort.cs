// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.Archive;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Capacity;

/// <summary>The actual Platform infrastructure binds its executor directly. This does not fabricate a
/// Platform module descriptor in a business module or expose an arbitrary plan/SQL transport.</summary>
internal sealed class CapacityJobPortFactory(IPlanExecutor executor, ulong generation, TimeProvider time, ICapacityJobAuthority authority)
{
    public ICapacityJobPort Create() => new CapacityJobPort(executor, generation, time, authority);
}

internal sealed class CapacityJobPort : ICapacityJobPort
{
    private readonly IPlanExecutor executor;
    private readonly ulong generation;
    private readonly TimeProvider time;
    private readonly ICapacityJobAuthority authority;
    private readonly CommitExecutor commits;
    private readonly CommandReceiptStore receipts;
    private readonly IReadOnlyDictionary<string, PlanDefinition> plans;
    internal CapacityJobPort(IPlanExecutor executor, ulong generation, TimeProvider time, ICapacityJobAuthority authority)
    {
        this.executor = executor; this.generation = generation; this.time = time; this.authority = authority;
        receipts = new(executor, generation, time);
        commits = new(executor, receipts, new InboxStore(executor, generation));
        plans = PlanManifest.All.Where(plan => plan.Id.StartsWith("platform.capacity-job-", StringComparison.Ordinal)).ToDictionary(plan => plan.Id, StringComparer.Ordinal);
        foreach (var required in new[] { "platform.capacity-job-load", "platform.capacity-job-create", "platform.capacity-job-claim", "platform.capacity-job-checkpoint" })
            if (!plans.ContainsKey(required)) throw new InvalidOperationException("Capacity requires its complete registered Platform plan set.");
    }

    public async Task<CapacityJobResult> ReadAsync(CapacityJobOwner owner, Guid jobId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!CapacityJobCodec.Owner(owner) || jobId == Guid.Empty) return new(CapacityJobStatus.Invalid);
        var permission = await authority.AuthorizeAsync(owner, jobId, "read", cancellationToken).ConfigureAwait(false);
        return permission == QuotaAuthorityStatus.Authorized ? await Load(owner, jobId, cancellationToken).ConfigureAwait(false) : new(Auth(permission));
    }

    public async Task<CapacityJobResult> CreateAsync(Guid commandId, CapacityJobDefinition definition, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (commandId == Guid.Empty || !CapacityJobCodec.Definition(definition)) return new(CapacityJobStatus.Invalid);
        if (definition.RecoveryGeneration != generation) return new(CapacityJobStatus.StaleGeneration);
        var permission = await authority.AuthorizeCreateAsync(definition, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        var job = new CapacityJobSnapshot(definition, null, null, 0, 0, CapacityJobState.Ready, "{}", definition.AvailableAtMicros);
        var envelope = CapacityJobCodec.Envelope(job);
        const string operation = "platform.capacity-job-create";
        var content = Fingerprint(operation, definition.Owner, writer => writer.WriteString("envelope", envelope));
        var prior = await Begin(commandId, definition.Owner, definition.JobId, operation, content.Hash, cancellationToken).ConfigureAwait(false);
        if (prior is not null) return prior;
        return await Commit(commandId, definition.Owner, operation, content, "platform.capacity-job-create",
            [[D1Values.Text(commandId.ToString("D")), D1Values.Text(definition.Owner.RealmId.ToString("D")), D1Values.Text(envelope)],
                [D1Values.Text(definition.JobId.ToString("D")), D1Values.Text(definition.JobType), D1Values.Text(envelope), D1Values.Int64(definition.AvailableAtMicros)]],
            job, cancellationToken).ConfigureAwait(false);
    }

    public async Task<CapacityJobResult> ClaimAsync(CapacityJobClaim claim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (claim is null || claim.CommandId == Guid.Empty || claim.JobId == Guid.Empty || !CapacityJobCodec.Owner(claim.Owner)
            || !CapacityJobCodec.Text(claim.Holder, 128) || claim.ExpectedFence is < 0 or long.MaxValue || claim.LeasedUntilMicros <= 0)
            return new(CapacityJobStatus.Invalid);
        const string operation = "platform.capacity-job-claim";
        var content = Fingerprint(operation, claim.Owner, writer =>
        {
            writer.WriteString("jobId", claim.JobId.ToString("D")); writer.WriteString("holder", claim.Holder);
            Number(writer, "expectedFence", claim.ExpectedFence); Number(writer, "leasedUntil", claim.LeasedUntilMicros);
        });
        var prior = await Begin(claim.CommandId, claim.Owner, claim.JobId, operation, content.Hash, cancellationToken).ConfigureAwait(false);
        if (prior is not null) return prior;
        var loaded = await Load(claim.Owner, claim.JobId, cancellationToken).ConfigureAwait(false);
        if (loaded.Status != CapacityJobStatus.Succeeded) return loaded;
        var old = loaded.Job!;
        var now = CapacityJobCodec.Now(time);
        if (claim.LeasedUntilMicros <= now || claim.LeasedUntilMicros > checked(now + 60000000)
            || old.Fence != claim.ExpectedFence || old.AvailableAtMicros > now
            || old.State is not (CapacityJobState.Ready or CapacityJobState.Leased) || old.State == CapacityJobState.Leased && old.LeasedUntilMicros > now)
            return new(CapacityJobStatus.Conflict);
        var exhausted = old.Attempts == old.Definition.MaximumAttempts;
        var next = old with { Holder = exhausted ? null : claim.Holder, LeasedUntilMicros = exhausted ? null : claim.LeasedUntilMicros,
            Attempts = exhausted ? old.Attempts : old.Attempts + 1, Fence = old.Fence + 1,
            State = exhausted ? CapacityJobState.DeadLettered : CapacityJobState.Leased };
        IReadOnlyList<D1Scalar> values = [D1Values.Text(claim.JobId.ToString("D")), D1Values.Text(claim.Owner.RealmId.ToString("D")),
            D1Values.Int64(old.Fence), D1Values.Int64(old.Attempts), D1Values.Text(CapacityJobCodec.Envelope(old)), D1Values.Int64(claim.LeasedUntilMicros)];
        return await Commit(claim.CommandId, claim.Owner, operation, content, "platform.capacity-job-claim",
            [[D1Values.Text(claim.CommandId.ToString("D")), .. values],
                [Optional(next.Holder), D1Values.Int64(next.LeasedUntilMicros ?? -1), D1Values.Int64(next.Attempts), D1Values.Int64(next.Fence), D1Values.Int64((int)next.State), D1Values.Text(claim.JobId.ToString("D"))]],
            next, cancellationToken).ConfigureAwait(false);
    }

    public async Task<CapacityJobResult> CheckpointAsync(CapacityJobCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (checkpoint is null || checkpoint.CommandId == Guid.Empty || !CapacityJobCodec.Owner(checkpoint.Owner)
            || checkpoint.Lease is null || checkpoint.Lease.JobId == Guid.Empty || checkpoint.Lease.Fence <= 0
            || !CapacityJobCodec.Text(checkpoint.Lease.Holder, 128) || checkpoint.Lease.LeasedUntilMicros <= 0
            || !CapacityJobCodec.Json(checkpoint.ProgressJson, 4096) || checkpoint.AvailableAtMicros < 0
            || checkpoint.State is not (CapacityJobState.Ready or CapacityJobState.Succeeded or CapacityJobState.DeadLettered))
            return new(CapacityJobStatus.Invalid);
        const string operation = "platform.capacity-job-checkpoint";
        var content = Fingerprint(operation, checkpoint.Owner, writer =>
        {
            writer.WriteString("jobId", checkpoint.Lease.JobId.ToString("D")); writer.WriteString("holder", checkpoint.Lease.Holder);
            Number(writer, "fence", checkpoint.Lease.Fence); Number(writer, "leasedUntil", checkpoint.Lease.LeasedUntilMicros);
            writer.WriteString("progress", checkpoint.ProgressJson); Number(writer, "state", (int)checkpoint.State); Number(writer, "availableAt", checkpoint.AvailableAtMicros);
        });
        var prior = await Begin(checkpoint.CommandId, checkpoint.Owner, checkpoint.Lease.JobId, operation, content.Hash, cancellationToken).ConfigureAwait(false);
        if (prior is not null) return prior;
        var loaded = await Load(checkpoint.Owner, checkpoint.Lease.JobId, cancellationToken).ConfigureAwait(false);
        if (loaded.Status != CapacityJobStatus.Succeeded) return loaded;
        var old = loaded.Job!;
        var now = CapacityJobCodec.Now(time);
        if (old.State != CapacityJobState.Leased || old.Holder != checkpoint.Lease.Holder || old.Fence != checkpoint.Lease.Fence
            || old.LeasedUntilMicros != checkpoint.Lease.LeasedUntilMicros || old.LeasedUntilMicros <= now
            || checkpoint.State == CapacityJobState.Ready && checkpoint.AvailableAtMicros < now) return new(CapacityJobStatus.Conflict);
        var next = old with { Holder = null, LeasedUntilMicros = null, State = checkpoint.State, ProgressJson = checkpoint.ProgressJson, AvailableAtMicros = checkpoint.AvailableAtMicros };
        return await Commit(checkpoint.CommandId, checkpoint.Owner, operation, content, "platform.capacity-job-checkpoint",
            [[D1Values.Text(checkpoint.CommandId.ToString("D")), D1Values.Text(checkpoint.Lease.JobId.ToString("D")), D1Values.Text(checkpoint.Owner.RealmId.ToString("D")),
                D1Values.Text(checkpoint.Lease.Holder), D1Values.Int64(checkpoint.Lease.Fence), D1Values.Int64(checkpoint.Lease.LeasedUntilMicros), D1Values.Text(CapacityJobCodec.Envelope(old))],
                [D1Values.Int64((int)next.State), D1Values.Text(CapacityJobCodec.Envelope(next)), D1Values.Int64(next.AvailableAtMicros), D1Values.Text(checkpoint.Lease.JobId.ToString("D"))]],
            next, cancellationToken).ConfigureAwait(false);
    }

    public async Task<CapacityJobResult> ReconcileAsync(CapacityJobOwner owner, Guid jobId, Guid commandId, CapacityJobMutation mutation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!CapacityJobCodec.Owner(owner) || jobId == Guid.Empty || commandId == Guid.Empty || !Enum.IsDefined(mutation))
            return new(CapacityJobStatus.Invalid);
        var permission = await authority.AuthorizeAsync(owner, jobId, "read", cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        try
        {
            var stored = await receipts.LoadAsync(commandId, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (stored is null) return new(CapacityJobStatus.NotFound);
            var operation = mutation == CapacityJobMutation.Claim ? "platform.capacity-job-claim" : "platform.capacity-job-checkpoint";
            if (stored.WorkspaceId != owner.WorkspaceId || stored.ActorRef != "capacity:" + owner.Kind + ":" + owner.OwnerId.ToString("D")
                || stored.Operation != operation) return new(CapacityJobStatus.ReusedIdentifier);
            if (stored.Status != CommandReceiptStatus.Succeeded) return new(CapacityJobStatus.Conflict);
            var job = CapacityJobCodec.DecodeResult(stored.ResultPayloadJson);
            if (job.Definition.Owner != owner || job.Definition.JobId != jobId) return new(CapacityJobStatus.ReusedIdentifier);
            if (job.Definition.RecoveryGeneration != generation) return new(CapacityJobStatus.StaleGeneration);
            return CapacityJobCodec.Now(time) >= stored.ExpiresAtMicros ? new(CapacityJobStatus.ReceiptExpired) : new(CapacityJobStatus.Replayed, job);
        }
        catch (PlanFailureException error) { return new(Failure(error.Kind)); }
        catch (Exception error) when (error is JsonException or FormatException or OverflowException) { return new(CapacityJobStatus.Conflict); }
    }

    private async Task<CapacityJobResult> Load(CapacityJobOwner owner, Guid jobId, CancellationToken cancellationToken)
    {
        try
        {
            var call = PlanCall.New(plans["platform.capacity-job-load"], owner.RealmId.ToString("D"), generation,
                [[D1Values.Text(jobId.ToString("D")), D1Values.Text(owner.RealmId.ToString("D"))]]);
            var result = await executor.ExecuteAsync(call, cancellationToken).ConfigureAwait(false);
            if (result.Rows.Count == 0) return new(CapacityJobStatus.NotFound);
            var row = result.Rows.Single();
            if (row.Count != 9) return new(CapacityJobStatus.Conflict);
            var envelope = CapacityJobCodec.DecodeEnvelope(RequiredText(row[7]));
            var job = new CapacityJobSnapshot(envelope.Definition, Text(row[2]), Integer(row[3]), checked((int)RequiredInteger(row[4])),
                RequiredInteger(row[5]), (CapacityJobState)RequiredInteger(row[6]), envelope.ProgressJson, RequiredInteger(row[8]));
            if (!CapacityJobCodec.Snapshot(job) || job.Definition.JobId != jobId || job.Definition.Owner != owner
                || RequiredText(row[0]) != jobId.ToString("D") || RequiredText(row[1]) != job.Definition.JobType)
                return new(CapacityJobStatus.Conflict);
            if (job.Definition.RecoveryGeneration != generation) return new(CapacityJobStatus.StaleGeneration);
            return new(CapacityJobStatus.Succeeded, job);
        }
        catch (PlanFailureException error) { return new(Failure(error.Kind)); }
        catch (Exception error) when (error is JsonException or FormatException or InvalidOperationException or OverflowException) { return new(CapacityJobStatus.Conflict); }
    }

    private async Task<CapacityJobResult?> Begin(Guid commandId, CapacityJobOwner owner, Guid jobId, string operation, string hash, CancellationToken cancellationToken)
    {
        var permission = await authority.AuthorizeAsync(owner, jobId, operation, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        try
        {
            var replay = await commits.PreflightAsync(Identity(commandId, owner, operation, hash), cancellationToken).ConfigureAwait(false);
            return replay.Kind == ReplayKind.NotSeen ? null : Replay(replay.Kind, replay.Stored?.ResultPayloadJson, owner, jobId);
        }
        catch (PlanFailureException error) { return new(Failure(error.Kind)); }
    }

    private async Task<CapacityJobResult> Commit(Guid commandId, CapacityJobOwner owner, string operation, (string Json, string Hash) content,
        string planId, IReadOnlyList<IReadOnlyList<D1Scalar>> ownerArguments, CapacityJobSnapshot result, CancellationToken cancellationToken)
    {
        var now = Math.Max(CapacityJobCodec.Now(time), 1);
        var receipt = new CommandReceipt(Identity(commandId, owner, operation, content.Hash), CapacityJobCodec.Result(result), null, now, checked(now + 604800000000));
        var change = new ChangeRecord(1, content.Json);
        var values = new CommitTailValues(receipt, [], change);
        var plan = plans[planId];
        var scope = owner.RealmId.ToString("D");
        var call = PlanCall.New(plan, scope, generation, CommitTail.Bind(plan, scope, ownerArguments.Select(a => a.ToArray()).ToArray(), values));
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                var outcome = await commits.ExecuteAsync(call, values, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (outcome.Kind == CommitKind.Committed) return new(CapacityJobStatus.Succeeded, result);
                if (outcome.Kind is not CommitKind.Unknown || attempt >= 2)
                    return outcome.Kind switch
                    {
                        CommitKind.Replayed => Replay(ReplayKind.Replay, outcome.Stored?.ResultPayloadJson, owner, result.Definition.JobId),
                        CommitKind.ReusedIdentifier => new(CapacityJobStatus.ReusedIdentifier),
                        CommitKind.ReceiptExpired => new(CapacityJobStatus.ReceiptExpired),
                        CommitKind.Unknown => new(CapacityJobStatus.UnknownOutcome),
                        _ => new(CapacityJobStatus.Conflict),
                    };
            }
            catch (PlanFailureException error)
            {
                if (attempt >= 2 || error.Kind is not (PlanFailureKind.Unavailable or PlanFailureKind.Overloaded or PlanFailureKind.Transport))
                    return new(Failure(error.Kind));
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25 * (1 << attempt)), time, cancellationToken).ConfigureAwait(false);
        }
    }
    private CapacityJobResult Replay(ReplayKind kind, string? json, CapacityJobOwner owner, Guid jobId)
    {
        if (kind == ReplayKind.ReusedIdentifier) return new(CapacityJobStatus.ReusedIdentifier);
        if (kind == ReplayKind.Expired) return new(CapacityJobStatus.ReceiptExpired);
        if (kind != ReplayKind.Replay) return new(CapacityJobStatus.Conflict);
        try
        {
            var value = CapacityJobCodec.DecodeResult(json);
            if (value.Definition.RecoveryGeneration != generation) return new(CapacityJobStatus.StaleGeneration);
            return value.Definition.Owner == owner && value.Definition.JobId == jobId ? new(CapacityJobStatus.Replayed, value) : new(CapacityJobStatus.Conflict);
        }
        catch (Exception error) when (error is JsonException or FormatException) { return new(CapacityJobStatus.Conflict); }
    }
    private static CommandIdentity Identity(Guid commandId, CapacityJobOwner owner, string operation, string hash) =>
        new(commandId, owner.WorkspaceId, "capacity:" + owner.Kind + ":" + owner.OwnerId.ToString("D"), operation, hash);
    private static (string Json, string Hash) Fingerprint(string operation, CapacityJobOwner owner, Action<Utf8JsonWriter> fields)
    {
        using var bytes = new MemoryStream();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject(); writer.WriteString("kind", operation); writer.WriteString("realm", owner.RealmId.ToString("D"));
            if (owner.WorkspaceId is { } workspace) writer.WriteString("workspace", workspace.ToString("D")); else writer.WriteNull("workspace");
            writer.WriteString("ownerKind", owner.Kind); writer.WriteString("ownerId", owner.OwnerId.ToString("D")); fields(writer); writer.WriteEndObject();
        }
        var json = System.Text.Encoding.UTF8.GetString(bytes.ToArray());
        return (json, CapacityJobCodec.Hash(json));
    }
    private static void Number(Utf8JsonWriter writer, string name, long value) => writer.WriteString(name, value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    private static string RequiredText(D1Scalar value) => D1Values.TryGetText(value, out var text) ? text : throw new FormatException();
    private static long RequiredInteger(D1Scalar value) => D1Values.TryGetInt64(value, out var integer) ? integer : throw new FormatException();
    private static string? Text(D1Scalar value) => D1Values.IsNull(value) ? null : RequiredText(value);
    private static long? Integer(D1Scalar value) => D1Values.IsNull(value) ? null : RequiredInteger(value);
    private static D1Scalar Optional(string? value) => value is null ? D1Values.Null() : D1Values.Text(value);
    private static CapacityJobStatus Auth(QuotaAuthorityStatus value) => value switch
    {
        QuotaAuthorityStatus.Unavailable => CapacityJobStatus.Unavailable,
        QuotaAuthorityStatus.Stale => CapacityJobStatus.StaleGeneration,
        _ => CapacityJobStatus.Denied,
    };
    private static CapacityJobStatus Failure(PlanFailureKind value) => value switch
    {
        PlanFailureKind.StaleGeneration => CapacityJobStatus.StaleGeneration,
        PlanFailureKind.UnknownOutcome => CapacityJobStatus.UnknownOutcome,
        PlanFailureKind.Unavailable or PlanFailureKind.Overloaded or PlanFailureKind.Transport => CapacityJobStatus.Unavailable,
        _ => CapacityJobStatus.Conflict,
    };
}
