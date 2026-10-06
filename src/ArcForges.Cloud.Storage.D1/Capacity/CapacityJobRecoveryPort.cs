// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Cloud.Modules;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Capacity;

internal sealed class CapacityJobRecoveryPort : ICapacityJobRecoveryPort
{
    private readonly IPlanExecutor executor;
    private readonly ulong generation;
    private readonly TimeProvider time;
    private readonly ICapacityJobRecoveryAuthority authority;
    private readonly PlanDefinition plan;
    private readonly HashSet<string> jobTypes;
    private readonly string jobTypesJson;
    internal CapacityJobRecoveryPort(IPlanExecutor executor, ulong generation, TimeProvider time, ICapacityJobRecoveryAuthority authority,
        IEnumerable<string> registeredJobTypes)
    {
        this.executor = executor; this.generation = generation; this.time = time; this.authority = authority;
        jobTypes = registeredJobTypes.ToHashSet(StringComparer.Ordinal);
        if (jobTypes.Count is < 1 or > 32 || jobTypes.Any(type => !CapacityJobCodec.Text(type, 64)
            || type.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))))
            throw new InvalidOperationException("Capacity recovery requires bounded registered job types.");
        jobTypesJson = JsonSerializer.Serialize(jobTypes.Order(StringComparer.Ordinal).ToArray(), CapacityJobJson.Default.StringArray);
        plan = PlanManifest.All.Single(p => p.Id == "platform.capacity-job-due");
    }

    public async Task<CapacityDuePage> ReadDueAsync(CapacityDueCursor? after, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (after is not null && (after.DueAtMicros < 0 || after.JobId == Guid.Empty)) return new(CapacityJobStatus.Invalid);
        var permission = await authority.GetCurrentAsync(cancellationToken).ConfigureAwait(false);
        if (permission.Status != QuotaAuthorityStatus.Authorized || permission.Scope is null)
            return new(permission.Status switch
            {
                QuotaAuthorityStatus.Unavailable => CapacityJobStatus.Unavailable,
                QuotaAuthorityStatus.Stale => CapacityJobStatus.StaleGeneration,
                _ => CapacityJobStatus.Denied,
            });
        var scope = permission.Scope;
        if (scope.RealmId == Guid.Empty) return new(CapacityJobStatus.Denied);
        if (scope.RecoveryGeneration != generation) return new(CapacityJobStatus.StaleGeneration);
        try
        {
            var now = CapacityJobCodec.Now(time);
            var call = PlanCall.New(plan, scope.RealmId.ToString("D"), generation,
                [[D1Values.Text(scope.RealmId.ToString("D")), D1Values.Text(generation.ToString(CultureInfo.InvariantCulture)),
                    D1Values.Text(jobTypesJson),
                    D1Values.Int64(now), D1Values.Int64(after?.DueAtMicros ?? -1), D1Values.Int64(after?.DueAtMicros ?? -1),
                    D1Values.Text(after?.JobId.ToString("D") ?? "")]]);
            var result = await executor.ExecuteAsync(call, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (result.Rows.Count > 10) return new(CapacityJobStatus.Conflict);
            List<CapacityJobSnapshot> jobs = [];
            var previous = after;
            foreach (var row in result.Rows)
            {
                if (row.Count != 10) return new(CapacityJobStatus.Conflict);
                var envelope = CapacityJobCodec.DecodeEnvelope(Text(row[7]));
                var job = new CapacityJobSnapshot(envelope.Definition, NullableText(row[2]), NullableInteger(row[3]),
                    checked((int)Integer(row[4])), Integer(row[5]), (CapacityJobState)Integer(row[6]), envelope.ProgressJson, Integer(row[8]));
                var due = Integer(row[9]);
                var id = job.Definition.JobId.ToString("D");
                if (!CapacityJobCodec.Snapshot(job) || Text(row[0]) != id || Text(row[1]) != job.Definition.JobType
                    || !jobTypes.Contains(job.Definition.JobType)
                    || job.Definition.Owner.RealmId != scope.RealmId || job.Definition.RecoveryGeneration != generation
                    || job.State is not (CapacityJobState.Ready or CapacityJobState.Leased)
                    || due != (job.State == CapacityJobState.Ready ? job.AvailableAtMicros : job.LeasedUntilMicros)
                    || due < 0 || due > now || previous is not null && (due < previous.DueAtMicros
                        || due == previous.DueAtMicros && string.CompareOrdinal(id, previous.JobId.ToString("D")) <= 0))
                    return new(CapacityJobStatus.Conflict);
                previous = new(due, job.Definition.JobId); jobs.Add(job);
            }
            return new(CapacityJobStatus.Succeeded, jobs, jobs.Count == 10 ? previous : null);
        }
        catch (PlanFailureException error)
        {
            return new(error.Kind switch
            {
                PlanFailureKind.StaleGeneration => CapacityJobStatus.StaleGeneration,
                PlanFailureKind.Unavailable or PlanFailureKind.Overloaded or PlanFailureKind.Transport => CapacityJobStatus.Unavailable,
                _ => CapacityJobStatus.Conflict,
            });
        }
        catch (Exception error) when (error is JsonException or FormatException or OverflowException or InvalidOperationException)
        { return new(CapacityJobStatus.Conflict); }
    }
    private static string Text(D1Scalar value) => D1Values.TryGetText(value, out var text) ? text : throw new FormatException();
    private static long Integer(D1Scalar value) => D1Values.TryGetInt64(value, out var number) ? number : throw new FormatException();
    private static string? NullableText(D1Scalar value) => D1Values.IsNull(value) ? null : Text(value);
    private static long? NullableInteger(D1Scalar value) => D1Values.IsNull(value) ? null : Integer(value);
}
