// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Storage.Platform;

/// <summary>
/// The infrastructure-owned Platform authority uses only its own exact named read. Every resolution rereads storage, including closed
/// states. Only explicitly transient read outcomes retry (at most three attempts); no authority row or failure is cached.
/// </summary>
internal sealed class RecoveryEpochReader : IRecoveryEpochPort
{
    private static readonly ModuleDescriptor Owner = ModuleDescriptor.Create("Platform", "platform");
    private readonly IModulePlanPort plans;
    private readonly TimeProvider time;

    public RecoveryEpochReader(IModulePlanPortFactory factory, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(factory);
        plans = factory.For(Owner);
        this.time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public async Task<RecoveryEpochResult> ReadAsync(Guid realmId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty) return RecoveryEpochResult.Refused(RecoveryEpochFailure.InvalidRealm);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            ModulePlanOutcome outcome;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8), time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            try
            {
                outcome = await plans.ReadAsync(new ModulePlanRead("platform.recovery-current", "platform",
                    [PlanValue.FromText(realmId.ToString("D"))]), linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
            {
                outcome = ModulePlanOutcome.Of(ModulePlanStatus.Unavailable);
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (outcome.Status is ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome)
            {
                if (attempt == 2) return RecoveryEpochResult.Refused(RecoveryEpochFailure.Unavailable);
                await Task.Delay(TimeSpan.FromMilliseconds(50 * (attempt + 1)), time, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (outcome.Status == ModulePlanStatus.StaleGeneration) return RecoveryEpochResult.Refused(RecoveryEpochFailure.StaleGeneration);
            if (outcome.Status != ModulePlanStatus.Succeeded) return RecoveryEpochResult.Refused(RecoveryEpochFailure.Defect);
            if (outcome.Rows.Count == 0) return RecoveryEpochResult.Refused(RecoveryEpochFailure.Missing);
            if (outcome.Rows.Count != 1 || outcome.Rows[0].Count != 4) return RecoveryEpochResult.Refused(RecoveryEpochFailure.Defect);
            var row = outcome.Rows[0];
            if (row[0].Kind != PlanValueKind.Text || row.Skip(1).Any(value => value.Kind != PlanValueKind.Int64))
                return RecoveryEpochResult.Refused(RecoveryEpochFailure.Defect);
            if (!string.Equals(row[0].AsText(), realmId.ToString("D"), StringComparison.Ordinal)) return RecoveryEpochResult.Refused(RecoveryEpochFailure.Defect);
            var generation = row[1].AsInt64();
            var state = row[2].AsInt64();
            var revision = row[3].AsInt64();
            if (generation < 0 || revision <= 0 || state is < 1 or > 4) return RecoveryEpochResult.Refused(RecoveryEpochFailure.Defect);
            if (state != 4) return RecoveryEpochResult.Refused(RecoveryEpochFailure.Closed);
            return RecoveryEpochResult.Available(new RecoveryEpochSnapshot(realmId, generation, revision));
        }

        throw new InvalidOperationException("The bounded recovery read exhausted its closed attempt loop.");
    }
}
