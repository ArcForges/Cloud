// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Reflection;
using ArcForges.Cloud.Generation;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Tools.Generation;
using Xunit;

namespace ArcForges.Cloud.Tests.Generation;

/// <summary>
/// CLOUD.84 S40(2): the Worker's named-plan transport guards are declared once in C# (StorageGuards) and generated into the Worker
/// table. Each declaration must equal the host value it mirrors, so the Worker can never accept a call the host would refuse, and the
/// generated table carries exactly these values.
/// </summary>
public sealed class StorageGuardsTests
{
    [Fact]
    public void TheDeadlineBudgetIsTheHostTimeoutCap()
    {
        Assert.Equal(StorageGuards.MaxDeadlineAheadMilliseconds, (int)WorkerPlanExecutor.MaxTimeout.TotalMilliseconds);
    }

    [Fact]
    public void TheClockToleranceIsTheHostGraceWindow()
    {
        var grace = (TimeSpan)typeof(WorkerPlanExecutor)
            .GetField("Grace", BindingFlags.NonPublic | BindingFlags.Static)!
            .GetValue(null)!;
        Assert.Equal(StorageGuards.DeadlineClockToleranceMilliseconds, (int)grace.TotalMilliseconds);
    }

    [Fact]
    public void TheValueBoundsAreThePlanArgumentBounds()
    {
        Assert.Equal(PlanArguments.MaxTextLength, StorageGuards.MaxTextLength);
        Assert.Equal(PlanArguments.MaxBytesLength, StorageGuards.MaxBytesLength);
    }

    [Fact]
    public void TheIntegerTextBoundsAreTheExactRangesOfTheColumnTypes()
    {
        Assert.Equal(StorageGuards.Int64Min, long.MinValue.ToString(CultureInfo.InvariantCulture));
        Assert.Equal(StorageGuards.Int64Max, long.MaxValue.ToString(CultureInfo.InvariantCulture));
        Assert.Equal(StorageGuards.Uint64Max, ulong.MaxValue.ToString(CultureInfo.InvariantCulture));
    }

    [Fact]
    public void TheGuardConstraintIsTheNameTheFamilyGuardsRaise()
    {
        Assert.Equal("af_guard_failed", StorageGuards.GuardConstraintName);
    }

    [Fact]
    public void TheGeneratedWorkerTableCarriesTheSameStorageGuards()
    {
        var storage = HostReader.Read().Storage;
        Assert.Equal(StorageGuards.MaxDeadlineAheadMilliseconds, storage.MaxDeadlineAheadMilliseconds);
        Assert.Equal(StorageGuards.DeadlineClockToleranceMilliseconds, storage.DeadlineClockToleranceMilliseconds);
        Assert.Equal(StorageGuards.GuardConstraintName, storage.GuardConstraintName);
        Assert.Equal(StorageGuards.MaxTextLength, storage.MaxTextLength);
        Assert.Equal(StorageGuards.MaxBytesLength, storage.MaxBytesLength);
        Assert.Equal(StorageGuards.Int64Min, storage.Int64Min);
        Assert.Equal(StorageGuards.Int64Max, storage.Int64Max);
        Assert.Equal(StorageGuards.Uint64Max, storage.Uint64Max);
        Assert.Equal(StorageGuards.MaxDecimalSignificantDigits, storage.MaxDecimalSignificantDigits);
        Assert.Equal(StorageGuards.MaxDecimalFractionDigits, storage.MaxDecimalFractionDigits);
    }
}
