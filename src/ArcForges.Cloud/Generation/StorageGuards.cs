// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Generation;

/// <summary>
/// The transport guards the Worker applies to a named-plan call before it binds or runs any SQL (CLOUD.84 S34(1) and S40(2); Design D1
/// profile section 3). They are value declarations only: the plan decisions (which statements, their order, the ownership and commit-tail
/// rules, the write targets) come from the generated plan tables, and the Worker holds none of them. tools/ArcForges.Cloud.Generation reads
/// these constants and emits them into worker/tables/cloud-tables.generated.ts as storageGuards. StorageGuardsTests checks that each one
/// equals the host value it mirrors (WorkerPlanExecutor and PlanArguments), so the Worker cannot accept a call the host refuses.
/// </summary>
internal static class StorageGuards
{
    /// <summary>The caller deadline is at most this far ahead of the Worker's clock (WorkerPlanExecutor.MaxTimeout).</summary>
    public const int MaxDeadlineAheadMilliseconds = 10_000;

    /// <summary>The tolerance for the clock difference between the Container and the Worker (WorkerPlanExecutor's grace).</summary>
    public const int DeadlineClockToleranceMilliseconds = 2_000;

    /// <summary>The D1 constraint name a failed guard raises (the family guard expansion names it in every guard statement).</summary>
    public const string GuardConstraintName = "af_guard_failed";

    /// <summary>The bound of one text argument or result, in characters (PlanArguments.MaxTextLength).</summary>
    public const int MaxTextLength = 262144;

    /// <summary>The bound of one bytes argument or result, once decoded (PlanArguments.MaxBytesLength).</summary>
    public const int MaxBytesLength = 262144;

    /// <summary>The smallest int64, as the exact decimal text that is the only accepted spelling of an int64 argument.</summary>
    public const string Int64Min = "-9223372036854775808";

    /// <summary>The largest int64, as the exact decimal text.</summary>
    public const string Int64Max = "9223372036854775807";

    /// <summary>The largest uint64, as the exact decimal text.</summary>
    public const string Uint64Max = "18446744073709551615";

    /// <summary>A canonical decimal has at most this many significant digits (the sign and the point are not counted).</summary>
    public const int MaxDecimalSignificantDigits = 28;

    /// <summary>A canonical decimal has at most this many fractional digits.</summary>
    public const int MaxDecimalFractionDigits = 9;
}
