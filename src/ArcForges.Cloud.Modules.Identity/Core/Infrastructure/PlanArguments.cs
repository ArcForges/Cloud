// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Globalization;

namespace ArcForges.Cloud.Modules.Identity.Core.Infrastructure;

internal enum PlanArgumentKind
{
    Text,
    Int64,
    Bytes,
    Null,
}

/// <summary>
/// One typed argument of a named plan statement, in the form the plan bridge binds: text, an exact signed 64-bit integer (carried as
/// canonical decimal text, never a floating-point number), bytes (base64url without padding) or a null. The module names no SQL: it
/// only fills the arguments of statements that are checked into <c>storage/plans</c>.
/// </summary>
internal readonly record struct PlanArgument(PlanArgumentKind Kind, string? Value)
{
    public static PlanArgument Text(string value) => new(PlanArgumentKind.Text, value ?? throw new ArgumentNullException(nameof(value)));

    public static PlanArgument NullableText(string? value) => value is null ? Null : Text(value);

    public static PlanArgument Int64(long value) => new(PlanArgumentKind.Int64, value.ToString(CultureInfo.InvariantCulture));

    /// <summary>An optional integer: the plans bind the sentinel -1 and turn it into NULL, because every stored counter and flag is never negative.</summary>
    public static PlanArgument OptionalInt64(long? value) => Int64(value ?? -1);

    public static PlanArgument Flag(bool? value) => Int64(value is null ? -1 : value.Value ? 1 : 0);

    public static PlanArgument Bytes(ReadOnlySpan<byte> value) => new(PlanArgumentKind.Bytes, Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_'));

    public static PlanArgument OptionalBytes(ImmutableArray<byte> value) => value.IsDefault ? Null : Bytes(value.AsSpan());

    public static PlanArgument Null { get; } = new(PlanArgumentKind.Null, null);
}

/// <summary>
/// A statement contribution to the family <c>account-enrollment</c>: the module that owns the statement, whether it is a revision
/// guard or a record mutation, its stable key and its arguments (the guard's key values and expected revision, or the mutation's values).
/// </summary>
internal sealed record StatementContribution(string Module, string Kind, string Key, ImmutableArray<PlanArgument> Arguments);
