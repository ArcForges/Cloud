// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Cloud.Modules;

/// <summary>The kinds of exact scalar a module may pass to, or read from, a named storage plan.</summary>
public enum PlanValueKind
{
    Null,
    Int64,
    Text,
    Bytes,
    Bool,
}

/// <summary>
/// One exact scalar of a named storage plan. A 64-bit integer is never a floating-point number on any path; the storage layer carries it
/// as canonical decimal text. The value names no table, no column and no SQL: the plan (a reviewed, checked-in file of the calling
/// module's own owner) decides what a position means.
/// </summary>
public readonly struct PlanValue : IEquatable<PlanValue>
{
    private readonly long integer;
    private readonly string? text;
    private readonly byte[]? bytes;

    private PlanValue(PlanValueKind kind, long integer = 0, string? text = null, byte[]? bytes = null)
    {
        Kind = kind;
        this.integer = integer;
        this.text = text;
        this.bytes = bytes;
    }

    public PlanValueKind Kind { get; }

    public bool IsNull => Kind == PlanValueKind.Null;

    public static PlanValue Null { get; } = new(PlanValueKind.Null);

    public static PlanValue FromInt64(long value) => new(PlanValueKind.Int64, integer: value);

    public static PlanValue FromBool(bool value) => new(PlanValueKind.Bool, integer: value ? 1 : 0);

    public static PlanValue FromText(string value) => new(PlanValueKind.Text, text: value ?? throw new ArgumentNullException(nameof(value)));

    public static PlanValue FromBytes(ReadOnlySpan<byte> value) => new(PlanValueKind.Bytes, bytes: value.ToArray());

    /// <summary>A null value, or the text.</summary>
    public static PlanValue FromOptionalText(string? value) => value is null ? Null : FromText(value);

    public long AsInt64() => Kind == PlanValueKind.Int64 ? integer : throw Mismatch(PlanValueKind.Int64);

    public bool AsBool() => Kind == PlanValueKind.Bool ? integer == 1 : throw Mismatch(PlanValueKind.Bool);

    public string AsText() => Kind == PlanValueKind.Text ? text! : throw Mismatch(PlanValueKind.Text);

    public ReadOnlySpan<byte> AsBytes() => Kind == PlanValueKind.Bytes ? bytes : throw Mismatch(PlanValueKind.Bytes);

    /// <summary>The text, or null when the value is null.</summary>
    public string? AsOptionalText() => IsNull ? null : AsText();

    /// <summary>The integer, or null when the value is null.</summary>
    public long? AsOptionalInt64() => IsNull ? null : AsInt64();

    private InvalidOperationException Mismatch(PlanValueKind wanted) => new("The plan value is " + Kind + " but " + wanted + " was requested.");

    public bool Equals(PlanValue other) =>
        Kind == other.Kind && integer == other.integer && string.Equals(text, other.text, StringComparison.Ordinal)
        && (bytes is null ? other.bytes is null : other.bytes is not null && bytes.AsSpan().SequenceEqual(other.bytes));

    public override bool Equals(object? obj) => obj is PlanValue other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Kind, integer, text);

    public static bool operator ==(PlanValue left, PlanValue right) => left.Equals(right);

    public static bool operator !=(PlanValue left, PlanValue right) => !left.Equals(right);

    /// <summary>A description that never carries a value (a plan value may be a payload).</summary>
    public override string ToString() => Kind == PlanValueKind.Int64 ? integer.ToString(CultureInfo.InvariantCulture) : Kind.ToString();
}
