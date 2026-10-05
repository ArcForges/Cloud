// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage.Physical;

/// <summary>
/// The logical type of one physical column (Design D1 profile section 2). The kind fixes the stored representation, the exact
/// bind form (64-bit values and decimals travel as canonical decimal text, never as a floating-point number) and the check that the
/// database also enforces.
/// </summary>
internal enum PhysicalKind
{
    /// <summary>Canonical lower-case UUID text.</summary>
    Id,
    Text,
    /// <summary>Case-sensitive ASCII <c>[A-Za-z0-9._:/-]{1,128}</c>.</summary>
    Key,
    ProductId,
    ModelId,
    Bool,
    Int32,
    Int64,
    /// <summary>A non-negative signed 64-bit revision.</summary>
    Rev,
    /// <summary>UTC microseconds since the Unix epoch as a signed 64-bit integer.</summary>
    Instant,
    /// <summary>Canonical decimal text of an unsigned 64-bit integer.</summary>
    Uint64,
    /// <summary>Canonical decimal text, at most 28 significant digits and 9 fractional digits.</summary>
    Decimal,
    /// <summary>Three upper-case ASCII letters.</summary>
    Currency,
    /// <summary>A 32-byte value.</summary>
    Hash,
    Bytes,
    Proto,
    Json,
    /// <summary>A closed enum stored as its registered number.</summary>
    Enum,
}

internal enum PhysicalJsonRoot
{
    Any,
    Object,
    Array,
}

internal sealed record PhysicalColumn(
    string Name,
    PhysicalKind Kind,
    bool Nullable,
    string? EnumName = null,
    PhysicalJsonRoot JsonRoot = PhysicalJsonRoot.Any,
    int? MaxBytes = null);

internal sealed record PhysicalEnumMember(string Name, int Number);

/// <summary>A closed enum registry entry. Numbers are never reused or renumbered.</summary>
internal sealed record PhysicalEnum(string Name, bool PreserveUnknown, IReadOnlyList<PhysicalEnumMember> Members)
{
    public bool TryGetNumber(string name, out int number)
    {
        foreach (var member in Members)
        {
            if (member.Name != name) continue;
            number = member.Number;
            return true;
        }

        number = 0;
        return false;
    }

    public bool TryGetName(int number, out string name)
    {
        foreach (var member in Members)
        {
            if (member.Number != number) continue;
            name = member.Name;
            return true;
        }

        name = "";
        return false;
    }
}

internal sealed class PhysicalTable
{
    private readonly Dictionary<string, PhysicalColumn> byName;

    public PhysicalTable(string name, string owner, IReadOnlyList<PhysicalColumn> columns, IReadOnlyList<string> primaryKey)
    {
        Name = name;
        Owner = owner;
        Columns = columns;
        PrimaryKey = primaryKey;
        byName = new Dictionary<string, PhysicalColumn>(columns.Count, StringComparer.Ordinal);
        foreach (var column in columns) byName.Add(column.Name, column);
    }

    public string Name { get; }

    public string Owner { get; }

    public IReadOnlyList<PhysicalColumn> Columns { get; }

    public IReadOnlyList<string> PrimaryKey { get; }

    public PhysicalColumn Column(string name) =>
        byName.TryGetValue(name, out var column) ? column : throw new PhysicalValueException("The table " + Name + " has no column " + name + ".");

    public bool TryGetColumn(string name, out PhysicalColumn column)
    {
        if (byName.TryGetValue(name, out var found))
        {
            column = found;
            return true;
        }

        column = null!;
        return false;
    }
}

/// <summary>A value that does not fit its column: refused before anything is sent, or a defect when it came from the database.</summary>
internal sealed class PhysicalValueException(string message) : Exception(message);

internal static partial class PhysicalSchema
{
    private static readonly Lazy<Dictionary<string, PhysicalTable>> TableIndex =
        new(() => Tables.ToDictionary(table => table.Name, StringComparer.Ordinal));

    private static readonly Lazy<Dictionary<string, PhysicalEnum>> EnumIndex =
        new(() => Enums.ToDictionary(entry => entry.Name, StringComparer.Ordinal));

    public static PhysicalTable FindTable(string name) =>
        TableIndex.Value.TryGetValue(name, out var table) ? table : throw new PhysicalValueException("The physical schema has no table " + name + ".");

    public static PhysicalEnum FindEnum(string name) =>
        EnumIndex.Value.TryGetValue(name, out var entry) ? entry : throw new PhysicalValueException("The physical schema has no enum " + name + ".");
}
