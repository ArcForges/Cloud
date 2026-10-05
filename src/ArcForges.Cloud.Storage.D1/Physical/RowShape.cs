// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Physical;

/// <summary>
/// An ordered set of columns of one table that a named plan statement binds or returns. A typed repository declares its shape once;
/// the shape encodes a row to the exact scalars in that order, decodes a result row back, and yields the plan parameter list a
/// plan definition needs, so the bind and result kinds of a plan cannot drift from the physical schema.
/// </summary>
internal sealed class RowShape
{
    private readonly PhysicalColumn[] columns;

    public RowShape(PhysicalTable table, params string[] columnNames)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(columnNames);
        if (columnNames.Length == 0) throw new PhysicalValueException("A row shape names at least one column.");
        if (columnNames.Distinct(StringComparer.Ordinal).Count() != columnNames.Length) throw new PhysicalValueException("A row shape names a column twice.");
        Table = table;
        columns = columnNames.Select(table.Column).ToArray();
    }

    public PhysicalTable Table { get; }

    public IReadOnlyList<PhysicalColumn> Columns => columns;

    /// <summary>The bind or result parameters, in column order, for a plan statement definition.</summary>
    public IReadOnlyList<PlanParam> Params() => columns.Select(ColumnCodec.ParamOf).ToArray();

    /// <summary>Encodes one logical row. Every column of the shape needs a value; a missing or extra column is refused.</summary>
    public D1Scalar[] Bind(IReadOnlyDictionary<string, PhysicalValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count != columns.Length) throw new PhysicalValueException("The row has " + values.Count + " values for " + columns.Length + " columns.");
        var scalars = new D1Scalar[columns.Length];
        for (var index = 0; index < columns.Length; index++)
        {
            var column = columns[index];
            if (!values.TryGetValue(column.Name, out var value)) throw new PhysicalValueException("The row has no value for " + column.Name + ".");
            scalars[index] = ColumnCodec.Encode(column, value);
        }

        return scalars;
    }

    /// <summary>Decodes one result row, strictly. A count or kind that does not match the shape is a defect.</summary>
    public Dictionary<string, PhysicalValue> Read(IReadOnlyList<D1Scalar> row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (row.Count != columns.Length) throw new PhysicalValueException("The result row has " + row.Count + " scalars for " + columns.Length + " columns.");
        var values = new Dictionary<string, PhysicalValue>(columns.Length, StringComparer.Ordinal);
        for (var index = 0; index < columns.Length; index++) values.Add(columns[index].Name, ColumnCodec.Decode(columns[index], row[index]));
        return values;
    }
}
