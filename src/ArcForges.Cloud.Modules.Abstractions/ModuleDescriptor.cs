// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Modules;

/// <summary>
/// The identity of one Cloud module boundary: its project name, its data-model schema, the directory that owns its named
/// storage plans and the prefix of every physical table it owns (<c>&lt;schema&gt;_&lt;snake_case_entity&gt;</c>, Design D1 profile
/// section 2). The values are derived from the schema, so a module cannot claim a plan directory or a table prefix of another owner.
/// </summary>
public sealed partial record ModuleDescriptor
{
    private ModuleDescriptor(string name, string schema)
    {
        Name = name;
        Schema = schema;
        PlanOwner = schema.Replace('_', '-');
        TablePrefix = schema + "_";
    }

    /// <summary>The module name, the last segment of its project <c>ArcForges.Cloud.Modules.&lt;Name&gt;</c>.</summary>
    public string Name { get; }

    /// <summary>The data-model schema of the module (the dotted SQL schema of model 01 that becomes the table prefix).</summary>
    public string Schema { get; }

    /// <summary>The plan owner: the directory <c>storage/plans/&lt;owner&gt;</c> and the first segment of every plan id of the module.</summary>
    public string PlanOwner { get; }

    /// <summary>Every physical table of the module starts with this prefix; no other module may read or write such a table.</summary>
    public string TablePrefix { get; }

    public static ModuleDescriptor Create(string name, string schema)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(schema);
        if (!NamePattern().IsMatch(name)) throw new ArgumentException("A module name is PascalCase letters and digits.", nameof(name));
        if (!SchemaPattern().IsMatch(schema)) throw new ArgumentException("A schema is lower-case snake_case.", nameof(schema));
        return new ModuleDescriptor(name, schema);
    }

    [GeneratedRegex("^[A-Z][A-Za-z0-9]*$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();

    [GeneratedRegex("^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex SchemaPattern();
}
