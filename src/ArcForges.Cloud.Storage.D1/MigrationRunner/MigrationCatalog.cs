// SPDX-License-Identifier: AGPL-3.0-only
// The migration catalog rules (RES-cloud-d1-migrations; CLOUD.84 U9): one global sequence of numbered migrations, each locked by its
// checksum in migrations.lock.json. The rules are pure: the caller (tools/ArcForges.Cloud.Generation) reads the files and the lock
// and writes the results back. A merged migration is never edited: the lock holds its checksum and `check --base` compares the lock
// with the base branch.
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Cloud.Storage.D1.MigrationRunner;

/// <summary>One entry of migrations.lock.json.</summary>
public sealed record LockEntry(int Sequence, string File, string Module, string Mode, string Sha256);

/// <summary>A file of the migrations directory: its name and its text (decoded as UTF-8, byte order mark kept).</summary>
public sealed record SourceFile(string Name, string Text);

/// <summary>A numbered migration with its parsed statements and checksum.</summary>
public sealed record Migration(
    int Sequence,
    string File,
    string Module,
    MigrationMode Mode,
    IReadOnlyDictionary<string, string> Options,
    string Sha256,
    string Text,
    IReadOnlyList<SqlStatement> Statements);

public static class MigrationCatalog
{
    /// <summary>The lock file name and its schema version.</summary>
    public const string LockFileName = "migrations.lock.json";

    /// <summary>The numbered files of a directory, sorted by name (ordinal, as the file system orders them).</summary>
    public static List<SourceFile> SortedSqlFiles(IEnumerable<SourceFile> files) =>
        files.Where(file => file.Name.EndsWith(".sql", StringComparison.Ordinal))
            .OrderBy(file => file.Name, StringComparer.Ordinal)
            .ToList();

    /// <summary>The SHA-256 identity of the locked schema: the highest sequence and a hash over every sequence and checksum.</summary>
    public static (int Highest, string Hash) LockIdentity(IReadOnlyList<LockEntry> entries)
    {
        var builder = new StringBuilder();
        foreach (var entry in entries) builder.Append(entry.Sequence).Append(':').Append(entry.Sha256).Append('\n');
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
        return (entries.Count == 0 ? 0 : entries[^1].Sequence, hash);
    }

    /// <summary>Loads and validates the numbered migrations against the lock. Throws on the first inconsistency.</summary>
    public static IReadOnlyList<Migration> Load(IEnumerable<SourceFile> files, IReadOnlyList<LockEntry> locked)
    {
        var sorted = SortedSqlFiles(files);
        var migrations = new List<Migration>();
        for (var position = 0; position < sorted.Count; position++)
        {
            var file = sorted[position];
            var numbered = MigrationSql.ParseNumberedFileName(file.Name)
                ?? throw Refuse($"migration file {file.Name} does not match NNNN_<module>__<slug>.sql");
            if (numbered.Sequence != position)
                throw Refuse($"migrations must be numbered 0000.. without a gap or duplicate: {file.Name} is at position {position}");
            var header = MigrationSql.ParseHeader(file.Text);
            if (header.Module != numbered.Module)
                throw Refuse($"{file.Name}: header module {header.Module} differs from the file name");
            IReadOnlyList<SqlStatement> statements;
            if (header.Mode == MigrationMode.Backfill)
            {
                MigrationSql.ParseBackfill(file.Text);
                statements = [];
            }
            else
            {
                statements = MigrationSql.SplitStatements(file.Text);
                if (statements.Count == 0) throw Refuse($"{file.Name}: no statements");
                CheckModes(file.Name, header.Mode, statements);
            }

            migrations.Add(new Migration(
                numbered.Sequence,
                file.Name,
                header.Module,
                header.Mode,
                header.Options,
                MigrationSql.ChecksumOf(file.Text),
                file.Text,
                statements));
        }

        if (locked.Count != migrations.Count)
            throw Refuse($"{LockFileName} has {locked.Count} entries for {migrations.Count} migration files");
        for (var position = 0; position < migrations.Count; position++)
        {
            var migration = migrations[position];
            var entry = locked[position];
            if (entry.Sequence != migration.Sequence)
                throw Refuse($"{LockFileName}: sequence at position {position}");
            if (entry.File != migration.File)
                throw Refuse($"{LockFileName}: file of sequence {migration.Sequence}");
            if (entry.Module != migration.Module)
                throw Refuse($"{LockFileName}: module of {migration.File}");
            if (entry.Mode != MigrationSql.ModeName(migration.Mode))
                throw Refuse($"{LockFileName}: mode of {migration.File}");
            if (entry.Sha256 != migration.Sha256)
                throw Refuse($"{migration.File} was edited after it was locked: a merged migration is never edited, add a new one");
        }

        return migrations;
    }

    /// <summary>Locks every numbered file that is not locked yet, and returns the complete lock (the caller writes it).</summary>
    public static List<LockEntry> LockNumbered(IReadOnlyList<LockEntry> existing, IEnumerable<SourceFile> files)
    {
        var entries = new List<LockEntry>(existing);
        var sorted = SortedSqlFiles(files);
        for (var position = 0; position < sorted.Count; position++)
        {
            var file = sorted[position];
            if (position < entries.Count)
            {
                if (entries[position].File != file.Name)
                    throw Refuse($"{LockFileName} does not match {file.Name}");
                continue;
            }

            var numbered = MigrationSql.ParseNumberedFileName(file.Name)
                ?? throw Refuse($"migration file {file.Name} does not match NNNN_<module>__<slug>.sql");
            if (numbered.Sequence != position) throw Refuse($"{file.Name}: sequence must be {position}");
            var header = MigrationSql.ParseHeader(file.Text);
            entries.Add(new LockEntry(position, file.Name, header.Module, MigrationSql.ModeName(header.Mode), MigrationSql.ChecksumOf(file.Text)));
        }

        return entries;
    }

    /// <summary>
    /// The lock of the base branch must be a prefix of this lock: a merged migration is never edited, removed or renumbered.
    /// </summary>
    public static List<string> AppendOnlyProblems(IReadOnlyList<LockEntry> baseEntries, IReadOnlyList<LockEntry> current)
    {
        var problems = new List<string>();
        for (var position = 0; position < baseEntries.Count; position++)
        {
            var entry = baseEntries[position];
            if (position >= current.Count)
            {
                problems.Add($"migration {entry.File} was removed");
                continue;
            }

            var now = current[position];
            if (now.File != entry.File || now.Sha256 != entry.Sha256 || now.Sequence != entry.Sequence)
                problems.Add($"merged migration {entry.File} was edited or renumbered ({now.File})");
        }

        return problems;
    }

    /// <summary>Validates one pending file (module__slug.sql) and returns its module.</summary>
    public static string CheckPendingFile(string name, string text)
    {
        var module = MigrationSql.ParsePendingModule(name)
            ?? throw Refuse($"pending migration {name} does not match <module>__<slug>.sql");
        var header = MigrationSql.ParseHeader(text);
        if (header.Module != module) throw Refuse($"{name}: header module differs from the file name");
        if (header.Mode == MigrationMode.Backfill)
        {
            MigrationSql.ParseBackfill(text);
        }
        else
        {
            var statements = MigrationSql.SplitStatements(text);
            if (statements.Count == 0) throw Refuse($"{name}: no statements");
            CheckModes(name, header.Mode, statements);
        }

        return module;
    }

    /// <summary>The name a pending migration takes when it is numbered: the four-digit sequence, an underscore and the file name.</summary>
    public static string NumberedName(int existingCount, string file) =>
        $"{existingCount.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)}_{file}";

    private static void CheckModes(string name, MigrationMode mode, IReadOnlyList<SqlStatement> statements)
    {
        var problems = MigrationSql.ModeViolations(mode, statements);
        if (problems.Count > 0) throw Refuse($"{name}: {string.Join("; ", problems)}");
    }

    private static MigrationError Refuse(string message) => new("catalog", message);
}
