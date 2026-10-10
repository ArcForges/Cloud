// SPDX-License-Identifier: AGPL-3.0-only
// The narrow surface the migration engine needs from a D1 database: one atomic batch of positional-bind statements (CLOUD.84 U9,
// S41(1)). The engine binds and reads 64-bit values as canonical decimal text (CAST(? AS INTEGER) and CAST(column AS TEXT)), so no
// value is ever read as a floating-point number. Three clients implement it: the Cloudflare D1 REST API (the gated deployment job,
// in tools/ArcForges.Cloud.Generation), a test-only SQLite oracle, and any future binding.
namespace ArcForges.Cloud.Storage.D1.MigrationRunner;

/// <summary>A refusal of the migration engine. The code is stable text for the job log; the message never carries a credential.</summary>
public sealed class MigrationError(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>An error reported by a database client. The message is the database's, never a request header or a credential.</summary>
public sealed class MigrationClientException(string message) : Exception(message);

/// <summary>One statement of a batch. Each bind is a string, a long or null (a bind of null is SQL NULL).</summary>
public sealed record MigrationStatement(string Sql, IReadOnlyList<object?> Params);

/// <summary>The result of one statement: rows changed by a write, and the rows of a SELECT as text cells in column order.</summary>
public sealed record BatchResult(long Changes, IReadOnlyList<IReadOnlyList<string?>> Rows);

public interface IMigrationClient
{
    /// <summary>Runs the statements in order as one atomic transaction: all commit or none does.</summary>
    Task<IReadOnlyList<BatchResult>> BatchAsync(IReadOnlyList<MigrationStatement> statements, CancellationToken cancellationToken);
}
