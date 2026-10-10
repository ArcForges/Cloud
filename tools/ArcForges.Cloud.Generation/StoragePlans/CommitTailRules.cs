// SPDX-License-Identifier: AGPL-3.0-only
// The commit tail rules (Design D1 profile section 4, CLOUD.04) as the storage-plan generator checks them (CLOUD.84 U7; port of
// eng/verification/commit-tail.ts). A module write plan that declares `-- tail: v1 [events=N] [inbox]` must end with exactly the canonical
// tail statements for those options followed by the guard release. The statement texts below are the same as commit-tail.ts.
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Tools.Generation.StoragePlans;

public sealed record TailStatement(string Role, string Sql, IReadOnlyList<PlanParameter> Params);

/// <summary>A parsed tail header: either the canonical tail (with its options) or a stated reason for having none.</summary>
public sealed record TailDeclaration(bool IsNone, int Events, bool Inbox, string Reason);

public static partial class CommitTailRules
{
    /// <summary>The change archive is the one stream whose key starts with this prefix; an owner scope never does.</summary>
    public const string ArchiveStreamKey = "platform:change-archive";

    public const int MaxTailEvents = 16;

    /// <summary>Every leading statement of a plan that declares a tail starts with this.</summary>
    public const string GuardInsertPrefix = "INSERT INTO platform_command_guard (command_id, guard_key, allowed)";

    /// <summary>Tables only a tail (or a platform plan) may write: a module write plan never names one as a write target.</summary>
    public static readonly IReadOnlyList<string> ReservedTables =
    [
        "platform_command",
        "platform_inbox",
        "platform_outbox",
        "platform_outbox_position",
        "platform_sequence_stream",
        "platform_change_archive",
    ];

    private static readonly PlanParameter Text = new("text", false);
    private static readonly PlanParameter Int64 = new("int64", false);
    private static readonly PlanParameter Scope = new("scope", false);
    private static readonly PlanParameter NullableText = new("text", true);

    private static readonly TailStatement InboxStatement = new(
        "inbox",
        """
        INSERT INTO platform_inbox (source, message_id, received_at, processed_at, outcome, expires_at)
        VALUES (?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), 1, CAST(? AS INTEGER));
        """,
        [Text, Text, Int64, Int64, Int64]);

    private static readonly TailStatement ReceiptStatement = new(
        "receipt",
        """
        INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, 2, ?, NULLIF(CAST(? AS INTEGER), -1), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));
        """,
        [Text, NullableText, Text, Text, Text, Text, Int64, Int64, Int64]);

    private static readonly TailStatement StreamStatement = new(
        "stream",
        """
        INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
        VALUES (?, 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
        ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
        """,
        [Scope, Int64]);

    private static readonly TailStatement OutboxStatement = new(
        "outbox",
        """
        INSERT INTO platform_outbox (outbox_id, aggregate_kind, aggregate_id, aggregate_rev, event_type, payload, workspace_id, correlation_id, causation_id, state, attempts, created_at, dispatched_at)
        VALUES (?, ?, ?, CAST(? AS INTEGER), ?, ?, ?, ?, ?, 1, 0, CAST(? AS INTEGER), NULL);
        """,
        [Text, Text, Text, Int64, Text, Text, NullableText, Text, NullableText, Int64]);

    private static readonly TailStatement PositionStatement = new(
        "position",
        """
        INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence)
        VALUES (?, ?, (SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = ?));
        """,
        [Text, Scope, Scope]);

    private static readonly TailStatement ArchiveStreamStatement = new(
        "archive-stream",
        $"""
        INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
        VALUES ('{ArchiveStreamKey}', 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
        ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
        """,
        [Int64]);

    private static readonly TailStatement ArchiveStatement = new(
        "archive",
        $"""
        INSERT INTO platform_change_archive (archive_sequence, command_id, schema_version, record, record_hash, created_at)
        VALUES ((SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = '{ArchiveStreamKey}'), ?, CAST(? AS INTEGER), ?, ?, CAST(? AS INTEGER));
        """,
        [Text, Int64, Text, new PlanParameter("bytes", false), Int64]);

    /// <summary>The last statement of every plan that uses guard rows: no committed state holds one.</summary>
    public static readonly TailStatement ReleaseStatement = new(
        "guard-release",
        "DELETE FROM platform_command_guard WHERE command_id = ?;",
        [Text]);

    private static readonly Regex GuardStatementPattern = new(
        @"^INSERT INTO platform_command_guard \(command_id, guard_key, allowed\) SELECT \?, '[A-Za-z0-9._:/-]{1,128}', ",
        RegexOptions.CultureInvariant);

    private static readonly Regex EventsOption = new(@"^events=(\d{1,2})$", RegexOptions.CultureInvariant);

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    private static partial Regex Whitespace();

    /// <summary>Whitespace-insensitive comparison form of one statement.</summary>
    public static string Collapse(string sql) => Whitespace().Replace(sql, " ").Trim();

    /// <summary>The statements, in order, that follow a plan's own mutations and precede the release.</summary>
    public static List<TailStatement> CanonicalTail(int events, bool inbox)
    {
        SqlText.Require(
            events >= 0 && events <= MaxTailEvents,
            $"a tail carries 0 to {MaxTailEvents} outbox events");
        var statements = new List<TailStatement>();
        if (inbox) statements.Add(InboxStatement);
        statements.Add(ReceiptStatement);
        for (var index = 0; index < events; index++)
        {
            statements.Add(StreamStatement);
            statements.Add(OutboxStatement);
            statements.Add(PositionStatement);
        }

        statements.Add(ArchiveStreamStatement);
        statements.Add(ArchiveStatement);
        return statements;
    }

    /// <summary>Parses `v1 [events=N] [inbox]` or `none &lt;reason of at least ten characters&gt;`.</summary>
    public static TailDeclaration ParseTailHeader(string value, string where)
    {
        if (value.StartsWith("none", StringComparison.Ordinal))
        {
            var reason = value[4..].Trim();
            SqlText.Require(
                reason.Length >= 10,
                $"{where}: '-- tail: none' states the reason in at least ten characters");
            return new TailDeclaration(true, 0, false, reason);
        }

        var parts = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        SqlText.Require(
            parts.Length > 0 && parts[0] == "v1",
            $"{where}: a tail header is 'v1 [events=N] [inbox]' or 'none <reason>'");
        var events = 0;
        var inbox = false;
        var seenEvents = false;
        foreach (var part in parts.Skip(1))
        {
            var match = EventsOption.Match(part);
            if (match.Success)
            {
                SqlText.Require(!seenEvents, $"{where}: duplicate events");
                seenEvents = true;
                events = int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
            }
            else
            {
                SqlText.Require(part == "inbox" && !inbox, $"{where}: unknown tail option '{part}'");
                inbox = true;
            }
        }

        SqlText.Require(events <= MaxTailEvents, $"{where}: at most {MaxTailEvents} outbox events");
        return new TailDeclaration(false, events, inbox, string.Empty);
    }

    private static bool SameParams(IReadOnlyList<PlanParameter> actual, IReadOnlyList<PlanParameter> expected) =>
        actual.Count == expected.Count
        && actual.Zip(expected).All(pair => pair.First.Kind == pair.Second.Kind && pair.First.Nullable == pair.Second.Nullable);

    /// <summary>
    /// Checks a plan that declares a tail: guard inserts first, at least one owner statement, then exactly the canonical tail and the guard
    /// release. Returns the owner statement range (guards, owner end), or null when the plan declares no tail.
    /// </summary>
    public static (int OwnerStart, int OwnerEnd)? AssertTail(
        string planId,
        string access,
        IReadOnlyList<PlanStatement> statements,
        TailDeclaration declaration)
    {
        if (declaration.IsNone) return null;
        SqlText.Require(access == "write", $"{planId}: only a write plan carries a commit tail");
        var suffix = CanonicalTail(declaration.Events, declaration.Inbox).Append(ReleaseStatement).ToList();
        var guards = 0;
        while (guards < statements.Count && GuardStatementPattern.IsMatch(Collapse(statements[guards].Sql)))
        {
            SqlText.Require(
                statements[guards].Params.Count > 0 && statements[guards].Params[0].Kind == "text",
                $"{planId}: guard statement {guards + 1} binds the command id as its first parameter");
            guards++;
        }

        SqlText.Require(
            guards >= 1,
            $"{planId}: statement 1 must be a guard insert '{GuardInsertPrefix} SELECT ?, '<guard key>', ...'");
        var ownerEnd = statements.Count - suffix.Count;
        SqlText.Require(
            ownerEnd - guards >= 1,
            $"{planId}: a plan with a tail has at least one guard, at least one owner statement and the {suffix.Count} tail and release statements");
        for (var index = 0; index < suffix.Count; index++)
        {
            var expected = suffix[index];
            var at = ownerEnd + index;
            var where = $"{planId}: tail statement {index + 1} ({expected.Role}), plan statement {at + 1}";
            SqlText.Require(at >= 0 && at < statements.Count, $"{where} is missing");
            var actual = statements[at];
            SqlText.Require(
                Collapse(actual.Sql) == Collapse(expected.Sql),
                $"{where} differs from the canonical text; run node eng/verification/commit-tail.ts print");
            SqlText.Require(SameParams(actual.Params, expected.Params), $"{where} has different parameter kinds");
        }

        for (var index = guards; index < ownerEnd; index++)
        {
            SqlText.Require(
                !GuardStatementPattern.IsMatch(Collapse(statements[index].Sql)),
                $"{planId}: owner statement {index + 1} is a guard insert after a mutation: guards come first");
        }

        return (guards, ownerEnd);
    }
}
