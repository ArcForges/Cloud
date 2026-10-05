// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage.Physical;

/// <summary>The migration bookkeeping row the host reads at readiness (platform_schema_state).</summary>
internal readonly record struct SchemaState(long SchemaVersion, long ReadHorizon, long WriteHorizon);

internal readonly record struct SchemaCompatibilityResult(bool CanRead, bool CanWrite, string Reason);

/// <summary>
/// Whether this build may use the database, and the compatible-rollback rule (Design D1 profile section 6): a build never runs
/// against a schema older than the one it expects; the read and write horizons name the oldest builds that may still read and
/// write, so rolling the application back before a cutover is compatible and after it is not. The migration runner applies the same
/// rule from its own copy (eng/migrations/runner.ts, <c>compatibility</c>), and a shared vector file pins both.
/// </summary>
internal static class SchemaCompatibility
{
    /// <summary>The highest migration this build was compiled against.</summary>
    public static int ApplicationSchemaVersion => PhysicalSchema.HighestMigration;

    public static SchemaCompatibilityResult Check(SchemaState state, long applicationSchemaVersion)
    {
        if (applicationSchemaVersion > state.SchemaVersion)
            return new SchemaCompatibilityResult(false, false, "the application expects a newer schema than the database has applied");
        var canRead = applicationSchemaVersion >= state.ReadHorizon;
        var canWrite = applicationSchemaVersion >= state.WriteHorizon;
        var reason = canWrite ? "compatible" : canRead ? "the build is below the write horizon" : "the build is below the read horizon";
        return new SchemaCompatibilityResult(canRead, canWrite, reason);
    }
}
