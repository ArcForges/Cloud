// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.SharedFamilies;

/// <summary>
/// What one module contributes to a family batch: the arguments of one statement of the plan, named by its module, class and stable
/// key (Design SU-02). A module never supplies SQL, a table name or the command identity.
/// </summary>
internal sealed record FamilyContribution(FamilyModule Module, FamilyClass Class, string Key, IReadOnlyList<D1Scalar> Arguments);

/// <summary>
/// The typed arguments of the five guard primitives, in exactly the parameter order the generator expands them (after the command
/// identity, which the unit of work supplies). The SQL of a guard is generated once from the physical manifest; these builders
/// make it impossible to pass a lease's values to a revision's slot, and refuse a value no guard could mean.
/// </summary>
internal static class FamilyGuards
{
    /// <summary>
    /// A row, found by its key columns, whose <paramref name="match"/> columns equal what the caller decided on (the authorization rows of
    /// the batch). With <paramref name="freshAfterMicros"/> the row's expiry column must be later than that UTC instant.
    /// </summary>
    public static FamilyContribution Authorization(FamilyModule module, string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> match, long? freshAfterMicros = null)
        => Exists(FamilyClass.Authorization, module, key, by, match, freshAfterMicros);

    /// <summary>The same shape as <see cref="Authorization"/> for the active policy or configuration rows the decision used.</summary>
    public static FamilyContribution Policy(FamilyModule module, string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> match, long? freshAfterMicros = null)
        => Exists(FamilyClass.Policy, module, key, by, match, freshAfterMicros);

    /// <summary>
    /// Captures the trusted server observation as a lower bound for a registered Identity security guard. The generated SQL also
    /// checks the actual SQLite UTC clock at the authorization statement; this argument never replaces that clock.
    /// </summary>
    public static FamilyContribution SecurityAuthorization(string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> match, long capturedServerMicros)
    {
        RequireNonNegative(capturedServerMicros);
        return Exists(FamilyClass.Authorization, FamilyModule.Identity, key, by, match, capturedServerMicros);
    }

    /// <summary>A registered persisted due deadline is checked against the actual database clock, never a caller-supplied instant.</summary>
    public static FamilyContribution SecurityDueAuthorization(string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> match)
        => Exists(FamilyClass.Authorization, FamilyModule.Identity, key, by, match, null);

    /// <summary>The row's revision equals the revision the caller read. A row that does not exist has revision zero.</summary>
    public static FamilyContribution Revision(FamilyModule module, string key, IReadOnlyList<D1Scalar> by, long expectedRevision)
    {
        RequireNonNegative(expectedRevision);
        return Build(FamilyClass.Revision, module, key, by, [D1Values.Int64(expectedRevision)]);
    }

    /// <summary>
    /// The row's revision and its captured exact balance columns equal what the checked C# arithmetic used, so a balance that moved after
    /// it was read can never be debited from a stale calculation.
    /// </summary>
    public static FamilyContribution Balance(FamilyModule module, string key, IReadOnlyList<D1Scalar> by, long expectedRevision, IReadOnlyList<D1Scalar> exact)
    {
        RequireNonNegative(expectedRevision);
        RequireAny(exact);
        return Build(FamilyClass.Balance, module, key, by, [D1Values.Int64(expectedRevision), .. exact]);
    }

    /// <summary>
    /// The holder, the fence and an unexpired lease equal the caller's at the trusted instant <paramref name="nowMicros"/>, so a holder whose
    /// lease expired or was taken over (a higher fence) cannot finalize.
    /// </summary>
    public static FamilyContribution Lease(FamilyModule module, string key, IReadOnlyList<D1Scalar> by, string holder, long fence, long nowMicros)
    {
        ArgumentNullException.ThrowIfNull(holder);
        RequireNonNegative(fence);
        if (holder.Length == 0 || nowMicros < 0) throw Invalid("lease");
        return Build(FamilyClass.Lease, module, key, by, [D1Values.Text(holder), D1Values.Int64(fence), D1Values.Int64(nowMicros)]);
    }

    /// <summary>The arguments of a hand-written mutation statement (bucket, reservation or record) of the module that owns its tables.</summary>
    public static FamilyContribution Mutation(FamilyModule module, FamilyClass @class, string key, IReadOnlyList<D1Scalar> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (@class is not (FamilyClass.Bucket or FamilyClass.Reservation or FamilyClass.Record)) throw Invalid("mutation class");
        return new FamilyContribution(module, @class, RequireKey(key), arguments.ToArray());
    }

    private static FamilyContribution Exists(FamilyClass kind, FamilyModule module, string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> match, long? freshAfterMicros)
    {
        RequireAny(match);
        if (freshAfterMicros is < 0) throw Invalid("fresh");
        var rest = new List<D1Scalar>(match);
        if (freshAfterMicros is { } fresh) rest.Add(D1Values.Int64(fresh));
        return Build(kind, module, key, by, rest);
    }

    private static FamilyContribution Build(FamilyClass kind, FamilyModule module, string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> rest)
    {
        RequireAny(by);
        var arguments = new List<D1Scalar>(by.Count + rest.Count);
        arguments.AddRange(by);
        arguments.AddRange(rest);
        return new FamilyContribution(module, kind, RequireKey(key), arguments);
    }

    private static string RequireKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length == 0) throw Invalid("key");
        return key;
    }

    private static void RequireAny(IReadOnlyList<D1Scalar> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count == 0 || values.Any(value => value is null)) throw Invalid("empty argument list");
    }

    private static void RequireNonNegative(long value)
    {
        if (value < 0) throw Invalid("negative revision or fence");
    }

    private static FamilyViolationException Invalid(string detail) => new(FamilyViolation.InvalidArguments, detail);
}
