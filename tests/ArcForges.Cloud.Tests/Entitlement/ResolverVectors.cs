// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// The recorder of the resolver parity vectors (AF-CTR-03 part B, F1/N2). The Go center ports the resolver line for line; this file
/// records every input the C# suites hand to it and every output it answers, as data the Go test replays
/// (<c>center/internal/entitlement/testdata/csharp-resolver-vectors.json</c>). Two corpus kinds exist: resolver vectors (a record set,
/// the definitions and an instant, with the snapshot or the refusal the C# resolver answered) and admission vectors (an issue
/// request with the admitted result or the refusal reason). Nothing here is production code; it records, it never changes a result.
/// <para>
/// Where a vector comes from. A test that calls the resolver directly goes through <see cref="Resolve"/>. A test that goes through the
/// service (<see cref="EntitlementServiceFacade"/>, the type <c>EntitlementHarness.Service</c> returns) reaches the resolver inside
/// the service, where nothing can observe it; the facade therefore records it from the service's own port traffic: every commit
/// carries the records and the snapshot it derived (exact), and the two outcomes that commit nothing, an unchanged refresh and a
/// refused history, are re-derived from the loaded state by the same formulas the service uses and checked against what the service
/// answered, so a divergence fails the run instead of recording a guess.
/// </para>
/// </summary>
internal static class ResolverVectors
{
    private static readonly AsyncLocal<Row?> Current = new();
    private static readonly AsyncLocal<long> CurrentCall = new();
    private static long calls;

    /// <summary>The service call (facade method) this async flow is inside, or 0: port events carry it so interleaved calls stay apart.</summary>
    internal static long Call => CurrentCall.Value;

    /// <summary>Starts a service call; assign the result to nothing, the identity flows down the async calls of the caller.</summary>
    internal static long BeginCall() => CurrentCall.Value = Interlocked.Increment(ref calls);

    /// <summary>The row being recorded in this async flow, or null when nothing records (an ordinary test run).</summary>
    internal static Row? Active => Current.Value;

    /// <summary>Starts recording one test row; dispose to stop.</summary>
    internal static IDisposable Begin(Row row)
    {
        var previous = Current.Value;
        Current.Value = row;
        return new Scope(() => Current.Value = previous);
    }

    /// <summary>The resolver, recorded when a row is being recorded. Every direct call of a covered suite goes through it.</summary>
    internal static EntitlementSnapshot Resolve(EntitlementRecordSet records, EntitlementDefinitions definitions, UtcMicros asOf)
    {
        var row = Current.Value;
        try
        {
            var snapshot = EntitlementResolver.Resolve(records, definitions, asOf);
            row?.Add(new ResolverVector(records, definitions, asOf, snapshot, null));
            return snapshot;
        }
        catch (ResolverInputException exception)
        {
            row?.Add(new ResolverVector(records, definitions, asOf, null, exception.Message));
            throw;
        }
    }

    /// <summary>Grant admission, recorded when a row is being recorded.</summary>
    internal static string? Admit(IssueGrantRequest request)
    {
        var refusal = GrantAdmission.Validate(request);
        Current.Value?.Add(new AdmissionVector(request, refusal));
        return refusal;
    }

    private sealed class Scope(Action end) : IDisposable
    {
        public void Dispose() => end();
    }
}

internal sealed record ResolverVector(EntitlementRecordSet Records, EntitlementDefinitions Definitions, UtcMicros AsOf, EntitlementSnapshot? Result, string? Error);

internal sealed record AdmissionVector(IssueGrantRequest Request, string? Refusal);

/// <summary>Everything recorded while one test row ran, plus the port traffic of the services under it.</summary>
internal sealed class Row(string name)
{
    private readonly List<object> vectors = [];

    public string Name { get; } = name;

    /// <summary>When true nothing is recorded (a row whose interleaving is not deterministic, excluded by name).</summary>
    public bool Muted { get; set; }

    public List<PortEvent> Events { get; } = [];

    public IReadOnlyList<object> Vectors => vectors;

    public void Add(object vector)
    {
        if (!Muted) vectors.Add(vector);
    }
}

/// <summary>One thing a service did through its ports, in order.</summary>
internal abstract record PortEvent
{
    public long Call { get; } = ResolverVectors.Call;
}

internal sealed record LoadEvent(string WorkspaceId, EntitlementState State) : PortEvent;

internal sealed record ClockEvent(UtcMicros Value) : PortEvent;

internal sealed record IdEvent(string Id) : PortEvent;

internal sealed record CommitEvent(string WorkspaceId, EntitlementState? Loaded, EntitlementAppend Append, EntitlementSnapshot Snapshot, CommitOutcome Outcome) : PortEvent;

/// <summary>Logs the clock reads of the service under it.</summary>
internal sealed class RecordingTimeProvider(TimeProvider inner) : TimeProvider
{
    public override DateTimeOffset GetUtcNow()
    {
        var now = inner.GetUtcNow();
        ResolverVectors.Active?.Events.Add(new ClockEvent(UtcMicros.FromDateTimeOffset(now)));
        return now;
    }
}

internal sealed class RecordingIds(IEntitlementIdSource inner) : IEntitlementIdSource
{
    public string NewId()
    {
        var id = inner.NewId();
        ResolverVectors.Active?.Events.Add(new IdEvent(id));
        return id;
    }
}

/// <summary>Logs the loads and commits of the service under it and records every commit as an exact resolver vector.</summary>
internal sealed class RecordingStore(IEntitlementStore inner, FixedDefinitions definitions) : IEntitlementStore
{
    private readonly Dictionary<(long Call, string Workspace), EntitlementState> loaded = [];

    public async ValueTask<EntitlementState> LoadAsync(string workspaceId, CancellationToken cancellationToken)
    {
        var state = await inner.LoadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        if (ResolverVectors.Active is { } row)
        {
            lock (loaded) loaded[(ResolverVectors.Call, workspaceId)] = state;
            row.Events.Add(new LoadEvent(workspaceId, state));
        }

        return state;
    }

    public async ValueTask<CommitOutcome> CommitAsync(
        string workspaceId, long expectedRevision, EntitlementAppend append, EntitlementSnapshot snapshot, CancellationToken cancellationToken)
    {
        var outcome = await inner.CommitAsync(workspaceId, expectedRevision, append, snapshot, cancellationToken).ConfigureAwait(false);
        if (ResolverVectors.Active is { } row)
        {
            EntitlementState? state;
            lock (loaded) state = loaded.GetValueOrDefault((ResolverVectors.Call, workspaceId));
            row.Events.Add(new CommitEvent(workspaceId, state, append, snapshot, outcome));
            if (state is not null)
            {
                // The committed snapshot was derived from exactly the loaded records plus what the commit appended, under the active
                // definitions, at the instant the snapshot names: replaying that through the resolver must reproduce the snapshot.
                var records = state.Records with
                {
                    Grants = state.Records.Grants.AddRange(append.Grants),
                    Revocations = state.Records.Revocations.AddRange(append.Revocations),
                    Activations = state.Records.Activations.AddRange(append.Activations),
                    Terms = state.Records.Terms.AddRange(append.Terms.Select(term => term.Fact)),
                    TermActions = state.Records.TermActions.AddRange(append.TermActions.Select(action => action.Fact)),
                    StatusFacts = state.Records.StatusFacts.AddRange(append.StatusFacts.Select(fact => fact.Fact)),
                };
                var replayed = ResolverVectors.Resolve(records, definitions.Current(), snapshot.ComputedAt);
                if (!replayed.SameAs(snapshot)) throw new InvalidOperationException("The vector recorder could not reproduce a committed snapshot from the loaded state.");
            }
        }

        return outcome;
    }

    public ValueTask<FeatureReleaseOutcome> AppendFeatureReleaseAsync(FeatureReleaseFact release, CancellationToken cancellationToken) =>
        inner.AppendFeatureReleaseAsync(release, cancellationToken);
}

/// <summary>
/// The service the harness returns: the real <see cref="EntitlementService"/> over recording ports, with the same five calls. It
/// converts implicitly to the service itself (the grant-port adapter takes the service), whose commits are recorded by the store
/// decorator all the same.
/// </summary>
internal sealed class EntitlementServiceFacade(EntitlementService inner, FixedDefinitions definitions)
{
    public EntitlementService Inner { get; } = inner;

    public static implicit operator EntitlementService(EntitlementServiceFacade facade) => facade.Inner;

    public async ValueTask<EntitlementResult<EntitlementSnapshot>> ReadAsync(string workspaceId, CancellationToken cancellationToken)
    {
        var call = ResolverVectors.BeginCall();
        var mark = Mark();
        var result = await Inner.ReadAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        Observe(Operation.Read, call, mark, null, result.Error, result.Detail, result.Value);
        return result;
    }

    public async ValueTask<EntitlementResult<EntitlementSnapshot>> RefreshAsync(string workspaceId, CancellationToken cancellationToken)
    {
        var call = ResolverVectors.BeginCall();
        var mark = Mark();
        var result = await Inner.RefreshAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        Observe(Operation.Refresh, call, mark, null, result.Error, result.Detail, result.Value);
        return result;
    }

    public async ValueTask<EntitlementResult<Grant>> IssueGrantAsync(IssueGrantRequest request, CancellationToken cancellationToken)
    {
        var call = ResolverVectors.BeginCall();
        ResolverVectors.Admit(request);
        var mark = Mark();
        var result = await Inner.IssueGrantAsync(request, cancellationToken).ConfigureAwait(false);
        Observe(Operation.Issue, call, mark, request, result.Error, result.Detail, null);
        return result;
    }

    public async ValueTask<EntitlementResult<Revocation>> RevokeGrantAsync(RevokeGrantRequest request, CancellationToken cancellationToken)
    {
        var call = ResolverVectors.BeginCall();
        var mark = Mark();
        var result = await Inner.RevokeGrantAsync(request, cancellationToken).ConfigureAwait(false);
        Observe(Operation.Revoke, call, mark, request, result.Error, result.Detail, null);
        return result;
    }

    public async ValueTask<RebuildReport> VerifyRebuildAsync(string workspaceId, CancellationToken cancellationToken)
    {
        var call = ResolverVectors.BeginCall();
        var mark = Mark();
        var report = await Inner.VerifyRebuildAsync(workspaceId, cancellationToken).ConfigureAwait(false);
        // The rebuild resolves the stored computation instant again from the loaded records and commits nothing: record the resolver
        // call it made, and check the derivation against the rebuilt snapshot the service reported.
        if (ResolverVectors.Active is { } row && report.Rebuilt is { } rebuilt && report.Stored is { } stored)
        {
            var load = row.Events.Skip(mark).OfType<LoadEvent>().LastOrDefault(e => e.Call == call);
            if (load is not null && !ResolverVectors.Resolve(load.State.Records, definitions.Current(), stored.ComputedAt).SameAs(rebuilt))
            {
                throw new InvalidOperationException("The vector recorder could not reproduce a rebuild.");
            }
        }

        return report;
    }

    private static int Mark() => ResolverVectors.Active?.Events.Count ?? 0;

    private enum Operation
    {
        Read,
        Refresh,
        Issue,
        Revoke,
    }

    /// <summary>
    /// Records the resolver calls of the outcomes that commit nothing, from the port traffic of the call. A call that committed is
    /// recorded exactly by the store decorator; a call that stopped before it resolved (a replay, a stale version, a read of a snapshot
    /// that is still valid) called no resolver and has nothing to record.
    /// </summary>
    private void Observe(Operation operation, long call, int mark, object? request, EntitlementError? error, string? detail, EntitlementSnapshot? value)
    {
        if (ResolverVectors.Active is not { } row) return;
        var events = row.Events.Skip(mark).Where(e => e.Call == call).ToList();
        if (events.OfType<CommitEvent>().Any(commit => commit.Outcome == CommitOutcome.Committed)) return;
        var attempts = Attempts(events, skipFirst: operation == Operation.Read);
        if (attempts.Count == 0) return;
        var (load, clock, id) = attempts[^1];
        var current = definitions.Current();
        var candidate = Candidate(operation, request, load.State, clock.Value, id?.Id, current, out var now);
        if (candidate is null) return;
        EntitlementSnapshot? derived = null;
        string? refusal = null;
        try
        {
            derived = ResolverVectors.Resolve(candidate.Value.Records, current, now);
        }
        catch (ResolverInputException exception)
        {
            refusal = exception.Message;
        }

        // The derivation must agree with what the service answered, or the run fails: a vector is never a guess.
        if (error == EntitlementError.InvalidHistory)
        {
            var below = derived is not null && load.State.Snapshot is { } stored && derived.Version < stored.Version;
            var agrees = refusal is not null ? refusal == detail : below && detail is not null && detail.Contains("fell below", StringComparison.Ordinal);
            if (!agrees) throw new InvalidOperationException("The vector recorder derived a different refusal than the service answered: " + (refusal ?? "none") + " / " + detail);
        }
        else if (error is null && (operation == Operation.Read || operation == Operation.Refresh))
        {
            if (derived is null || load.State.Snapshot is not { } storedSnapshot || value is null)
            {
                throw new InvalidOperationException("The vector recorder derived a refresh the service did not make.");
            }

            // An unchanged refresh returns the stored snapshot untouched.
            var unchanged = candidate.Value.Activations.IsEmpty && storedSnapshot.Version == derived.Version && storedSnapshot.Content.SameEffectAs(derived.Content)
                && storedSnapshot.ValidUntil == derived.ValidUntil;
            if (!unchanged) throw new InvalidOperationException("The vector recorder derived a refresh that would have been committed.");
        }
    }

    private static List<(LoadEvent Load, ClockEvent Clock, IdEvent? Id)> Attempts(List<PortEvent> events, bool skipFirst)
    {
        var attempts = new List<(LoadEvent, ClockEvent, IdEvent?)>();
        for (var i = 0; i < events.Count; i++)
        {
            if (events[i] is not LoadEvent load || i + 1 >= events.Count || events[i + 1] is not ClockEvent clock) continue;
            IdEvent? id = i + 2 < events.Count ? events[i + 2] as IdEvent : null;
            attempts.Add((load, clock, id));
        }

        if (skipFirst && attempts.Count > 0) attempts.RemoveAt(0);
        return attempts;
    }

    private readonly record struct Derived(EntitlementRecordSet Records, ImmutableArray<DefinitionsActivation> Activations);

    /// <summary>The record set the service resolves in one attempt, by the formulas of EntitlementService (kept private there).</summary>
    private static Derived? Candidate(Operation operation, object? request, EntitlementState state, UtcMicros clock, string? id, EntitlementDefinitions current, out UtcMicros now)
    {
        UtcMicros ReadNow() => state.Snapshot is { } stored ? UtcMicros.Max(clock, stored.ComputedAt) : clock;
        UtcMicros WriteNow() => state.Snapshot is { } stored ? UtcMicros.Max(clock, new UtcMicros(stored.ComputedAt.Value + 1)) : clock;
        Derived With(EntitlementRecordSet records, UtcMicros at)
        {
            if (!records.Activations.IsEmpty && RecordSetValidator.LastActivation(records).Version == current.Version) return new Derived(records, []);
            var added = new DefinitionsActivation(current.Version, at);
            return new Derived(records with { Activations = records.Activations.Add(added) }, [added]);
        }

        switch (operation)
        {
            case Operation.Read:
            case Operation.Refresh:
                var needsActivation = state.Records.Activations.IsEmpty || RecordSetValidator.LastActivation(state.Records).Version != current.Version;
                now = needsActivation ? WriteNow() : ReadNow();
                return With(state.Records, now);
            case Operation.Issue when request is IssueGrantRequest issue && id is not null:
                now = WriteNow();
                var grant = new Grant(id, issue.WorkspaceId, issue.Kind, issue.Subject, issue.Value, issue.Source, issue.SourceRef, issue.EffectiveFrom,
                    issue.EffectiveUntil, issue.IssuedByActor, now, issue.Reason);
                var withActivation = With(state.Records, now);
                return withActivation with { Records = withActivation.Records with { Grants = withActivation.Records.Grants.Add(grant) } };
            case Operation.Revoke when request is RevokeGrantRequest revoke && id is not null:
                now = WriteNow();
                var revocation = new Revocation(id, revoke.GrantId, revoke.ReasonCode, revoke.EffectiveFrom ?? now, revoke.IssuedByActor, now);
                var revoked = With(state.Records, now);
                return revoked with { Records = revoked.Records with { Revocations = revoked.Records.Revocations.Add(revocation) } };
        }

        now = default;
        return null;
    }
}

/// <summary>Writes the recorded corpus as the JSON the Go test reads. Names and shapes follow the C# records; every instant is whole microseconds.</summary>
internal static class VectorJson
{
    public static string Write(IReadOnlyList<(string Row, IReadOnlyList<object> Vectors)> rows, IReadOnlyDictionary<string, string> excluded)
    {
        var resolver = new List<(string Json, List<string> Rows)>();
        var admission = new List<(string Json, List<string> Rows)>();
        var resolverIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        var admissionIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        var perRow = new List<(string Row, int Resolver, int Admission)>();
        foreach (var (name, vectors) in rows)
        {
            var resolverCount = 0;
            var admissionCount = 0;
            foreach (var vector in vectors)
            {
                switch (vector)
                {
                    case ResolverVector resolverVector:
                        resolverCount++;
                        Add(resolver, resolverIndex, Serialize(w => WriteResolver(w, resolverVector)), name);
                        break;
                    case AdmissionVector admissionVector:
                        admissionCount++;
                        Add(admission, admissionIndex, Serialize(w => WriteAdmission(w, admissionVector)), name);
                        break;
                }
            }

            perRow.Add((name, resolverCount, admissionCount));
        }

        return Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("source", "tests/ArcForges.Cloud.Tests/Entitlement (ResolverVectorsTests); rewrite with ARCFORGES_UPDATE_RESOLVER_VECTORS=1 then prettier");
            writer.WriteStartArray("resolver");
            for (var i = 0; i < resolver.Count; i++) WriteIndexed(writer, "r", i, resolver[i]);
            writer.WriteEndArray();
            writer.WriteStartArray("admission");
            for (var i = 0; i < admission.Count; i++) WriteIndexed(writer, "a", i, admission[i]);
            writer.WriteEndArray();
            writer.WriteStartObject("rows");
            foreach (var (name, resolverCount, admissionCount) in perRow)
            {
                writer.WriteStartObject(name);
                writer.WriteNumber("resolver", resolverCount);
                writer.WriteNumber("admission", admissionCount);
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
            writer.WriteStartObject("excluded");
            foreach (var (name, reason) in excluded.OrderBy(pair => pair.Key, StringComparer.Ordinal)) writer.WriteString(name, reason);
            writer.WriteEndObject();
            writer.WriteEndObject();
        });
    }

    private static void Add(List<(string Json, List<string> Rows)> list, Dictionary<string, int> index, string json, string row)
    {
        if (!index.TryGetValue(json, out var at))
        {
            at = list.Count;
            index[json] = at;
            list.Add((json, []));
        }

        if (!list[at].Rows.Contains(row)) list[at].Rows.Add(row);
    }

    private static void WriteIndexed(Utf8JsonWriter writer, string prefix, int index, (string Json, List<string> Rows) item)
    {
        using var document = JsonDocument.Parse(item.Json);
        writer.WriteStartObject();
        writer.WriteString("id", prefix + (index + 1).ToString("D4", System.Globalization.CultureInfo.InvariantCulture));
        writer.WriteStartArray("rows");
        foreach (var row in item.Rows) writer.WriteStringValue(row);
        writer.WriteEndArray();
        foreach (var property in document.RootElement.EnumerateObject()) property.WriteTo(writer);
        writer.WriteEndObject();
    }

    private static string Serialize(Action<Utf8JsonWriter> write)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false, SkipValidation = false }))
        {
            write(writer);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteResolver(Utf8JsonWriter writer, ResolverVector vector)
    {
        writer.WriteStartObject();
        WriteDefinitions(writer, vector.Definitions);
        WriteRecords(writer, vector.Records);
        writer.WriteNumber("asOf", vector.AsOf.Value);
        writer.WriteStartObject("expect");
        if (vector.Result is { } snapshot)
        {
            writer.WriteNumber("version", snapshot.Version);
            writer.WriteNumber("computedAt", snapshot.ComputedAt.Value);
            Optional(writer, "validUntil", snapshot.ValidUntil);
            writer.WriteString("canonical", snapshot.Content.Canonical());
        }
        else
        {
            writer.WriteString("error", vector.Error);
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteAdmission(Utf8JsonWriter writer, AdmissionVector vector)
    {
        var request = vector.Request;
        writer.WriteStartObject();
        writer.WriteStartObject("request");
        writer.WriteString("workspaceId", request.WorkspaceId);
        Enum(writer, "kind", request.Kind);
        writer.WriteString("subject", request.Subject);
        Value(writer, request.Value);
        Enum(writer, "source", request.Source);
        Text(writer, "sourceRef", request.SourceRef);
        writer.WriteNumber("effectiveFrom", request.EffectiveFrom.Value);
        Optional(writer, "effectiveUntil", request.EffectiveUntil);
        writer.WriteString("issuedByActor", request.IssuedByActor);
        Text(writer, "reason", request.Reason);
        writer.WriteEndObject();
        if (vector.Refusal is null) writer.WriteNull("refusal");
        else writer.WriteString("refusal", vector.Refusal);
        writer.WriteEndObject();
    }

    private static void WriteDefinitions(Utf8JsonWriter writer, EntitlementDefinitions definitions)
    {
        writer.WriteStartObject("definitions");
        writer.WriteString("version", definitions.Version);
        writer.WriteBoolean("isSelfHostRealm", definitions.IsSelfHostRealm);
        writer.WriteStartArray("capabilities");
        foreach (var capability in definitions.Capabilities)
        {
            writer.WriteStartObject();
            writer.WriteString("key", capability.Key);
            writer.WriteBoolean("requiresPaidTerm", capability.RequiresPaidTerm);
            Text(writer, "featureGate", capability.FeatureGate);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("quotas");
        foreach (var quota in definitions.Quotas)
        {
            writer.WriteStartObject();
            writer.WriteString("key", quota.Key);
            Enum(writer, "combination", quota.Combination);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("allowances");
        foreach (var allowance in definitions.Allowances)
        {
            writer.WriteStartObject();
            writer.WriteString("key", allowance.Key);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteRecords(Utf8JsonWriter writer, EntitlementRecordSet records)
    {
        writer.WriteStartObject("records");
        writer.WriteString("workspaceId", records.WorkspaceId);
        writer.WriteStartArray("grants");
        foreach (var grant in records.Grants)
        {
            writer.WriteStartObject();
            writer.WriteString("grantId", grant.GrantId);
            writer.WriteString("workspaceId", grant.WorkspaceId);
            Enum(writer, "kind", grant.Kind);
            writer.WriteString("subject", grant.Subject);
            Value(writer, grant.Value);
            Enum(writer, "source", grant.Source);
            Text(writer, "sourceRef", grant.SourceRef);
            writer.WriteNumber("effectiveFrom", grant.EffectiveFrom.Value);
            Optional(writer, "effectiveUntil", grant.EffectiveUntil);
            writer.WriteString("issuedByActor", grant.IssuedByActor);
            writer.WriteNumber("createdAt", grant.CreatedAt.Value);
            Text(writer, "reason", grant.Reason);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("revocations");
        foreach (var revocation in records.Revocations)
        {
            writer.WriteStartObject();
            writer.WriteString("revocationId", revocation.RevocationId);
            writer.WriteString("grantId", revocation.GrantId);
            writer.WriteString("reasonCode", revocation.ReasonCode);
            writer.WriteNumber("effectiveFrom", revocation.EffectiveFrom.Value);
            writer.WriteString("issuedByActor", revocation.IssuedByActor);
            writer.WriteNumber("createdAt", revocation.CreatedAt.Value);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("terms");
        foreach (var term in records.Terms)
        {
            writer.WriteStartObject();
            writer.WriteString("termId", term.TermId);
            Enum(writer, "kind", term.Kind);
            writer.WriteNumber("startsAt", term.StartsAt.Value);
            writer.WriteNumber("endsAt", term.EndsAt.Value);
            Optional(writer, "graceEndsAt", term.GraceEndsAt);
            writer.WriteNumber("authorizedAt", term.AuthorizedAt.Value);
            writer.WriteNumber("createdAt", term.CreatedAt.Value);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("termActions");
        foreach (var action in records.TermActions)
        {
            writer.WriteStartObject();
            writer.WriteString("termId", action.TermId);
            Enum(writer, "kind", action.Kind);
            writer.WriteNumber("effectiveAt", action.EffectiveAt.Value);
            writer.WriteNumber("recordedAt", action.RecordedAt.Value);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("statusFacts");
        foreach (var fact in records.StatusFacts)
        {
            writer.WriteStartObject();
            writer.WriteNumber("recordedAt", fact.RecordedAt.Value);
            Enum(writer, "status", fact.Status);
            writer.WriteBoolean("autoRenew", fact.AutoRenew);
            writer.WriteBoolean("purchasePending", fact.PurchasePending);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("featureReleases");
        foreach (var release in records.FeatureReleases)
        {
            writer.WriteStartObject();
            writer.WriteString("feature", release.Feature);
            writer.WriteNumber("releasedAt", release.ReleasedAt.Value);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("activations");
        foreach (var activation in records.Activations)
        {
            writer.WriteStartObject();
            writer.WriteString("version", activation.Version);
            writer.WriteNumber("activatedAt", activation.ActivatedAt.Value);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void Value(Utf8JsonWriter writer, GrantValue? value)
    {
        if (value is null)
        {
            writer.WriteNull("value");
            return;
        }

        writer.WriteStartObject("value");
        switch (value)
        {
            case CapabilityValue:
                writer.WriteString("type", "Capability");
                break;
            case QuotaValue quota:
                writer.WriteString("type", "Quota");
                writer.WriteNumber("limit", quota.Limit);
                writer.WriteNumber("priority", quota.Priority);
                break;
            case AllowanceValue allowance:
                writer.WriteString("type", "Allowance");
                writer.WriteString("capacityPlanRef", allowance.CapacityPlanRef);
                writer.WriteNumber("priority", allowance.Priority);
                break;
            default:
                throw new InvalidOperationException("An unknown grant value type.");
        }

        writer.WriteEndObject();
    }

    /// <summary>An enum as its C# name, or as its number when the value is undefined (a test that checks the refusal of one).</summary>
    private static void Enum<T>(Utf8JsonWriter writer, string name, T value)
        where T : struct, System.Enum
    {
        if (System.Enum.IsDefined(value)) writer.WriteString(name, value.ToString());
        else writer.WriteNumber(name, Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture));
    }

    private static void Optional(Utf8JsonWriter writer, string name, UtcMicros? value)
    {
        if (value is { } micros) writer.WriteNumber(name, micros.Value);
        else writer.WriteNull(name);
    }

    private static void Text(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is null) writer.WriteNull(name);
        else writer.WriteString(name, value);
    }
}
