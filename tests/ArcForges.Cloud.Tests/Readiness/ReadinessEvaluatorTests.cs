// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Readiness;
using ArcForges.Cloud.Storage;
using Xunit;

namespace ArcForges.Cloud.Tests.Readiness;

/// <summary>
/// WP-21.07 (CLOUD.84 S39(1)): the readiness evaluation in C#, one-for-one with the cases of the retired TypeScript model and evaluation tests
/// (readiness-model.test.ts and readiness-evaluate.test.ts). Each case judges the whole report from raw observations and the host's D1 check;
/// the Worker-side cases (probes, classification of an unreachable Container, the bounded waits, the strict reading of a reply) stay in
/// tests/worker/readiness-transport.test.ts.
/// </summary>
public sealed class ReadinessEvaluatorTests
{
    private const string Revision = "0123456789abcdef0123456789abcdef01234567";
    private const string OtherManifest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static readonly ReadinessComponent Ready = ReadinessComponent.Ready(ReadinessEvidence.Probed);

    /// <summary>The observations of a proof Worker whose every declared binding is met and whose probes answered.</summary>
    private static ReadinessObservations Complete(string environment = ReadinessVocabulary.Proof, string manifest = PlanManifest.Hash) => new(
        environment,
        Revision,
        manifest,
        ReadinessVocabulary.Bindings.ToDictionary(binding => binding.Name, _ => true),
        new ReadinessProbe("ready", 3),
        new ReadinessProbe("ready", 3));

    /// <summary>A production Worker: only its declared bindings are met, and the proof-only bindings are absent.</summary>
    private static ReadinessObservations Production() => new(
        ReadinessVocabulary.Production,
        Revision,
        PlanManifest.Hash,
        ReadinessVocabulary.Bindings.ToDictionary(binding => binding.Name, binding => binding.Environments.Contains(ReadinessVocabulary.Production)));

    private static ReadinessReport Evaluate(ReadinessObservations observations, ReadinessComponent? d1 = null) =>
        ReadinessEvaluator.Evaluate(observations, d1 ?? Ready, PlanManifest.Hash, "1", HostRevision.Current);

    private static ReadinessComponent Component(ReadinessReport report, string id) => id switch
    {
        "ingress" => report.Components.Ingress,
        "container" => report.Components.Container,
        "d1" => report.Components.D1,
        "durableObject" => report.Components.DurableObject,
        "r2" => report.Components.R2,
        "queue" => report.Components.Queue,
        _ => throw new ArgumentOutOfRangeException(nameof(id), id, "Not a component of the report."),
    };

    private static IEnumerable<string> Others(string component) => ReadinessVocabulary.Components.Where(id => id != component);

    [Fact]
    public void AHealthyCompleteProofEnvironmentIsReadyAndEveryComponentIsReadySeparately()
    {
        var report = Evaluate(Complete());
        Assert.Equal("ready", report.Status);
        Assert.True(report.Ready);
        Assert.Equal("proof", report.Environment);
        Assert.Equal(ReadinessVocabulary.Schema, report.Schema);
        foreach (var id in ReadinessVocabulary.Components)
            Assert.Equal(ReadinessStates.Ready, Component(report, id).State);
        // A Queue binding is checked for shape only, so its evidence is bound and it says nothing about delivery.
        Assert.Equal(ReadinessEvidence.Bound, report.Components.Queue.Evidence);
        Assert.Equal(ReadinessEvidence.Probed, report.Components.Container.Evidence);
        Assert.Equal(PlanManifest.Hash, report.Host?.ManifestHash);
        Assert.Equal("1", report.Host?.SchemaVersion);
        Assert.Equal(HostRevision.Current, report.Host?.Revision);
    }

    [Fact]
    public void TheProductionEnvironmentRequiresOnlyTheIngressAndTheContainer()
    {
        var report = Evaluate(Production());
        Assert.Equal("production", report.Environment);
        Assert.Equal("ready", report.Status);
        Assert.Equal(["ingress", "container"], ReadinessVocabulary.Components.Where(id => Component(report, id).State != ReadinessStates.NotRequired));
        foreach (var id in new[] { "d1", "durableObject", "r2", "queue" })
            Assert.Equal(ReadinessStates.NotRequired, Component(report, id).State);
    }

    [Theory]
    [InlineData("SOURCE_REVISION", "ingress", "binding_missing")]
    [InlineData("HELLO_RATE_LIMITER", "ingress", "binding_missing")]
    [InlineData("ALLOWED_ORIGIN", "ingress", "binding_missing")]
    [InlineData("DB", "d1", "binding_missing")]
    [InlineData("RECOVERY_GENERATION", "d1", "binding_missing")]
    [InlineData("HMAC_C2W_KEY", "d1", "key_missing")]
    [InlineData("JOB_COORDINATOR", "durableObject", "binding_missing")]
    [InlineData("OBJECTS", "r2", "binding_missing")]
    [InlineData("REALM_ID", "r2", "binding_missing")]
    [InlineData("WAKE_QUEUE", "queue", "binding_missing")]
    [InlineData("CLOUD_CONTAINER", "container", "binding_missing")]
    [InlineData("CSRF_SECRET", "container", "key_missing")]
    [InlineData("HMAC_W2C_KEY", "container", "key_missing")]
    public void AMissingBindingFailsReadinessInItsComponentAndNothingElse(string name, string component, string reason)
    {
        var bindings = ReadinessVocabulary.Bindings.ToDictionary(binding => binding.Name, _ => true);
        bindings[name] = false;
        var observations = Complete() with
        {
            Bindings = bindings,
            DurableObject = component == "durableObject" ? null : new ReadinessProbe("ready", 3),
            R2 = component == "r2" ? null : new ReadinessProbe("ready", 3),
        };
        var report = Evaluate(observations, ReadinessComponent.Ready(ReadinessEvidence.Probed));
        Assert.False(report.Ready);
        Assert.Equal(ReadinessStates.Misconfigured, report.Status);
        var judged = Component(report, component);
        Assert.Equal(ReadinessStates.Misconfigured, judged.State);
        Assert.Equal(reason, judged.Reason);
        Assert.Equal(new[] { name }, judged.Missing);
        foreach (var other in Others(component))
            Assert.NotEqual(ReadinessStates.Misconfigured, Component(report, other).State);
    }

    [Fact]
    public void APlanManifestMismatchIsMisconfiguredEvenWhenTheHostSaysReady()
    {
        var report = Evaluate(Complete(manifest: OtherManifest));
        Assert.Equal(new ReadinessComponent(ReadinessStates.Misconfigured, ReadinessReasons.PlanHashMismatch, ReadinessEvidence.Probed), report.Components.D1);
        Assert.Equal(ReadinessStates.Ready, report.Components.Container.State);
        Assert.Equal(ReadinessStates.Misconfigured, report.Status);
        Assert.False(report.Ready);
    }

    [Theory]
    [InlineData("misconfigured", "plan_hash_mismatch", "misconfigured")]
    [InlineData("misconfigured", "recovery_generation_mismatch", "misconfigured")]
    [InlineData("misconfigured", "key_mismatch", "misconfigured")]
    [InlineData("misconfigured", "schema_mismatch", "misconfigured")]
    [InlineData("unavailable", "d1_unavailable", "unavailable")]
    public void AHostDetectedD1ProblemIsPassedThroughAsMisconfiguredOrAnOutage(string state, string reason, string status)
    {
        var report = Evaluate(Complete(), new ReadinessComponent(state, reason, ReadinessEvidence.Probed));
        Assert.Equal(state, report.Components.D1.State);
        Assert.Equal(reason, report.Components.D1.Reason);
        Assert.Equal(status, report.Status);
        Assert.False(report.Ready);
    }

    [Theory]
    [InlineData("ready", null, null, 3)]
    [InlineData("no_answer_in_wait", ReadinessReasons.NoAnswerInWait, ReadinessStates.Unavailable, 8000)]
    [InlineData("unreachable", ReadinessReasons.Unreachable, ReadinessStates.Unavailable, 12)]
    public void TheDurableObjectAndR2OutcomesAreTheirOwnComponentsWithTheirEvidence(string outcome, string? reason, string? state, int elapsed)
    {
        var observations = Complete() with
        {
            DurableObject = new ReadinessProbe(outcome, elapsed),
            R2 = new ReadinessProbe(outcome, elapsed),
        };
        var report = Evaluate(observations);
        foreach (var component in new[] { report.Components.DurableObject, report.Components.R2 })
        {
            Assert.Equal(state ?? ReadinessStates.Ready, component.State);
            Assert.Equal(reason, component.Reason);
            Assert.Equal(ReadinessEvidence.Probed, component.Evidence);
            Assert.Equal(elapsed, component.ElapsedMs);
        }

        Assert.Equal(state is null ? ReadinessStates.Ready : ReadinessStates.Unavailable, report.Status);
    }

    [Fact]
    public void EveryCombinationOfComponentStatesIsReadyOnlyWhenEachIsReadyOrNotRequired()
    {
        var states = ReadinessVocabulary.States;
        var combinations = 0;
        var indices = new int[ReadinessVocabulary.Components.Length];
        while (true)
        {
            var components = indices.Select(index => new ReadinessComponent(states[index])).ToList();
            var expected = components.All(component => component.State is ReadinessStates.Ready or ReadinessStates.NotRequired);
            Assert.Equal(expected, ReadinessEvaluator.Summarize(components) == ReadinessStates.Ready);
            combinations++;
            var position = indices.Length - 1;
            while (position >= 0 && ++indices[position] == states.Length)
            {
                indices[position] = 0;
                position--;
            }

            if (position < 0) break;
        }

        // Eight states per component would be 6^6 = 46656 combinations: every one is judged.
        Assert.Equal(46656, combinations);
    }

    [Fact]
    public void TheStatusFollowsAFixedOrderMisconfiguredUnavailableStartingThenAnUndeterminedComponent()
    {
        static ReadinessComponent[] Only(IReadOnlyDictionary<string, string> changes) =>
            ReadinessVocabulary.Components.Select(id => new ReadinessComponent(changes.TryGetValue(id, out var state) ? state : ReadinessStates.Ready)).ToArray();

        Assert.Equal(ReadinessStates.Ready, ReadinessEvaluator.Summarize(Only(new Dictionary<string, string>())));
        Assert.Equal(ReadinessStates.Misconfigured, ReadinessEvaluator.Summarize(Only(new Dictionary<string, string> { ["queue"] = ReadinessStates.Misconfigured, ["d1"] = ReadinessStates.Unavailable })));
        Assert.Equal(ReadinessStates.Unavailable, ReadinessEvaluator.Summarize(Only(new Dictionary<string, string> { ["container"] = ReadinessStates.Starting, ["r2"] = ReadinessStates.Unavailable })));
        Assert.Equal(ReadinessStates.Starting, ReadinessEvaluator.Summarize(Only(new Dictionary<string, string> { ["container"] = ReadinessStates.Starting, ["d1"] = ReadinessStates.Unknown })));
        Assert.Equal(ReadinessStates.Unavailable, ReadinessEvaluator.Summarize(Only(new Dictionary<string, string> { ["d1"] = ReadinessStates.Unknown })));
        Assert.Equal(ReadinessStates.Ready, ReadinessEvaluator.Summarize(Only(new Dictionary<string, string> { ["d1"] = ReadinessStates.NotRequired, ["r2"] = ReadinessStates.NotRequired })));
    }

    [Fact]
    public void OnlyARetryableStatusIsWorthRetrying()
    {
        var statuses = ReadinessVocabulary.Statuses.Select(ReadinessEvaluator.IsTransient).ToArray();
        Assert.Equal([false, true, true, false], statuses);
    }

    [Fact]
    public void AMalformedObservationIsRefusedAndNeverEvaluated()
    {
        var unknownEnvironment = Complete(environment: "staging");
        var longRevision = Complete() with { WorkerRevision = new string('r', 81) };
        var upperHash = Complete() with { ManifestHash = PlanManifest.Hash.ToUpperInvariant() };
        var shortHash = Complete() with { ManifestHash = "abc" };
        var missingName = Complete() with { Bindings = ReadinessVocabulary.Bindings.Skip(1).ToDictionary(binding => binding.Name, _ => true) };
        var extraName = Complete() with
        {
            Bindings = ReadinessVocabulary.Bindings.Concat(new[] { new ReadinessBinding("ingress", "SURPRISE", ["proof"]) }).ToDictionary(binding => binding.Name, _ => true),
        };
        var madeUpOutcome = Complete() with { DurableObject = new ReadinessProbe("made_up", 1) };
        var negativeElapsed = Complete() with { R2 = new ReadinessProbe("ready", -1) };
        var absentProbe = Complete() with { DurableObject = null };
        var absentR2 = Complete() with { R2 = null };
        foreach (var observations in new[] { unknownEnvironment, longRevision, upperHash, shortHash, missingName, extraName, madeUpOutcome, negativeElapsed, absentProbe, absentR2 })
        {
            Assert.False(ReadinessEvaluator.IsWellFormed(observations));
            Assert.Throws<ArgumentException>(() => Evaluate(observations));
        }

        // A production Worker has no probes of its proof components, so their absence is correct there.
        Assert.True(ReadinessEvaluator.IsWellFormed(Production()));
        Assert.True(ReadinessEvaluator.IsWellFormed(Complete()));
    }
}
