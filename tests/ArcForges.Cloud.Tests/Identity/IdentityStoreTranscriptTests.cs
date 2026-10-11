// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Workspace;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// The transcript of the identity store's plan calls (CLOUD.72), the input of the opt-in workerd run (eng/verification/d1-identity-local.ts,
/// transcript mode). The identity service and its production D1 store, composed as the Identity and Workspace modules register
/// themselves, run fixed scenarios on the real plan and family ports over the production Worker plan code on SQLite (the COM.16 bridge);
/// every call that reaches the executor is recorded exactly as C# built it (plan, version, owner scope, recovery generation, typed
/// arguments) with the bridge's answer (status, changes, rows) and the row counts of the identity, workspace and platform tables after
/// it. Concurrent groups record each contender's write and the multiset of their answers, because which contender wins is not fixed;
/// the receipt reads of the losers follow from that and are recorded by the sequential scenarios instead.
/// <para>
/// Identifiers, command identifiers and the clock are deterministic, so the transcript is too: the test fails when the recorded calls or
/// answers differ from tests/ArcForges.Cloud.Tests/Identity/Vectors/identity-store-transcript.json, and rewrites the file (formatted by the
/// repository's prettier) when IDENTITY_TRANSCRIPT_UPDATE=1. The workerd run executes the same calls on workerd's D1 and compares
/// statuses, rows and counts generically; it adds no business assertion of its own. SQLite is not D1, and neither run is a Cloudflare
/// result.
/// </para>
/// </summary>
public sealed class IdentityStoreTranscriptTests : IDisposable
{
    private const string UpdateVariable = "IDENTITY_TRANSCRIPT_UPDATE";
    private const ulong ActiveGeneration = 1;
    private const int Contenders = 25;

    private static readonly RealmId RealmA = IdentityHarness.RealmA;
    private static readonly RealmId RealmB = IdentityHarness.RealmB;
    private static readonly DateTimeOffset Start = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    /// <summary>The tables whose row counts follow every step (validated by the workerd run as plain identifiers).</summary>
    private static readonly string[] Tables =
    [
        "identity_user", "identity_auth_identity", "identity_recovery_code", "workspace_workspace", "platform_command", "platform_outbox", "platform_change_archive",
        "platform_command_guard",
    ];

    private readonly SqliteBridgeExecutor bridge = new(recoveryGeneration: ActiveGeneration);
    private readonly FakeTime time = new(Start);
    private readonly TranscriptIds ids = new();
    private readonly List<ServiceProvider> providers = [];
    private int commands;

    public IdentityStoreTranscriptTests() => recorder = new RecordingExecutor(bridge, Tables);

    private readonly RecordingExecutor recorder;

    public void Dispose()
    {
        foreach (var provider in providers) provider.Dispose();
        bridge.Dispose();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string TranscriptPath() =>
        Path.Combine(T.RepoRoot().FullName, "tests", "ArcForges.Cloud.Tests", "Identity", "Vectors", "identity-store-transcript.json");

    [Fact]
    public async Task TheStoresRecordedPlanCallsAndAnswersEqualTheCommittedTranscript()
    {
        var transcript = await RecordAsync();
        var path = TranscriptPath();

        if (Environment.GetEnvironmentVariable(UpdateVariable) == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, transcript.ToJsonString(new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }) + "\n", new UTF8Encoding(false), Ct);
            Format(path); // compact JSON first, so prettier keeps each typed value on one line
        }

        Assert.True(File.Exists(path), "The transcript is missing; regenerate it with " + UpdateVariable + "=1.");
        var committed = JsonNode.Parse(await File.ReadAllTextAsync(path, Ct));
        Assert.True(JsonNode.DeepEquals(committed, transcript), Difference(committed, transcript));
    }

    [Fact]
    public async Task TheTranscriptCoversEveryIdentityPlanTheGuardsTheGroupsAndAStaleGeneration()
    {
        var transcript = await RecordAsync();
        var steps = transcript["steps"]!.AsArray();
        var calls = steps.SelectMany(step => step!["call"] is { } call ? [call] : step!["group"]!.AsArray().Select(item => item!)).ToList();
        var plans = calls.Select(call => call["plan"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        string[] expected =
        [
            PlanManifest.Families.AccountEnrollmentCreateUser.Id, PlanManifest.Identity.CredentialAdd.Id, PlanManifest.Identity.CredentialRevoke.Id,
            PlanManifest.Identity.CredentialRelabel.Id, PlanManifest.Identity.UserRename.Id, PlanManifest.Identity.UserLoad.Id, PlanManifest.Identity.CredentialGet.Id,
            PlanManifest.Identity.CredentialRows.Id, PlanManifest.Identity.RecoveryActive.Id, PlanManifest.Workspace.WorkspaceGet.Id,
            PlanManifest.Workspace.WorkspaceByOwner.Id, PlanManifest.Platform.CommandLoad.Id,
        ];
        Assert.All(expected, id => Assert.Contains(id, plans));

        var statuses = steps.Where(step => step!["expect"] is not null).Select(step => step!["expect"]!["status"]!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        Assert.Superset(new HashSet<string>(["ok", "precondition", "constraint", "staleGeneration"], StringComparer.Ordinal), statuses);
        Assert.Contains(calls, call => call["recoveryGeneration"]!.GetValue<string>() != ActiveGeneration.ToString(CultureInfo.InvariantCulture));

        // Every concurrent group committed exactly one contender and refused the others whole as a precondition.
        var groups = steps.Where(step => step!["group"] is not null).ToList();
        Assert.Equal(3, groups.Count);
        foreach (var group in groups)
        {
            var outcomes = group!["outcomes"]!.AsArray().Select(outcome => outcome!["status"]!.GetValue<string>()).ToList();
            Assert.Single(outcomes, status => status == "ok");
            Assert.All(outcomes.Where(status => status != "ok"), status => Assert.Equal("precondition", status));
        }

        Assert.All(steps, step => Assert.Equal(Tables.Length, step!["counts"]!.AsArray().Count));
        Assert.Equal(0, steps[^1]!["counts"]![Array.IndexOf(Tables, "platform_command_guard")]!.GetValue<long>());

        // The equality check is not vacuous: one changed answer is a difference, and the message names its step.
        var tampered = transcript.DeepClone();
        var refusal = tampered["steps"]!.AsArray().Select((step, index) => (step, index)).First(item => item.step!["expect"]?["status"]?.GetValue<string>() == "precondition");
        refusal.step!["expect"]!["status"] = "ok";
        Assert.False(JsonNode.DeepEquals(tampered, transcript));
        Assert.StartsWith($"The transcript differs at step {refusal.index}:", Difference(tampered, transcript), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // The scenarios
    // ------------------------------------------------------------------------------------------------------------------------

    private async Task<JsonObject> RecordAsync()
    {
        var (service, store) = Compose(recorder);

        recorder.Scenario = "an-enrollment-commits-and-every-read-is-realm-scoped";
        var ada = await EnrollAsync(service, "ada@example.test", RealmA);
        foreach (var realm in new[] { RealmA, RealmB })
        {
            await store.FindUserAsync(realm, ada.User.Id, Ct);
            await store.FindCredentialAsync(realm, "official-email", "ada@example.test", Ct);
            await store.ListCredentialsAsync(realm, ada.User.Id, Ct);
            await store.FindWorkspaceAsync(realm, ada.Workspace.Id, Ct);
            await store.FindWorkspaceByOwnerAsync(realm, ada.User.Id, Ct);
            await store.HasActiveRecoveryPathAsync(realm, ada.User.Id, Ct);
        }

        recorder.Scenario = "a-second-enrollment-of-the-credential-signs-in-and-writes-nothing";
        Assert.False((await EnrollAsync(service, "ada@example.test", RealmA)).CreatedUser);

        recorder.Scenario = "the-same-subject-in-another-realm-enrolls-separately";
        var adaB = await EnrollAsync(service, "ada@example.test", RealmB);
        Assert.NotEqual(ada.User.Id, adaB.User.Id);

        recorder.Scenario = "credential-lifecycle-commits-with-revisions-and-the-last-credential-is-refused";
        var caller = IdentityHarness.Caller(ada);
        var passkey = Value(await service.AddCredentialAsync(caller, Command(), IdentityHarness.Passkey("passkey-subject"), Ct));
        Value(await service.RelabelCredentialAsync(caller, Command(), passkey.Id, "Laptop", Ct));
        Value(await service.RenameUserAsync(caller, Command(), "Ada L.", Ct));
        Value(await service.RevokeCredentialAsync(caller, Command(), ada.Credential.Id, Ct));
        Assert.Equal(IdentityError.LastCredential, (await service.RevokeCredentialAsync(caller, Command(), passkey.Id, Ct)).Error);

        recorder.Scenario = "stale-guards-are-refused-whole";
        var grace = await EnrollAsync(service, "grace@example.test", RealmA);
        var graceCaller = IdentityHarness.Caller(grace);
        IdentityCommit[] stale =
        [
            new IdentityCommit.RenameUser(Command(), grace.Workspace.Id, graceCaller, 0, "Stale"),
            new IdentityCommit.RelabelCredential(Command(), grace.Workspace.Id, graceCaller, grace.Credential.Id, 9, "Stale"),
            new IdentityCommit.RevokeCredential(Command(), grace.Workspace.Id, graceCaller, grace.Credential.Id, 1, 1, new UtcMicros(5)),
            new IdentityCommit.AddCredential(Command(), grace.Workspace.Id, graceCaller, 7, grace.Credential with { Id = AuthIdentityId.Parse(ids.NewId()), Subject = "x@example.test" }),
            new IdentityCommit.Enroll(Command(), grace.User, grace.Credential, grace.Workspace),
        ];
        foreach (var commit in stale) Assert.Equal(CommitOutcome.Refused, await store.CommitAsync(commit, Ct));

        recorder.Scenario = "a-reused-command-identifier-is-a-conflict-and-writes-nothing";
        var reusedCommand = Command();
        var hopper = Value(await service.CompleteEnrollmentAsync(Request("hopper@example.test", RealmA, reusedCommand), Ct));
        Assert.Equal(IdentityError.IdentifierConflict, (await service.CompleteEnrollmentAsync(Request("other@example.test", RealmA, reusedCommand), Ct)).Error);
        Assert.Equal(IdentityError.IdentifierConflict, (await service.RenameUserAsync(IdentityHarness.Caller(hopper), reusedCommand, "Hopper G.", Ct)).Error);

        recorder.Scenario = "a-lost-response-is-resent-identically-and-replays-from-its-receipt";
        var (lostResponse, _) = Compose(new LossyExecutor(recorder, PlanManifest.Identity.UserRename.Id, executeFirst: true, loseReconciliation: true));
        Value(await lostResponse.RenameUserAsync(IdentityHarness.Caller(hopper), Command(), "Grace H.", Ct));

        recorder.Scenario = "a-lost-request-is-resent-identically-and-commits-once";
        var (lostRequest, _) = Compose(new LossyExecutor(recorder, PlanManifest.Families.AccountEnrollmentCreateUser.Id, executeFirst: false, loseReconciliation: false));
        Assert.True((await EnrollAsync(lostRequest, "lovelace@example.test", RealmA)).CreatedUser);

        recorder.Scenario = "a-receipt-past-its-window-is-an-expired-refusal-and-nothing-runs-again";
        var (expiring, _) = Compose(new LossyExecutor(recorder, PlanManifest.Identity.UserRename.Id, executeFirst: true, loseReconciliation: true, onLoss: () => time.Advance(TimeSpan.FromDays(7))));
        Assert.Equal(IdentityError.ReceiptExpired, (await expiring.RenameUserAsync(graceCaller, Command(), "Grace B.", Ct)).Error);

        recorder.Scenario = "an-enrollment-meeting-its-own-command-probes-the-receipt-and-signs-in";
        var probeRequest = Request("babbage@example.test", RealmA, Command());
        EnrollmentOutcome? original = null;
        var hooked = new HookedStore(store, async () => original = Value(await service.CompleteEnrollmentAsync(probeRequest, Ct)));
        var racing = new IdentityService(hooked, ids, time);
        var probed = Value(await racing.CompleteEnrollmentAsync(probeRequest, Ct));
        Assert.False(probed.CreatedUser);
        Assert.Equal(original!.User, probed.User);

        recorder.Scenario = "colliding-random-identifiers-are-refused-whole-and-retried-fresh";
        ids.Script(ada.User.Id.Value);
        Assert.NotEqual(ada.User.Id, (await EnrollAsync(service, "collide-user@example.test", RealmA)).User.Id);
        ids.Script(adaB.User.Id.Value);
        Assert.NotEqual(adaB.User.Id, (await EnrollAsync(service, "collide-realm@example.test", RealmA)).User.Id);
        ids.Script(passkey.Id.Value);
        Assert.NotEqual(passkey.Id, Value(await service.AddCredentialAsync(caller, Command(), IdentityHarness.Email("second@example.test"), Ct)).Id);

        recorder.Scenario = "a-stale-recovery-generation-is-refused-before-anything-runs";
        var (staleService, staleStore) = Compose(recorder, generation: ActiveGeneration + 1);
        Assert.Equal(IdentityStoreFailure.Unavailable, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await staleStore.FindUserAsync(RealmA, ada.User.Id, Ct))).Failure);
        Assert.Equal(IdentityStoreFailure.Unavailable, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await staleService.CompleteEnrollmentAsync(Request("stale@example.test", RealmA, Command()), Ct))).Failure);

        await ConcurrentAsync("concurrent-enrollments-of-one-credential-commit-once", store, Enumerable.Range(0, Contenders).Select(_ => NewEnrollment("contended@example.test")).ToArray());

        recorder.Scenario = "setup-two-users-for-the-concurrent-links";
        var linkA = await EnrollAsync(service, "link-a@example.test", RealmA);
        var linkB = await EnrollAsync(service, "link-b@example.test", RealmA);
        await ConcurrentAsync("concurrent-links-of-one-credential-to-two-users-commit-once", store,
        [
            NewLink(linkA, "shared-subject"),
            NewLink(linkB, "shared-subject"),
        ]);

        recorder.Scenario = "setup-a-user-with-two-credentials-for-the-concurrent-revocations";
        var revoking = await EnrollAsync(service, "revoke@example.test", RealmA);
        var second = Value(await service.AddCredentialAsync(IdentityHarness.Caller(revoking), Command(), IdentityHarness.Email("revoke-second@example.test"), Ct));
        var at = UtcMicros.FromDateTimeOffset(time.GetUtcNow());
        await ConcurrentAsync("concurrent-revocations-never-leave-a-user-without-a-credential", store,
        [
            new IdentityCommit.RevokeCredential(Command(), revoking.Workspace.Id, IdentityHarness.Caller(revoking), revoking.Credential.Id, 1, 2, at),
            new IdentityCommit.RevokeCredential(Command(), revoking.Workspace.Id, IdentityHarness.Caller(revoking), second.Id, 1, 2, at),
        ]);

        return new JsonObject
        {
            ["schemaVersion"] = 1,
            ["note"] = "Generated by tests/ArcForges.Cloud.Tests/Identity/IdentityStoreTranscriptTests.cs (" + UpdateVariable + "=1): the identity store's plan calls as C# built them and the "
                + "answers of the production Worker plan code on SQLite. Executed on workerd's D1 by eng/verification/d1-identity-local.ts (opt-in, never CI); not a Cloudflare result.",
            ["recoveryGeneration"] = ActiveGeneration.ToString(CultureInfo.InvariantCulture),
            ["tables"] = new JsonArray([.. Tables.Select(table => (JsonNode)JsonValue.Create(table))]),
            ["steps"] = recorder.Steps.DeepClone(),
        };
    }

    /// <summary>Starts every commit in order (each computes its context before its first await) and records the group once all are done.</summary>
    private async Task ConcurrentAsync(string scenario, IIdentityStore store, IdentityCommit[] commits)
    {
        recorder.Scenario = scenario;
        recorder.BeginGroup();
        var outcomes = await Task.WhenAll(commits.Select(commit => store.CommitAsync(commit, Ct).AsTask()).ToArray());
        await recorder.EndGroupAsync(Ct);
        Assert.Single(outcomes, outcome => outcome == CommitOutcome.Committed);
        Assert.All(outcomes.Where(outcome => outcome != CommitOutcome.Committed), outcome => Assert.Equal(CommitOutcome.Refused, outcome));
    }

    private IdentityCommit.Enroll NewEnrollment(string subject)
    {
        var now = UtcMicros.FromDateTimeOffset(time.GetUtcNow());
        var user = new User(UserId.Parse(ids.NewId()), RealmA, "Contender", UserState.Active, now, null, 1);
        var credential = new AuthIdentity(AuthIdentityId.Parse(ids.NewId()), user.Id, RealmA, "official-email", AuthMethod.EmailCode, subject, null, null, null, now, null, null, 1);
        return new IdentityCommit.Enroll(Command(), user, credential, IdentityRules.NewPersonalWorkspace(WorkspaceId.Parse(ids.NewId()), user));
    }

    private IdentityCommit.AddCredential NewLink(EnrollmentOutcome account, string subject)
    {
        var now = UtcMicros.FromDateTimeOffset(time.GetUtcNow());
        var credential = new AuthIdentity(AuthIdentityId.Parse(ids.NewId()), account.User.Id, account.User.Realm, "official-email", AuthMethod.EmailCode, subject, null, null, null, now, null, null, 1);
        return new IdentityCommit.AddCredential(Command(), account.Workspace.Id, IdentityHarness.Caller(account), account.User.Revision, credential);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Composition and helpers
    // ------------------------------------------------------------------------------------------------------------------------

    private (IdentityService Service, IIdentityStore Store) Compose(IPlanExecutor executor, ulong generation = ActiveGeneration)
    {
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(time);
        services.AddSingleton<IModulePlanPortFactory>(new ModulePlanPortFactory(executor, generation, time));
        services.AddSingleton<IModuleFamilyPortFactory>(new ModuleFamilyPortFactory(executor, generation, time));
        services.AddSingleton<IIdentityIdSource>(ids);
        ((IModuleBoundary)WorkspaceModule.Instance).Register(services);
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        var provider = services.BuildServiceProvider();
        providers.Add(provider);
        return (provider.GetRequiredService<IdentityService>(), provider.GetRequiredService<IIdentityStore>());
    }

    /// <summary>Command identifiers are canonical and distinct from the record identifiers (another prefix).</summary>
    private string Command() => $"10000000-0000-4000-8000-{Interlocked.Increment(ref commands):x12}";

    private EnrollmentRequest Request(string subject, RealmId realm, string command) => new(realm, command, "Ada", IdentityHarness.Email(subject));

    private async Task<EnrollmentOutcome> EnrollAsync(IdentityService service, string subject, RealmId realm) =>
        Value(await service.CompleteEnrollmentAsync(Request(subject, realm, Command()), Ct));

    private static TValue Value<TValue>(IdentityResult<TValue> result)
    {
        Assert.True(result.IsSuccess, "the identity call failed: " + result.Error);
        return result.Value!;
    }

    /// <summary>Formats the regenerated file with the repository's pinned prettier, as `npm run format` would.</summary>
    private static void Format(string path)
    {
        var root = T.RepoRoot().FullName;
        var prettier = Path.Combine(root, "node_modules", "prettier", "bin", "prettier.cjs");
        Assert.True(File.Exists(prettier), "Install the Node dependencies (npm ci) before regenerating the transcript.");
        var info = new ProcessStartInfo("node") { WorkingDirectory = root, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add(prettier);
        info.ArgumentList.Add("--write");
        info.ArgumentList.Add(Path.GetRelativePath(root, path));
        using var process = Process.Start(info)!;
        process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }

    /// <summary>Names the first step that differs, so a reviewer sees what changed before regenerating.</summary>
    private static string Difference(JsonNode? committed, JsonNode recorded)
    {
        var left = committed?["steps"]?.AsArray() ?? [];
        var right = recorded["steps"]!.AsArray();
        for (var index = 0; index < Math.Max(left.Count, right.Count); index++)
        {
            var a = index < left.Count ? left[index] : null;
            var b = index < right.Count ? right[index] : null;
            if (!JsonNode.DeepEquals(a, b))
                return $"The transcript differs at step {index}: committed {a?.ToJsonString() ?? "(none)"}, recorded {b?.ToJsonString() ?? "(none)"}. Regenerate with {UpdateVariable}=1 only after a reviewed change.";
        }

        return $"The transcript header differs. Regenerate with {UpdateVariable}=1 only after a reviewed change.";
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // The recorder and the external-failure doubles
    // ------------------------------------------------------------------------------------------------------------------------

    /// <summary>Records every call that reaches the bridge with its answer and, outside a group, the table counts after it.</summary>
    private sealed class RecordingExecutor(SqliteBridgeExecutor inner, string[] tables) : IPlanExecutor
    {
        private readonly Lock gate = new();
        private List<JsonObject>? group;

        public string Scenario { get; set; } = "";

        public JsonArray Steps { get; } = [];

        public void BeginGroup() => group = [];

        public async Task EndGroupAsync(CancellationToken cancellationToken)
        {
            var members = group!;
            group = null;
            var calls = members.Select(member => member["call"]!.DeepClone()).OrderBy(call => call.ToJsonString(), StringComparer.Ordinal);
            var outcomes = members.Select(member => member["outcome"]!.DeepClone()).OrderBy(outcome => outcome.ToJsonString(), StringComparer.Ordinal);
            Steps.Add(new JsonObject
            {
                ["scenario"] = Scenario,
                ["group"] = new JsonArray([.. calls]),
                ["outcomes"] = new JsonArray([.. outcomes]),
                ["counts"] = await CountsAsync(cancellationToken).ConfigureAwait(false),
            });
        }

        public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
        {
            try
            {
                var result = await inner.ExecuteAsync(call, cancellationToken).ConfigureAwait(false);
                await RecordAsync(call, Success(result), cancellationToken).ConfigureAwait(false);
                return result;
            }
            catch (PlanFailureException failure)
            {
                await RecordAsync(call, new JsonObject { ["status"] = WireName(failure.Kind) }, cancellationToken).ConfigureAwait(false);
                throw;
            }
        }

        private async Task RecordAsync(PlanCall call, JsonObject outcome, CancellationToken cancellationToken)
        {
            if (group is { } members)
            {
                // A group keeps each contender's write; the receipt reads after a refusal depend on which contender won.
                if (call.Plan.Access == PlanAccess.Write)
                {
                    lock (gate) members.Add(new JsonObject { ["call"] = Call(call), ["outcome"] = outcome });
                }

                return;
            }

            var counts = await CountsAsync(cancellationToken).ConfigureAwait(false);
            Steps.Add(new JsonObject { ["scenario"] = Scenario, ["call"] = Call(call), ["expect"] = outcome, ["counts"] = counts });
        }

        private async Task<JsonArray> CountsAsync(CancellationToken cancellationToken)
        {
            var row = (await inner.QueryAsync("SELECT " + string.Join(", ", tables.Select(table => "(SELECT COUNT(*) FROM " + table + ")")), cancellationToken).ConfigureAwait(false)).Single();
            return new JsonArray([.. row.Select(cell => (JsonNode)JsonValue.Create(long.Parse(cell!, CultureInfo.InvariantCulture)))]);
        }

        private static JsonObject Call(PlanCall call)
        {
            var request = ExecutePlanRequestJson.Serialize(new ExecutePlanRequest
            {
                PlanId = call.Plan.Id,
                PlanVersion = call.Plan.Version,
                ManifestHash = PlanManifest.Hash,
                RequestId = call.RequestId.ToString("D"),
                RecoveryGeneration = call.RecoveryGeneration.ToString(CultureInfo.InvariantCulture),
                OwnerScope = call.OwnerScope,
                Arguments = call.Arguments,
                DeadlineUtc = "2026-10-10T12:00:05.0000000Z",
            });
            return new JsonObject
            {
                ["plan"] = call.Plan.Id,
                ["version"] = call.Plan.Version,
                ["ownerScope"] = call.OwnerScope,
                ["recoveryGeneration"] = call.RecoveryGeneration.ToString(CultureInfo.InvariantCulture),
                ["arguments"] = JsonNode.Parse(request)!["arguments"]!.DeepClone(),
            };
        }

        private static JsonObject Success(PlanResult result)
        {
            var response = ExecutePlanResponseJson.Serialize(new ExecutePlanResponseExecutePlanSuccess(new ExecutePlanSuccess
            {
                RequestId = "00000000-0000-4000-8000-000000000000",
                ManifestHash = PlanManifest.Hash,
                Rows = [.. result.Rows.Select(row => row.ToArray())],
                Changes = result.Changes.ToString(CultureInfo.InvariantCulture),
            }));
            var parsed = JsonNode.Parse(response)!;
            return new JsonObject { ["status"] = "ok", ["changes"] = parsed["changes"]!.DeepClone(), ["rows"] = parsed["rows"]!.DeepClone() };
        }

        /// <summary>The contract's failure names, as the Worker returns them.</summary>
        private static string WireName(PlanFailureKind kind) => kind switch
        {
            PlanFailureKind.InvalidPlan => "invalidPlan",
            PlanFailureKind.StaleGeneration => "staleGeneration",
            PlanFailureKind.Precondition => "precondition",
            PlanFailureKind.Constraint => "constraint",
            PlanFailureKind.Overloaded => "overloaded",
            PlanFailureKind.Unavailable => "unavailable",
            PlanFailureKind.UnknownOutcome => "unknownOutcome",
            _ => throw new InvalidOperationException("The bridge answered a failure the contract does not name: " + kind),
        };
    }

    /// <summary>Sequential identifiers; <see cref="Script"/> puts identifiers in front (a collision with an existing record).</summary>
    private sealed class TranscriptIds : IIdentityIdSource
    {
        private readonly Lock gate = new();
        private readonly Queue<string> scripted = new();
        private long next = 0x100;

        public void Script(params string[] first)
        {
            lock (gate)
            {
                foreach (var id in first) scripted.Enqueue(id);
            }
        }

        public string NewId()
        {
            lock (gate) return scripted.TryDequeue(out var id) ? id : $"00000000-0000-4000-8000-{++next:x12}";
        }
    }

    /// <summary>Loses the first send of one plan, after executing it (a lost response) or before (a lost request), and optionally the receipt read after it.</summary>
    private sealed class LossyExecutor(IPlanExecutor inner, string planId, bool executeFirst, bool loseReconciliation, Action? onLoss = null) : IPlanExecutor
    {
        private bool lost;
        private bool reconciliationLost;

        public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
        {
            if (call.Plan.Id == planId && !lost)
            {
                lost = true;
                if (executeFirst) await inner.ExecuteAsync(call, cancellationToken);
                throw new PlanFailureException(PlanFailureKind.UnknownOutcome);
            }

            if (loseReconciliation && lost && !reconciliationLost && call.Plan.Id == PlanManifest.Platform.CommandLoad.Id)
            {
                reconciliationLost = true;
                onLoss?.Invoke();
                throw new PlanFailureException(PlanFailureKind.UnknownOutcome);
            }

            return await inner.ExecuteAsync(call, cancellationToken);
        }
    }

    /// <summary>Runs another request of the same command to completion before the first commit (that request winning the race).</summary>
    private sealed class HookedStore(IIdentityStore inner, Func<Task> beforeFirstCommit) : IIdentityStore
    {
        private Func<Task>? hook = beforeFirstCommit;

        public ValueTask<User?> FindUserAsync(RealmId realm, UserId id, CancellationToken cancellationToken) => inner.FindUserAsync(realm, id, cancellationToken);

        public ValueTask<CredentialLookup?> FindCredentialAsync(RealmId realm, string providerId, string subject, CancellationToken cancellationToken) =>
            inner.FindCredentialAsync(realm, providerId, subject, cancellationToken);

        public ValueTask<IReadOnlyList<AuthIdentity>> ListCredentialsAsync(RealmId realm, UserId id, CancellationToken cancellationToken) => inner.ListCredentialsAsync(realm, id, cancellationToken);

        public ValueTask<Workspace?> FindWorkspaceAsync(RealmId realm, WorkspaceId id, CancellationToken cancellationToken) => inner.FindWorkspaceAsync(realm, id, cancellationToken);

        public ValueTask<Workspace?> FindWorkspaceByOwnerAsync(RealmId realm, UserId owner, CancellationToken cancellationToken) => inner.FindWorkspaceByOwnerAsync(realm, owner, cancellationToken);

        public ValueTask<bool> HasActiveRecoveryPathAsync(RealmId realm, UserId id, CancellationToken cancellationToken) => inner.HasActiveRecoveryPathAsync(realm, id, cancellationToken);

        public async ValueTask<CommitOutcome> CommitAsync(IdentityCommit commit, CancellationToken cancellationToken)
        {
            if (hook is { } run)
            {
                hook = null;
                await run();
            }

            return await inner.CommitAsync(commit, cancellationToken);
        }
    }
}
