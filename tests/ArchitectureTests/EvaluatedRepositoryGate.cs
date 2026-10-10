// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The shared engine over Cloud's real evaluated project graph. It needs the completed Release build and the canonical naming
/// report, and runs in the Linux source job (RP-09 unverified, asserted as the only finding) and in the hosted quality job after
/// the existing secret scan (<c>ARCFORGES_ARCHITECTURE_GATE=hosted</c>, every rule must hold).
/// </summary>
public sealed class EvaluatedRepositoryGate
{
    /// <summary>The offline model dispatch tests (HAR.40 (c)) that exercise the dispatch port, its client and the envelope admission.</summary>
    private static readonly string[] DispatchTests =
    [
        "ASuccessfulCallSendsTheClosedEnvelopeWithTheFrozenRequestAndReturnsTheAnswer", "EveryPreDispatchAdmissionRefusesWithoutAnyCall",
        "ARequestOverTheCallerCapIsRefusedBeforeAnyCall", "ARefusedAdmissionSpendsNoToken", "ARequestThatCannotBeSerialisedSpendsNoToken",
        "ThePerModelTokenBucketRefusesAnEmptyBucketAndRefillsWithTime", "AnAdapterRefusalIsAPreDispatchRefusal",
        "AnAdapterFailureAfterTheBindingIsUnknownAndNeverRetried", "ATransportFailureIsUnknown", "ACallThatOutlastsItsDeadlineIsUnknownWithTheDeadlineReason",
        "ACallerCancellationIsUnknownWithTheCancelledReason", "AnAnswerOverTheCallerCapOrNotAJsonObjectIsUnknown",
        "AStreamRequestIsRefusedBeforeAnyTokenIsSpent", "AnAnswerThatIsNotJsonIsUnknownWhateverItsBody",
    ];

    /// <summary>The offline wake tests (HAR.40 (f) and (g)) that exercise the wake service and its claim under the Worker version.</summary>
    private static readonly string[] WakeTests =
    [
        "AWakeClaimsAPinnedWaitingRunUnderTheWorkerVersionUnderItsStoredPinAndReleasesItToWaiting", "AWakeForARunThatNeverStoredAPinIsNotClaimedAndWritesNothing",
        "AWakeForAHeldRunIsRetriedUntilItsLeaseExpiresAndAnAbsentRunIsTakenAndChangesNothing",
        "AWakeWhoseReleaseCannotSettleIsStoppedSoItIsRetried", "AWakeWithAMalformedWorkerVersionIsRefusedByTheService",
        "AWakeWhoseRunReadIsNotServedIsUnavailableAndChangesNothing", "AWakeWhoseAttemptReadIsNotServedReleasesItsLeaseAndTheRetryClaimsAndSettles",
    ];

    /// <summary>The wake route tests: the route exists only under the foundation configuration and verifies before it parses.</summary>
    private static readonly string[] RouteTests =
    [
        "TheEndpointVerifiesBeforeItParsesAndAnswersThroughItsStatusCodes", "WithoutAWakePortTheRouteDoesNotExist",
        "TheWakePathIsDeclaredToTheIngressOnlyUnderTheFoundationConfiguration",
    ];

    /// <summary>The real tests of the alarm client's schedule path (HAR.40 alarm arming).</summary>
    private static readonly string[] AlarmScheduleTests =
    [
        "AScheduleIsOneClosedPostToTheScheduleRouteOfTheHarnessHost", "AnyReplyOtherThanTheExactScheduledReplyIsARefusal",
        "ATransportFailureIsAFailClosedRefusal", "ACallerThatIsCancelledOrAHungReplyAreFailClosedRefusals",
    ];

    /// <summary>The real tests of the alarm client's cancel path (HAR.40 alarm arming).</summary>
    private static readonly string[] AlarmCancelTests = ["ACancelIsOneClosedRunKeyPostToTheCancelRouteAndItsFailureIsSwallowed"];

    /// <summary>The public Cloud API and the real test methods that exercise each member. A new public member fails RP-10 until mapped here.</summary>
    private static readonly (string Api, string Method, string TestType, string[] Tests)[] ApiTests =
    [
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "DatabaseNameFor", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["ProductionDeclaresNoBusinessDatabaseAndProofNamesItsReservedOneFromWranglerJson"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "FormatReport", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheProofStepMigratesTheRealCatalogThroughTheRestClientPrintsReceiptsAndTheCompatibilityRecordAndNoSecret", "TheDryRunAppliesTheRealCatalogToAnEmptyDatabaseWithTheSameGatedFlow"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "IsAccountId", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheLiveStepRefusesAPullRequestAForkAnotherBranchAnotherRepositoryAndACandidateOfAnotherCommit"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "IsDatabaseId", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheDatabaseIdComesFromAnExactNameLookupAMissingDuplicatedOrFailedLookupRefusesAndNothingIsCreated"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "IsRevision", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheLiveStepRefusesAPullRequestAForkAnotherBranchAnotherRepositoryAndACandidateOfAnotherCommit"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "OverrideDatabaseId", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheDatabaseIdComesFromAnExactNameLookupAMissingDuplicatedOrFailedLookupRefusesAndNothingIsCreated"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "PlanFor", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["AMalformedOrUnknownPlanIsRefused", "TheManifestNamesTheBackfillAndTheCutoverAContractNeedsConsentAndTheSoak"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "RequireContext", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheLiveStepRefusesAPullRequestAForkAnotherBranchAnotherRepositoryAndACandidateOfAnotherCommit"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "RequireGatePassed", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["AFailingMigrationStepStopsPromotionWithExitCode1ARefusedGateRecordAndNoPromotionWithoutAPassedRecord"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "RunGateAsync", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["WithoutAManifestPlanOnlyExpandMigrationsAreAppliedAndTheStepStopsBeforeBackfillCutoverAndContract", "TheManifestNamesTheBackfillAndTheCutoverAContractNeedsConsentAndTheSoak"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "RunnerIdentity", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheProofStepMigratesTheRealCatalogThroughTheRestClientPrintsReceiptsAndTheCompatibilityRecordAndNoSecret"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "Scrub", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["ScrubRemovesASecretWhereverItAppearsAndIgnoresEmptyValues"]),
        ("ArcForges.Cloud.Storage.D1.Deploy.DeployGate", "SelectDatabaseId", "ArcForges.Cloud.Tests.Reduction.DeployTests", ["TheDatabaseIdComesFromAnExactNameLookupAMissingDuplicatedOrFailedLookupRefusesAndNothingIsCreated"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.IMigrationClient", "BatchAsync", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["FreshDatabaseReceivesEveryMigrationInOrderWithReceiptsAndEqualsTheManifest"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationCatalog", "AppendOnlyProblems", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheIntegrationOwnerNumbersPendingMigrationsInOrderAndLocksThemAndTheLockStaysAppendOnlyAgainstItsBase"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationCatalog", "CheckPendingFile", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheIntegrationOwnerNumbersPendingMigrationsInOrderAndLocksThemAndTheLockStaysAppendOnlyAgainstItsBase"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationCatalog", "Load", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["EditingALockedMigrationLeavingAGapOrMismatchingAHeaderIsRefused", "TheCommittedCatalogIsGaplessLockedAndParsesInItsModes"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationCatalog", "LockIdentity", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheCommittedCatalogIsGaplessLockedAndParsesInItsModes"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationCatalog", "LockNumbered", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheCommittedCatalogIsGaplessLockedAndParsesInItsModes", "TheIntegrationOwnerNumbersPendingMigrationsInOrderAndLocksThemAndTheLockStaysAppendOnlyAgainstItsBase"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationCatalog", "NumberedName", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheIntegrationOwnerNumbersPendingMigrationsInOrderAndLocksThemAndTheLockStaysAppendOnlyAgainstItsBase"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationCatalog", "SortedSqlFiles", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["EditingALockedMigrationLeavingAGapOrMismatchingAHeaderIsRefused"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationEngine", "ApplyPendingAsync", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["FreshDatabaseReceivesEveryMigrationInOrderWithReceiptsAndEqualsTheManifest"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationEngine", "Compatibility", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["CutoverWaitsForItsVerifiedBackfillsAndMovesTheHorizonsAndAContractWaitsForSoakAndConsent"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationEngine", "Micros", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["ABackfillLongerThanItsLeaseRenewsItPageByPageAndIsNeverMistakenForAStaleMigrator"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationEngine", "StatusAsync", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["SecondRunAppliesNothingTakesAHigherFenceAndReleasesTheLease"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ChecksumOf", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["LineEndingsDoNotChangeAChecksumOrTheStatements"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ModeName", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["EveryModeAcceptsOnlyItsOwnStatementsAndNoMigrationControlsTransactionsOrPragmas"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ModeViolations", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["EveryModeAcceptsOnlyItsOwnStatementsAndNoMigrationControlsTransactionsOrPragmas"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "NormalizeNewlines", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["LineEndingsDoNotChangeAChecksumOrTheStatements"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ParseBackfill", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheBackfillSectionsAreValidatedOneStatementEachRevisionGuardKeyCursorAndAtMost100Rows"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ParseHeader", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["EditingALockedMigrationLeavingAGapOrMismatchingAHeaderIsRefused"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ParseMode", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["EditingALockedMigrationLeavingAGapOrMismatchingAHeaderIsRefused"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ParseNumberedFileName", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheIntegrationOwnerNumbersPendingMigrationsInOrderAndLocksThemAndTheLockStaysAppendOnlyAgainstItsBase"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ParsePendingModule", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheIntegrationOwnerNumbersPendingMigrationsInOrderAndLocksThemAndTheLockStaysAppendOnlyAgainstItsBase"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "ShortChecksum", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["EditedMergedMigrationIsRefusedByItsReceiptChecksumAndDatabaseAheadIsRefused"]),
        ("ArcForges.Cloud.Storage.D1.MigrationRunner.MigrationSql", "SplitStatements", "ArcForges.Cloud.Tests.Reduction.MigrationRunnerTests", ["TheStatementSplitterKeepsTriggerBodiesStringsAndCommentsWhole"]),
        ("ArcForges.Cloud.HelloEndpoint", "SayHello", "ArcForges.Cloud.Tests.HelloEndpointTests",
            ["PreservesThePublishedGreeting", "EmptyNameHasThePublishedStatus", "OversizedNameIsResourceExhausted"]),
        ("ArcForges.Cloud.BuildIdentity", "Resolve", "ArcForges.Cloud.Tests.BuildIdentityTests",
            ["NineRealSourceKindsAreIndependentAndDeterministic", "CurrentContractsReceiptShapeResolvesThroughTheHelloSchemaSource", "InvalidSourcesCannotProduceAReport"]),
        ("ArcForges.Cloud.BuildIdentity", "ValidateBuild", "ArcForges.Cloud.Tests.BuildIdentityTests", ["DirtyOrIncompleteCiIdentityIsRejected"]),
        ("ArcForges.Cloud.BuildIdentity", "FromAssembly", "ArcForges.Cloud.Tests.BuildMetadataTests", ["EveryOwnedAssemblyCarriesActualSourceAndBuildIdentity"]),
        // CLOUD.02: the module boundary types. Descriptor creation is tested directly; the boundary entry points are exercised through
        // the host composition that lists every module and by the composed host that maps them.
        ("ArcForges.Cloud.Modules.ModuleDescriptor", "Create", "ArcForges.Cloud.Tests.ModuleBoundaryTests",
            ["AMalformedDescriptorCannotBeCreated", "DescriptorsDeriveTheOwnerAndThePrefixFromTheSchemaOnly"]),
        ("ArcForges.Cloud.Modules.IModuleBoundary", "Register", "ArcForges.Cloud.Tests.ModuleBoundaryTests",
            ["TheHostListsEveryBoundaryOnceAndAListedBoundaryServesNothing", "TheComposedHostStillServesOnlyHelloAndHealthAndRefusesEveryModulePath"]),
        ("ArcForges.Cloud.Modules.IModuleBoundary", "Map", "ArcForges.Cloud.Tests.ModuleBoundaryTests",
            ["TheHostListsEveryBoundaryOnceAndAListedBoundaryServesNothing", "TheComposedHostStillServesOnlyHelloAndHealthAndRefusesEveryModulePath"]),
        // COM.16: the published grant port and the generic plan-execution port. The grant port is exercised through its Entitlement implementation
        // (no Entitlement type crosses it); the plan port through the adapter of the plan bridge and the D1 store that uses it; the plan value
        // type directly and through every plan call.
        ("ArcForges.Cloud.Modules.IEntitlementGrantPort", "IssueGrantAsync", "ArcForges.Cloud.Tests.Entitlement.GrantPortContractTests",
            ["AGrantIsIssuedWithItsSnapshotAndReportedAsPrimitives", "AReplayBySourceReferenceIsAnIdempotentNoOpAndADifferentGrantUnderTheReferenceIsAConflict",
                "AMalformedRequestIsRefusedBeforeAnyStoreCallAndNeverCoerced"]),
        ("ArcForges.Cloud.Modules.IEntitlementGrantPort", "RevokeGrantAsync", "ArcForges.Cloud.Tests.Entitlement.GrantPortContractTests",
            ["ARevocationNamesOneGrantGuardsTheVersionAndReplaysAsANoOp", "ASubMicrosecondRevocationInstantAndAMalformedRevocationAreRefused"]),
        ("ArcForges.Cloud.Modules.IModulePlanPort", "ReadAsync", "ArcForges.Cloud.Tests.Entitlement.ModulePlanPortTests",
            ["ARoundTripCarriesExactTypedValuesTheScopeAndTheRecoveryGeneration", "EveryPlanFailureBecomesATypedStatus"]),
        ("ArcForges.Cloud.Modules.IModulePlanPort", "WriteAsync", "ArcForges.Cloud.Tests.Entitlement.ModulePlanPortTests",
            ["EveryPlanFailureBecomesATypedStatus", "ACommitForAPlanThatDeclaresNoTailIsRejected"]),
        ("ArcForges.Cloud.Modules.IModulePlanPortFactory", "For", "ArcForges.Cloud.Tests.Entitlement.ModulePlanPortTests",
            ["APlanOfAnotherOwnerIsRefusedBeforeAnythingIsSent", "AnUnknownPlanAndAnAccessMismatchAreCallerDefectsThatNeverReachTheExecutor"]),
        ("ArcForges.Cloud.Modules.ModulePlanOutcome", "Of", "ArcForges.Cloud.Tests.Entitlement.ModulePlanPortTests", ["EveryPlanFailureBecomesATypedStatus"]),
        // HAR.40: the model dispatch port and its client (Agent module), the wake port (Task module) and the wake route. The real tests are the
        // offline dispatch and wake suites of ArcForges.Cloud.Tests.HarnessFoundation; the wake route is exercised through the composed host.
        ("ArcForges.Cloud.Modules.IModelDispatchPort", "SnapshotOf", "ArcForges.Cloud.Tests.HarnessFoundation.AgentDispatchTests", ["ASnapshotExistsOnlyForAnAdmittedModel"]),
        ("ArcForges.Cloud.Modules.IModelDispatchPort", "DispatchAsync", "ArcForges.Cloud.Tests.HarnessFoundation.AgentDispatchTests", DispatchTests),
        ("ArcForges.Cloud.Modules.Agent.Dispatch.Application.ModelDispatchClient", "SnapshotOf", "ArcForges.Cloud.Tests.HarnessFoundation.AgentDispatchTests", ["ASnapshotExistsOnlyForAnAdmittedModel"]),
        ("ArcForges.Cloud.Modules.Agent.Dispatch.Application.ModelDispatchClient", "DispatchAsync", "ArcForges.Cloud.Tests.HarnessFoundation.AgentDispatchTests", DispatchTests),
        ("ArcForges.Cloud.Modules.Agent.Dispatch.Domain.ModelDispatchOptions", "Create", "ArcForges.Cloud.Tests.HarnessFoundation.AgentDispatchTests",
            ["TheBaseAddressIsExactlyTheAiInternalRootOverPlainHttp", "AnAdmittedSetAndItsCapsAreBoundedWhenTheOptionsAreBuilt"]),
        ("ArcForges.Cloud.Modules.IHarnessWakePort", "Authenticate", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessWakeTests", ["TheServiceAuthenticatesOnlyWhatTheHostVerifierAccepts"]),
        ("ArcForges.Cloud.Modules.IHarnessWakePort", "HandleAsync", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessWakeTests", WakeTests),
        ("ArcForges.Cloud.Modules.Task.Harness.Wake.HarnessWakeService", "Authenticate", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessWakeTests", ["TheServiceAuthenticatesOnlyWhatTheHostVerifierAccepts"]),
        ("ArcForges.Cloud.Modules.Task.Harness.Wake.HarnessWakeService", "HandleAsync", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessWakeTests", WakeTests),
        ("ArcForges.Cloud.Modules.Task.Harness.Wake.HarnessWakeEndpoint", "Map", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessWakeTests", RouteTests),
        ("ArcForges.Cloud.Modules.Task.TaskModule", "Map", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessWakeTests", RouteTests),
        // HAR.40 alarm arming: the alarm port (Abstractions) and its outbound client (Task module). The real tests are the closed-request, fail-closed
        // and reply suites of HarnessAlarmClientTests; the executor's arm-before-commit order is tested in HarnessAlarmArmingTests.
        ("ArcForges.Cloud.Modules.IHarnessAlarmPort", "ScheduleAsync", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessAlarmClientTests", AlarmScheduleTests),
        ("ArcForges.Cloud.Modules.IHarnessAlarmPort", "CancelAsync", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessAlarmClientTests", AlarmCancelTests),
        ("ArcForges.Cloud.Modules.Task.Harness.Wake.HarnessAlarmClient", "ScheduleAsync", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessAlarmClientTests", AlarmScheduleTests),
        ("ArcForges.Cloud.Modules.Task.Harness.Wake.HarnessAlarmClient", "CancelAsync", "ArcForges.Cloud.Tests.HarnessFoundation.HarnessAlarmClientTests", AlarmCancelTests),
        .. new[] { "FromInt64", "FromBool", "FromText", "FromBytes", "FromOptionalText", "AsInt64", "AsBool", "AsText", "AsBytes", "AsOptionalText", "AsOptionalInt64", "Equals", "GetHashCode", "ToString" }
            .Select(member => ("ArcForges.Cloud.Modules.PlanValue", member, "ArcForges.Cloud.Tests.Entitlement.ModulePlanPortTests",
                new[] { "PlanValuesAreExactAndNeverDescribeTheirContent", "ARoundTripCarriesExactTypedValuesTheScopeAndTheRecoveryGeneration" })),
    ];

    [Fact]
    public void ActualCloudProjectsSatisfyTheSharedArchitecturePolicy()
    {
        string root = CloudRepository.FindRoot();
        string head = CloudRepository.Head(root);
        bool hosted = HostedEvidence.IsHostedMode(Environment.GetEnvironmentVariable);

        var projects = CloudRepository.Classifications.Select(classification => ProjectGraph.Evaluate(root, classification, "Release")).ToArray();
        var compilations = projects.ToDictionary(project => project.Classification.Path, CloudRepository.ReadCompilation, StringComparer.Ordinal);
        string report = CloudRepository.Read(root, "artifacts/evidence/naming.json");
        var evidence = new[]
        {
            CloudRepository.ReadNamingEvidence(report, head, "RP-01"),
            CloudRepository.ReadNamingEvidence(report, head, "RP-08"),
            HostedEvidence.Resolve(Environment.GetEnvironmentVariable, head,
                CiWiring.Check(CloudRepository.Read(root, ".github/workflows/ci.yml"), CloudRepository.Read(root, "package.json")), hosted),
        };
        var repository = new RepositoryFacts(root, CloudRepository.Owner, projects,
            CloudRepository.ParseExceptions(CloudRepository.Read(root, "eng/policy/exceptions.json")), ContractTestBindings(compilations));
        var configuration = new RepositoryPolicyConfiguration(head, CloudRepository.ReadInputHashes(root),
            CloudRepository.ReadPackageLicences(projects), new HashSet<string>(StringComparer.Ordinal), [], [], evidence);
        var findings = PolicyEngine.Check(repository, configuration, compilations, DateOnly.FromDateTime(DateTime.UtcNow)).ToList();

        var serviceProject = projects.Single(project => project.Classification.Path == CloudRepository.Service);
        // The source checks below ran on the service project alone while it held all the code. Code now also lives in the Native AOT
        // projects it references (the plan bridge and the module boundaries), so the same checks run on every production project.
        foreach (var production in projects.Where(project => project.Classification.Production))
        {
            string path = production.Classification.Path;
            var compilation = compilations[path];
            string directory = Path.GetDirectoryName(Path.GetFullPath(Path.Combine(root, path)))!;
            // Banned-symbol findings inside the SDK's own generator output are not Cloud-authored (see CloudRepository.IsOfficialGeneratorOutput).
            findings.RemoveAll(finding => finding.Rule.StartsWith("BAN-", StringComparison.Ordinal) && CloudRepository.IsOfficialGeneratorOutput(finding.Path, directory));
            foreach (string problem in CloudAotPolicy.FindSuppressions(compilation, directory))
            {
                findings.Add(new PolicyFinding("RP-07", path, "Trim or AOT suppression at " + problem));
            }

            foreach (string problem in CloudAotPolicy.FindUnregisteredJsonSerialization(compilation, directory))
            {
                findings.Add(new PolicyFinding("BAN-REFLECTION", path, "JSON serialization without compile-time metadata at " + problem));
            }

            foreach (string problem in ContractConsumptionPolicy.CheckServiceBases(compilation, directory).Concat(ContractConsumptionPolicy.CheckNoAuthoredWireMessages(compilation, directory))
                .Concat(ContractConsumptionPolicy.FindHandBuiltRpcDescriptors(compilation, directory)).Concat(ContractConsumptionPolicy.FindTextEncodedGrpcWeb(compilation, directory)))
            {
                findings.Add(new PolicyFinding("AT-04", path, problem));
            }
        }

        foreach (var unverified in evidence.Where(item => !item.Passed))
        {
            findings.AddRange(unverified.Findings);
        }

        Assert.True(serviceProject.Properties["PublishAot"] == "true" && serviceProject.OutputType == "Exe", "The service must stay the Native AOT executable.");
        if (!hosted)
        {
            // Everything except the hosted secret-scan ordering is verified here; that one rule needs the quality job.
            Assert.Contains(findings, finding => finding.Rule == "RP-09");
            findings.RemoveAll(finding => finding.Rule == "RP-09");
        }

        Assert.True(findings.Count == 0, string.Join(Environment.NewLine, findings.Select(finding => $"{finding.Rule} {finding.Path}:{finding.Line} {finding.Message}")));
    }

    private static IReadOnlyList<ContractTestBinding> ContractTestBindings(IReadOnlyDictionary<string, CSharpCompilation> compilations)
    {
        var tests = compilations[CloudRepository.ServiceTests];
        var service = compilations[CloudRepository.Service];
        var result = new List<ContractTestBinding>();
        foreach (var (api, method, testType, names) in ApiTests)
        {
            var apiMethods = service.GetTypeByMetadataName(api)?.GetMembers(method).OfType<IMethodSymbol>().ToArray() ?? [];
            var testMethods = tests.GetTypeByMetadataName(testType)?.GetMembers().OfType<IMethodSymbol>().Where(candidate => names.Contains(candidate.Name)).ToArray() ?? [];
            Assert.True(apiMethods.Length > 0 && testMethods.Length == names.Length, $"The contract test map names a missing member: {api}.{method}.");
            result.AddRange(from apiMethod in apiMethods
                            from test in testMethods
                            select new ContractTestBinding(PolicyEngine.MethodIdentity(apiMethod), CloudRepository.ServiceTests, PolicyEngine.MethodIdentity(test)));
        }

        return result;
    }
}

/// <summary>RP-09 is the existing required secret scan. It is trusted only in the hosted job that runs the architecture host after it.</summary>
internal static class HostedEvidence
{
    public const string Variable = "ARCFORGES_ARCHITECTURE_GATE";

    public static bool IsHostedMode(Func<string, string?> environment) => environment(Variable) == "hosted";

    public static ExternalPolicyEvidence Resolve(Func<string, string?> environment, string head, IReadOnlyList<string> workflowProblems, bool hosted)
    {
        const string rule = "RP-09";
        string? source = environment("GITHUB_SHA");
        bool identity = environment("GITHUB_ACTIONS") == "true" && environment("GITHUB_JOB") == "quality" && source == head && head.Length == 40;
        if (hosted && identity && workflowProblems.Count == 0)
        {
            return new ExternalPolicyEvidence(rule, head, true, []);
        }

        string reason = !hosted ? "The secret scan result is only trusted in the hosted quality job."
            : !identity ? "The hosted gate requires the exact GitHub quality job and source identity."
            : "The hosted workflow no longer orders the secret scan before the architecture gate.";
        return new ExternalPolicyEvidence(rule, head, false, [new PolicyFinding(rule, ".github/workflows/ci.yml", reason)]);
    }
}
