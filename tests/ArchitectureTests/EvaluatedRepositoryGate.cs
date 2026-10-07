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
    /// <summary>The public Cloud API and the real test methods that exercise each member. A new public member fails RP-10 until mapped here.</summary>
    private static readonly (string Api, string Method, string TestType, string[] Tests)[] ApiTests =
    [
        ("ArcForges.Cloud.Modules.IEntitlementGrantPort", "IssueGrantAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.VersionedDefinitionCompositionTests",
            ["ProductionGrantBindingUsesCurrentAsyncDefinitionsAndHistoricalRebuildPinsStoredVersion", "CancellationAfterTheRealGrantCommitDoesNotReportSuccessOrUndoTheGrant"]),
        ("ArcForges.Cloud.Modules.IEntitlementGrantPort", "RevokeGrantAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.VersionedDefinitionCompositionTests",
            ["ProductionRevocationRetainsExistingExpectedVersionAndExactReplayRules"]),
        ("ArcForges.Cloud.Modules.IResolverDefinitionValidator", "Validate", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionValidatorTests",
            ["CompleteDefinitionsPreserveDistinctOwnerSemanticsAndDefensiveCopies"]),
        ("ArcForges.Cloud.Modules.IResolverDefinitionPort", "PublishAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionPersistenceTests",
            ["ConcurrentConflictingSameVersionRollsBackAllLosingEffects", "ExactReceiptReplayRequiresHistoricalAuthorityButNotArtifactAvailability", "CallerCancellationAfterRealCommitNeverReturnsSuccessOrClaimsRollback"]),
        ("ArcForges.Cloud.Modules.IResolverDefinitionPort", "ReadAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionPersistenceTests",
            ["LaterApprovedIdenticalReusePreservesFirstProvenanceAndHistoricalDefinitions"]),
        ("ArcForges.Cloud.Modules.ICurrentResolverDefinitionSource", "ReadAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionPersistenceTests",
            ["CurrentHeadChangedDuringReadCannotReturnEarlierDefinitions"]),
        ("ArcForges.Cloud.Modules.ICurrentResolverDefinitionSource", "RevalidateAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionPersistenceTests",
            ["CurrentHeadChangedDuringReadCannotReturnEarlierDefinitions"]),
        ("ArcForges.Cloud.Modules.IResolverApprovedConfigurationSource", "ReadCurrentAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionPersistenceTests",
            ["CurrentHeadChangedDuringReadCannotReturnEarlierDefinitions"]),
        ("ArcForges.Cloud.Modules.IResolverApprovedConfigurationSource", "ReadHistoricalAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionPersistenceTests",
            ["ExactReceiptReplayRequiresHistoricalAuthorityButNotArtifactAvailability", "UnauthorizedOrAlteredArtifactCannotReachAnyWrite"]),
        ("ArcForges.Cloud.Modules.IResolverDefinitionArtifactPort", "ReadAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.ResolverDefinitionPersistenceTests",
            ["UnauthorizedOrAlteredArtifactCannotReachAnyWrite"]),
        ("ArcForges.Cloud.Modules.IResolverConfigurationParticipant", "PrepareCurrentAsync", "ArcForges.Cloud.Tests.ResolverDefinitionAuthority.VersionedDefinitionCompositionTests",
            ["ARealAuthorityRaceAfterCapabilityPreparationRefusesEveryBatchWithoutAnyEffect", "ForeignIssuerWrongScopeAndLegacyUnscopedCapabilitiesNeverReachTheWriter"]),
        ("ArcForges.Cloud.Modules.IIdentityDeletionLifecyclePort", "ReadAsync", "ArcForges.Cloud.Tests.Deletion.DeletionReaderTests",
            ["ExistingDisclosureIsIndependentOfNewRequestConfiguration", "MalformedShapeAndEnumOverflowNeverBecomeAuthority", "SampleAfterReadsEnforcesExactDeadlineAndCurrentUserState", "RetryIsBoundedAndCancellationStopsBeforeAnotherDispatch"]),
        ("ArcForges.Cloud.Modules.IIdentityDeletionLifecyclePort", "PrepareAsync", "ArcForges.Cloud.Tests.Deletion.DeletionTransitionTests",
            ["PersistedDeadlineCapabilityUsesActualOwnerFactoryAndFreshRevisionWithoutWriting"]),
        .. new[] { "Available", "Refused" }.Select(member => ("ArcForges.Cloud.Modules.IdentityDeletionResult", member,
            "ArcForges.Cloud.Tests.Deletion.DeletionTransitionTests", new[] { "PublicResultContractsRejectNullOrUndefinedAndMaintainExclusiveOutcomes" })),
        .. new[] { "Available", "Refused" }.Select(member => ("ArcForges.Cloud.Modules.IdentityDeletionFamilyResult", member,
            "ArcForges.Cloud.Tests.Deletion.DeletionTransitionTests", new[] { "PublicResultContractsRejectNullOrUndefinedAndMaintainExclusiveOutcomes" })),
        ("ArcForges.Cloud.Modules.IRealmAuthorityFamilyPort", "PrepareAsync", "ArcForges.Cloud.Tests.Platform.RecoveryFamilyGuardTests",
            ["RealReaderAndSameIssuerComposeExactRecoveryArgumentsWithoutPlatformPrivilege", "InvalidCapabilitiesNeverReadAReceiptOrMutate", "UnavailableStaleOrUnregisteredIssuerCannotProduceASuccessfulCapability", "CancellationBeforePrepareNeverCallsStorage"]),
        .. new[] { "Available", "Refused" }.Select(member => ("ArcForges.Cloud.Modules.RealmAuthorityFamilyResult", member,
            "ArcForges.Cloud.Tests.Platform.RecoveryFamilyGuardTests", new[] { "FamilyResultContractsRemainClosedAndRejectMissingAuthorityOrCapability" })),
        ("ArcForges.Cloud.Modules.IRealmAuthorityPort", "ResolveAsync", "ArcForges.Cloud.Tests.RealmAuthority.RealmAuthorityTests",
            ["ActualOwnerReadAndConfiguredAuthorityFollowDurableCurrentStateWithoutAdoptingNewGeneration", "MissingInvalidOrNoncanonicalConfigurationRefusesBeforeStorage", "LazyImmutableConfigurationNeverUsesProofDefaultsAndUnavailableExecutorRefuses"]),
        ("ArcForges.Cloud.Modules.IRecoveryEpochPort", "ReadAsync", "ArcForges.Cloud.Tests.RealmAuthority.RealmAuthorityTests",
            ["ActualReadKeepsRealmsIsolatedAndConcurrentResolutionsRereadEachCurrentVersion", "TransientReadsRetryBoundedlyAndCallerCancellationStopsBackoff", "ReadDeadlineIsBoundedAndInFlightCallerCancellationIsPropagated", "MalformedRowsInvalidRealmAndClosedStatesFailClosed"]),
        .. new[] { "Available", "Refused" }.Select(member => ("ArcForges.Cloud.Modules.RecoveryEpochResult", member,
            "ArcForges.Cloud.Tests.RealmAuthority.RealmAuthorityTests", new[] { "SharedPortValidatesDependencySnapshotAndClosedResultContracts" })),
        .. new[] { "Available", "Refused" }.Select(member => ("ArcForges.Cloud.Modules.RealmAuthorityResult", member,
            "ArcForges.Cloud.Tests.RealmAuthority.RealmAuthorityTests", new[] { "SharedPortValidatesDependencySnapshotAndClosedResultContracts" })),
        ("ArcForges.Cloud.Modules.Commerce.Adapters.BillingProviderFactory", "Create", "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
            ["FactoryUsesFixedEnvironmentAuthenticationAndNormalizesPriceAndRegions", "TimeoutAndDisposalCancelActualInFlightOperationsAndDisposalIsIdempotent"]),
        ("ArcForges.Cloud.Modules.Commerce.Adapters.CustomerPortalLink", "ToString", "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
            ["CustomerPortalIsBoundToCustomerAndItsTemporaryTokenIsNotInDiagnostics"]),
        ("ArcForges.Cloud.Modules.Commerce.Adapters.IBillingProvider", "GetPriceAsync", "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
            ["FactoryUsesFixedEnvironmentAuthenticationAndNormalizesPriceAndRegions"]),
        ("ArcForges.Cloud.Modules.Commerce.Adapters.IBillingProvider", "CreateCheckoutAsync", "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
            ["CheckoutBindsCapturedTermsAndServerMetadataBeforeOneRealMutation", "RegionTermsApprovalAndRenewalCapsAreRealAdmissionChecks", "CapturedRegionalCurrencyCanCheckoutWithoutCurrencyFallback"]),
        .. new[] { "GetTransactionAsync", "ListTransactionsAsync", "GetSubscriptionAsync", "ListSubscriptionsAsync", "GetAdjustmentAsync", "ListAdjustmentsAsync", "ListEventsAsync" }
            .Select(member => ("ArcForges.Cloud.Modules.Commerce.Adapters.IBillingProvider", member, "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
                new[] { "TransactionsSubscriptionsAdjustmentsAndEventPagesAreNormalizedWithoutInstrumentData" })),
        .. new[] { "CancelSubscriptionAsync", "ReactivateScheduledCancellationAsync" }
            .Select(member => ("ArcForges.Cloud.Modules.Commerce.Adapters.IBillingProvider", member, "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
                new[] { "CancelAtPeriodEndAndReactivationUseExactMutationContracts" })),
        ("ArcForges.Cloud.Modules.Commerce.Adapters.IBillingProvider", "CreateRefundAsync", "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
            ["FullAndPartialRefundReturnPendingApprovalRatherThanClaimingSuccess"]),
        ("ArcForges.Cloud.Modules.Commerce.Adapters.IBillingProvider", "CreateCustomerPortalAsync", "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
            ["CustomerPortalIsBoundToCustomerAndItsTemporaryTokenIsNotInDiagnostics", "CrossCustomerPortalRequestIsRefusedBeforeMutation"]),
        ("ArcForges.Cloud.Modules.Commerce.Adapters.IBillingProvider", "VerifyWebhook", "ArcForges.Cloud.Tests.Commerce.Adapter.ProviderAdapterTests",
            ["RawBodySignaturesRotationFreshnessAndStableReplayIdentityAreVerified", "AuthenticatedMalformedPayloadIsQuarantinedAndUnknownEventStaysUnsupported"]),
        ("ArcForges.Cloud.Modules.CatalogueCanonical", "Create", "ArcForges.Cloud.Tests.Commerce.Catalogue.CatalogueTests", ["CanonicalProjectionAndCompositionAreDeterministicAndFailClosed"]),
        ("ArcForges.Cloud.Modules.ICataloguePublicationAuthority", "VerifyAsync", "ArcForges.Cloud.Tests.Commerce.Catalogue.CatalogueTests", ["ActualEvidenceIsRequiredAndEveryBindingOrApprovalFailureRefusesBeforePersistence"]),
        ("ArcForges.Cloud.Modules.ICataloguePublicationPort", "PublishAsync", "ArcForges.Cloud.Tests.Commerce.Catalogue.CatalogueTests", ["CanonicalProjectionAndCompositionAreDeterministicAndFailClosed", "LostSuccessfulResponseRetriesSameReceiptAndTransientFailuresAreBounded", "GuardedRacesCommitExactlyOneAndStaleOrStructuralChangesLeaveNoPartialEffects"]),
        ("ArcForges.Cloud.Modules.ICatalogueStatePort", "ReadAsync", "ArcForges.Cloud.Tests.Commerce.Catalogue.CatalogueTests", ["GuardedRacesCommitExactlyOneAndStaleOrStructuralChangesLeaveNoPartialEffects"]),
        ("ArcForges.Cloud.Modules.ICatalogueQueryPort", "ReadPriceAsync", "ArcForges.Cloud.Tests.Commerce.Catalogue.CatalogueTests", ["PersistedPricesSupersedeAtStartAndExpiredNewestNeverResurrectsHistory", "CompletedOrderAndCapturedPaymentRetainOriginalPriceAfterPublication"]),
        ("ArcForges.Cloud.Modules.ICatalogueQueryPort", "ReadEffectiveAsync", "ArcForges.Cloud.Tests.Commerce.Catalogue.CatalogueTests", ["PersistedPricesSupersedeAtStartAndExpiredNewestNeverResurrectsHistory"]),
        ("ArcForges.Cloud.Modules.ICatalogueQueryPort", "ListAsync", "ArcForges.Cloud.Tests.Commerce.Catalogue.CatalogueTests", ["CanonicalProjectionAndCompositionAreDeterministicAndFailClosed", "KeysetPagesAndReadFailuresHaveExplicitBoundedResults"]),
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
        ("ArcForges.Cloud.Modules.IModuleFamilyPort", "InspectAsync", "ArcForges.Cloud.Tests.Families.ModuleFamilyPortTests", ["InspectionReturnsNotSeenAndPreservesTypedStorageFailures"]),
        ("ArcForges.Cloud.Modules.IModuleFamilyPort", "ReadAsync", "ArcForges.Cloud.Tests.Families.ModuleFamilyPortTests", ["ParticipantReadsAreRestrictedToExactEnrollmentWorkspacePlans"]),
        ("ArcForges.Cloud.Modules.IModuleFamilyPort", "WriteAsync", "ArcForges.Cloud.Tests.Families.ModuleFamilyPortTests", ["ForeignContributionsAreRejectedBeforeAnyReceiptRead"]),
        ("ArcForges.Cloud.Modules.IModuleFamilyPort", "Contribute", "ArcForges.Cloud.Tests.Families.ModuleFamilyPortTests", ["OwnerCapabilitiesCombineAcrossModulesAndCannotBeForgedOrCrossFactories"]),
        ("ArcForges.Cloud.Modules.IModuleFamilyPort", "ContributeScoped", "ArcForges.Cloud.Tests.Families.ScopedModuleFamilyPortTests",
            ["InvalidScopedCapabilityNeverReadsAReceiptOrMutates", "CorrectScopedCapabilityCommitsOnceAndConcurrentRetriesReplay", "NonCanonicalOrEmptyScopeCannotMintACapability"]),
        ("ArcForges.Cloud.Modules.IModuleFamilyPortFactory", "For", "ArcForges.Cloud.Tests.Families.ModuleFamilyPortTests", ["UnknownFamiliesAndNonParticipantsNeverReachStorage"]),
        .. new[] { "FromInt64", "FromBool", "FromText", "FromBytes", "FromOptionalText", "AsInt64", "AsBool", "AsText", "AsBytes", "AsOptionalText", "AsOptionalInt64", "Equals", "GetHashCode", "ToString" }
            .Select(member => ("ArcForges.Cloud.Modules.PlanValue", member, "ArcForges.Cloud.Tests.Entitlement.ModulePlanPortTests",
                new[] { "PlanValuesAreExactAndNeverDescribeTheirContent", "ARoundTripCarriesExactTypedValuesTheScopeAndTheRecoveryGeneration" })),
        // CLOUD.07: actual owner stores and persistent guard/lifecycle cases exercise each primitive.
        ("ArcForges.Cloud.Modules.ICapacityJobPort", "ReadAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["PersistentCreateReplayCompetingClaimsAndGuardedCheckpointSurviveAdapterRestart"]),
        ("ArcForges.Cloud.Modules.ICapacityJobPort", "CreateAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["PersistentCreateReplayCompetingClaimsAndGuardedCheckpointSurviveAdapterRestart", "CurrentAuthorizationGenerationAndCancelledReadsDoNotExposeOrMutateAcceptedJob"]),
        ("ArcForges.Cloud.Modules.ICapacityJobPort", "ClaimAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["PersistentCreateReplayCompetingClaimsAndGuardedCheckpointSurviveAdapterRestart"]),
        ("ArcForges.Cloud.Modules.ICapacityJobPort", "CheckpointAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["PersistentCreateReplayCompetingClaimsAndGuardedCheckpointSurviveAdapterRestart"]),
        ("ArcForges.Cloud.Modules.ICapacityJobPort", "ReconcileAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["LostClaimAndContinuationAcknowledgementsReconcileWithoutNewLeaseTermsOrDuplicateReadWork"]),
        ("ArcForges.Cloud.Modules.ICapacityJobAuthority", "AuthorizeCreateAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["CurrentAuthorizationGenerationAndCancelledReadsDoNotExposeOrMutateAcceptedJob"]),
        ("ArcForges.Cloud.Modules.ICapacityJobAuthority", "AuthorizeAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["CurrentAuthorizationGenerationAndCancelledReadsDoNotExposeOrMutateAcceptedJob"]),
        ("ArcForges.Cloud.Modules.ICapacityJobRecoveryAuthority", "GetCurrentAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["RecoveryEnumeratesOnlyRegisteredCurrentRealmGenerationDueRowsWithBoundedKeyset"]),
        ("ArcForges.Cloud.Modules.ICapacityJobRecoveryPort", "ReadDueAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["RecoveryEnumeratesOnlyRegisteredCurrentRealmGenerationDueRowsWithBoundedKeyset"]),
        ("ArcForges.Cloud.Modules.ICapacityJobProcessor", "ProcessAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["ActualSignedPrivateWakeRunsRealMeasurementAndProducesBoundHistoricalReport", "LostClaimAndContinuationAcknowledgementsReconcileWithoutNewLeaseTermsOrDuplicateReadWork"]),
        ("ArcForges.Cloud.Modules.ICapacityWakeScheduler", "ScheduleAsync", "ArcForges.Cloud.Tests.CapacityTests.CapacityJobTests", ["ActualSignedSchedulerRetriesSameDurableWakeAndKeepsCurrentAuthorizationBeforeDispatch", "SchedulerBoundsActiveAndQueuedRequestsAndShutdownDistinguishesForwardedHints"]),
        .. new[] { "AuthorizeCommandAsync", "AuthorizeReadAsync", "AuthorizeBudgetAsync", "AuthorizeAdmissionAsync", "AuthorizeEffectAsync", "AuthorizeCleanupAsync" }
            .Select(member => ("ArcForges.Cloud.Modules.IQuotaKernelAuthority", member, "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests",
                new[] { "ReplayRequiresCurrentPermissionButNotNewMeasurementAndExpiredIdentifierNeverWritesAgain", "MultiLimitAdmissionIsAtomicAndConcurrentStaleReservationCannotOverdraw", "ExpiryOnlySchedulesCleanupAndUnverifiedCleanupNeverFreesPhysicalBytes" })),
        ("ArcForges.Cloud.Modules.IQuotaMeasurementAuthority", "VerifyAsync", "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests", ["PositivePhysicalEvidenceAndDeletionReceiptsCannotBeCountedTwiceAcrossReservations", "ExpiryOnlySchedulesCleanupAndUnverifiedCleanupNeverFreesPhysicalBytes"]),
        ("ArcForges.Cloud.Modules.IQuotaKernelPort", "ReadBudgetAsync", "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests", ["MultiLimitAdmissionIsAtomicAndConcurrentStaleReservationCannotOverdraw"]),
        ("ArcForges.Cloud.Modules.IQuotaKernelPort", "ReadReservationAsync", "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests", ["ExpiryOnlySchedulesCleanupAndUnverifiedCleanupNeverFreesPhysicalBytes"]),
        ("ArcForges.Cloud.Modules.IQuotaKernelPort", "PublishBudgetAsync", "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests", ["DowngradePreservesMeasuredUseAndHoldsWhileNewAdmissionsFail"]),
        ("ArcForges.Cloud.Modules.IQuotaKernelPort", "ReserveAsync", "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests", ["MultiLimitAdmissionIsAtomicAndConcurrentStaleReservationCannotOverdraw", "CallerMutationCannotReplaceTermsBetweenCanonicalSnapshotAndAdmissionAuthority"]),
        ("ArcForges.Cloud.Modules.IQuotaKernelPort", "ApplyAsync", "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests", ["PositivePhysicalEvidenceAndDeletionReceiptsCannotBeCountedTwiceAcrossReservations", "JobTakeoverBetweenAuthorizationAndWriteRefusesOldFenceAndPreservesHolds"]),
        ("ArcForges.Cloud.Modules.IQuotaKernelPort", "RequestCleanupAsync", "ArcForges.Cloud.Tests.CapacityQuotaTests.QuotaKernelTests", ["ExpiryOnlySchedulesCleanupAndUnverifiedCleanupNeverFreesPhysicalBytes"]),
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

            foreach (string problem in PolicyBoundaryGuard.Check(compilation))
            {
                findings.Add(new PolicyFinding("BD", path, problem));
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
