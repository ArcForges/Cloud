// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Identity.Core.Application;

/// <summary>A persistence failure is never an absent user or an authorization decision. Callers distinguish a temporary outage from generation skew and defects.</summary>
internal enum IdentityStorageFailure
{
    Unavailable,
    OutcomeUnknown,
    StaleGeneration,
    InvalidPlan,
}

/// <summary>Contains a closed reason only, never provider text, credentials or SQL. Cancellation is propagated separately.</summary>
internal sealed class IdentityStorageException(IdentityStorageFailure failure) : Exception("Identity persistence failed: " + failure)
{
    public IdentityStorageFailure Failure { get; } = failure;
}
