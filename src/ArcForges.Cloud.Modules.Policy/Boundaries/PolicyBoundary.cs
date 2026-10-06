// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Policy.Boundaries;

/// <summary>
/// A control-plane restriction is never an entitlement, preference, runtime-readiness fact or request authorization.
/// Implementations carry this marker only within the Policy owner; the semantic architecture gate enforces the separation
/// through signatures, generic arguments, inheritance and executable references, including aliases.
/// </summary>
internal interface IPolicyControlPlaneValue;
