// SPDX-License-Identifier: AGPL-3.0-only
// Phase 1 has no published and reviewed security-bridge successor to promote.
// A later reviewed change must bind the actual release and restore the guarded
// delivery path. No environment variable or caller claim can bypass this stop.
export function requireSecurityBridgeSuccessor(): void {
  throw new Error(
    "The security bridge successor is not yet bound; phase-1 bridge operations are unavailable.",
  );
}
