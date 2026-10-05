// SPDX-License-Identifier: AGPL-3.0-only
// The sentinel errors an ingress request aborts with. They are compared by identity, so every module
// that decides on an abort reason shares these instances.
export const deadlineError = new Error("RPC deadline exceeded.");
export const canceledError = new Error("Request canceled.");
export const bodyTimeoutError = new Error("Request body timed out.");
export const bodySizeError = new Error("Body size limit exceeded.");
export const coldStartError = new Error("Container did not become ready in time.");

/** gRPC status codes the Worker produces itself. */
export const grpcStatus = {
  canceled: 1,
  invalidArgument: 3,
  deadlineExceeded: 4,
  permissionDenied: 7,
  unavailable: 14,
  unauthenticated: 16,
} as const;
