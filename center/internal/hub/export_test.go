// SPDX-License-Identifier: AGPL-3.0-only

package hub

// SigningInputs is how many signing inputs the hub built (the integration tests check that a malformed message reaches none).
func SigningInputs() int64 { return signingInputs.Load() }
