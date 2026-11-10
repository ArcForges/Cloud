// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package migrate

import "os"

type localBridgeExecutable struct {
	path       string
	digest     string
	extraFiles []*os.File
}

func openLocalBridge(string) (*localBridgeExecutable, error) {
	return nil, ErrCTR06RetirementUnproven
}
func (*localBridgeExecutable) close() {}
