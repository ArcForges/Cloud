// SPDX-License-Identifier: AGPL-3.0-only

package routes

import "time"

// SurfaceNodes is the configured surface for the V2 device and remote management APIs.
const SurfaceNodes = "nodes"

// The legacy bridge uses these deadlines while reconciling its retained cohort.
const (
	RoutedDeadline     = 10 * time.Second
	RoutedFileDeadline = 15 * time.Second
)

// Nodes registers the public V2 management APIs.
func Nodes() (Module, error) {
	module := Module{Name: "nodes", Surface: SurfaceNodes, Budgets: map[string]Budget{}}
	if err := addManagementRoutes(&module); err != nil {
		return Module{}, err
	}
	return module, nil
}
