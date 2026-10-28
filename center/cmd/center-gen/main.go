// SPDX-License-Identifier: AGPL-3.0-only

// Command center-gen writes the outputs generated from the center's registrations. It is a development tool, never part of the
// image: `go run ./cmd/center-gen worker-tables` (or `python eng/center.py generate`) writes
// worker/tables/center-tables.generated.ts; `go run ./cmd/center-gen worker-tables -check` fails when the committed file differs.
// The center's Go test TestCommittedWorkerTablesAreCurrent runs the same check on both verification legs.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArcForges/Cloud/center/internal/workertables"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	check := len(arguments) == 2 && arguments[1] == "-check"
	if len(arguments) == 0 || arguments[0] != "worker-tables" || len(arguments) > 2 || (len(arguments) == 2 && !check) {
		return fmt.Errorf("usage: center-gen worker-tables [-check]")
	}
	root, err := workertables.RepositoryRoot(".")
	if err != nil {
		return err
	}
	generated, err := workertables.Generate()
	if err != nil {
		return err
	}
	target := filepath.Join(root, filepath.FromSlash(workertables.Path))
	if check {
		committed, err := os.ReadFile(target)
		if err != nil || string(committed) != generated {
			return fmt.Errorf("out of date: %s; run python eng/center.py generate and commit the result", workertables.Path)
		}
		fmt.Println("The generated Worker production table is current.")
		return nil
	}
	if err = os.WriteFile(target, []byte(generated), 0o644); err != nil {
		return err
	}
	fmt.Println("Generated " + workertables.Path + ".")
	return nil
}
