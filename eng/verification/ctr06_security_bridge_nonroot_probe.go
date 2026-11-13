// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func main() {
	if os.Geteuid() != 1654 {
		fmt.Fprintln(os.Stderr, "unexpected probe uid")
		os.Exit(2)
	}
	result := map[string]string{}
	read := func(p string) error {
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		defer f.Close()
		h := sha256.New()
		if _, e = io.Copy(h, f); e != nil {
			return e
		}
		result[p] = hex.EncodeToString(h.Sum(nil))
		return nil
	}
	if err := read("/app/LICENSE"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	err := filepath.WalkDir("/app/notices", func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular %s", p)
		}
		return read(p)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"uid": os.Geteuid(), "members": result}); err != nil {
		os.Exit(5)
	}
}
