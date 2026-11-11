// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
)

// The proof is ephemeral; only its public digest is retained in PostgreSQL.
// Neither malformed input nor OIDC validation ever echoes the input bytes.
func readCTR06Proof(ctx context.Context, path string) (*bridgeproof.Verified, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 || before.Size() > 65536 {
		return nil, errors.New("invalid private proof file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("invalid private proof file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("invalid private proof file")
	}
	var envelope struct {
		Context bridgeproof.Context `json:"context"`
		Token   string              `json:"token"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.New("invalid private proof file")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid private proof file")
	}
	return bridgeproof.VerifyGitHub(ctx, envelope.Token, envelope.Context, time.Now())
}
