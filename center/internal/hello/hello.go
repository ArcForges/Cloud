// SPDX-License-Identifier: AGPL-3.0-only

// Package hello is the anonymous, bounded Hello of the public contract arcforges.hello.v1, moved unchanged in behaviour from
// the Go Hello proof: a greeting of at most 256 UTF-16 code units, the same status codes and messages as the C# host, NUL and
// Unicode preserved byte for byte, and, with Neon enabled, the greeting read from PostgreSQL in a bounded read-only transaction
// with no local fallback.
package hello

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect/v2"
	hellov1 "github.com/ArcForges/Contracts/go/arcforges/hello/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxNameUTF16Units bounds the name, as the C# host counts it.
const MaxNameUTF16Units = 256

// Timeout bounds one greeting, the database included.
const Timeout = 15 * time.Second

// Greeting produces the greeting of a validated name.
type Greeting func(ctx context.Context, name string) (string, error)

// Stateless is the greeting without a database.
func Stateless(_ context.Context, name string) (string, error) { return "Hello, " + name + "!", nil }

// Server implements arcforges.hello.v1.HelloService.
type Server struct {
	Greeting Greeting
}

// SayHello greets a non-empty name of at most 256 UTF-16 code units.
func (s *Server) SayHello(ctx context.Context, request *hellov1.SayHelloRequest) (*hellov1.SayHelloResponse, error) {
	name := request.GetName()
	if name == "" || !utf8.ValidString(name) {
		return nil, connect.NewError(connect.CodeInvalidArgument, "Name must not be empty.")
	}
	units := 0
	for _, r := range name {
		units++
		if r > 0xffff {
			units++
		}
	}
	if units > MaxNameUTF16Units {
		return nil, connect.NewError(connect.CodeResourceExhausted, "Name exceeds 256 UTF-16 code units.")
	}
	deadline, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	message, err := s.Greeting(deadline, name)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, connect.NewError(connect.CodeDeadlineExceeded, "Hello request timed out.")
		}
		if errors.Is(err, context.Canceled) {
			return nil, connect.NewError(connect.CodeCanceled, "Hello request cancelled.")
		}
		// Never expose PostgreSQL errors or fall back to a successful local greeting.
		return nil, connect.NewError(connect.CodeUnavailable, "Hello database unavailable.")
	}
	return &hellov1.SayHelloResponse{Message: message}, nil
}

// Database is the greeting read from PostgreSQL: the same bytea concatenation as the C# host in a read-only transaction with a
// five-second statement timeout, so NUL and Unicode survive unchanged.
func Database(pool *pgxpool.Pool) Greeting {
	return func(ctx context.Context, name string) (string, error) {
		transaction, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return "", err
		}
		defer func() { _ = transaction.Rollback(ctx) }()
		if _, err = transaction.Exec(ctx, "SET LOCAL statement_timeout = 5000"); err != nil {
			return "", err
		}
		var greeting []byte
		err = transaction.QueryRow(ctx,
			"SELECT convert_to('Hello, ', 'UTF8') || $1::bytea || convert_to('!', 'UTF8')",
			[]byte(name)).Scan(&greeting)
		if err != nil {
			return "", err
		}
		if err = transaction.Rollback(ctx); err != nil {
			return "", err
		}
		return string(greeting), nil
	}
}
