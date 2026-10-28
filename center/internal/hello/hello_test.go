// SPDX-License-Identifier: AGPL-3.0-only

package hello

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	hellov1 "github.com/ArcForges/Contracts/go/arcforges/hello/v1"
)

func TestTheBoundsAndStatusesAreTheHostOnes(t *testing.T) {
	server := &Server{Greeting: Stateless}
	for _, name := range []string{"ArcForges", "\u4e16\u754c \U0001f44b", "NUL\x00check", " ", strings.Repeat("x", 256), strings.Repeat("\U0001f44b", 128)} {
		reply, err := server.SayHello(t.Context(), &hellov1.SayHelloRequest{Name: name})
		if err != nil || reply.GetMessage() != "Hello, "+name+"!" {
			t.Fatalf("%q: %v", name, err)
		}
	}
	for name, want := range map[string]struct {
		code    connect.Code
		message string
	}{
		"":                                      {connect.CodeInvalidArgument, "Name must not be empty."},
		"\xff":                                  {connect.CodeInvalidArgument, "Name must not be empty."},
		strings.Repeat("x", 257):                {connect.CodeResourceExhausted, "Name exceeds 256 UTF-16 code units."},
		strings.Repeat("\U0001f44b", 129):       {connect.CodeResourceExhausted, "Name exceeds 256 UTF-16 code units."},
		strings.Repeat("\u00e9", 257):           {connect.CodeResourceExhausted, "Name exceeds 256 UTF-16 code units."},
		strings.Repeat("\U0001f44b", 128) + "x": {connect.CodeResourceExhausted, "Name exceeds 256 UTF-16 code units."},
	} {
		_, err := server.SayHello(t.Context(), &hellov1.SayHelloRequest{Name: name})
		var connectError *connect.Error
		if !errors.As(err, &connectError) || connectError.Code() != want.code || connectError.Message() != want.message {
			t.Fatalf("%q: %v", name, err)
		}
	}
}

func TestDatabaseFailureHasNoFallbackOrPrivateDetail(t *testing.T) {
	server := &Server{Greeting: func(context.Context, string) (string, error) { return "", errors.New("synthetic-private-credential") }}
	reply, err := server.SayHello(t.Context(), &hellov1.SayHelloRequest{Name: "ArcForges"})
	if reply != nil || connect.CodeOf(err) != connect.CodeUnavailable || strings.Contains(err.Error(), "synthetic-private") {
		t.Fatalf("database failure: %v", err)
	}
}

func TestCancellationAndDeadlinesKeepTheirStatus(t *testing.T) {
	server := &Server{Greeting: func(ctx context.Context, _ string) (string, error) { return "", ctx.Err() }}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := server.SayHello(ctx, &hellov1.SayHelloRequest{Name: "ArcForges"}); connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("cancellation: %v", err)
	}
	expired := &Server{Greeting: func(context.Context, string) (string, error) { return "", context.DeadlineExceeded }}
	if _, err := expired.SayHello(t.Context(), &hellov1.SayHelloRequest{Name: "ArcForges"}); connect.CodeOf(err) != connect.CodeDeadlineExceeded {
		t.Fatalf("deadline: %v", err)
	}
	if message, _ := Stateless(t.Context(), "x"); message != "Hello, x!" {
		t.Fatal(message)
	}
}
