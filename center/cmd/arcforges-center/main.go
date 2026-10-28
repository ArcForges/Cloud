// SPDX-License-Identifier: AGPL-3.0-only

// Command arcforges-center is the ArcForges center: one executable that serves the public routes (serve, the default),
// applies the PostgreSQL migrations (migrate, from AF-CTR-02 part B) and reports its identity (version, --build-info).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ArcForges/Cloud/center/internal/buildinfo"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/server"
)

const usage = `usage: arcforges-center [command]

commands:
  serve         serve the public routes (the default); configured by ARCFORGES_CENTER_* (docs/center.md)
  migrate       apply the PostgreSQL migrations (not available in this build)
  version       print the build identity as JSON (also --build-info)
  help          print this help
`

func main() {
	os.Exit(run(os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

func run(arguments []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	command := "serve"
	if len(arguments) > 0 {
		command = arguments[0]
	}
	if len(arguments) > 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch command {
	case "serve":
		return serve(lookup, stderr)
	case "version", "--build-info":
		document, err := buildinfo.Document("not-probed", buildinfo.Center{})
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if err = json.NewEncoder(stdout).Encode(document); err != nil {
			return 1
		}
		return 0
	case "migrate":
		_, _ = fmt.Fprintln(stderr, "arcforges-center migrate is not available in this build: the PostgreSQL store and its migrations arrive with AF-CTR-02 part B; nothing was changed.")
		return 2
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
}

func serve(lookup func(string) (string, bool), stderr io.Writer) int {
	cfg, err := config.Load(lookup)
	logger := observe.NewLogger(stderr, cfg.LogLevel)
	if err != nil {
		logger.Error("the center refused to start", "error", err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = server.Run(ctx, cfg, logger); err != nil {
		logger.Error("the center stopped", "error", err.Error())
		return 1
	}
	return 0
}
